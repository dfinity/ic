use crate::ni_dkg::fs_ni_dkg::forward_secure::{CHUNK_MAX, CHUNK_MIN, CHUNK_SIZE};
use crate::ni_dkg::fs_ni_dkg::nizk_chunking::{CHALLENGE_BITS, NUM_ZK_REPETITIONS};
use ic_crypto_internal_bls12_381_type::{Gt, Scalar};
use std::sync::LazyLock;
pub struct HonestDealerDlogLookupTable {
    table: Vec<u32>,
}
static LINEAR_DLOG_SEARCH: LazyLock<HonestDealerDlogLookupTable> =
    LazyLock::new(HonestDealerDlogLookupTable::create);

impl HonestDealerDlogLookupTable {
    fn create() -> Self {
        let mut x = Gt::identity();

        let mut table = vec![0u32; CHUNK_SIZE];
        for i in CHUNK_MIN..=CHUNK_MAX {
            table[i as usize] = x.short_hash_for_linear_search();
            x += Gt::generator();
        }

        Self { table }
    }

    pub fn new() -> &'static Self {
        &LINEAR_DLOG_SEARCH
    }

    /// Solve several discrete logarithms
    pub fn solve_several(&self, targets: &[Gt]) -> Vec<Option<Scalar>> {
        use subtle::{ConditionallySelectable, ConstantTimeEq};

        let target_hashes = targets
            .iter()
            .map(|t| t.short_hash_for_linear_search())
            .collect::<Vec<_>>();

        // This code assumes that CHUNK_MAX fits in a u16
        let mut scan_results = vec![0u16; targets.len()];

        for x in CHUNK_MIN..=CHUNK_MAX {
            let x_hash = self.table[x as usize];

            for i in 0..targets.len() {
                let hashes_eq = x_hash.ct_eq(&target_hashes[i]);
                scan_results[i].conditional_assign(&(x as u16), hashes_eq);
            }
        }

        // Now confirm the results (since collisions may have occurred
        // if the dealer was dishonest) and convert to Scalar

        let mut results = Vec::with_capacity(targets.len());

        for i in 0..targets.len() {
            /*
            After finding a candidate we must perform a multiplication in order
            to tell if we found the dlog correctly, or if there was a collision
            due to a dishonest dealer.

            If no match was found then scan_results[i] will just be zero, we
            perform the multiplication anyway and then reject the candidate dlog.
             */
            if Gt::g_mul_u16(scan_results[i]) == targets[i] {
                results.push(Some(Scalar::from_u64(scan_results[i] as u64)));
            } else {
                results.push(None);
            }
        }

        results
    }
}

/*
* To minimize the memory stored in the BSGS table, instead of storing
* elements of Gt directly (576 bytes) we first hash them using
* SHA-224.  This reduces the memory consumption by approximately a
* factor of 20, and is quite fast to compute especially as production
* node machines all have SHA-NI support.
*
* Rust's HashMap usually hashes using SipHash with a random seed.
* This prevents against denial of service attacks caused by malicious
* keys. Here we instead use a very simple hash which is safe because
* we know that all of our keys were generated via a cryptographic hash
* already. This also disables the randomization step. This is safe
* because we only ever hash the serialization of elements of Gt g*i,
* where i is a smallish integer that depends on various NIDKG
* parameters.
*/

struct ShiftXorHasher {
    state: u64,
}

impl std::hash::Hasher for ShiftXorHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.state = self.state.rotate_left(8) ^ u64::from(byte);
        }
    }

    fn finish(&self) -> u64 {
        self.state
    }
}

struct BuildShiftXorHasher;

impl std::hash::BuildHasher for BuildShiftXorHasher {
    type Hasher = ShiftXorHasher;
    fn build_hasher(&self) -> ShiftXorHasher {
        ShiftXorHasher { state: 0 }
    }
}

struct BabyStepGiantStepTable {
    // Table storing the baby steps
    table: Vec<([u8; Self::GT_REPR_SIZE], usize)>,
    prefix_set: std::collections::HashSet<[u8; Self::GT_REPR_PREFIX_SIZE], BuildShiftXorHasher>,
}

/// The table for storing the baby steps of BSGS
///
/// TODO(CRP-2308) use a better data structure than HashMap here.
impl BabyStepGiantStepTable {
    const GT_REPR_SIZE: usize = 28;
    /// The byte length of the prefix is chosen to be the smallest possible that
    /// gives us a small number of false positives. The space of the prefixes
    /// is, therefore, 2^(5*8) = 2^40. Given that we use the hash prefix, the
    /// prefixes are pseudo-random. Therefore, the probability of having a false
    /// positive equals the number of possible prefixes (2^40) divided by the
    /// number of distinct prefixes in the table. For simplicity, we bound this
    /// probability by the number of the prefixes in general, which is the case
    /// when all stored prefixes are indeed distinct.
    ///
    /// Our BSGS table contains around a million elements for multiplier 1 with
    /// current production subnet sizes (e.g., 28 nodes -> 978928, 40 nodes ->
    /// 1170043). In production, we use a table with multiplier 20, totaling in
    /// approx. 20mil elements. The probability of a false positive is therefore
    /// bounded by 2^log2(20mil)/2^40, which is approx. 1 in 55 thousand. If we
    /// increase the multiplier to our current optimal value (approx. 64), then
    /// the probability is around 1 in 17 thousand. Given that on a false
    /// positive we only need to perform one additional lookup that is slower by
    /// a small constant (say, very roughly, factor 5 slowdown), handling false
    /// positives is a small runtime overhead.
    ///
    /// If it happens that the table size is increased by much more, then we can
    /// reduce the false positive probability simply by increasing the prefix
    /// size by 1 byte or more.
    const GT_REPR_PREFIX_SIZE: usize = 5;

    fn hash_gt(gt: &Gt) -> ([u8; Self::GT_REPR_PREFIX_SIZE], [u8; Self::GT_REPR_SIZE]) {
        let hash = ic_crypto_sha2::Sha224::hash(&gt.tag());
        let prefix =
            <[u8; Self::GT_REPR_PREFIX_SIZE]>::try_from(&hash[0..Self::GT_REPR_PREFIX_SIZE])
                .unwrap_or_else(|_| {
                    panic!(
                        "hash should always be larger than {}B",
                        Self::GT_REPR_PREFIX_SIZE
                    )
                });
        (prefix, hash)
    }

    /// Return a table size appropriate for solving BSGS in [0,range) while
    /// keeping within the given table size constraints.
    ///
    /// The default size is the square root of the range, as is usual for BSGS.
    /// If the memory limit allows for it, instead a small multiple of the
    /// sqrt is used. However we always use at least the square root of the range,
    /// since decreasing below that increases the costs of the online step.
    fn compute_table_size(range: usize, max_mbytes: usize, max_table_mul: usize) -> usize {
        let sqrt = (range as f64).sqrt().ceil() as usize;

        // Number of bytes per element in the main (Gt->usize) table
        let main_table_bytes_per_elem = Self::GT_REPR_SIZE + 8;

        // Estimate of HashMap/HashSet overhead from https://ntietz.com/blog/rust-hashmap-overhead/
        let hash_set_overhead = 1.73_f64;

        let prefix_filter_bytes_per_elem = hash_set_overhead * (Self::GT_REPR_PREFIX_SIZE as f64);

        let storage =
            (main_table_bytes_per_elem as f64 + prefix_filter_bytes_per_elem) * (sqrt as f64);

        let max_bytes = max_mbytes * 1024 * 1024;

        for mult in (1..=max_table_mul).rev() {
            let est_storage = ((mult as f64) * storage) as usize;

            if est_storage < max_bytes {
                return mult * sqrt;
            }
        }

        sqrt
    }

    /// Returns the table plus the giant step
    fn new(base: &Gt, table_size: usize) -> (Self, Gt) {
        let mut table = Vec::with_capacity(table_size);
        let mut prefix_set =
            std::collections::HashSet::with_capacity_and_hasher(table_size, BuildShiftXorHasher);
        let mut accum = Gt::identity();

        for i in 0..table_size {
            let (prefix, hash) = Self::hash_gt(&accum);
            table.push((hash, i));
            // we are not checking the return value of `insert` because
            // duplicate prefixes do not affect the correctness
            prefix_set.insert(prefix);
            accum += base;
        }
        table.sort_unstable();

        (Self { table, prefix_set }, accum.neg())
    }

    /// Return the value if gt exists in this table
    fn get(&self, gt: &Gt) -> Option<usize> {
        let (prefix, hash) = Self::hash_gt(gt);
        if self.prefix_set.contains(&prefix) {
            match self.table.binary_search_by_key(&hash, |&(key, _value)| key) {
                Ok(i) => Some(self.table[i].1),
                _ => None,
            }
        } else {
            None
        }
    }
}

pub struct BabyStepGiantStep {
    // Table storing the baby steps
    table: BabyStepGiantStepTable,
    // Group element `G * -n`, where `G` is the base element used for the discrete log problem.
    giant_step: Gt,
    // Group element used as an offset to scale down the discrete log in the `0..range`.
    offset: Gt,
    // Size of the baby steps table
    n: usize,
    // Number of giant steps to take
    giant_steps: usize,
    // Integer representing the smallest discrete log in the search space.
    lo: isize,
}

impl BabyStepGiantStep {
    /// Set up a table for Baby-Step Giant-step to solve the discrete logarithm
    /// problem in the range `[lo..lo+range)` with respect to base element `base`.
    ///
    /// To reduce the cost of the online search phase of the algorithm, this
    /// implementation supports using a larger table than the typical `sqrt(n)`.
    /// The parameters `max_mbytes` and `max_table_mul` control how large a
    /// table is created. We always create at least a `sqrt(n)` sized table, but
    /// try to create instead `k*sqrt(n)` sized if the parameters allow.
    ///
    /// `max_table_mul` controls the maximum value of `k`. Setting
    /// `max_table_mul` to zero is effectively ignored.
    ///
    /// `max_mbytes` sets a limit on the total memory consumed by the table.
    /// This is not precise as, while we try to account for the overhead of the
    /// data structure used, it is based only on some rough estimates.
    pub fn new(
        base: &Gt,
        lo: isize,
        range: usize,
        max_mbytes: usize,
        max_table_mul: usize,
    ) -> Self {
        let table_size =
            BabyStepGiantStepTable::compute_table_size(range, max_mbytes, max_table_mul);

        let giant_steps = if range > 0 && table_size > 0 {
            range.div_ceil(table_size)
        } else {
            0
        };

        let (table, giant_step) = BabyStepGiantStepTable::new(base, table_size);

        let offset = base * Scalar::from_isize(lo).neg();

        Self {
            table,
            giant_step,
            offset,
            n: table_size,
            giant_steps,
            lo,
        }
    }

    /// Solve the discrete logarithm problem for the group element `tgt` using
    /// Baby-Step Giant-Step.
    ///
    /// Returns `None` if the discrete logarithm is not in the searched range.
    pub fn solve(&self, tgt: &Gt) -> Option<Scalar> {
        let mut step = tgt + &self.offset;

        for giant_step in 0..self.giant_steps {
            if let Some(i) = self.table.get(&step) {
                let x = self.lo + (i + self.n * giant_step) as isize;
                return Some(Scalar::from_isize(x));
            }
            step += &self.giant_step;
        }

        None
    }
}

pub struct CheatingDealerDlogSolver {
    baby_giant: BabyStepGiantStep,
    // Maximum scale factor used by a malicious dealer for out-of-range chunks.
    scale_range: usize,
}

impl CheatingDealerDlogSolver {
    const MAX_TABLE_MBYTES: usize = 2 * 1024; // 2 GiB

    // We limit the maximum table size when compiling without optimizations
    // since otherwise the table becomes so expensive to compute that bazel
    // will fail the test with timeouts.
    const LARGEST_TABLE_MUL: usize = if cfg!(debug_assertions) { 2 } else { 20 };

    pub fn new(n: usize, m: usize) -> Self {
        let scale_range = 1 << CHALLENGE_BITS;
        let ss = n * m * (CHUNK_SIZE - 1) * (scale_range - 1);
        let zz = 2 * NUM_ZK_REPETITIONS * ss;

        let bsgs_lo = 1 - zz as isize;
        let bsgs_range = 2 * zz - 1;

        let baby_giant = BabyStepGiantStep::new(
            Gt::generator(),
            bsgs_lo,
            bsgs_range,
            Self::MAX_TABLE_MBYTES,
            Self::LARGEST_TABLE_MUL,
        );
        Self {
            baby_giant,
            scale_range,
        }
    }

    /// Searches for discrete log for a malicious DKG participant whose NIZK
    /// chunking proof checks out, which implies certain bounds on the search
    ///
    /// This function is not constant time, but it only leaks information in the
    /// event that a dealer is already dishonest, and the only information it
    /// leaks is the value that the dishonest dealer sent.
    pub fn solve(&self, target: &Gt) -> Option<Scalar> {
        /*
        For some Delta in [1..E - 1] the answer s satisfies (Delta * s) in
        [1 - Z..Z - 1].

        For each delta in [1..E - 1] we compute target*delta and use
        baby-step-giant-step to find `scaled_answer` such that:
           base*scaled_answer = target*delta

         Then `base * (scaled_answer / delta) = target`
          (here division is modulo the group order
         That is, the discrete log of target is `scaled_answer / delta`.
        */
        let mut target_power = Gt::identity();
        for delta in 1..self.scale_range {
            target_power += target;

            if let Some(scaled_answer) = self.baby_giant.solve(&target_power) {
                let inv_delta = Scalar::from_usize(delta)
                    .inverse()
                    .expect("Delta is always invertible");
                let result = scaled_answer * inv_delta;
                return Some(result);
            }
        }
        None
    }
}
