use crate::ni_dkg::fs_ni_dkg::forward_secure::{CHUNK_MAX, CHUNK_MIN, CHUNK_SIZE};
use crate::ni_dkg::fs_ni_dkg::nizk_chunking::{CHALLENGE_BITS, NUM_ZK_REPETITIONS};
use ic_crypto_internal_bls12_381_type::{Gt, Scalar};

pub struct HonestDealerDlogLookupTable {
    table: Vec<u32>,
}

lazy_static::lazy_static! {
    static ref LINEAR_DLOG_SEARCH: HonestDealerDlogLookupTable = HonestDealerDlogLookupTable::create();
}

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

        // Now confirm the results (since collisions may have occured
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

pub struct BabyStepGiantStep {
    // Table storing the baby steps
    table: std::collections::HashMap<[u8; Gt::BYTES], isize>,
    // Group element `G * -n`, where `G` is the base element used for the discrete log problem.
    giant_step: Gt,
    // Group element used as an offset to scale down the discrete log in the `0..range`.
    offset: Gt,
    // Size of the baby steps table
    n: isize,
    // Integer representing the smallest discrete log in the search space.
    lo: isize,
    // Size of the search space.
    range: isize,
}

impl BabyStepGiantStep {
    /// Set up a table for Baby-Step Giant-step to solve the discrete logarithm
    /// problem in the range `lo..lo+range` with respect to base element `base``.
    pub fn new(base: &Gt, lo: isize, range: isize) -> Self {
        let n = (range as f64).sqrt().ceil() as isize;

        let mut table = std::collections::HashMap::new();
        let mut accum = Gt::identity();

        for i in 0..n {
            table.insert(accum.tag(), i);
            accum += base;
        }

        let giant_step = accum.neg();

        let offset = base * Scalar::from_isize(lo).neg();

        Self {
            table,
            giant_step,
            offset,
            n,
            lo,
            range,
        }
    }

    /// Solve the discrete logarithm problem for the group element `tgt` using
    /// Baby-Step Giant-Step.
    ///
    /// Returns `None` if the discrete logarithm is not in the searched range.
    pub fn solve(&self, tgt: &Gt) -> Option<Scalar> {
        let baby_steps = if self.range > 0 && self.n >= 0 {
            self.range / self.n
        } else {
            0
        };

        let mut step = tgt + &self.offset;

        for baby_step in 0..baby_steps {
            if let Some(i) = self.table.get(&step.tag()) {
                let x = self.lo + self.n * baby_step;
                return Some(Scalar::from_isize(x + i));
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
    pub fn new(n: usize, m: usize) -> Self {
        let scale_range = 1 << CHALLENGE_BITS;
        let ss = n * m * (CHUNK_SIZE - 1) * (scale_range - 1);
        let zz = (2 * NUM_ZK_REPETITIONS * ss) as isize;

        let baby_giant = BabyStepGiantStep::new(Gt::generator(), 1 - zz, 2 * zz - 1);
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
