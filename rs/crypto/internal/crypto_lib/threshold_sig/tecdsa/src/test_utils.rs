use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::{zk::ProofOfDLogEquivalence, *};

/// Corrupts this dealing by modifying the ciphertext intended for
/// recipient(s) indicated with `corruption_targets`.
///
/// This is only intended for testing and should not be called in
/// production code.
pub fn corrupt_dealing(
    dealing: &IDkgDealingInternal,
    corruption_targets: &[NodeIndex],
    seed: Seed,
) -> ThresholdEcdsaResult<IDkgDealingInternal> {
    let curve_type = dealing.commitment.curve_type();

    let mut rng = seed.into_rng();
    let randomizer = EccScalar::random(curve_type, &mut rng)?;

    let ciphertext = match &dealing.ciphertext {
        MEGaCiphertext::Single(c) => {
            let mut ctexts = c.ctexts.to_vec();

            for target in corruption_targets {
                let target = *target as usize;
                ctexts[target] = ctexts[target].add(&randomizer)?;
            }

            MEGaCiphertextSingle {
                ephemeral_key: c.ephemeral_key,
                pop_public_key: c.pop_public_key,
                pop_proof: c.pop_proof,
                ctexts,
            }
            .into()
        }
        MEGaCiphertext::Pairs(c) => {
            let mut ctexts = c.ctexts.to_vec();

            for target in corruption_targets {
                let target = *target as usize;
                ctexts[target].0 = ctexts[target].0.add(&randomizer)?;
            }

            MEGaCiphertextPair {
                ephemeral_key: c.ephemeral_key,
                pop_public_key: c.pop_public_key,
                pop_proof: c.pop_proof,
                ctexts,
            }
            .into()
        }
    };

    Ok(IDkgDealingInternal {
        ciphertext,
        commitment: dealing.commitment.clone(),
        proof: dealing.proof.clone(),
    })
}

/// Corrupts this dealing for all receivers by modifying the ciphertexts
///
/// This is only intended for testing and should not be called in
/// production code.
pub fn corrupt_dealing_for_all_recipients(
    dealing: &IDkgDealingInternal,
    seed: Seed,
) -> ThresholdEcdsaResult<IDkgDealingInternal> {
    let all_recipients = (0..dealing.ciphertext.recipients() as NodeIndex).collect::<Vec<_>>();
    corrupt_dealing(dealing, &all_recipients, seed)
}

/// Corrupts ZK proof in the complaint by incrementing the underlying ECC scalars by 1,
/// `shared_secret` remains correct
///
/// This is only intended for testing and should not be called in
/// production code.
pub fn corrupt_complaint_zk_proof(
    complaint: &IDkgComplaintInternal,
) -> ThresholdEcdsaResult<IDkgComplaintInternal> {
    let curve_type = complaint.proof.challenge.curve_type();

    // corrupt challenge and response
    let corrupted_challenge = complaint.proof.challenge.add(&EccScalar::one(curve_type))?;
    let corrupted_response = complaint.proof.response.add(&EccScalar::one(curve_type))?;

    // construct `ProofOfDLogEquivalence` from corrupted `challenge` and `response`
    let corrupted_zk_proof = ProofOfDLogEquivalence {
        challenge: corrupted_challenge,
        response: corrupted_response,
    };

    // return a corrupted `IDkgComplaintInternal` instance
    Ok(IDkgComplaintInternal {
        proof: corrupted_zk_proof,
        shared_secret: complaint.shared_secret,
    })
}

/// Likely corrupts `shared_secret` in `complaint` by doubling it,
/// ZK proof remains correct
///
/// This is only intended for testing and should not be called in
/// production code.
pub fn corrupt_complaint_shared_secret(
    complaint: &IDkgComplaintInternal,
) -> ThresholdEcdsaResult<IDkgComplaintInternal> {
    // double `shared_secret` which likely invalides it
    let corrupted_shared_secret = complaint.shared_secret.mul_by_node_index(1u32)?;

    // return a corrupted `IDkgComplaintInternal` instance
    Ok(IDkgComplaintInternal {
        proof: complaint.proof,
        shared_secret: corrupted_shared_secret,
    })
}

/// Corrupts `opening` by incrementing the contained scalar(s) by one
///
/// This is only intended for testing and should not be called in
/// production code.
pub fn corrupt_opening(opening: &CommitmentOpening) -> ThresholdEcdsaResult<CommitmentOpening> {
    let corrupted_opening: CommitmentOpening = match &opening {
        CommitmentOpening::Simple(x) => {
            let corrupted_x = x.add(&EccScalar::one(x.curve_type()))?;
            CommitmentOpening::Simple(corrupted_x)
        }
        CommitmentOpening::Pedersen(x, y) => {
            let corrupted_x = x.add(&EccScalar::one(x.curve_type()))?;
            let corrupted_y = y.add(&EccScalar::one(y.curve_type()))?;
            CommitmentOpening::Pedersen(corrupted_x, corrupted_y)
        }
    };
    Ok(corrupted_opening)
}

pub fn seeded_rng() -> ChaCha20Rng {
    let mut thread_rng = rand::thread_rng();
    let seed = thread_rng.gen::<u64>();
    println!("RNG seed {}", seed);
    ChaCha20Rng::seed_from_u64(seed)
}
