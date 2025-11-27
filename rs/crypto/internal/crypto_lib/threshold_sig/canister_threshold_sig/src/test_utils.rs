use crate::{zk::ProofOfDLogEquivalence, *};
use strum::EnumIter;

/// Corrupts this dealing by modifying the ciphertext intended for
/// recipient(s) indicated with `corruption_targets`.
///
/// This is only intended for testing and should not be called in
/// production code.
pub fn corrupt_dealing(
    dealing: &IDkgDealingInternal,
    corruption_targets: &[NodeIndex],
    seed: Seed,
) -> CanisterThresholdResult<IDkgDealingInternal> {
    let curve_type = dealing.commitment.curve_type();

    let rng = &mut seed.into_rng();
    let randomizer = EccScalar::random(curve_type, rng);

    let ciphertext = match &dealing.ciphertext {
        MEGaCiphertext::Single(c) => {
            let mut ctexts = c.ctexts.to_vec();

            for target in corruption_targets {
                let target = *target as usize;
                ctexts[target] = ctexts[target].add(&randomizer)?;
            }

            MEGaCiphertextSingle {
                ephemeral_key: c.ephemeral_key.clone(),
                pop_public_key: c.pop_public_key.clone(),
                pop_proof: c.pop_proof.clone(),
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
                ephemeral_key: c.ephemeral_key.clone(),
                pop_public_key: c.pop_public_key.clone(),
                pop_proof: c.pop_proof.clone(),
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

/// Corrupts a complaint using the functionality that corresponds to the enum variant.
///
/// This is only intended for testing and should not be called in production code.
#[derive(Debug, EnumIter)]
pub enum ComplaintCorrupter {
    /// Corrupts ZK proof in the complaint by incrementing the underlying ECC scalars by 1,
    /// `shared_secret` remains correct.
    CorruptZkProof,
    /// Overwhelmingly likely corrupts `shared_secret` in `complaint` by
    /// doubling it, ZK proof remains correct.
    CorruptSharedSecret,
}

impl ComplaintCorrupter {
    /// Corrupts a complaint using the function that this struct was initialized with.
    pub fn clone_and_corrupt_complaint(
        &self,
        complaint: &IDkgComplaintInternal,
    ) -> Result<IDkgComplaintInternal, CanisterThresholdError> {
        match self {
            Self::CorruptZkProof => Self::corrupt_complaint_zk_proof(complaint),
            Self::CorruptSharedSecret => Self::corrupt_complaint_shared_secret(complaint),
        }
    }

    fn corrupt_complaint_zk_proof(
        complaint: &IDkgComplaintInternal,
    ) -> CanisterThresholdResult<IDkgComplaintInternal> {
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
            shared_secret: complaint.shared_secret.clone(),
        })
    }

    fn corrupt_complaint_shared_secret(
        complaint: &IDkgComplaintInternal,
    ) -> CanisterThresholdResult<IDkgComplaintInternal> {
        // double `shared_secret` which likely invalides it
        let corrupted_shared_secret = complaint.shared_secret.mul_by_node_index_vartime(1u32)?;

        // return a corrupted `IDkgComplaintInternal` instance
        Ok(IDkgComplaintInternal {
            proof: complaint.proof.clone(),
            shared_secret: corrupted_shared_secret,
        })
    }
}

/// Corrupts `opening` by incrementing the contained scalar(s) by one
///
/// This is only intended for testing and should not be called in
/// production code.
pub fn corrupt_opening(opening: &CommitmentOpening) -> CanisterThresholdResult<CommitmentOpening> {
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
