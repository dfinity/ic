use crate::*;

/// Corrupts this dealing by modifying the ciphertext intended for
/// recipient(s) indicated with `corruption_targets`.
///
/// This is only intended for testing and should not be called in
/// production code.
pub fn corrupt_dealing(
    dealing: &IDkgDealingInternal,
    corruption_targets: &[NodeIndex],
    randomness: ic_types::Randomness,
) -> ThresholdEcdsaResult<IDkgDealingInternal> {
    let curve_type = dealing.commitment.curve_type();

    let mut rng = Seed::from_randomness(&randomness).into_rng();
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
    randomness: ic_types::Randomness,
) -> ThresholdEcdsaResult<IDkgDealingInternal> {
    let all_recipients = (0..dealing.ciphertext.recipients() as NodeIndex).collect::<Vec<_>>();
    corrupt_dealing(dealing, &all_recipients, randomness)
}
