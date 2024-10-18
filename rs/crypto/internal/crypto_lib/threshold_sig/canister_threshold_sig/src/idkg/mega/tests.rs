use crate::{CanisterThresholdError, IDkgDealingInternal, MEGaPrivateKey, SecretShares};
use ic_crypto_internal_seed::Seed;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

#[test]
fn should_fail_if_commitment_check_opening_fails() {
    let alg = crate::IdkgProtocolAlgorithm::EcdsaSecp256k1;
    let curve = alg.curve();
    let associated_data = b"assoc_data_test";

    let rng = &mut reproducible_rng();

    let sk0 = MEGaPrivateKey::generate(curve, rng);
    let pk0 = sk0.public_key();

    let sk1 = MEGaPrivateKey::generate(curve, rng);
    let pk1 = sk1.public_key();

    let dealer_index = 0;
    let receiver_index = 1;
    let threshold = 1;

    let dealing = IDkgDealingInternal::new(
        &SecretShares::Random,
        alg,
        Seed::from_rng(rng),
        threshold,
        &[pk0.clone(), pk1.clone()],
        dealer_index,
        associated_data,
    )
    .expect("should create dealing");

    // decrypt_and_check should fail because the receiver index does not match the key indexes; the
    // receiver index is 1, but the provided secret key `sk0` and public key `pk0` are at index 0.
    assert_eq!(
        dealing.ciphertext.decrypt_and_check(
            alg,
            &dealing.commitment,
            associated_data,
            dealer_index,
            receiver_index,
            &sk0,
            &pk0,
        ),
        Err(CanisterThresholdError::InvalidCommitment)
    );
}
