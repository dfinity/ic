use ic_crypto_temp_crypto_vault::RemoteVaultEnvironment;
use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;
use proptest::proptest;
use proptest::result::maybe_err;
use std::sync::Arc;

use ic_crypto_internal_csp::vault::api::PublicRandomSeedGeneratorError;
use ic_crypto_internal_csp_proptest_utils::{arb_public_random_seed_generator_error, arb_seed};
use ic_crypto_internal_seed::Seed;

mod common;
use common::proptest_config_for_delegation;

proptest! {
    #![proptest_config(proptest_config_for_delegation())]
    #[test]
    fn should_delegate_for_new_public_seed(
        expected_result in maybe_err(arb_seed(), arb_public_random_seed_generator_error())
    ) {
        let mut local_vault = MockLocalCspVault::new();
        local_vault
            .expect_new_public_seed()
            .times(1)
            .return_const(expected_result.clone());
        let env = RemoteVaultEnvironment::start_server_with_local_csp_vault(Arc::new(local_vault));
        let remote_vault = env.new_vault_client();

        let result = remote_vault.new_public_seed();

        assert_equals_comparing_seeds_indirectly(result, expected_result);
    }
}

fn assert_equals_comparing_seeds_indirectly(
    actual: Result<Seed, PublicRandomSeedGeneratorError>,
    expected: Result<Seed, PublicRandomSeedGeneratorError>,
) {
    match (actual, expected) {
        (Ok(actual_seed), Ok(expected_seed)) => {
            // Seed voluntarily does not implement Eq, PartialEq to avoid extracting the value
            // We compare 2 Seeds indirectly by instantiating 2 RNGs and checking we get the same result.
            let actual_rng = actual_seed.into_rng();
            let expected_rng = expected_seed.into_rng();
            assert_eq!(actual_rng, expected_rng);
        }
        (Err(actual_err), Err(expected_err)) => assert_eq!(actual_err, expected_err),
        _ => panic!("unexpected result"),
    }
}
