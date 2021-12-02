//! Tests of the whole NiDKG protocol
use crate::vault::local_csp_vault::test_utils::new_csp_vault;
use crate::vault::test_utils;
use crate::vault::test_utils::ni_dkg::fixtures::MockNetwork;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4,
        max_shrink_iters: 0,
        .. ProptestConfig::default()
    })]

    #[test]
    fn ni_dkg_should_work_with_all_players_acting_correctly(seed: [u8;32], network_size in MockNetwork::MIN_SIZE..MockNetwork::DEFAULT_MAX_SIZE, num_reshares in 0..4) {
      test_utils::ni_dkg::test_ni_dkg_should_work_with_all_players_acting_correctly(seed, network_size, num_reshares, new_csp_vault);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4,
        max_shrink_iters: 0,
        .. ProptestConfig::default()
    })]

    #[test]
    fn create_dealing_should_detect_errors(seed: [u8;32], network_size in MockNetwork::MIN_SIZE..=MockNetwork::DEFAULT_MAX_SIZE, num_reshares in 0..4) {
      test_utils::ni_dkg::test_create_dealing_should_detect_errors(seed, network_size, num_reshares, new_csp_vault);
    }
}

#[test]
fn test_retention() {
    test_utils::ni_dkg::test_retention(new_csp_vault);
}
