use crate::api::e2e::{handle::IcHandle, testnet::Testnet};
use crate::tests::testcase_5_2_does_not_stop::test_impl;

/// Testcase 5.2 in its end-to-end test incarnation.
///
/// Takes the IC instance to run on in the form of an already deployed testnet.
pub async fn e2e_test(
    testnet: Testnet,
    sleeptime: Option<u64>,
    num_canisters: Option<u64>,
    size_level: Option<u64>,
    random_seed: Option<u64>,
) {
    let ic = IcHandle::from_testnet(testnet);

    test_impl(&ic, sleeptime, num_canisters, size_level, random_seed).await
}
