use crate::api::e2e::{handle::IcHandle, testnet::Testnet};
use crate::tests::testcase_4_3_xnet_slo::stop_chatters;
use crate::tests::{cleanup_canister_ids, locate_canister_ids, testcase_4_3_xnet_slo::test_impl};

/// Testcase 4.3 in its end-to-end test incarnation.
///
/// Takes the IC instance to run on in the form of an already deployed testnet.
#[allow(clippy::too_many_arguments)]
pub async fn e2e_test(
    testnet: Testnet,
    subnets: Option<u64>,
    runtime: Option<u64>,
    rate: Option<u64>,
    payload_size: Option<u64>,
    targeted_latency: Option<u64>,
    key_file: Option<String>,
    wallet_canisters: Option<Vec<String>>,
    cycles_per_subnet: Option<u64>,
    canisters_to_cleanup: Option<Vec<String>>,
    skip_cleanup: bool,
    all_to_one: bool,
) {
    let ic = match key_file {
        Some(key_file) => IcHandle::from_testnet_with_principal_from_file(testnet, key_file),
        _ => IcHandle::from_testnet(testnet),
    };

    if let Some(canisters_to_cleanup) = canisters_to_cleanup {
        if skip_cleanup {
            println!(
                "Warning: --skip_cleanup flag is ignored when --canisters_to_cleanup is provided."
            );
        }
        let wallet_canisters = wallet_canisters.unwrap_or_default();
        // If there a some canisters left to be cleaned up we call stop() on them just
        // to be sure that they don't keep consuming cycles while we are
        // depositing them back onto the wallets.
        stop_chatters(
            &locate_canister_ids(canisters_to_cleanup.clone(), wallet_canisters.clone(), &ic)
                .iter()
                .map(|locator| locator.canister())
                .collect::<Vec<_>>(),
            |_| { /* do nothing */ },
        )
        .await;
        cleanup_canister_ids(canisters_to_cleanup, wallet_canisters, &ic).await;
        return;
    }

    test_impl(
        &ic,
        subnets,
        runtime,
        rate,
        payload_size,
        targeted_latency,
        wallet_canisters,
        cycles_per_subnet,
        skip_cleanup,
        all_to_one,
    )
    .await
}
