use ic_fondue::log::info;

use crate::util::{get_random_nns_node_endpoint, runtime_from_url};

use ic_fondue::{ic_manager::IcHandle, internet_computer::InternetComputer};

use ic_nns_governance::pb::v1::{GovernanceError, NeuronInfo};

use crate::nns::NnsExt;
use canister_test::Canister;
use dfn_candid::candid_one;

use ic_nns_common::types::NeuronId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::pb::v1::governance_error::ErrorType;
use ic_registry_subnet_type::SubnetType;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;

/// A test runs within a given IC configuration.
pub fn config() -> InternetComputer {
    InternetComputer::new().add_fast_single_node_subnet(SubnetType::System)
}

/// This is a simple example (proof of concept) of how the Proptest framework
/// can be employed to fuzz test a canister API method.
///
/// What is tested here is not very interesting. The intention is that this can
/// serve as a basis to write more interesting fuzz tests for canisters using
/// the Proptest framework in the future.
///
/// Note that `TestRunner::run` cannot be used since that does not work for
/// `async` methods. Also, the `proptest!` macro cannot be used in this context
/// because it is intended for unit tests (i.e. with `#[test]` annotation)
pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    ctx.install_nns_canisters(&handle, true);
    let mut rng = ctx.rng.clone();
    let endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        endpoint.assert_ready(ctx).await;
        let nns = runtime_from_url(endpoint.url.clone());

        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);

        let mut runner = TestRunner::default();
        for _ in 0..256 {
            let neuron_id = Box::new((0..u64::MAX).new_tree(&mut runner).unwrap());
            assert!(
                get_neuron_returns_not_found_error(&governance, ctx, neuron_id.current()).await
            );
            // If the assertion fails, it would be possible to apply 'shrinking'
            // to find the 'simplest' input that causes a failure. We could do
            // this at a later point.
            // See https://altsysrq.github.io/proptest-book/proptest/tutorial/shrinking-basics.html.
        }
    });
}

async fn get_neuron_returns_not_found_error(
    governance: &Canister<'_>,
    ctx: &ic_fondue::pot::Context,
    neuron_id: u64,
) -> bool {
    info!(
        ctx.logger,
        "getting neuron info for neuron id {:?}", neuron_id
    );
    let result = governance
        .query_(
            "get_neuron_info",
            candid_one::<Result<NeuronInfo, GovernanceError>, NeuronId>,
            NeuronId(neuron_id),
        )
        .await;
    result.unwrap()
        == Err(GovernanceError {
            error_type: ErrorType::NotFound as i32,
            error_message: "".to_string(),
        })
}
