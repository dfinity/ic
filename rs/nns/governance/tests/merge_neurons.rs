//! The unit tests for `Governance` use *test fixtures*. The fixtures
//! are defi data_source: (), timestamp_seconds: ()ned as small but
//! complex/weird configurations of neurons and proposals against which several
//! tests are run.

use fixtures::{NNSBuilder, NeuronBuilder};
use futures::future::FutureExt;
use ic_base_types::PrincipalId;
use ic_nervous_system_common::ONE_YEAR_SECONDS;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance::{
    governance::MAX_DISSOLVE_DELAY_SECONDS,
    pb::v1::{
        ManageNeuron,
        manage_neuron::{Command, Merge},
    },
};
use ic_nns_governance_api::{
    NetworkEconomics,
    manage_neuron_response::{Command as CommandResponse, MergeResponse},
};
use proptest::prelude::{TestCaseError, proptest};

#[cfg(feature = "tla")]
use ic_nns_governance::governance::tla::{TLA_TRACES_LKEY, check_traces as tla_check_traces};
#[cfg(feature = "tla")]
use tla_instrumentation_proc_macros::with_tla_trace_check;

// Using a `pub mod` works around spurious dead code warnings; see
// https://github.com/rust-lang/rust/issues/46379
pub mod fixtures;

const DEFAULT_TEST_START_TIMESTAMP_SECONDS: u64 = 999_111_000_u64;

#[allow(clippy::too_many_arguments)]
#[allow(clippy::vec_init_then_push)]
fn do_test_merge_neurons(
    mut n1_cached_stake: u64,
    n1_maturity: u64,
    n1_fees: u64,
    n1_dissolve: u64,
    n1_age: u64,
    mut n2_cached_stake: u64,
    n2_maturity: u64,
    n2_fees: u64,
    n2_dissolve: u64,
    n2_age: u64,
) -> Result<(), TestCaseError> {
    // Ensure that the cached_stake includes the fees
    n1_cached_stake += n1_fees;
    n2_cached_stake += n2_fees;

    // Start the NNS 20 years after genesis, to give lots of time for aging.
    let epoch = DEFAULT_TEST_START_TIMESTAMP_SECONDS + (20 * ONE_YEAR_SECONDS);

    let controller = PrincipalId::new_user_test_id(42);

    let mut nns = NNSBuilder::new()
        .set_start_time(epoch)
        .set_economics(NetworkEconomics::with_default_values())
        .with_supply(0) // causes minting account to be created
        .add_account_for(controller, 0)
        // the source
        .add_neuron(
            NeuronBuilder::new(1, n1_cached_stake, controller)
                .set_dissolve_delay(n1_dissolve)
                .set_maturity(n1_maturity)
                .set_neuron_fees(n1_fees)
                .set_aging_since_timestamp(epoch.saturating_sub(n1_age)),
        )
        // the target
        .add_neuron(
            NeuronBuilder::new(2, n2_cached_stake, controller)
                .set_dissolve_delay(n2_dissolve)
                .set_maturity(n2_maturity)
                .set_neuron_fees(n2_fees)
                .set_aging_since_timestamp(epoch.saturating_sub(n2_age)),
        )
        .create();

    // advance by a year, just to spice things up
    nns.advance_time_by(ONE_YEAR_SECONDS);

    // First simulate
    let simulate_neuron_response = nns.governance.simulate_manage_neuron(
        &controller,
        ManageNeuron {
            id: Some(NeuronId { id: 2 }),
            neuron_id_or_subaccount: None,
            command: Some(Command::Merge(Merge {
                source_neuron_id: Some(NeuronId { id: 1 }),
            })),
        },
    );

    let merge_neuron_response = nns
        .governance
        .merge_neurons(
            &NeuronId { id: 2 },
            &controller,
            &Merge {
                source_neuron_id: Some(NeuronId { id: 1 }),
            },
        )
        .now_or_never()
        .unwrap()
        .unwrap();

    // Assert simulated result is the same as actual result
    pretty_assertions::assert_eq!(merge_neuron_response, simulate_neuron_response);

    // Assert that simulate response gives correct outputs
    match merge_neuron_response.command.unwrap() {
        CommandResponse::Merge(m) => {
            let MergeResponse {
                source_neuron,
                target_neuron,
                source_neuron_info,
                target_neuron_info,
            } = m;
            let source_neuron = source_neuron.unwrap();
            let target_neuron = target_neuron.unwrap();
            let source_neuron_info = source_neuron_info.unwrap();
            let target_neuron_info = target_neuron_info.unwrap();

            let source_neuron_id = source_neuron.id.unwrap();
            let target_neuron_id = target_neuron.id.unwrap();

            pretty_assertions::assert_eq!(
                source_neuron,
                nns.governance
                    .get_full_neuron(&source_neuron_id, &source_neuron.controller.unwrap())
                    .unwrap()
            );
            pretty_assertions::assert_eq!(
                target_neuron,
                nns.governance
                    .get_full_neuron(&target_neuron_id, &target_neuron.controller.unwrap())
                    .unwrap()
            );
            pretty_assertions::assert_eq!(
                source_neuron_info,
                nns.governance
                    .get_neuron_info(&source_neuron_id, controller)
                    .unwrap()
            );
            pretty_assertions::assert_eq!(
                target_neuron_info,
                nns.governance
                    .get_neuron_info(&target_neuron_id, controller)
                    .unwrap()
            );
        }
        CommandResponse::Error(e) => panic!("Received Error: {e}"),
        _ => panic!("Wrong response received"),
    }

    Ok(())
}

proptest! {

#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_merge_neurons_small(
    n1_stake in 0u64..50_000,
    n1_maturity in 0u64..500_000_000,
    n1_fees in 0u64..20_000,
    n1_dissolve in 1u64..MAX_DISSOLVE_DELAY_SECONDS,
    n1_age in 0u64..315_360_000,
    n2_stake in 0u64..50_000,
    n2_maturity in 0u64..500_000_000,
    n2_fees in 0u64..20_000,
    n2_dissolve in 1u64..MAX_DISSOLVE_DELAY_SECONDS,
    n2_age in 0u64..315_360_000
) {
    do_test_merge_neurons(
        n1_stake,
        n1_maturity,
        n1_fees,
        n1_dissolve,
        n1_age,
        n2_stake,
        n2_maturity,
        n2_fees,
        n2_dissolve,
        n2_age,
    )?;
}

#[test]
fn test_merge_neurons_normal(
    n1_stake in 0u64..500_000_000,

    n1_maturity in 0u64..500_000_000,
    n1_fees in 0u64..20_000,
    n1_dissolve in 1u64..MAX_DISSOLVE_DELAY_SECONDS,
    n1_age in 0u64..315_360_000,
    n2_stake in 0u64..500_000_000,
    n2_maturity in 0u64..500_000_000,
    n2_fees in 0u64..20_000,
    n2_dissolve in 1u64..MAX_DISSOLVE_DELAY_SECONDS,
    n2_age in 0u64..315_360_000
) {
    do_test_merge_neurons(
        n1_stake,
        n1_maturity,
        n1_fees,
        n1_dissolve,
        n1_age,
        n2_stake,
        n2_maturity,
        n2_fees,
        n2_dissolve,
        n2_age,
    )?;
}

}
