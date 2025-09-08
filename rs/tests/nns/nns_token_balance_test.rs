/* tag::catalog[]
Title:: Balance is computed correctly and can be queried

Goal:: Demonstrate E2E that users can query ICPT balance and obtain a correct results

Runbook::
. Setup NNS with a ledger canister tracking test neurons' account
. Upgrade the `lifeline` canister to become universal
. Create 5 universal canisters in application subnet, these will have accounts
. Run a chain of 10 transactions (initiated from the UCs)
. Check expected balances between Txns for sender and recipient
. Check all accounts at the end
. Upgrade `governance` to become universal
. Use new `governance` to initiate transfers between neuron accounts
. Check balances of the subaccounts, considering fees.

Success:: balances obtained by queries matches expected balances after transfers

Notes:: Long term: Implement as property test, talk to DMD and Bogdan before starting. Needs addition of sub-account tests. We need to adopt a few items from OriginalRunbook (below).

Framework:: create IC principals and sign on their behalf, ledger canister part of NNS initialization, send queries and update requests and process their responses

Coverage::
. Ledger accounts can be manipulated in a way that respect the global invariants
. Querying ledger accounts (also with subaccounts) works
. Subaccounts behave as expected w.r.t. transfers

end::catalog[] */

use anyhow::Result;
use canister_test::Canister;
use dfn_candid::candid_one;
use futures::future::join_all;
use ic_canister_client::Sender;
use ic_ledger_core::tokens::{CheckedAdd, CheckedSub};
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_2_ID, TEST_NEURON_2_OWNER_KEYPAIR,
};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID};
use ic_nns_governance_api::{GovernanceError, Neuron, governance_error::ErrorType};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_system_test_driver::{
    driver::{
        ic::InternetComputer,
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
        },
    },
    util::{
        UniversalCanister, block_on, get_icp_balance, runtime_from_url, transact_icp,
        transact_icp_subaccount,
    },
};
use ic_types::CanisterId;
use icp_ledger::{DEFAULT_TRANSFER_FEE, Subaccount, Tokens};
use slog::info;
use std::convert::TryFrom;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn test(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let nns_agent = nns_node.with_default_agent(|agent| async move { agent });
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let app_node = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap()
        .nodes()
        .next()
        .unwrap();
    let app_agent = app_node.with_default_agent(|agent| async move { agent });
    info!(log, "Installing NNS canisters ...");
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters");

    block_on(async move {
        // upgrade the `lifeline` canister, since it is the minting
        // canister as tracked by the ledger
        let lifeline = UniversalCanister::upgrade_with_args(
            &nns_runtime,
            &nns_agent,
            &LIFELINE_CANISTER_ID,
            Vec::new(),
        )
        .await;
        let (can1, can2, can3, can4, can5) = tokio::join!(
            UniversalCanister::new_with_retries(&app_agent, app_node.effective_canister_id(), &log),
            UniversalCanister::new_with_retries(&app_agent, app_node.effective_canister_id(), &log),
            UniversalCanister::new_with_retries(&app_agent, app_node.effective_canister_id(), &log),
            UniversalCanister::new_with_retries(&app_agent, app_node.effective_canister_id(), &log),
            UniversalCanister::new_with_retries(&app_agent, app_node.effective_canister_id(), &log)
        );
        let ledger = Canister::new(&nns_runtime, LEDGER_CANISTER_ID);

        // verify that `lifeline` (as the minting canister) is fully stocked
        let minting_balance = Tokens::from_tokens(10000).unwrap();
        assert_eq!(
            Ok(minting_balance),
            get_icp_balance(
                &ledger,
                &CanisterId::try_from(lifeline.canister_id().as_slice()).unwrap(),
                None
            )
            .await
        );

        let fee = DEFAULT_TRANSFER_FEE.get_e8s();
        assert_eq!(
            transact_icp(&log, &ledger, &lifeline, 400, &can1).await,
            Ok(Tokens::from_e8s(400))
        );
        assert_eq!(
            transact_icp(&log, &ledger, &lifeline, 1800 + 3 * fee, &can2,).await,
            Ok(Tokens::from_e8s(1800 + 3 * fee))
        );
        assert_eq!(
            transact_icp(&log, &ledger, &can2, 750, &can3).await,
            Ok(Tokens::from_e8s(750))
        );
        assert_eq!(
            transact_icp(&log, &ledger, &lifeline, 859 + 2 * fee, &can4).await,
            Ok(Tokens::from_e8s(859 + 2 * fee))
        );
        assert_eq!(
            transact_icp(&log, &ledger, &lifeline, 23 + 2 * fee, &can5).await,
            Ok(Tokens::from_e8s(23 + 2 * fee))
        );
        assert_eq!(
            transact_icp(&log, &ledger, &lifeline, 1750, &can2).await,
            Ok(Tokens::from_e8s(2800 + fee * 2))
        );
        // transact_icp(&logger, &ledger, &can4, 1000, &lifeline) // not possible
        assert_eq!(
            transact_icp(&log, &ledger, &can2, 800, &can5).await,
            Ok(Tokens::from_e8s(823 + fee * 2))
        );
        assert_eq!(
            transact_icp(&log, &ledger, &can5, 0, &can5).await,
            Ok(Tokens::from_e8s(823 + fee))
        ); // self, zero
        assert_eq!(
            transact_icp(&log, &ledger, &can5, 42, &can5).await,
            Ok(Tokens::from_e8s(823))
        ); // self
        assert_eq!(
            transact_icp(&log, &ledger, &can2, 0, &can5).await,
            Ok(Tokens::from_e8s(823))
        ); // zero
        assert_eq!(
            transact_icp(&log, &ledger, &lifeline, fee, &can5).await,
            Ok(Tokens::from_e8s(823 + fee))
        ); // zero

        async fn get_uc_balance(
            ledger: &Canister<'_>,
            can: &UniversalCanister<'_>,
        ) -> Result<Tokens, String> {
            get_icp_balance(
                ledger,
                &CanisterId::try_from(can.canister_id().as_slice()).unwrap(),
                None,
            )
            .await
        }

        // check whether all accounts still sum up
        let account_holders = [&lifeline, &can1, &can2, &can3, &can4, &can5];
        let obtainers = account_holders
            .iter()
            .map(|a| get_uc_balance(&ledger, a))
            .collect::<Vec<_>>();
        let funds: Vec<_> = join_all(obtainers).await;
        assert_eq!(
            minting_balance
                .checked_sub(&Tokens::from_e8s(11 * fee))
                .unwrap(),
            funds.iter().fold(Tokens::ZERO, |s, f| s
                .checked_add(&f.clone().unwrap())
                .unwrap())
        );

        // as a preparation, get the subaccounts of neurons
        let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

        // verify that test identity is not authorised
        let authz_fail = governance
            .query_(
                "get_full_neuron",
                candid_one::<Result<Neuron, GovernanceError>, _>,
                TEST_NEURON_1_ID,
            )
            .await
            .expect("cannot obtain full_neuron?");
        assert_eq!(
            authz_fail.err().unwrap().error_type,
            ErrorType::NotAuthorized as i32
        );

        let n1 = governance
            .query_from_sender(
                "get_full_neuron",
                candid_one::<Result<Neuron, GovernanceError>, _>,
                TEST_NEURON_1_ID,
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .expect("cannot obtain full_neuron?")
            .expect("error accessing neuron?");

        let n2 = governance
            .query_from_sender(
                "get_full_neuron",
                candid_one::<Result<Neuron, GovernanceError>, _>,
                TEST_NEURON_2_ID,
                &Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR),
            )
            .await
            .expect("cannot obtain full_neuron?")
            .expect("error accessing neuron?");

        // upgrade `governance` to universal
        let governance = UniversalCanister::upgrade_with_args(
            &nns_runtime,
            &nns_agent,
            &GOVERNANCE_CANISTER_ID,
            Vec::new(),
        )
        .await;

        // perform a few subaccount transfers
        // first: account -> subaccount
        let subaccount2 =
            Subaccount::try_from(n2.account.as_slice()).expect("vector size is not 32?");

        assert_eq!(
            transact_icp_subaccount(
                &log,
                &ledger,
                (&can5, None),
                100,
                (&governance, Some(subaccount2)),
            )
            .await,
            Ok(Tokens::from_e8s(100_000_100))
        );

        // second: subaccount -> subaccount
        let subaccount1 =
            Subaccount::try_from(n1.account.as_slice()).expect("vector size is not 32?");

        assert_eq!(
            transact_icp_subaccount(
                &log,
                &ledger,
                (&governance, Some(subaccount2)),
                100,
                (&governance, Some(subaccount1)),
            )
            .await,
            Ok(Tokens::from_e8s(1_000_000_100))
        );

        // third: subaccount -> subaccount (checking the fee consumption from second
        // step)
        assert_eq!(
            transact_icp_subaccount(
                &log,
                &ledger,
                (&governance, Some(subaccount1)),
                100,
                (&governance, Some(subaccount2))
            )
            .await,
            Ok(Tokens::from_e8s(100_000_100 - fee))
        );

        // fourth: subaccount -> account (checking the fee consumption from first step)
        assert_eq!(
            transact_icp_subaccount(
                &log,
                &ledger,
                (&governance, Some(subaccount2)),
                100,
                (&can5, None),
            )
            .await,
            Ok(Tokens::from_e8s(823))
        );
    });
}
