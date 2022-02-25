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

use crate::util::{
    assert_create_agent, get_icp_balance, get_random_application_node_endpoint,
    get_random_nns_node_endpoint, runtime_from_url, transact_icp, transact_icp_subaccount,
    UniversalCanister,
};

use ic_fondue::{ic_instance::InternetComputer, ic_manager::IcHandle};

use crate::nns::NnsExt;

use canister_test::Canister;
use dfn_candid::candid_one;
use futures::future::join_all;
use ic_canister_client::Sender;
use ic_nns_constants::{
    ids::{TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_2_OWNER_KEYPAIR},
    GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID,
};
use ic_nns_governance::pb::v1::{governance_error::ErrorType, GovernanceError, Neuron};
use ic_nns_test_utils::ids::{TEST_NEURON_1_ID, TEST_NEURON_2_ID};
use ic_registry_subnet_type::SubnetType;
use ic_types::CanisterId;
use ledger_canister::{Subaccount, Tokens, DEFAULT_TRANSFER_FEE};
use std::convert::TryFrom;

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    // Install NNS canisters
    ctx.install_nns_canisters(&handle, true);

    let mut rng = ctx.rng.clone();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        // choose a random nodes from the nns subnet
        let nns_endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
        nns_endpoint.assert_ready(ctx).await;

        // choose a random node from the application subnet
        let application_endpoint = get_random_application_node_endpoint(&handle, &mut rng);
        application_endpoint.assert_ready(ctx).await;

        // upgrade the `lifeline` canister, since it is the minting
        // canister as tracked by the ledger
        let nns = runtime_from_url(nns_endpoint.url.clone());
        let nns_agent = assert_create_agent(nns_endpoint.url.as_str()).await;
        let lifeline = UniversalCanister::upgrade(&nns, &nns_agent, &LIFELINE_CANISTER_ID).await;

        let agent = assert_create_agent(application_endpoint.url.as_str()).await;
        let (can1, can2, can3, can4, can5) = tokio::join!(
            UniversalCanister::new(&agent),
            UniversalCanister::new(&agent),
            UniversalCanister::new(&agent),
            UniversalCanister::new(&agent),
            UniversalCanister::new(&agent)
        );
        let ledger = Canister::new(&nns, LEDGER_CANISTER_ID);

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
            transact_icp(ctx, &ledger, &lifeline, 400, &can1).await,
            Ok(Tokens::from_e8s(400))
        );
        assert_eq!(
            transact_icp(ctx, &ledger, &lifeline, 1800 + 3 * fee, &can2,).await,
            Ok(Tokens::from_e8s(1800 + 3 * fee))
        );
        assert_eq!(
            transact_icp(ctx, &ledger, &can2, 750, &can3).await,
            Ok(Tokens::from_e8s(750))
        );
        assert_eq!(
            transact_icp(ctx, &ledger, &lifeline, 859 + 2 * fee, &can4).await,
            Ok(Tokens::from_e8s(859 + 2 * fee))
        );
        assert_eq!(
            transact_icp(ctx, &ledger, &lifeline, 23 + 2 * fee, &can5).await,
            Ok(Tokens::from_e8s(23 + 2 * fee))
        );
        assert_eq!(
            transact_icp(ctx, &ledger, &lifeline, 1750, &can2).await,
            Ok(Tokens::from_e8s(2800 + fee * 2))
        );
        // transact_icp(ctx, &ledger, &can4, 1000, &lifeline) // not possible
        assert_eq!(
            transact_icp(ctx, &ledger, &can2, 800, &can5).await,
            Ok(Tokens::from_e8s(823 + fee * 2))
        );
        assert_eq!(
            transact_icp(ctx, &ledger, &can5, 0, &can5).await,
            Ok(Tokens::from_e8s(823 + fee))
        ); // self, zero
        assert_eq!(
            transact_icp(ctx, &ledger, &can5, 42, &can5).await,
            Ok(Tokens::from_e8s(823))
        ); // self
        assert_eq!(
            transact_icp(ctx, &ledger, &can2, 0, &can5).await,
            Ok(Tokens::from_e8s(823))
        ); // zero
        assert_eq!(
            transact_icp(ctx, &ledger, &lifeline, fee, &can5).await,
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
        let account_holders = vec![&lifeline, &can1, &can2, &can3, &can4, &can5];
        let obtainers = account_holders
            .iter()
            .map(|a| get_uc_balance(&ledger, a))
            .collect::<Vec<_>>();
        let funds: Vec<_> = join_all(obtainers).await;
        assert_eq!(
            (minting_balance - Tokens::from_e8s(11 * fee)).unwrap(),
            funds
                .iter()
                .fold(Tokens::ZERO, |s, f| (s + f.clone().unwrap()).unwrap())
        );

        // as a preparation, get the subaccounts of neurons
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);

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
            authz_fail.err().unwrap().error_type(),
            ErrorType::NotAuthorized
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
        let governance =
            UniversalCanister::upgrade(&nns, &nns_agent, &GOVERNANCE_CANISTER_ID).await;

        // perform a few subaccount transfers
        // first: account -> subaccount
        let subaccount2 =
            Subaccount::try_from(n2.account.as_slice()).expect("vector size is not 32?");

        assert_eq!(
            transact_icp_subaccount(
                ctx,
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
                ctx,
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
                ctx,
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
                ctx,
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
