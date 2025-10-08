use anyhow::Result;
use candid::{Decode, Nat};
use canister_test::{Canister, Project, Wasm};
use cycles_minting::{TestAgent, UserHandle, make_user_ed25519};
use cycles_minting_canister::{CREATE_CANISTER_REFUND_FEE, DEFAULT_CYCLES_PER_XDR, TokensToCycles};
use dfn_candid::candid_one;
use ic_canister_client::{HttpClient, Sender};
use ic_config::subnet_config::CyclesAccountManagerConfig;
use ic_ledger_core::tokens::CheckedAdd;
use ic_limits::{MAX_INGRESS_BYTES_PER_MESSAGE_APP_SUBNET, SMALL_APP_SUBNET_MAX_SIZE};
use ic_management_canister_types_private::{CanisterIdRecord, CanisterStatusResultV2};
use ic_nervous_system_clients::canister_status::CanisterStatusResult as RootCanisterStatusResult;
use ic_nervous_system_common_test_keys::{
    TEST_USER1_KEYPAIR, TEST_USER1_PRINCIPAL, TEST_USER2_KEYPAIR,
};
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, ROOT_CANISTER_ID,
};
use ic_nns_test_utils::governance::upgrade_nns_canister_by_proposal;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::InternetComputer;
use ic_system_test_driver::systest;
use ic_system_test_driver::{
    driver::{
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
        },
    },
    nns::set_authorized_subnetwork_list,
    util::{block_on, runtime_from_url},
};
use ic_types::Cycles;
use icp_ledger::{Operation, Tokens};
use num_traits::ToPrimitive;
use slog::info;

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
    let logger = env.logger();
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters");
    let app_node = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap()
        .nodes()
        .next()
        .unwrap();
    block_on(async move {
        let agent_client = HttpClient::new();
        let tst = TestAgent::new(&nns_node.get_public_url(), &agent_client);
        let user1 = UserHandle::new(
            &nns_node.get_public_url(),
            &agent_client,
            &TEST_USER1_KEYPAIR,
            LEDGER_CANISTER_ID,
            CYCLES_MINTING_CANISTER_ID,
        );
        let user2 = UserHandle::new(
            &nns_node.get_public_url(),
            &agent_client,
            &TEST_USER2_KEYPAIR,
            LEDGER_CANISTER_ID,
            CYCLES_MINTING_CANISTER_ID,
        );

        let (controller_user_keypair, controller_pid) = make_user_ed25519(7);
        let controller_user = UserHandle::new(
            &nns_node.get_public_url(),
            &agent_client,
            &controller_user_keypair,
            LEDGER_CANISTER_ID,
            CYCLES_MINTING_CANISTER_ID,
        );

        let xdr_permyriad_per_icp = 1_000_000; // = 100 XDR/ICP
        let icpts_to_cycles = TokensToCycles {
            xdr_permyriad_per_icp,
            cycles_per_xdr: DEFAULT_CYCLES_PER_XDR.into(),
        };

        let cmc_canister_status: RootCanisterStatusResult = Canister::new(&nns, ROOT_CANISTER_ID)
            .update_from_sender(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(CYCLES_MINTING_CANISTER_ID),
                &Sender::Anonymous,
            )
            .await
            .unwrap();
        let cmc_initial_cycles_balance = cmc_canister_status.cycles.0.to_u64().unwrap();

        /* The first attempt to create a canister should fail because we
         * haven't registered subnets with the cycles minting canister. */
        info!(logger, "creating canister (no subnets)");

        let send_amount = Tokens::new(0, 1_000_000).unwrap();

        let (err, refund_block) = user1
            .create_canister_cmc(send_amount, None, &controller_user, None, None)
            .await
            .unwrap_err();

        info!(logger, "error: {}", err);
        assert!(err.contains("No subnets in which to create a canister"));

        /* Check that the funds for the failed creation attempt are returned to use
         * (minus the fees). */
        let refund_block = refund_block.unwrap();
        tst.check_refund(
            refund_block,
            send_amount,
            CREATE_CANISTER_REFUND_FEE,
            *TEST_USER1_PRINCIPAL,
        )
        .await;

        /* Register a subnet. */
        info!(logger, "registering subnets");
        let app_subnet_ids: Vec<_> = topology
            .subnets()
            .filter_map(|s| (s.subnet_type() == SubnetType::Application).then_some(s.subnet_id))
            .collect();
        set_authorized_subnetwork_list(&nns, None, app_subnet_ids.clone())
            .await
            .unwrap();

        /* Create with funds < the canister creation fee. */
        info!(logger, "creating canister (not enough funds)");

        let small_amount = Tokens::new(0, 30_000).unwrap();

        let (err, no_refund_block) = user1
            .create_canister_cmc(small_amount, None, &controller_user, None, None)
            .await
            .unwrap_err();

        info!(logger, "error: {}", err);
        assert!(err.contains("Creating a canister requires a fee of"));

        /* There should be no refund, all the funds will be burned. */
        assert!(no_refund_block.is_none());

        let block = tst.get_tip().await.unwrap();
        let txn = block.transaction();

        match txn.operation {
            Operation::Burn {
                from,
                amount,
                spender,
            } => {
                assert_eq!(small_amount, amount);
                assert_eq!(tst.get_balance(from).await, Tokens::ZERO);
                assert_eq!(spender, None);
            }
            _ => panic!("unexpected block {txn:?}"),
        }

        /* Create with sufficient funds. */
        info!(logger, "creating canister");

        let initial_amount = Tokens::new(50, 0).unwrap();

        let bh = user1
            .pay_for_canister(initial_amount, None, &controller_pid)
            .await;
        let new_canister_id = controller_user
            .notify_canister_create_cmc(bh, None, &controller_pid, None, None)
            .await
            .unwrap();

        // second notify should return the success result together with canister id
        let tip = tst.get_tip().await.unwrap();
        let can_id = controller_user
            .notify_canister_create_cmc(bh, None, &controller_pid, None, None)
            .await
            .unwrap();
        assert_eq!(new_canister_id, can_id);
        let tip2 = tst.get_tip().await.unwrap();
        assert_eq!(tip, tip2, "No block should have been created");

        /* Check that the funds for the canister creation attempt are burned. */
        let block = tst.get_tip().await.unwrap();
        let txn = block.transaction();

        match txn.operation {
            Operation::Burn {
                from,
                amount,
                spender,
            } => {
                assert_eq!(amount, initial_amount);
                assert_eq!(tst.get_balance(from).await, Tokens::ZERO);
                assert_eq!(spender, None);
            }
            _ => panic!("unexpected block {txn:?}"),
        }

        // notification through the ledger path should fail
        user1
            .notify_canister_create_ledger(bh, None, &controller_pid)
            .await
            .unwrap_err();

        info!(logger, "topping up");

        let topup1 = Tokens::new(5, 0).unwrap();
        let topup2 = Tokens::new(5, 0).unwrap();
        let topup3 = Tokens::new(15, 0).unwrap();
        let top_up_amount = topup1
            .checked_add(&topup2)
            .unwrap()
            .checked_add(&topup3)
            .unwrap();

        user1
            .top_up_canister_cmc(topup1, None, &new_canister_id)
            .await
            .unwrap();
        assert_eq!(
            tst.get_balance(user1.acc_for_top_up(&new_canister_id))
                .await,
            Tokens::ZERO,
            "All funds from cmc subaccount should have disappeared"
        );

        let bh = user1.pay_for_top_up(topup2, None, &new_canister_id).await;
        user1
            .notify_top_up_cmc(bh, None, &new_canister_id)
            .await
            .unwrap();
        // ledger path should fail
        user1
            .notify_top_up_ledger(bh, None, &new_canister_id)
            .await
            .unwrap_err();

        let tip = tst.get_tip().await.unwrap();
        // cmc now returns the status of notification (so success again, but doesn't mint cycles again)
        user1
            .notify_top_up_cmc(bh, None, &new_canister_id)
            .await
            .unwrap();
        let tip2 = tst.get_tip().await.unwrap();
        assert_eq!(tip, tip2, "No block should have been created");

        let bh = user1.pay_for_top_up(topup3, None, &new_canister_id).await;

        // ledger notification should fail
        user1
            .notify_top_up_ledger(bh, None, &new_canister_id)
            .await
            .unwrap_err();
        // cmc should return successful topup status
        user1
            .notify_top_up_cmc(bh, None, &new_canister_id)
            .await
            .unwrap();

        assert_eq!(
            tst.get_balance(user1.acc_for_top_up(&new_canister_id))
                .await,
            Tokens::ZERO,
            "All funds from cmc subaccount should have disappeared after topups"
        );

        // notification should fail on ledger path
        user2
            .notify_top_up_ledger(bh, None, &new_canister_id)
            .await
            .unwrap_err();

        /* Check the controller / cycles balance. */
        let new_canister_status: CanisterStatusResultV2 =
            runtime_from_url(app_node.get_public_url(), app_node.effective_canister_id())
                .get_management_canister_with_effective_canister_id(new_canister_id.into())
                .update_from_sender(
                    "canister_status",
                    candid_one,
                    CanisterIdRecord::from(new_canister_id),
                    &Sender::from_keypair(&controller_user_keypair),
                )
                .await
                .unwrap();
        assert_eq!(new_canister_status.controller(), controller_pid);
        let config = CyclesAccountManagerConfig::application_subnet();
        let max_fees = scale_cycles(
            config.canister_creation_fee
                + config.ingress_message_reception_fee
                + config.ingress_byte_reception_fee * MAX_INGRESS_BYTES_PER_MESSAGE_APP_SUBNET,
        )
        .get();
        let expected_cycles = icpts_to_cycles
            .to_cycles(initial_amount.checked_add(&top_up_amount).unwrap())
            .get();
        assert!(new_canister_status.cycles() <= expected_cycles);
        assert!(new_canister_status.cycles() >= expected_cycles.checked_sub(max_fees).unwrap());
        // Ensure that `max_fees` are neglibigle (less than 1%) w.r.t. `expected_cycles`
        // and thus the above check that `new_canister_status.cycles()`
        // are in [expected_cycles - max_fees..expected_cycles] is meaningful.
        assert!(100 * max_fees < expected_cycles);

        /* Check that the funds for the canister top up attempt are burned. */
        let block = tst.get_tip().await.unwrap();
        let txn = block.transaction();

        match txn.operation {
            Operation::Burn {
                from,
                amount,
                spender,
            } => {
                assert_eq!(amount, topup3);
                assert_eq!(tst.get_balance(from).await, Tokens::ZERO);
                assert_eq!(spender, None);
            }
            _ => panic!("unexpected block {txn:?}"),
        }

        /* Override the list of subnets for a specific controller. */
        info!(logger, "registering subnets override");
        let system_subnet_ids: Vec<_> = topology
            .subnets()
            .filter_map(|s| (s.subnet_type() == SubnetType::System).then_some(s.subnet_id))
            .collect();
        set_authorized_subnetwork_list(&nns, Some(controller_pid), system_subnet_ids)
            .await
            .unwrap();

        info!(logger, "creating NNS canister");

        let nns_amount = Tokens::new(0, 1_000_000).unwrap();

        let new_canister_id = user1
            .create_canister_cmc(nns_amount, None, &controller_user, None, None)
            .await
            .unwrap();

        /* Check the controller / cycles balance. */
        let new_canister_status: CanisterStatusResultV2 = nns
            .get_management_canister_with_effective_canister_id(new_canister_id.into())
            .update_from_sender(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(new_canister_id),
                &Sender::from_keypair(&controller_user_keypair),
            )
            .await
            .unwrap();

        assert_eq!(new_canister_status.controller(), controller_pid);
        assert_eq!(
            new_canister_status.cycles(),
            icpts_to_cycles.to_cycles(nns_amount).get()
        );

        /* Try upgrading the cycles minting canister. This should
         * preserve its state (such as the principal -> subnets
         * mappings). Note: we first update to a dummy canister
         * because upgrade_nns_canister_by_proposal() doesn't want to
         * upgrade to the same version of the canister. */
        info!(logger, "upgrading cycles minting canister to empty module");

        let wasm = wat::parse_str("(module)").unwrap();

        let arg = candid::encode_one(Some(cycles_minting_canister::CyclesCanisterInitPayload {
            ledger_canister_id: Some(LEDGER_CANISTER_ID),
            governance_canister_id: Some(GOVERNANCE_CANISTER_ID),
            cycles_ledger_canister_id: None,
            exchange_rate_canister: None,
            minting_account_id: None,
            last_purged_notification: None,
        }))
        .unwrap();

        upgrade_nns_canister_by_proposal(
            &Canister::new(&nns, CYCLES_MINTING_CANISTER_ID),
            &Canister::new(&nns, GOVERNANCE_CANISTER_ID),
            &Canister::new(&nns, ROOT_CANISTER_ID),
            true,
            Wasm::from_bytes(wasm),
            Some(arg),
        )
        .await;

        info!(logger, "creating NNS canister (will fail)");
        let block = user1
            .pay_for_canister(nns_amount, None, &controller_pid)
            .await;
        let err = controller_user
            .notify_canister_create_cmc(block, None, &controller_pid, None, None)
            .await
            .unwrap_err();

        assert!(
            err.0.contains("has no update method"),
            "Error message was: {}",
            err.0
        );

        info!(logger, "upgrading cycles minting canister");
        let wasm = Project::cargo_bin_maybe_from_env("cycles-minting-canister", &[]);

        let arg = candid::encode_one(Some(cycles_minting_canister::CyclesCanisterInitPayload {
            ledger_canister_id: Some(LEDGER_CANISTER_ID),
            governance_canister_id: Some(GOVERNANCE_CANISTER_ID),
            cycles_ledger_canister_id: None,
            exchange_rate_canister: None,
            minting_account_id: None,
            last_purged_notification: None,
        }))
        .unwrap();

        upgrade_nns_canister_by_proposal(
            &Canister::new(&nns, CYCLES_MINTING_CANISTER_ID),
            &Canister::new(&nns, GOVERNANCE_CANISTER_ID),
            &Canister::new(&nns, ROOT_CANISTER_ID),
            true,
            wasm,
            Some(arg),
        )
        .await;

        info!(logger, "creating NNS canister");

        controller_user
            .notify_canister_create_cmc(block, None, &controller_pid, None, None)
            .await
            .unwrap();

        /* Exceed the daily cycles minting limit. */
        info!(logger, "creating canister (exceeding daily limit)");

        let amount = Tokens::new(1_500, 0).unwrap();

        let (err, refund_block) = user1
            .create_canister_cmc(amount, None, &controller_user, None, None)
            .await
            .unwrap_err();

        info!(logger, "error: {}", err);
        assert!(
            err.contains(
                "cycles have been minted in the last 3600 seconds, please try again later"
            )
        );

        let refund_block = refund_block.unwrap();
        tst.check_refund(
            refund_block,
            amount,
            CREATE_CANISTER_REFUND_FEE,
            *TEST_USER1_PRINCIPAL,
        )
        .await;

        /* Test getting the total number of cycles minted. */
        let result: Vec<u8> = tst
            .query(&CYCLES_MINTING_CANISTER_ID, "total_cycles_minted", vec![])
            .await
            .unwrap();
        let cycles_minted: Nat = Decode!(&result, Nat).unwrap();

        // Total ICPs successfully minted.
        let total_icpts = initial_amount
            .checked_add(&top_up_amount)
            .unwrap()
            .checked_add(&nns_amount)
            .unwrap()
            .checked_add(&nns_amount)
            .unwrap();

        // Cycles are only minted when the amount needed exceeds the cycles balance of the CMC, so
        // the total amount of cylces is the sum of the minted cycles and the initial cycles
        // balance.
        let total_cycles: Nat = cycles_minted + cmc_initial_cycles_balance;

        assert_eq!(
            total_cycles,
            Nat::from(icpts_to_cycles.to_cycles(total_icpts))
        );
    });
}

fn scale_cycles(cycles: Cycles) -> Cycles {
    let subnet_size: usize = 1; // Subnet has only a single node, see usage of `add_fast_single_node_subnet` in `config()`.
    (cycles * subnet_size) / SMALL_APP_SUBNET_MAX_SIZE
}
