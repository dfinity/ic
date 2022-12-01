use crate::driver::pot_dsl::get_ic_handle_and_ctx;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{HasTopologySnapshot, IcNodeContainer, NnsInstallationExt};
use crate::nns::{
    change_subnet_type_assignment, change_subnet_type_assignment_with_failure,
    get_governance_canister, set_authorized_subnetwork_list,
    set_authorized_subnetwork_list_with_failure, submit_external_proposal_with_test_id,
    update_subnet_type, update_xdr_per_icp,
};
use crate::util::{
    assert_all_ready, get_random_application_node_endpoint, get_random_nns_node_endpoint,
    get_random_node_endpoint_of_subnet, runtime_from_url,
};

use crate::driver::ic::InternetComputer;
use canister_test::{Canister, Project, Wasm};
use cycles_minting_canister::{
    create_canister_txn, top_up_canister_txn, CreateCanisterResult,
    IcpXdrConversionRateCertifiedResponse, NotifyCreateCanister, NotifyError, NotifyTopUp,
    TokensToCycles, TopUpCanisterResult, CREATE_CANISTER_REFUND_FEE, DEFAULT_CYCLES_PER_XDR,
};
use dfn_candid::{candid_one, CandidOne};
use dfn_protobuf::{ProtoBuf, ToProto};
use ic_canister_client::{Agent, Ed25519KeyPair, HttpClient, Sender};
use ic_certification::verify_certified_data;
use ic_config::subnet_config::CyclesAccountManagerConfig;
use ic_constants::SMALL_APP_SUBNET_MAX_SIZE;
use ic_crypto::threshold_sig_public_key_from_der;
use ic_crypto_tree_hash::MixedHashTree;
use ic_ic00_types::{CanisterIdRecord, CanisterStatusResult};
use ic_ledger_core::block::BlockType;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_USER1_KEYPAIR, TEST_USER1_PRINCIPAL, TEST_USER2_KEYPAIR,
};
use ic_nns_common::types::{NeuronId, UpdateIcpXdrConversionRatePayload};
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, ROOT_CANISTER_ID,
};
use ic_nns_governance::pb::v1::NnsFunction;
use ic_nns_test_utils::{
    governance::{
        submit_external_update_proposal_allowing_error, upgrade_nns_canister_by_proposal,
    },
    ids::TEST_NEURON_1_ID,
};
use ic_registry_subnet_type::SubnetType;
use ic_rosetta_test_utils::make_user;
use ic_types::{CanisterId, Cycles, PrincipalId};
use icp_ledger::protobuf::TipOfChainRequest;
use icp_ledger::{
    tokens_from_proto, AccountBalanceArgs, AccountIdentifier, Block, BlockArg, BlockIndex,
    BlockRes, CyclesResponse, NotifyCanisterArgs, Operation, Subaccount, TipOfChainRes, Tokens,
    DEFAULT_TRANSFER_FEE,
};
use on_wire::{FromWire, IntoWire};
use slog::info;
use std::sync::atomic::{AtomicU64, Ordering};
use url::Url;

/// [EXC-1168] Flag to turn on cost scaling according to a subnet replication factor.
const USE_COST_SCALING_FLAG: bool = true;

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn config_with_multiple_app_subnets(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
        .add_fast_single_node_subnet(SubnetType::Application)
        .add_fast_single_node_subnet(SubnetType::Application)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

// TODO(EXC-1168): remove after cost scaling is fully implemented.
fn scale_cycles(cycles: Cycles) -> Cycles {
    let subnet_size: u128 = match USE_COST_SCALING_FLAG {
        true => 1, // Subnet has only a single node, see usage of `add_fast_single_node_subnet` in `config()`.
        false => SMALL_APP_SUBNET_MAX_SIZE as u128,
    };
    let reference_subnet_size = SMALL_APP_SUBNET_MAX_SIZE as u128;

    Cycles::from((cycles.get() * subnet_size) / reference_subnet_size)
}

pub fn test(env: TestEnv) {
    let logger = env.logger();

    info!(logger, "Installing NNS canisters on the root subnet...");
    env.topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap()
        .install_nns_canisters()
        .expect("Could not install NNS canisters");
    info!(&logger, "NNS canisters installed successfully.");

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    let (handle, ref ctx) = get_ic_handle_and_ctx(env.clone());

    rt.block_on(async move {
        let mut rng = ctx.rng.clone();

        let nns_endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
        nns_endpoint.assert_ready(ctx).await;

        let nns = runtime_from_url(nns_endpoint.url.clone());

        let agent_client = HttpClient::new();
        let tst = TestAgent::new(&nns_endpoint.url, &agent_client);
        let user1 = UserHandle::new(
            &nns_endpoint.url,
            &agent_client,
            &TEST_USER1_KEYPAIR,
            LEDGER_CANISTER_ID,
            CYCLES_MINTING_CANISTER_ID,
        );
        let user2 = UserHandle::new(
            &nns_endpoint.url,
            &agent_client,
            &TEST_USER2_KEYPAIR,
            LEDGER_CANISTER_ID,
            CYCLES_MINTING_CANISTER_ID,
        );

        let (_acc, controller_user_keypair, _pk, controller_pid) = make_user(7);

        let xdr_permyriad_per_icp = 5_000; // = 0.5 XDR/ICP
        let icpts_to_cycles = TokensToCycles {
            xdr_permyriad_per_icp,
            cycles_per_xdr: DEFAULT_CYCLES_PER_XDR.into(),
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Set the XDR-to-cycles conversion rate.
        info!(logger, "setting CYCLES_PER_XDR");
        update_xdr_per_icp(&nns, timestamp, xdr_permyriad_per_icp)
            .await
            .unwrap();

        // Set the XDR-to-cycles conversion rate, but expect it to fail
        info!(logger, "setting conversion rate to 0, failure expected");
        let governance_canister = get_governance_canister(&nns);
        let proposal_payload = UpdateIcpXdrConversionRatePayload {
            timestamp_seconds: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            xdr_permyriad_per_icp: 0,
            ..Default::default()
        };

        submit_external_update_proposal_allowing_error(
            &governance_canister,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::IcpXdrConversionRate,
            proposal_payload,
            "Test Title".to_string(),
            "Test Summary".to_string(),
        )
        .await
        .unwrap_err();

        let canister = Canister::new(&nns, CYCLES_MINTING_CANISTER_ID);
        /* Test getting the conversion rate */
        let mut conversion_rate_response = canister
            .query_(
                "get_icp_xdr_conversion_rate",
                candid_one::<IcpXdrConversionRateCertifiedResponse, ()>,
                (),
            )
            .await
            .unwrap();

        let icp_xdr_conversion_rate = conversion_rate_response.data;
        // Check that the first call changed the value but not the second one
        assert_eq!(
            icp_xdr_conversion_rate.xdr_permyriad_per_icp,
            xdr_permyriad_per_icp
        );

        let pk_bytes = handle
            .ic_prep_working_dir
            .as_ref()
            .unwrap()
            .root_public_key()
            .expect("failed to read threshold sig PK bytes");
        let pk = threshold_sig_public_key_from_der(&pk_bytes[..])
            .expect("failed to decode threshold sig PK");

        let mixed_hash_tree: MixedHashTree =
            serde_cbor::from_slice(&conversion_rate_response.hash_tree).unwrap();
        // Verify the authenticity of the root hash stored by the canister in the
        // certified_data field
        verify_certified_data(
            &conversion_rate_response.certificate[..],
            &CYCLES_MINTING_CANISTER_ID,
            &pk,
            mixed_hash_tree.digest().as_bytes(),
        )
        .unwrap();

        let proposal_payload = UpdateIcpXdrConversionRatePayload {
            timestamp_seconds: timestamp,
            xdr_permyriad_per_icp: xdr_permyriad_per_icp + 1234,
            ..Default::default()
        };

        // Set the XDR-to-cycles conversion rate again but with the same timestamp.
        // No change expected.
        info!(logger, "setting CYCLES_PER_XDR");
        submit_external_proposal_with_test_id(
            &governance_canister,
            NnsFunction::IcpXdrConversionRate,
            proposal_payload,
        )
        .await;

        conversion_rate_response = canister
            .query_(
                "get_icp_xdr_conversion_rate",
                candid_one::<IcpXdrConversionRateCertifiedResponse, ()>,
                (),
            )
            .await
            .unwrap();

        let icp_xdr_conversion_rate = conversion_rate_response.data;
        // Check rate hasn't changed
        assert_eq!(
            icp_xdr_conversion_rate.xdr_permyriad_per_icp,
            xdr_permyriad_per_icp
        );

        /* The first attempt to create a canister should fail because we
         * haven't registered subnets with the cycles minting canister. */
        info!(logger, "creating canister (no subnets)");

        let send_amount = Tokens::new(2, 0).unwrap();

        let (err, refund_block) = user1
            .create_canister_cmc(send_amount, None, &controller_pid, None)
            .await
            .unwrap_err();

        info!(logger, "error: {}", err);
        assert!(err.contains("No subnets in which to create a canister"));

        /* Check that the funds for the failed creation attempt are returned to use
         * (minus the fees). */
        let refund_block = refund_block.unwrap();
        tst.check_refund(refund_block, send_amount, CREATE_CANISTER_REFUND_FEE)
            .await;

        // remove when ledger notify goes away
        {
            let (err, refund_block) = user1
                .create_canister_ledger(send_amount, None, &controller_pid)
                .await
                .unwrap_err();

            info!(logger, "error: {}", err);
            assert!(err.contains("No subnets in which to create a canister"));

            /* Check that the funds for the failed creation attempt are returned to use
             * (minus the fees). */
            let refund_block = refund_block.unwrap();
            tst.check_refund(refund_block, send_amount, CREATE_CANISTER_REFUND_FEE)
                .await;
        }

        /* Register a subnet. */
        info!(logger, "registering subnets");
        let app_subnets: Vec<_> = handle
            .as_permutation(&mut rng)
            .filter(|ep| ep.subnet.as_ref().map(|s| s.type_of) == Some(SubnetType::Application))
            .collect();
        assert_all_ready(app_subnets.as_slice(), ctx).await;

        let app_subnet_ids: Vec<_> = app_subnets
            .into_iter()
            .map(|e| e.subnet.as_ref().expect("unassigned node not permitted").id)
            .collect();

        set_authorized_subnetwork_list(&nns, None, app_subnet_ids.clone())
            .await
            .unwrap();

        /* Create with funds < the canister creation fee. */
        info!(logger, "creating canister (not enough funds 1)");

        let small_amount = Tokens::new(0, 500_000).unwrap();

        let (err, refund_block) = user1
            .create_canister_cmc(small_amount, None, &controller_pid, None)
            .await
            .unwrap_err();

        info!(logger, "error: {}", err);
        assert!(err.contains("Creating a canister requires a fee of"));

        let refund_block = refund_block.unwrap();
        tst.check_refund(refund_block, small_amount, CREATE_CANISTER_REFUND_FEE)
            .await;

        // remove when ledger notify goes away
        {
            let (err, refund_block) = user1
                .create_canister_ledger(small_amount, None, &controller_pid)
                .await
                .unwrap_err();

            info!(logger, "error: {}", err);
            assert!(err.contains("Creating a canister requires a fee of"));

            let refund_block = refund_block.unwrap();
            tst.check_refund(refund_block, small_amount, CREATE_CANISTER_REFUND_FEE)
                .await;
        }

        /* Create with funds < the refund fee. */
        info!(logger, "creating canister (not enough funds 2)");

        let tiny_amount = (DEFAULT_TRANSFER_FEE + Tokens::from_e8s(10_000)).unwrap();

        let (err, no_refund_block) = user1
            .create_canister_cmc(tiny_amount, None, &controller_pid, None)
            .await
            .unwrap_err();

        info!(logger, "error: {}", err);
        assert!(err.contains("Creating a canister requires a fee of"));

        /* There should be no refund, all the funds will be burned. */
        assert!(no_refund_block.is_none());

        let block = tst.get_tip().await.unwrap();
        let txn = block.transaction();

        match txn.operation {
            Operation::Burn { from, amount } => {
                assert_eq!(tiny_amount, amount);
                assert_eq!(tst.get_balance(from).await, Tokens::ZERO);
            }
            _ => panic!("unexpected block {:?}", txn),
        }

        // remove when ledger notify goes away
        {
            let (err, no_refund_block) = user1
                .create_canister_ledger(tiny_amount, None, &controller_pid)
                .await
                .unwrap_err();

            info!(logger, "error: {}", err);
            assert!(err.contains("Creating a canister requires a fee of"));

            /* There should be no refund, all the funds will be burned. */
            assert!(no_refund_block.is_none());

            let block = tst.get_tip().await.unwrap();
            let txn = block.transaction();

            match txn.operation {
                Operation::Burn { from, amount } => {
                    assert_eq!(tiny_amount, amount);
                    assert_eq!(tst.get_balance(from).await, Tokens::ZERO);
                }
                _ => panic!("unexpected block {:?}", txn),
            }
        }

        /* Create with sufficient funds. */
        info!(logger, "creating canister");

        let initial_amount = Tokens::new(10_000, 0).unwrap();

        let bh = user1
            .pay_for_canister(initial_amount, None, &controller_pid)
            .await;
        let new_canister_id = user1
            .notify_canister_create_cmc(bh, None, &controller_pid, None)
            .await
            .unwrap();

        // second notify should return the success result together with canister id
        let tip = tst.get_tip().await.unwrap();
        let can_id = user1
            .notify_canister_create_cmc(bh, None, &controller_pid, None)
            .await
            .unwrap();
        assert_eq!(new_canister_id, can_id);
        let tip2 = tst.get_tip().await.unwrap();
        assert_eq!(tip, tip2, "No block should have been created");

        /* Check that the funds for the canister creation attempt are burned. */
        let block = tst.get_tip().await.unwrap();
        let txn = block.transaction();

        match txn.operation {
            Operation::Burn { from, amount } => {
                assert_eq!(amount, initial_amount);
                assert_eq!(tst.get_balance(from).await, Tokens::ZERO);
            }
            _ => panic!("unexpected block {:?}", txn),
        }

        // notification through the ledger path should fail
        user1
            .notify_canister_create_ledger(bh, None, &controller_pid)
            .await
            .unwrap_err();

        info!(logger, "topping up");

        let topup1 = Tokens::new(1000, 0).unwrap();
        let topup2 = Tokens::new(1000, 0).unwrap();
        let topup3 = Tokens::new(3000, 0).unwrap();
        let top_up_amount = ((topup1 + topup2).unwrap() + topup3).unwrap();

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
        // already notified. Ledger path should fail
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

        user1
            .notify_top_up_ledger(bh, None, &new_canister_id)
            .await
            .unwrap();
        // second notification fails
        user1
            .notify_top_up_ledger(bh, None, &new_canister_id)
            .await
            .unwrap_err();
        // cmc should return successful topup status
        let tip = tst.get_tip().await.unwrap();
        user1
            .notify_top_up_cmc(bh, None, &new_canister_id)
            .await
            .unwrap();
        let tip2 = tst.get_tip().await.unwrap();
        assert_eq!(tip, tip2, "No block should have been created");

        assert_eq!(
            tst.get_balance(user1.acc_for_top_up(&new_canister_id))
                .await,
            Tokens::ZERO,
            "All funds from cmc subaccount should have disappeared after topups"
        );

        //notification by a different user should fail on ledger path
        user2
            .notify_top_up_ledger(bh, None, &new_canister_id)
            .await
            .unwrap_err();

        /* Check the controller / cycles balance. */
        let msg_size = CandidOne(CanisterIdRecord::from(new_canister_id))
            .into_bytes()
            .unwrap()
            .len();

        let nonce_size = 8; // see RemoteTestRuntime::get_nonce_vec

        let application_endpoint = get_random_application_node_endpoint(&handle, &mut rng);
        application_endpoint.assert_ready(ctx).await;

        let new_canister_status: CanisterStatusResult =
            runtime_from_url(application_endpoint.url.clone())
                .get_management_canister()
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
        let fees = scale_cycles(
            config.canister_creation_fee
                + config.ingress_message_reception_fee
                + config.ingress_byte_reception_fee
                    * (msg_size + "canister_status".len() + nonce_size),
        );
        let expected_cycles =
            (icpts_to_cycles.to_cycles((initial_amount + top_up_amount).unwrap()) - fees).get();
        assert_eq!(new_canister_status.cycles(), expected_cycles);

        /* Check that the funds for the canister top up attempt are burned. */
        let block = tst.get_tip().await.unwrap();
        let txn = block.transaction();

        match txn.operation {
            Operation::Burn { from, amount } => {
                assert_eq!(amount, topup3);
                assert_eq!(tst.get_balance(from).await, Tokens::ZERO);
            }
            _ => panic!("unexpected block {:?}", txn),
        }

        // remove when ledger notify goes away
        {
            let new_canister_id = user1
                .create_canister_ledger(initial_amount, None, &controller_pid)
                .await
                .unwrap();

            /* Check that the funds for the canister creation attempt are burned. */
            let block = tst.get_tip().await.unwrap();
            let txn = block.transaction();

            match txn.operation {
                Operation::Burn { from, amount } => {
                    assert_eq!(amount, initial_amount);
                    assert_eq!(tst.get_balance(from).await, Tokens::ZERO);
                }
                _ => panic!("unexpected block {:?}", txn),
            }

            info!(logger, "topping up");

            let top_up_amount = Tokens::new(5_000, 0).unwrap();

            user1
                .top_up_canister_ledger(top_up_amount, None, &new_canister_id)
                .await
                .unwrap();

            /* Check the controller / cycles balance. */
            let msg_size = CandidOne(CanisterIdRecord::from(new_canister_id))
                .into_bytes()
                .unwrap()
                .len();

            let nonce_size = 8; // see RemoteTestRuntime::get_nonce_vec

            let application_endpoint = get_random_application_node_endpoint(&handle, &mut rng);
            application_endpoint.assert_ready(ctx).await;

            let new_canister_status: CanisterStatusResult =
                runtime_from_url(application_endpoint.url.clone())
                    .get_management_canister()
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
            let fees = scale_cycles(
                config.canister_creation_fee
                    + config.ingress_message_reception_fee
                    + config.ingress_byte_reception_fee
                        * (msg_size + "canister_status".len() + nonce_size),
            );
            let expected_cycles =
                (icpts_to_cycles.to_cycles((initial_amount + top_up_amount).unwrap()) - fees).get();
            assert_eq!(new_canister_status.cycles(), expected_cycles);

            /* Check that the funds for the canister top up attempt are burned. */
            let block = tst.get_tip().await.unwrap();
            let txn = block.transaction();

            match txn.operation {
                Operation::Burn { from, amount } => {
                    assert_eq!(amount, top_up_amount);
                    assert_eq!(tst.get_balance(from).await, Tokens::ZERO);
                }
                _ => panic!("unexpected block {:?}", txn),
            }
        }

        /* Override the list of subnets for a specific controller. */
        info!(logger, "registering subnets override");
        let system_subnets: Vec<_> = handle
            .as_permutation(&mut rng)
            .filter(|ep| ep.subnet.as_ref().map(|s| s.type_of) == Some(SubnetType::System))
            .collect();
        assert_all_ready(system_subnets.as_slice(), ctx).await;

        let system_subnet_ids = system_subnets
            .iter()
            .map(|x| x.subnet.clone().expect("unassigned node not permitted").id)
            .collect();

        set_authorized_subnetwork_list(&nns, Some(controller_pid), system_subnet_ids)
            .await
            .unwrap();

        info!(logger, "creating NNS canister");

        let nns_amount = Tokens::new(2, 0).unwrap();

        let new_canister_id = user1
            .create_canister_cmc(nns_amount, None, &controller_pid, None)
            .await
            .unwrap();

        /* Check the controller / cycles balance. */
        let new_canister_status: CanisterStatusResult = nns
            .get_management_canister()
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

        // remove when ledger notify goes away
        {
            let nns_amount = Tokens::new(2, 0).unwrap();

            let new_canister_id = user1
                .create_canister_ledger(nns_amount, None, &controller_pid)
                .await
                .unwrap();

            /* Check the controller / cycles balance. */
            let new_canister_status: CanisterStatusResult = nns
                .get_management_canister()
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
        }

        /* Try upgrading the cycles minting canister. This should
         * preserve its state (such as the principal -> subnets
         * mappings). Note: we first update to a dummy canister
         * because upgrade_nns_canister_by_proposal() doesn't want to
         * upgrade to the same version of the canister. */
        info!(logger, "upgrading cycles minting canister to empty module");

        let wasm = wabt::wat2wasm("(module)").unwrap();

        upgrade_nns_canister_by_proposal(
            &Canister::new(&nns, CYCLES_MINTING_CANISTER_ID),
            &Canister::new(&nns, GOVERNANCE_CANISTER_ID),
            &Canister::new(&nns, ROOT_CANISTER_ID),
            true,
            Wasm::from_bytes(wasm),
        )
        .await;

        info!(logger, "creating NNS canister (will fail)");
        let block = user1
            .pay_for_canister(nns_amount, None, &controller_pid)
            .await;
        let err = user1
            .notify_canister_create_cmc(block, None, &controller_pid, None)
            .await
            .unwrap_err();

        assert!(
            err.0.contains("has no update method"),
            "Error message was: {}",
            err.0
        );

        // remove when ledger notify goes away
        {
            let err = user1
                .notify_canister_create_ledger(block, None, &controller_pid)
                .await
                .unwrap_err();

            assert!(
                err.0.contains("has no update method"),
                "Error message was: {}",
                err.0
            );
        }

        info!(logger, "upgrading cycles minting canister");
        let wasm = Project::cargo_bin_maybe_from_env("cycles-minting-canister", &[]);

        upgrade_nns_canister_by_proposal(
            &Canister::new(&nns, CYCLES_MINTING_CANISTER_ID),
            &Canister::new(&nns, GOVERNANCE_CANISTER_ID),
            &Canister::new(&nns, ROOT_CANISTER_ID),
            true,
            wasm,
        )
        .await;

        info!(logger, "creating NNS canister");

        user1
            .notify_canister_create_cmc(block, None, &controller_pid, None)
            .await
            .unwrap();

        // remove when ledger notify goes away
        user1
            .create_canister_ledger(nns_amount, None, &controller_pid)
            .await
            .unwrap();

        /* Exceed the daily cycles minting limit. */
        info!(logger, "creating canister (exceeding daily limit)");

        let amount = Tokens::new(100_000, 0).unwrap();

        let (err, refund_block) = user1
            .create_canister_cmc(amount, None, &controller_pid, None)
            .await
            .unwrap_err();

        info!(logger, "error: {}", err);
        assert!(err
            .contains("cycles have been minted in the last 3600 seconds, please try again later"));

        let refund_block = refund_block.unwrap();
        tst.check_refund(refund_block, amount, CREATE_CANISTER_REFUND_FEE)
            .await;

        // remove when ledger notify goes away
        {
            let amount = Tokens::new(100_000, 0).unwrap();

            let (err, refund_block) = user1
                .create_canister_ledger(amount, None, &controller_pid)
                .await
                .unwrap_err();

            info!(logger, "error: {}", err);
            assert!(err.contains(
                "cycles have been minted in the last 3600 seconds, please try again later"
            ));

            let refund_block = refund_block.unwrap();
            tst.check_refund(refund_block, amount, CREATE_CANISTER_REFUND_FEE)
                .await;
        }

        /* Test getting the total number of cycles minted. */
        let cycles_minted: u64 = tst
            .query_pb(&CYCLES_MINTING_CANISTER_ID, "total_cycles_minted", ())
            .await
            .unwrap();

        let total_icpts = (((((small_amount + tiny_amount).unwrap() + initial_amount).unwrap()
            + top_up_amount)
            .unwrap()
            + nns_amount)
            .unwrap()
            + nns_amount)
            .unwrap();

        assert_eq!(
            Cycles::from(cycles_minted / 2),
            icpts_to_cycles.to_cycles(total_icpts)
        );
    });
}

pub fn create_canister_on_specific_subnet_type(env: TestEnv) {
    let logger = env.logger();

    info!(logger, "Installing NNS canisters on the root subnet...");
    env.topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap()
        .install_nns_canisters()
        .expect("Could not install NNS canisters");
    info!(&logger, "NNS canisters installed successfully.");

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    let (handle, ref ctx) = get_ic_handle_and_ctx(env.clone());

    rt.block_on(async move {
        let mut rng = ctx.rng.clone();

        let nns_endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
        nns_endpoint.assert_ready(ctx).await;

        let nns = runtime_from_url(nns_endpoint.url.clone());

        let agent_client = HttpClient::new();
        let tst = TestAgent::new(&nns_endpoint.url, &agent_client);
        let user1 = UserHandle::new(
            &nns_endpoint.url,
            &agent_client,
            &TEST_USER1_KEYPAIR,
            LEDGER_CANISTER_ID,
            CYCLES_MINTING_CANISTER_ID,
        );

        let (_acc, controller_user_keypair, _pk, controller_pid) = make_user(7);

        let xdr_permyriad_per_icp = 5_000; // = 0.5 XDR/ICP

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Set the XDR-to-cycles conversion rate.
        info!(logger, "setting CYCLES_PER_XDR");
        update_xdr_per_icp(&nns, timestamp, xdr_permyriad_per_icp)
            .await
            .unwrap();

        // The first attempt to create a canister should fail because we
        // haven't registered any subnets with the cycles minting canister.
        info!(logger, "creating canister (no subnets)");

        let send_amount = Tokens::new(2, 0).unwrap();

        let (err, refund_block) = user1
            .create_canister_cmc(send_amount, None, &controller_pid, None)
            .await
            .unwrap_err();

        info!(logger, "error: {}", err);
        assert!(err.contains("No subnets in which to create a canister"));

        // Check that the funds for the failed creation attempt are returned to use
        // (minus the fees).
        let refund_block = refund_block.unwrap();
        tst.check_refund(refund_block, send_amount, CREATE_CANISTER_REFUND_FEE)
            .await;

        // Register an authorized subnet and additionally assign a subnet to a type.
        info!(logger, "registering subnets");
        let app_subnets: Vec<_> = handle
            .as_permutation(&mut rng)
            .filter(|ep| ep.subnet.as_ref().map(|s| s.type_of) == Some(SubnetType::Application))
            .collect();
        assert_all_ready(app_subnets.as_slice(), ctx).await;

        let app_subnet_ids: Vec<_> = app_subnets
            .into_iter()
            .map(|e| e.subnet.as_ref().expect("unassigned node not permitted").id)
            .collect();

        let type1 = "Type1".to_string();

        let authorized_subnet = app_subnet_ids[0];
        let subnet_of_type1 = app_subnet_ids[1];

        set_authorized_subnetwork_list(&nns, None, vec![authorized_subnet])
            .await
            .unwrap();

        update_subnet_type(&nns, type1.clone()).await.unwrap();
        change_subnet_type_assignment(&nns, type1.clone(), vec![subnet_of_type1])
            .await
            .unwrap();

        // Cannot add a subnet that has a type assigned as an authorized subnet
        // and also cannot assign a type to a subnet that is already authorized.
        set_authorized_subnetwork_list_with_failure(
            &nns,
            None,
            vec![subnet_of_type1],
            format!(
                "Subnets {:?} are already assigned to a type and cannot be authorized",
                vec![subnet_of_type1]
            ),
        )
        .await;

        change_subnet_type_assignment_with_failure(
            &nns,
            type1.clone(),
            vec![authorized_subnet],
            format!(
                "The provided subnets {:?} are authorized for public access and cannot be assigned a type",
                vec![authorized_subnet]
            ),
        )
        .await;

        // Create canisters with sufficient funds on both an authorized and a
        // subnet with a specific type and confirm the canisters are created
        // on the expected subnet on each case.
        info!(logger, "creating canisters");
        let initial_amount = Tokens::new(10_000, 0).unwrap();

        let canister_on_authorized_subnet = user1
            .create_canister_cmc(initial_amount, None, &controller_pid, None)
            .await
            .unwrap();

        let canister_on_type1_subnet = user1
            .create_canister_cmc(initial_amount, None, &controller_pid, Some(type1))
            .await
            .unwrap();

        let node_on_authorized_subnet =
            get_random_node_endpoint_of_subnet(&handle, authorized_subnet, &mut rng);
        let node_on_type1_subnet =
            get_random_node_endpoint_of_subnet(&handle, subnet_of_type1, &mut rng);

        let _status: CanisterStatusResult = runtime_from_url(node_on_authorized_subnet.url.clone())
            .get_management_canister()
            .update_from_sender(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(canister_on_authorized_subnet),
                &Sender::from_keypair(&controller_user_keypair),
            )
            .await
            .unwrap();

        let _status: CanisterStatusResult = runtime_from_url(node_on_type1_subnet.url.clone())
            .get_management_canister()
            .update_from_sender(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(canister_on_type1_subnet),
                &Sender::from_keypair(&controller_user_keypair),
            )
            .await
            .unwrap();
    });
}

struct TestAgent {
    agent: Agent,
}

impl TestAgent {
    pub fn new(ic_url: &Url, agent_client: &HttpClient) -> Self {
        let agent = Agent::new_with_client(agent_client.clone(), ic_url.clone(), Sender::Anonymous);
        Self { agent }
    }

    pub async fn query_pb<Payload: ToProto, Res: ToProto>(
        &self,
        canister_id: &CanisterId,
        method: &str,
        payload: Payload,
    ) -> Result<Res, String> {
        let arg = ProtoBuf(payload).into_bytes()?;
        let bytes = self
            .agent
            .execute_query(canister_id, method, arg)
            .await?
            .ok_or_else(|| "Reply payload was empty".to_string())?;
        ProtoBuf::from_bytes(bytes).map(|c| c.0)
    }

    pub async fn get_block(&self, h: BlockIndex) -> Result<Option<Block>, String> {
        match self
            .query_pb(&LEDGER_CANISTER_ID, "block_pb", BlockArg(h))
            .await?
        {
            BlockRes(None) => Ok(None),
            BlockRes(Some(Ok(block))) => Ok(Some(Block::decode(block).unwrap())),
            BlockRes(Some(Err(canister_id))) => unimplemented! {"FIXME: {}", canister_id},
        }
    }

    pub async fn get_balance(&self, acc: AccountIdentifier) -> Tokens {
        let arg = AccountBalanceArgs::new(acc);
        let res: Result<Tokens, String> = self
            .query_pb(&LEDGER_CANISTER_ID, "account_balance_pb", arg)
            .await
            .map(tokens_from_proto);
        res.unwrap()
    }

    pub async fn get_tip(&self) -> Result<Block, String> {
        let resp: Result<TipOfChainRes, String> = self
            .query_pb(&LEDGER_CANISTER_ID, "tip_of_chain_pb", TipOfChainRequest {})
            .await;
        let tip_idx = resp.expect("tip_of_chain failed").tip_index;
        self.get_block(tip_idx).await.map(|opt| opt.unwrap())
    }

    pub async fn check_refund(
        &self,
        refund_block: BlockIndex,
        send_amount: Tokens,
        refund_fee: Tokens,
    ) {
        let block = self.get_block(refund_block).await.unwrap().unwrap();
        let txn = block.transaction();

        match txn.operation {
            Operation::Transfer { amount, to, .. } => {
                assert_eq!(
                    ((amount + DEFAULT_TRANSFER_FEE).unwrap() + refund_fee).unwrap(),
                    send_amount
                );
                assert_eq!(to, (*TEST_USER1_PRINCIPAL).into());
            }
            _ => panic!("unexpected block {:?}", txn),
        }

        let block = self.get_block(refund_block + 1).await.unwrap().unwrap();
        let txn = block.transaction();

        match txn.operation {
            Operation::Burn { from, amount } => {
                assert_eq!(refund_fee, amount);
                let balance = self.get_balance(from).await;
                assert_eq!(balance, Tokens::ZERO, "All funds should have been burned");
            }
            _ => panic!("unexpected block {:?}", txn),
        }
    }
}

pub struct UserHandle {
    agent: Agent,
    ledger_id: CanisterId,
    cmc_id: CanisterId,
    nonce: AtomicU64,
}

impl UserHandle {
    pub fn new(
        ic_url: &Url,
        http_client: &HttpClient,
        user_keypair: &Ed25519KeyPair,
        ledger_id: CanisterId,
        cmc_id: CanisterId,
    ) -> Self {
        let agent = Agent::new_with_client(
            http_client.clone(),
            ic_url.clone(),
            Sender::from_keypair(user_keypair),
        );
        Self {
            agent,
            ledger_id,
            cmc_id,
            nonce: AtomicU64::new(0),
        }
    }

    fn get_nonce(&self) -> Vec<u8> {
        self.nonce
            .fetch_add(1, Ordering::Relaxed)
            .to_be_bytes()
            .to_vec()
    }

    pub async fn update_pb<Payload: ToProto, Res: ToProto>(
        &self,
        canister_id: &CanisterId,
        method: &str,
        payload: Payload,
    ) -> Result<Res, String> {
        let arg = ProtoBuf(payload).into_bytes()?;
        let bytes = self
            .agent
            .execute_update(canister_id, method, arg, self.get_nonce())
            .await?
            .ok_or_else(|| "Reply payload was empty".to_string())?;
        ProtoBuf::from_bytes(bytes).map(|c| c.0)
    }

    pub async fn update_did<
        Payload: candid::CandidType,
        Res: serde::de::DeserializeOwned + candid::CandidType,
    >(
        &self,
        canister_id: &CanisterId,
        method: &str,
        payload: Payload,
    ) -> Result<Res, String> {
        let arg = CandidOne(payload).into_bytes()?;
        let bytes = self
            .agent
            .execute_update(canister_id, method, arg, self.get_nonce())
            .await?
            .ok_or_else(|| "Reply payload was empty".to_string())?;
        CandidOne::from_bytes(bytes).map(|c| c.0)
    }

    pub async fn create_canister_ledger(
        &self,
        amount: Tokens,
        sender_subaccount: Option<Subaccount>,
        controller_id: &PrincipalId,
    ) -> CreateCanisterResult {
        let block = self
            .pay_for_canister(amount, sender_subaccount, controller_id)
            .await;
        self.notify_canister_create_ledger(block, sender_subaccount, controller_id)
            .await
    }

    pub async fn create_canister_cmc(
        &self,
        amount: Tokens,
        sender_subaccount: Option<Subaccount>,
        controller_id: &PrincipalId,
        subnet_type: Option<String>,
    ) -> CreateCanisterResult {
        let block = self
            .pay_for_canister(amount, sender_subaccount, controller_id)
            .await;
        self.notify_canister_create_cmc(block, sender_subaccount, controller_id, subnet_type)
            .await
    }

    pub async fn top_up_canister_ledger(
        &self,
        amount: Tokens,
        sender_subaccount: Option<Subaccount>,
        target_canister_id: &CanisterId,
    ) -> TopUpCanisterResult {
        let block = self
            .pay_for_top_up(amount, sender_subaccount, target_canister_id)
            .await;
        self.notify_top_up_ledger(block, sender_subaccount, target_canister_id)
            .await
    }

    pub async fn top_up_canister_cmc(
        &self,
        amount: Tokens,
        sender_subaccount: Option<Subaccount>,
        target_canister_id: &CanisterId,
    ) -> TopUpCanisterResult {
        let block_idx = self
            .pay_for_top_up(amount, sender_subaccount, target_canister_id)
            .await;
        self.notify_top_up_cmc(block_idx, sender_subaccount, target_canister_id)
            .await
    }

    fn acc_for_top_up(&self, target_canister_id: &CanisterId) -> AccountIdentifier {
        AccountIdentifier::new(self.cmc_id.into(), Some(target_canister_id.into()))
    }

    pub async fn pay_for_canister(
        &self,
        amount: Tokens,
        sender_subaccount: Option<Subaccount>,
        controller_id: &PrincipalId,
    ) -> BlockIndex {
        let (send_args, _subaccount) =
            create_canister_txn(amount, sender_subaccount, &self.cmc_id, controller_id);

        self.update_pb(&self.ledger_id, "send_pb", send_args)
            .await
            .unwrap()
    }

    pub async fn pay_for_top_up(
        &self,
        amount: Tokens,
        sender_subaccount: Option<Subaccount>,
        target_canister_id: &CanisterId,
    ) -> BlockIndex {
        let (send_args, _subaccount) =
            top_up_canister_txn(amount, sender_subaccount, &self.cmc_id, target_canister_id);

        self.update_pb(&self.ledger_id, "send_pb", send_args)
            .await
            .unwrap()
    }

    pub async fn notify_canister_create_cmc(
        &self,
        block: BlockIndex,
        _sender_subaccount: Option<Subaccount>,
        controller_id: &PrincipalId,
        subnet_type: Option<String>,
    ) -> CreateCanisterResult {
        let notify_arg = NotifyCreateCanister {
            block_index: block,
            controller: *controller_id,
            subnet_type,
        };

        let result: Result<CanisterId, NotifyError> = self
            .update_did(&self.cmc_id, "notify_create_canister", notify_arg)
            .await
            .map_err(|err| (err, None))?;

        match result {
            Ok(cid) => Ok(cid),
            Err(NotifyError::Refunded {
                reason,
                block_index,
            }) => Err((reason, block_index)),
            Err(e) => Err((e.to_string(), None)),
        }
    }

    pub async fn notify_canister_create_ledger(
        &self,
        block: BlockIndex,
        sender_subaccount: Option<Subaccount>,
        controller_id: &PrincipalId,
    ) -> CreateCanisterResult {
        let subaccount = controller_id.into();
        let notify_args = NotifyCanisterArgs {
            block_height: block,
            max_fee: DEFAULT_TRANSFER_FEE,
            from_subaccount: sender_subaccount,
            to_canister: self.cmc_id,
            to_subaccount: Some(subaccount),
        };

        match self
            .update_pb(&self.ledger_id, "notify_pb", notify_args)
            .await
            .map_err(|err| (err, None))?
        {
            CyclesResponse::CanisterCreated(cid) => Ok(cid),
            CyclesResponse::ToppedUp(()) => {
                Err(("Unexpected response, 'topped up'".to_string(), None))
            }
            CyclesResponse::Refunded(err, height) => Err((err, height)),
        }
    }

    pub async fn notify_top_up_cmc(
        &self,
        block_idx: BlockIndex,
        _sender_subaccount: Option<Subaccount>,
        target_canister_id: &CanisterId,
    ) -> TopUpCanisterResult {
        let notify_arg = NotifyTopUp {
            block_index: block_idx,
            canister_id: *target_canister_id,
        };

        let result: Result<Cycles, NotifyError> = self
            .update_did(&self.cmc_id, "notify_top_up", notify_arg)
            .await
            .map_err(|err| (err, None))?;

        match result {
            Ok(_) => Ok(()),
            Err(NotifyError::Refunded {
                reason,
                block_index,
            }) => Err((reason, block_index)),
            Err(e) => Err((e.to_string(), None)),
        }
    }

    pub async fn notify_top_up_ledger(
        &self,
        block: BlockIndex,
        sender_subaccount: Option<Subaccount>,
        target_canister_id: &CanisterId,
    ) -> TopUpCanisterResult {
        let subaccount = target_canister_id.into();
        let notify_args = NotifyCanisterArgs {
            block_height: block,
            max_fee: DEFAULT_TRANSFER_FEE,
            from_subaccount: sender_subaccount,
            to_canister: self.cmc_id,
            to_subaccount: Some(subaccount),
        };

        match self
            .update_pb(&self.ledger_id, "notify_pb", notify_args)
            .await
            .map_err(|err| (err, None))?
        {
            CyclesResponse::CanisterCreated(_) => {
                Err(("Unexpected response, 'created canister'".to_string(), None))
            }
            CyclesResponse::ToppedUp(()) => Ok(()),
            CyclesResponse::Refunded(err, height) => Err((err, height)),
        }
    }
}
