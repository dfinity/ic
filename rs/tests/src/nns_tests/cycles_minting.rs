use ic_system_test_driver::{
    driver::{
        test_env::{HasIcPrepDir, TestEnv},
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
        },
    },
    nns::{
        change_subnet_type_assignment, change_subnet_type_assignment_with_failure,
        get_governance_canister, set_authorized_subnetwork_list,
        set_authorized_subnetwork_list_with_failure, submit_external_proposal_with_test_id,
        update_subnet_type, update_xdr_per_icp,
    },
    util::{block_on, runtime_from_url},
};

use canister_test::{Canister, Project, Wasm};
use cycles_minting_canister::{
    create_canister_txn, top_up_canister_txn, CreateCanisterResult,
    IcpXdrConversionRateCertifiedResponse, NotifyCreateCanister, NotifyError, NotifyTopUp,
    SubnetFilter, SubnetSelection, TokensToCycles, TopUpCanisterResult, CREATE_CANISTER_REFUND_FEE,
    DEFAULT_CYCLES_PER_XDR,
};
use dfn_candid::{candid_one, CandidOne};
use dfn_protobuf::{ProtoBuf, ToProto};
use ic_canister_client::{Agent, Ed25519KeyPair, HttpClient, Sender};
use ic_certification::verify_certified_data;
use ic_config::subnet_config::CyclesAccountManagerConfig;
use ic_crypto_tree_hash::MixedHashTree;
use ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_from_der;
use ic_ledger_core::{block::BlockType, tokens::CheckedAdd};
use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
use ic_management_canister_types::{CanisterIdRecord, CanisterStatusResult};
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR, TEST_USER1_KEYPAIR, TEST_USER1_PRINCIPAL,
    TEST_USER2_KEYPAIR,
};
use ic_nns_common::types::{NeuronId, UpdateIcpXdrConversionRatePayload};
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, ROOT_CANISTER_ID,
};
use ic_nns_governance_api::pb::v1::NnsFunction;
use ic_nns_test_utils::governance::{
    submit_external_update_proposal_allowing_error, upgrade_nns_canister_by_proposal,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::InternetComputer;
use ic_types::{CanisterId, Cycles, PrincipalId};
use icp_ledger::{
    protobuf::TipOfChainRequest, tokens_from_proto, AccountBalanceArgs, AccountIdentifier, Block,
    BlockArg, BlockIndex, BlockRes, CyclesResponse, Memo, NotifyCanisterArgs, Operation,
    Subaccount, TipOfChainRes, Tokens, TransferArgs, TransferError, DEFAULT_TRANSFER_FEE,
};
use on_wire::{FromWire, IntoWire};
use rand::{rngs::StdRng, SeedableRng};
use slog::info;
use std::sync::atomic::{AtomicU64, Ordering};
use url::Url;

fn make_user_ed25519(seed: u64) -> (ic_canister_client_sender::Ed25519KeyPair, PrincipalId) {
    let mut rng = StdRng::seed_from_u64(seed);
    let kp = ic_canister_client_sender::Ed25519KeyPair::generate(&mut rng);
    let public_key_der =
        ic_canister_client_sender::ed25519_public_key_to_der(kp.public_key.to_vec());
    let pid = PrincipalId::new_self_authenticating(&public_key_der);
    (kp, pid)
}

pub fn config(env: TestEnv) {
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

pub fn config_with_multiple_app_subnets(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
        .add_fast_single_node_subnet(SubnetType::Application)
        .add_fast_single_node_subnet(SubnetType::Application)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

fn scale_cycles(cycles: Cycles) -> Cycles {
    let subnet_size: usize = 1; // Subnet has only a single node, see usage of `add_fast_single_node_subnet` in `config()`.
    (cycles * subnet_size) / SMALL_APP_SUBNET_MAX_SIZE
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

        let pk_bytes = env
            .prep_dir("")
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

        // remove when ledger notify goes away
        {
            user1
                .transfer(
                    Tokens::from_e8s(send_amount.get_e8s() + 2 * DEFAULT_TRANSFER_FEE.get_e8s()),
                    controller_user.principal_id(),
                )
                .await;
            let (err, refund_block) = controller_user
                .create_canister_ledger(send_amount)
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
                controller_user.principal_id(),
            )
            .await;
        }

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
        info!(logger, "creating canister (not enough funds 1)");

        let small_amount = Tokens::new(0, 500_000).unwrap();

        let (err, refund_block) = user1
            .create_canister_cmc(small_amount, None, &controller_user, None, None)
            .await
            .unwrap_err();

        info!(logger, "error: {}", err);
        assert!(err.contains("Creating a canister requires a fee of"));

        let refund_block = refund_block.unwrap();
        tst.check_refund(
            refund_block,
            small_amount,
            CREATE_CANISTER_REFUND_FEE,
            *TEST_USER1_PRINCIPAL,
        )
        .await;

        // remove when ledger notify goes away
        {
            user1
                .transfer(
                    Tokens::from_e8s(small_amount.get_e8s() + DEFAULT_TRANSFER_FEE.get_e8s()),
                    controller_user.principal_id(),
                )
                .await;
            let (err, refund_block) = controller_user
                .create_canister_ledger(small_amount)
                .await
                .unwrap_err();

            info!(logger, "error: {}", err);
            assert!(err.contains("Creating a canister requires a fee of"));

            let refund_block = refund_block.unwrap();
            tst.check_refund(
                refund_block,
                small_amount,
                CREATE_CANISTER_REFUND_FEE,
                controller_user.principal_id(),
            )
            .await;
        }

        /* Create with funds < the refund fee. */
        info!(logger, "creating canister (not enough funds 2)");

        let tiny_amount = DEFAULT_TRANSFER_FEE
            .checked_add(&Tokens::from_e8s(10_000))
            .unwrap();

        let (err, no_refund_block) = user1
            .create_canister_cmc(tiny_amount, None, &controller_user, None, None)
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
                assert_eq!(tiny_amount, amount);
                assert_eq!(tst.get_balance(from).await, Tokens::ZERO);
                assert_eq!(spender, None);
            }
            _ => panic!("unexpected block {:?}", txn),
        }

        // remove when ledger notify goes away
        {
            user1
                .transfer(
                    Tokens::from_e8s(tiny_amount.get_e8s() + DEFAULT_TRANSFER_FEE.get_e8s()),
                    controller_user.principal_id(),
                )
                .await;
            let (err, no_refund_block) = controller_user
                .create_canister_ledger(tiny_amount)
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
                    assert_eq!(tiny_amount, amount);
                    assert_eq!(tst.get_balance(from).await, Tokens::ZERO);
                    assert_eq!(spender, None);
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

        let new_canister_status: CanisterStatusResult =
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
        let fees = scale_cycles(
            config.canister_creation_fee
                + config.ingress_message_reception_fee
                + config.ingress_byte_reception_fee
                    * (msg_size + "canister_status".len() + nonce_size),
        );
        let expected_cycles =
            (icpts_to_cycles.to_cycles(initial_amount.checked_add(&top_up_amount).unwrap()) - fees)
                .get();
        assert_eq!(new_canister_status.cycles(), expected_cycles);

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
            _ => panic!("unexpected block {:?}", txn),
        }

        // remove when ledger notify goes away
        {
            user1
                .transfer(
                    Tokens::from_e8s(initial_amount.get_e8s() + DEFAULT_TRANSFER_FEE.get_e8s()),
                    controller_user.principal_id(),
                )
                .await;
            let new_canister_id = controller_user
                .create_canister_ledger(initial_amount)
                .await
                .unwrap();

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

            let new_canister_status: CanisterStatusResult =
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
            let fees = scale_cycles(
                config.canister_creation_fee
                    + config.ingress_message_reception_fee
                    + config.ingress_byte_reception_fee
                        * (msg_size + "canister_status".len() + nonce_size),
            );
            let expected_cycles = (icpts_to_cycles
                .to_cycles(initial_amount.checked_add(&top_up_amount).unwrap())
                - fees)
                .get();
            assert_eq!(new_canister_status.cycles(), expected_cycles);

            /* Check that the funds for the canister top up attempt are burned. */
            let block = tst.get_tip().await.unwrap();
            let txn = block.transaction();

            match txn.operation {
                Operation::Burn {
                    from,
                    amount,
                    spender,
                } => {
                    assert_eq!(amount, top_up_amount);
                    assert_eq!(tst.get_balance(from).await, Tokens::ZERO);
                    assert_eq!(spender, None);
                }
                _ => panic!("unexpected block {:?}", txn),
            }
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

        let nns_amount = Tokens::new(2, 0).unwrap();

        let new_canister_id = user1
            .create_canister_cmc(nns_amount, None, &controller_user, None, None)
            .await
            .unwrap();

        /* Check the controller / cycles balance. */
        let new_canister_status: CanisterStatusResult = nns
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

        // remove when ledger notify goes away
        {
            let nns_amount = Tokens::new(2, 0).unwrap();
            user1
                .transfer(
                    Tokens::from_e8s(nns_amount.get_e8s() + DEFAULT_TRANSFER_FEE.get_e8s()),
                    controller_user.principal_id(),
                )
                .await;
            let new_canister_id = controller_user
                .create_canister_ledger(nns_amount)
                .await
                .unwrap();

            /* Check the controller / cycles balance. */
            let new_canister_status: CanisterStatusResult = nns
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
        }

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

        // remove when ledger notify goes away
        user1
            .transfer(
                Tokens::from_e8s(nns_amount.get_e8s() + DEFAULT_TRANSFER_FEE.get_e8s()),
                controller_user.principal_id(),
            )
            .await;
        controller_user
            .create_canister_ledger(nns_amount)
            .await
            .unwrap();

        /* Exceed the daily cycles minting limit. */
        info!(logger, "creating canister (exceeding daily limit)");

        let amount = Tokens::new(100_000, 0).unwrap();

        let (err, refund_block) = user1
            .create_canister_cmc(amount, None, &controller_user, None, None)
            .await
            .unwrap_err();

        info!(logger, "error: {}", err);
        assert!(err
            .contains("cycles have been minted in the last 3600 seconds, please try again later"));

        let refund_block = refund_block.unwrap();
        tst.check_refund(
            refund_block,
            amount,
            CREATE_CANISTER_REFUND_FEE,
            *TEST_USER1_PRINCIPAL,
        )
        .await;

        // remove when ledger notify goes away
        {
            let amount = Tokens::new(100_000, 0).unwrap();
            user1
                .transfer(
                    Tokens::from_e8s(amount.get_e8s() + DEFAULT_TRANSFER_FEE.get_e8s()),
                    controller_user.principal_id(),
                )
                .await;
            let (err, refund_block) = controller_user
                .create_canister_ledger(amount)
                .await
                .unwrap_err();

            info!(logger, "error: {}", err);
            assert!(err.contains(
                "cycles have been minted in the last 3600 seconds, please try again later"
            ));

            let refund_block = refund_block.unwrap();
            tst.check_refund(
                refund_block,
                amount,
                CREATE_CANISTER_REFUND_FEE,
                controller_user.principal_id(),
            )
            .await;
        }

        /* Test getting the total number of cycles minted. */
        let cycles_minted: u64 = tst
            .query_pb(&CYCLES_MINTING_CANISTER_ID, "total_cycles_minted", ())
            .await
            .unwrap();

        let total_icpts = small_amount
            .checked_add(&tiny_amount)
            .unwrap()
            .checked_add(&initial_amount)
            .unwrap()
            .checked_add(&top_up_amount)
            .unwrap()
            .checked_add(&nns_amount)
            .unwrap()
            .checked_add(&nns_amount)
            .unwrap();

        assert_eq!(
            Cycles::from(cycles_minted / 2),
            icpts_to_cycles.to_cycles(total_icpts)
        );
    });
}

pub fn create_canister_on_specific_subnet_type(env: TestEnv) {
    let logger = env.logger();
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters");
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

        let (controller_user_keypair, _controller_pid) = make_user_ed25519(7);
        let controller_user = UserHandle::new(
            &nns_node.get_public_url(),
            &agent_client,
            &controller_user_keypair,
            LEDGER_CANISTER_ID,
            CYCLES_MINTING_CANISTER_ID,
        );

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
            .create_canister_cmc(send_amount, None, &controller_user, None, None)
            .await
            .unwrap_err();

        info!(logger, "error: {}", err);
        assert!(err.contains("No subnets in which to create a canister"));

        // Check that the funds for the failed creation attempt are returned to use
        // (minus the fees).
        let refund_block = refund_block.unwrap();
        tst.check_refund(
            refund_block,
            send_amount,
            CREATE_CANISTER_REFUND_FEE,
            *TEST_USER1_PRINCIPAL,
        )
        .await;

        // Register an authorized subnet and additionally assign a subnet to a type.
        info!(logger, "registering subnets");
        let app_subnet_ids: Vec<_> = topology
            .subnets()
            .filter_map(|s| (s.subnet_type() == SubnetType::Application).then_some(s.subnet_id))
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

        // Create canisters with sufficient funds on
        //  - an authorized subnet
        //  - a subnet with a specified type via subnet_type
        //  - a subnet with a specified type via subnet_selection
        //  - a specific authorized subnet
        //  - a specific subnet of another type
        // and confirm the canisters are created on the expected subnet on each case.
        info!(logger, "creating canisters");
        let initial_amount = Tokens::new(10_000, 0).unwrap();

        let canister_on_authorized_subnet = user1
            .create_canister_cmc(initial_amount, None, &controller_user, None, None)
            .await
            .unwrap();

        let canister_on_type1_subnet = user1
            .create_canister_cmc(
                initial_amount,
                None,
                &controller_user,
                Some(type1.clone()),
                None,
            )
            .await
            .unwrap();

        let canister_on_type1_subnet_2 = user1
            .create_canister_cmc(
                initial_amount,
                None,
                &controller_user,
                None,
                Some(SubnetSelection::Filter(SubnetFilter {
                    subnet_type: Some(type1),
                })),
            )
            .await
            .unwrap();

        let canister_on_specific_subnet_authorized = user1
            .create_canister_cmc(
                initial_amount,
                None,
                &controller_user,
                None,
                Some(SubnetSelection::Subnet {
                    subnet: authorized_subnet,
                }),
            )
            .await
            .unwrap();

        let canister_on_specific_subnet_type1 = user1
            .create_canister_cmc(
                initial_amount,
                None,
                &controller_user,
                None,
                Some(SubnetSelection::Subnet {
                    subnet: subnet_of_type1,
                }),
            )
            .await
            .unwrap();

        let node_on_authorized_subnet = topology
            .subnets()
            .find_map(|s| (s.subnet_id == authorized_subnet).then_some(s.nodes().next().unwrap()))
            .unwrap();
        let node_on_type1_subnet = topology
            .subnets()
            .find_map(|s| (s.subnet_id == subnet_of_type1).then_some(s.nodes().next().unwrap()))
            .unwrap();

        let authorized_runtime = runtime_from_url(
            node_on_authorized_subnet.get_public_url(),
            node_on_authorized_subnet.effective_canister_id(),
        );
        let type1_runtime = runtime_from_url(
            node_on_type1_subnet.get_public_url(),
            node_on_type1_subnet.effective_canister_id(),
        );

        let _status: CanisterStatusResult = authorized_runtime
            .get_management_canister_with_effective_canister_id(
                canister_on_authorized_subnet.into(),
            )
            .update_from_sender(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(canister_on_authorized_subnet),
                &Sender::from_keypair(&controller_user_keypair),
            )
            .await
            .unwrap();

        let _status: CanisterStatusResult = type1_runtime
            .get_management_canister_with_effective_canister_id(canister_on_type1_subnet.into())
            .update_from_sender(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(canister_on_type1_subnet),
                &Sender::from_keypair(&controller_user_keypair),
            )
            .await
            .unwrap();

        let _status: CanisterStatusResult = type1_runtime
            .get_management_canister_with_effective_canister_id(canister_on_type1_subnet_2.into())
            .update_from_sender(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(canister_on_type1_subnet_2),
                &Sender::from_keypair(&controller_user_keypair),
            )
            .await
            .unwrap();

        let _status: CanisterStatusResult = authorized_runtime
            .get_management_canister_with_effective_canister_id(
                canister_on_specific_subnet_authorized.into(),
            )
            .update_from_sender(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(canister_on_specific_subnet_authorized),
                &Sender::from_keypair(&controller_user_keypair),
            )
            .await
            .unwrap();

        let _status: CanisterStatusResult = type1_runtime
            .get_management_canister_with_effective_canister_id(
                canister_on_specific_subnet_type1.into(),
            )
            .update_from_sender(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(canister_on_specific_subnet_type1),
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
        expected_destination_principal_id: PrincipalId,
    ) {
        let block = self.get_block(refund_block).await.unwrap().unwrap();
        let txn = block.transaction();

        match txn.operation {
            Operation::Transfer { amount, to, .. } => {
                assert_eq!(
                    amount
                        .checked_add(&DEFAULT_TRANSFER_FEE)
                        .unwrap()
                        .checked_add(&refund_fee)
                        .unwrap(),
                    send_amount
                );
                assert_eq!(
                    to,
                    AccountIdentifier::new(expected_destination_principal_id, None)
                );
            }
            _ => panic!("unexpected block {:?}", txn),
        }

        let block = self.get_block(refund_block + 1).await.unwrap().unwrap();
        let txn = block.transaction();

        match txn.operation {
            Operation::Burn {
                from,
                amount,
                spender,
            } => {
                assert_eq!(refund_fee, amount);
                let balance = self.get_balance(from).await;
                assert_eq!(balance, Tokens::ZERO, "All funds should have been burned");
                assert_eq!(spender, None);
            }
            _ => panic!("unexpected block {:?}", txn),
        }
    }
}

pub struct UserHandle {
    user_keypair: Ed25519KeyPair,
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
        let user_keypair = *user_keypair;

        Self {
            user_keypair,
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
            .execute_update(canister_id, canister_id, method, arg, self.get_nonce())
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
            .execute_update(canister_id, canister_id, method, arg, self.get_nonce())
            .await?
            .ok_or_else(|| "Reply payload was empty".to_string())?;
        CandidOne::from_bytes(bytes).map(|c| c.0)
    }

    /// Creates a canister via the deprecated ledger.notify flow. That is,
    ///
    ///     1. Send ICP to the CMC.
    ///
    ///     2. Call ledger.noitfy.
    pub async fn create_canister_ledger(&self, amount: Tokens) -> CreateCanisterResult {
        let block = self
            .pay_for_canister(amount, None, &self.principal_id())
            .await;
        self.notify_canister_create_ledger(block, None, &self.principal_id())
            .await
    }

    /// Creates a canister using the notify_create_canister flow. That is,
    ///
    ///     1. Send ICP to the CMC.
    ///
    ///     2. Call CMC.notify_create_canister.
    pub async fn create_canister_cmc(
        &self,
        amount: Tokens,
        sender_subaccount: Option<Subaccount>,
        controller: &UserHandle,
        subnet_type: Option<String>,
        subnet_selection: Option<SubnetSelection>,
    ) -> CreateCanisterResult {
        let block = self
            .pay_for_canister(amount, sender_subaccount, &controller.principal_id())
            .await;
        controller
            .notify_canister_create_cmc(
                block,
                sender_subaccount,
                &controller.principal_id(),
                subnet_type,
                subnet_selection,
            )
            .await
    }

    pub fn principal_id(&self) -> PrincipalId {
        PrincipalId::new_self_authenticating(&ic_canister_client_sender::ed25519_public_key_to_der(
            self.user_keypair.public_key.to_vec(),
        ))
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

    async fn transfer(&self, amount: Tokens, destination_principal_id: PrincipalId) {
        let transfer_args = TransferArgs {
            amount,
            to: AccountIdentifier::new(destination_principal_id, None).to_address(),

            fee: DEFAULT_TRANSFER_FEE,
            memo: Memo(0),
            from_subaccount: None,
            created_at_time: None,
        };

        let result: Result</* block index */ u64, TransferError> = self
            .update_did(&self.ledger_id, "transfer", transfer_args)
            .await
            .unwrap();
        result.unwrap();
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
        subnet_selection: Option<SubnetSelection>,
    ) -> CreateCanisterResult {
        #[allow(deprecated)]
        let notify_arg = NotifyCreateCanister {
            block_index: block,
            controller: *controller_id,
            subnet_type,
            subnet_selection,
            settings: None,
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
