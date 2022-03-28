use crate::nns::{
    get_governance_canister, set_authorized_subnetwork_list, submit_external_proposal_with_test_id,
    update_xdr_per_icp, NnsExt,
};
use crate::util::{
    assert_all_ready, get_random_application_node_endpoint, get_random_nns_node_endpoint,
    runtime_from_url,
};

use canister_test::{Canister, Project, Wasm};
use cycles_minting_canister::{
    create_canister_txn, top_up_canister_txn, CreateCanisterResult,
    IcpXdrConversionRateCertifiedResponse, TokensToCycles, TopUpCanisterResult,
    CREATE_CANISTER_REFUND_FEE, DEFAULT_CYCLES_PER_XDR,
};
use dfn_candid::{candid_one, CandidOne};
use dfn_protobuf::{ProtoBuf, ToProto};
use ic_canister_client::{Agent, HttpClient, Sender};
use ic_certified_vars::verify_certificate;
use ic_config::subnet_config::CyclesAccountManagerConfig;
use ic_crypto::threshold_sig_public_key_from_der;
use ic_crypto_tree_hash::MixedHashTree;
use ic_fondue::{ic_manager::IcHandle, prod_tests::ic::InternetComputer};
use ic_nns_common::types::{NeuronId, UpdateIcpXdrConversionRatePayload};
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, ROOT_CANISTER_ID,
};
use ic_nns_governance::pb::v1::NnsFunction;
use ic_nns_test_keys::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_USER1_KEYPAIR, TEST_USER1_PRINCIPAL, TEST_USER2_KEYPAIR,
};
use ic_nns_test_utils::{
    governance::{
        submit_external_update_proposal_allowing_error, upgrade_nns_canister_by_proposal,
    },
    ids::TEST_NEURON_1_ID,
};
use ic_registry_subnet_type::SubnetType;
use ic_rosetta_test_utils::make_user;
use ic_types::{
    ic00::{CanisterIdRecord, CanisterStatusResult},
    CanisterId, Cycles, PrincipalId,
};
use ledger_canister::protobuf::TipOfChainRequest;
use ledger_canister::{
    AccountBalanceArgs, AccountIdentifier, Block, BlockArg, BlockHeight, BlockRes, CyclesResponse,
    NotifyCanisterArgs, Operation, Subaccount, TipOfChainRes, Tokens, DEFAULT_TRANSFER_FEE,
};
use on_wire::{FromWire, IntoWire};
use slog::info;
use std::sync::atomic::{AtomicU64, Ordering};
use url::Url;

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    // Install NNS canisters
    ctx.install_nns_canisters(&handle, true);

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

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
        info!(ctx.logger, "setting CYCLES_PER_XDR");
        update_xdr_per_icp(&nns, timestamp, xdr_permyriad_per_icp)
            .await
            .unwrap();

        // Set the XDR-to-cycles conversion rate, but expect it to fail
        info!(ctx.logger, "setting conversion rate to 0, failure expected");
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
        verify_certificate(
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
        info!(ctx.logger, "setting CYCLES_PER_XDR");
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
        info!(ctx.logger, "creating canister (no subnets)");

        let send_amount = Tokens::new(2, 0).unwrap();

        let (err, refund_block) = user1
            .create_canister_cmc(send_amount, None, &controller_pid)
            .await
            .unwrap_err();

        info!(ctx.logger, "error: {}", err);
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

            info!(ctx.logger, "error: {}", err);
            assert!(err.contains("No subnets in which to create a canister"));

            /* Check that the funds for the failed creation attempt are returned to use
             * (minus the fees). */
            let refund_block = refund_block.unwrap();
            tst.check_refund(refund_block, send_amount, CREATE_CANISTER_REFUND_FEE)
                .await;
        }

        /* Register a subnet. */
        info!(ctx.logger, "registering subnets");
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
        info!(ctx.logger, "creating canister (not enough funds 1)");

        let small_amount = Tokens::new(0, 10_000_000).unwrap();

        let (err, refund_block) = user1
            .create_canister_cmc(small_amount, None, &controller_pid)
            .await
            .unwrap_err();

        info!(ctx.logger, "error: {}", err);
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

            info!(ctx.logger, "error: {}", err);
            assert!(err.contains("Creating a canister requires a fee of"));

            let refund_block = refund_block.unwrap();
            tst.check_refund(refund_block, small_amount, CREATE_CANISTER_REFUND_FEE)
                .await;
        }

        /* Create with funds < the refund fee. */
        info!(ctx.logger, "creating canister (not enough funds 2)");

        let tiny_amount = (DEFAULT_TRANSFER_FEE + Tokens::from_e8s(10_000)).unwrap();

        let (err, no_refund_block) = user1
            .create_canister_cmc(tiny_amount, None, &controller_pid)
            .await
            .unwrap_err();

        info!(ctx.logger, "error: {}", err);
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

            info!(ctx.logger, "error: {}", err);
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
        info!(ctx.logger, "creating canister");

        let initial_amount = Tokens::new(10_000, 0).unwrap();

        let bh = user1
            .pay_for_canister(initial_amount, None, &controller_pid)
            .await;
        let new_canister_id = user1
            .notify_canister_create_cmc(bh, None, &controller_pid)
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

        // notification through the ledger path should fail
        user1
            .notify_canister_create_ledger(bh, None, &controller_pid)
            .await
            .unwrap_err();

        info!(ctx.logger, "topping up");

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
        assert_eq!(
            new_canister_status.cycles(),
            (icpts_to_cycles.to_cycles((initial_amount + top_up_amount).unwrap())
                - config.canister_creation_fee
                - config.ingress_message_reception_fee
                - config.ingress_byte_reception_fee
                    * (msg_size + "canister_status".len() + nonce_size))
                .get()
        );

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

            info!(ctx.logger, "topping up");

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
            assert_eq!(
                new_canister_status.cycles(),
                (icpts_to_cycles.to_cycles((initial_amount + top_up_amount).unwrap())
                    - config.canister_creation_fee
                    - config.ingress_message_reception_fee
                    - config.ingress_byte_reception_fee
                        * (msg_size + "canister_status".len() + nonce_size))
                    .get()
            );

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
        info!(ctx.logger, "registering subnets override");
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

        info!(ctx.logger, "creating NNS canister");

        let nns_amount = Tokens::new(2, 0).unwrap();

        let new_canister_id = user1
            .create_canister_cmc(nns_amount, None, &controller_pid)
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
        info!(
            ctx.logger,
            "upgrading cycles minting canister to empty module"
        );

        let wasm = wabt::wat2wasm("(module)").unwrap();

        upgrade_nns_canister_by_proposal(
            &Canister::new(&nns, CYCLES_MINTING_CANISTER_ID),
            &Canister::new(&nns, GOVERNANCE_CANISTER_ID),
            &Canister::new(&nns, ROOT_CANISTER_ID),
            true,
            Wasm::from_bytes(wasm),
        )
        .await;

        info!(ctx.logger, "creating NNS canister (will fail)");
        let block = user1
            .pay_for_canister(nns_amount, None, &controller_pid)
            .await;
        let err = user1
            .notify_canister_create_cmc(block, None, &controller_pid)
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

        info!(ctx.logger, "upgrading cycles minting canister");
        let wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
            "rosetta-api/cycles_minting_canister",
            "cycles-minting-canister",
            &[],
        );

        upgrade_nns_canister_by_proposal(
            &Canister::new(&nns, CYCLES_MINTING_CANISTER_ID),
            &Canister::new(&nns, GOVERNANCE_CANISTER_ID),
            &Canister::new(&nns, ROOT_CANISTER_ID),
            true,
            wasm,
        )
        .await;

        info!(ctx.logger, "creating NNS canister");

        user1
            .notify_canister_create_cmc(block, None, &controller_pid)
            .await
            .unwrap();

        // remove when ledger notify goes away
        user1
            .create_canister_ledger(nns_amount, None, &controller_pid)
            .await
            .unwrap();

        /* Exceed the daily cycles minting limit. */
        info!(ctx.logger, "creating canister (exceeding daily limit)");

        let amount = Tokens::new(100_000, 0).unwrap();

        let (err, refund_block) = user1
            .create_canister_cmc(amount, None, &controller_pid)
            .await
            .unwrap_err();

        info!(ctx.logger, "error: {}", err);
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

            info!(ctx.logger, "error: {}", err);
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

    pub async fn get_block(&self, h: BlockHeight) -> Result<Option<Block>, String> {
        match self
            .query_pb(&LEDGER_CANISTER_ID, "block_pb", BlockArg(h))
            .await?
        {
            BlockRes(None) => Ok(None),
            BlockRes(Some(Ok(block))) => Ok(Some(block.decode().unwrap())),
            BlockRes(Some(Err(canister_id))) => unimplemented! {"FIXME: {}", canister_id},
        }
    }

    pub async fn get_balance(&self, acc: AccountIdentifier) -> Tokens {
        let arg = AccountBalanceArgs::new(acc);
        let res: Result<Tokens, String> = self
            .query_pb(&LEDGER_CANISTER_ID, "account_balance_pb", arg)
            .await;
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
        refund_block: BlockHeight,
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
        user_keypair: &ed25519_dalek::Keypair,
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
    ) -> CreateCanisterResult {
        let block = self
            .pay_for_canister(amount, sender_subaccount, controller_id)
            .await;
        self.notify_canister_create_cmc(block, sender_subaccount, controller_id)
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
    ) -> BlockHeight {
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
    ) -> BlockHeight {
        let (send_args, _subaccount) =
            top_up_canister_txn(amount, sender_subaccount, &self.cmc_id, target_canister_id);

        self.update_pb(&self.ledger_id, "send_pb", send_args)
            .await
            .unwrap()
    }

    pub async fn notify_canister_create_cmc(
        &self,
        block: BlockHeight,
        sender_subaccount: Option<Subaccount>,
        controller_id: &PrincipalId,
    ) -> CreateCanisterResult {
        // switch to cmc path when it's enabled
        self.notify_canister_create_ledger(block, sender_subaccount, controller_id)
            .await
    }

    pub async fn notify_canister_create_ledger(
        &self,
        block: BlockHeight,
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
        block_idx: BlockHeight,
        sender_subaccount: Option<Subaccount>,
        target_canister_id: &CanisterId,
    ) -> TopUpCanisterResult {
        // switch to cmc path when it's enabled
        self.notify_top_up_ledger(block_idx, sender_subaccount, target_canister_id)
            .await
    }

    pub async fn notify_top_up_ledger(
        &self,
        block: BlockHeight,
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
