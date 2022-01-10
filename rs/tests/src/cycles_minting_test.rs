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
    IcpXdrConversionRateCertifiedResponse, TokensToCycles, CREATE_CANISTER_REFUND_FEE,
    DEFAULT_CYCLES_PER_XDR,
};
use dfn_candid::{candid_one, CandidOne};
use dfn_protobuf::ProtoBuf;
use ic_canister_client::{Agent, HttpClient, Sender};
use ic_certified_vars::verify_certificate;
use ic_config::subnet_config::CyclesAccountManagerConfig;
use ic_crypto::threshold_sig_public_key_from_der;
use ic_crypto_tree_hash::MixedHashTree;
use ic_fondue::{ic_instance::InternetComputer, ic_manager::IcHandle};
use ic_nns_common::types::{NeuronId, UpdateIcpXdrConversionRatePayload};
use ic_nns_constants::{
    ids::{TEST_NEURON_1_OWNER_KEYPAIR, TEST_USER1_KEYPAIR, TEST_USER1_PRINCIPAL},
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
use ic_types::{
    ic00::{CanisterIdRecord, CanisterStatusResult},
    Cycles,
};
use ledger_canister::{
    self, Block, BlockArg, BlockHeight, BlockRes, Operation, Tokens, TRANSACTION_FEE,
};
use on_wire::{FromWire, IntoWire};
use slog::info;
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

        let (
            _controller_user_id,
            controller_user_keypair,
            _controller_user_public_key,
            controller_pid,
        ) = make_user(7);

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

        let (err, refund_block) = cycles_minting_client::CreateCanister {
            client: agent_client.clone(),
            ic_url: nns_endpoint.url.clone(),
            ledger_canister_id: &LEDGER_CANISTER_ID,
            cycles_canister_id: &CYCLES_MINTING_CANISTER_ID,
            sender_keypair: &TEST_USER1_KEYPAIR,
            sender_subaccount: None,
            amount: send_amount,
            controller_id: &controller_pid,
        }
        .execute()
        .await
        .unwrap_err();

        info!(ctx.logger, "error: {}", err);
        assert!(err.contains("No subnets in which to create a canister"));

        /* Check that the funds for the failed creation attempt are returned to use
         * (minus the fees). */
        let refund_block = refund_block.unwrap();
        check_refund(
            &nns_endpoint.url,
            &agent_client,
            refund_block,
            send_amount,
            CREATE_CANISTER_REFUND_FEE,
        )
        .await;

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
        info!(ctx.logger, "creating canister (not enough funds)");

        let insufficient_amount1 = Tokens::new(0, 10_000_000).unwrap();

        let (err, refund_block) = cycles_minting_client::CreateCanister {
            client: agent_client.clone(),
            ic_url: nns_endpoint.url.clone(),
            ledger_canister_id: &LEDGER_CANISTER_ID,
            cycles_canister_id: &CYCLES_MINTING_CANISTER_ID,
            sender_keypair: &TEST_USER1_KEYPAIR,
            sender_subaccount: None,
            amount: insufficient_amount1,
            controller_id: &controller_pid,
        }
        .execute()
        .await
        .unwrap_err();

        info!(ctx.logger, "error: {}", err);
        assert!(err.contains("Creating a canister requires a fee of"));

        let refund_block = refund_block.unwrap();
        check_refund(
            &nns_endpoint.url,
            &agent_client,
            refund_block,
            insufficient_amount1,
            CREATE_CANISTER_REFUND_FEE,
        )
        .await;

        /* Create with funds < the refund fee. */
        info!(ctx.logger, "creating canister (not enough funds)");

        let insufficient_amount2 = (TRANSACTION_FEE + Tokens::from_e8s(10_000)).unwrap();

        let (err, no_refund_block) = cycles_minting_client::CreateCanister {
            client: agent_client.clone(),
            ic_url: nns_endpoint.url.clone(),
            ledger_canister_id: &LEDGER_CANISTER_ID,
            cycles_canister_id: &CYCLES_MINTING_CANISTER_ID,
            sender_keypair: &TEST_USER1_KEYPAIR,
            sender_subaccount: None,
            amount: insufficient_amount2,
            controller_id: &controller_pid,
        }
        .execute()
        .await
        .unwrap_err();

        info!(ctx.logger, "error: {}", err);
        assert!(err.contains("Creating a canister requires a fee of"));

        /* There should be no refund, all the funds will be burned. */
        assert!(no_refund_block.is_none());

        let block = get_block(&nns_endpoint.url, &agent_client, refund_block + 4)
            .await
            .unwrap()
            .unwrap();

        let txn = block.transaction();

        match txn.operation {
            Operation::Burn { amount, .. } => {
                assert_eq!((insufficient_amount2 - TRANSACTION_FEE).unwrap(), amount);
            }
            _ => panic!("unexpected block {:?}", txn),
        }

        /* Create with sufficient funds. */
        info!(ctx.logger, "creating canister");

        let initial_amount = Tokens::new(10_000, 0).unwrap();

        let new_canister_id = cycles_minting_client::CreateCanister {
            client: agent_client.clone(),
            ic_url: nns_endpoint.url.clone(),
            ledger_canister_id: &LEDGER_CANISTER_ID,
            cycles_canister_id: &CYCLES_MINTING_CANISTER_ID,
            sender_keypair: &TEST_USER1_KEYPAIR,
            sender_subaccount: None,
            amount: initial_amount,
            controller_id: &controller_pid,
        }
        .execute()
        .await
        .unwrap();

        /* Check that the funds for the canister creation attempt are burned. */
        let block = get_block(&nns_endpoint.url, &agent_client, refund_block + 7)
            .await
            .unwrap()
            .unwrap();

        let txn = block.transaction();

        match txn.operation {
            Operation::Burn { amount, .. } => {
                assert_eq!((amount + TRANSACTION_FEE).unwrap(), initial_amount);
            }
            _ => panic!("unexpected block {:?}", txn),
        }

        info!(ctx.logger, "topping up");

        let top_up_amount = Tokens::new(5_000, 0).unwrap();

        cycles_minting_client::TopUpCanister {
            client: agent_client.clone(),
            ic_url: nns_endpoint.url.clone(),
            ledger_canister_id: &LEDGER_CANISTER_ID,
            cycles_canister_id: &CYCLES_MINTING_CANISTER_ID,
            sender_keypair: &TEST_USER1_KEYPAIR,
            sender_subaccount: None,
            amount: top_up_amount,
            target_canister_id: &new_canister_id,
        }
        .execute()
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
        let block = get_block(&nns_endpoint.url, &agent_client, refund_block + 10)
            .await
            .unwrap()
            .unwrap();

        let txn = block.transaction();

        match txn.operation {
            Operation::Burn { amount, .. } => {
                assert_eq!((amount + TRANSACTION_FEE).unwrap(), top_up_amount);
            }
            _ => panic!("unexpected block {:?}", txn),
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

        let new_canister_id = cycles_minting_client::CreateCanister {
            client: agent_client.clone(),
            ic_url: nns_endpoint.url.clone(),
            ledger_canister_id: &LEDGER_CANISTER_ID,
            cycles_canister_id: &CYCLES_MINTING_CANISTER_ID,
            sender_keypair: &TEST_USER1_KEYPAIR,
            sender_subaccount: None,
            amount: nns_amount,
            controller_id: &controller_pid,
        }
        .execute()
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
        let err = cycles_minting_client::CreateCanister {
            client: agent_client.clone(),
            ic_url: nns_endpoint.url.clone(),
            ledger_canister_id: &LEDGER_CANISTER_ID,
            cycles_canister_id: &CYCLES_MINTING_CANISTER_ID,
            sender_keypair: &TEST_USER1_KEYPAIR,
            sender_subaccount: None,
            amount: nns_amount,
            controller_id: &controller_pid,
        }
        .execute()
        .await
        .unwrap_err();
        assert!(
            err.0
                .contains("has no update method 'transaction_notification_pb'"),
            "Error message was: {}",
            err.0
        );

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

        cycles_minting_client::CreateCanister {
            client: agent_client.clone(),
            ic_url: nns_endpoint.url.clone(),
            ledger_canister_id: &LEDGER_CANISTER_ID,
            cycles_canister_id: &CYCLES_MINTING_CANISTER_ID,
            sender_keypair: &TEST_USER1_KEYPAIR,
            sender_subaccount: None,
            amount: nns_amount,
            controller_id: &controller_pid,
        }
        .execute()
        .await
        .unwrap();

        /* Exceed the daily cycles minting limit. */
        info!(ctx.logger, "creating canister (exceeding daily limit)");

        let amount = Tokens::new(100_000, 0).unwrap();

        let (err, refund_block) = cycles_minting_client::CreateCanister {
            client: agent_client.clone(),
            ic_url: nns_endpoint.url.clone(),
            ledger_canister_id: &LEDGER_CANISTER_ID,
            cycles_canister_id: &CYCLES_MINTING_CANISTER_ID,
            sender_keypair: &TEST_USER1_KEYPAIR,
            sender_subaccount: None,
            amount,
            controller_id: &controller_pid,
        }
        .execute()
        .await
        .unwrap_err();

        info!(ctx.logger, "error: {}", err);
        assert!(err
            .contains("cycles have been minted in the last 3600 seconds, please try again later"));

        let refund_block = refund_block.unwrap();
        check_refund(
            &nns_endpoint.url,
            &agent_client,
            refund_block,
            amount,
            CREATE_CANISTER_REFUND_FEE,
        )
        .await;

        /* Test getting the total number of cycles minted. */
        let bytes = Agent::new_with_client(
            agent_client.clone(),
            nns_endpoint.url.clone(),
            Sender::Anonymous,
        )
        .execute_query(
            &CYCLES_MINTING_CANISTER_ID,
            "total_cycles_minted",
            ProtoBuf(()).into_bytes().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        let cycles_minted: u64 = ProtoBuf::from_bytes(bytes).map(|c| c.0).unwrap();

        let total_icpts = (((((insufficient_amount1 + insufficient_amount2).unwrap()
            + initial_amount)
            .unwrap()
            + top_up_amount)
            .unwrap()
            + nns_amount)
            .unwrap()
            + nns_amount)
            .unwrap();

        assert_eq!(
            Cycles::from(cycles_minted),
            icpts_to_cycles.to_cycles(total_icpts)
        );
    });
}

async fn get_block(
    ic_url: &Url,
    agent_client: &HttpClient,
    block_index: BlockHeight,
) -> Result<Option<Block>, String> {
    let ledger_agent =
        Agent::new_with_client(agent_client.clone(), ic_url.clone(), Sender::Anonymous);

    let bytes = ledger_agent
        .execute_query(
            &LEDGER_CANISTER_ID,
            "block_pb",
            ProtoBuf(BlockArg(block_index)).into_bytes()?,
        )
        .await?
        .unwrap();
    let resp: Result<BlockRes, String> = ProtoBuf::from_bytes(bytes).map(|c| c.0);

    match resp? {
        BlockRes(None) => Ok(None),
        BlockRes(Some(Ok(block))) => Ok(Some(block.decode().unwrap())),
        BlockRes(Some(Err(canister_id))) => unimplemented! {"FIXME: {}", canister_id},
    }
}

async fn check_refund(
    ic_url: &Url,
    agent_client: &HttpClient,
    refund_block: BlockHeight,
    send_amount: Tokens,
    refund_fee: Tokens,
) {
    let block = get_block(ic_url, agent_client, refund_block)
        .await
        .unwrap()
        .unwrap();

    let txn = block.transaction();

    match txn.operation {
        Operation::Transfer { amount, to, .. } => {
            assert_eq!(
                ((amount + TRANSACTION_FEE).unwrap() + refund_fee).unwrap(),
                send_amount
            );
            assert_eq!(to, (*TEST_USER1_PRINCIPAL).into());
        }
        _ => panic!("unexpected block {:?}", txn),
    }

    let block = get_block(ic_url, agent_client, refund_block + 1)
        .await
        .unwrap()
        .unwrap();

    let txn = block.transaction();

    match txn.operation {
        Operation::Burn { amount, .. } => {
            assert_eq!(refund_fee, amount);
        }
        _ => panic!("unexpected block {:?}", txn),
    }
}
