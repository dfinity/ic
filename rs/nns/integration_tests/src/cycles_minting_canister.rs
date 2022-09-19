use canister_test::Canister;
use cycles_minting_canister::{
    ChangeSubnetTypeAssignmentArgs, IcpXdrConversionRateCertifiedResponse, SubnetListWithType,
    SubnetTypesToSubnetsResponse, UpdateSubnetTypeArgs, MEMO_TOP_UP_CANISTER,
};
use dfn_candid::candid_one;
use dfn_protobuf::protobuf;
use ic_canister_client_sender::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_USER1_KEYPAIR, TEST_USER1_PRINCIPAL,
};
use ic_nns_common::types::{NeuronId, ProposalId, UpdateIcpXdrConversionRatePayload};
use ic_nns_constants::{CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID};
use ic_nns_governance::pb::v1::{NnsFunction, ProposalStatus};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    governance::submit_external_update_proposal,
    governance::wait_for_final_state,
    ids::TEST_NEURON_1_ID,
    itest_helpers::{local_test_on_nns_subnet, NnsCanisters},
};
use ic_types_test_utils::ids::subnet_test_id;
use ledger_canister::{
    tokens_from_proto, AccountBalanceArgs, AccountIdentifier, BlockIndex, CyclesResponse, Memo,
    NotifyCanisterArgs, SendArgs, Subaccount, Tokens, DEFAULT_TRANSFER_FEE,
};

/// Test that the CMC's `icp_xdr_conversion_rate` can be updated via Governance
/// proposal.
#[test]
fn test_set_icp_xdr_conversion_rate() {
    local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let payload = UpdateIcpXdrConversionRatePayload {
            data_source: "test_set_icp_xdr_conversion_rate".to_string(),
            timestamp_seconds: 10,
            xdr_permyriad_per_icp: 200,
        };

        set_icp_xdr_conversion_rate(&nns_canisters, payload).await;

        Ok(())
    });
}

async fn set_icp_xdr_conversion_rate(
    nns: &NnsCanisters<'_>,
    payload: UpdateIcpXdrConversionRatePayload,
) {
    let proposal_id: ProposalId = submit_external_update_proposal(
        &nns.governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::IcpXdrConversionRate,
        payload.clone(),
        "<proposal created by set_icp_xdr_conversion_rate>".to_string(),
        "".to_string(),
    )
    .await;

    // Wait for the proposal to be accepted and executed.
    assert_eq!(
        wait_for_final_state(&nns.governance, proposal_id)
            .await
            .status(),
        ProposalStatus::Executed
    );

    let response: IcpXdrConversionRateCertifiedResponse = nns
        .cycles_minting
        .query_("get_icp_xdr_conversion_rate", candid_one, ())
        .await
        .unwrap();

    assert_eq!(response.data.timestamp_seconds, payload.timestamp_seconds);
    assert_eq!(
        response.data.xdr_permyriad_per_icp,
        payload.xdr_permyriad_per_icp
    );
}

/// Test that we can top-up the Governance canister with cycles when the CMC has
/// a set exchange rate
#[test]
fn test_cmc_mints_cycles_when_cmc_has_exchange_rate() {
    local_test_on_nns_subnet(|runtime| async move {
        let account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
        let icpts = Tokens::new(100, 0).unwrap();

        // The CMC subaccount to send ICP to. In this test we try to top-up an existing
        // canister, and Governance is simply a convenient pre-existing canister.
        let subaccount: Subaccount = GOVERNANCE_CANISTER_ID.get_ref().into();

        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .with_ledger_account(account, icpts)
            .build();

        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let payload = UpdateIcpXdrConversionRatePayload {
            data_source: "test_set_icp_xdr_conversion_rate".to_string(),
            timestamp_seconds: 10,
            xdr_permyriad_per_icp: 20_000,
        };

        set_icp_xdr_conversion_rate(&nns_canisters, payload).await;

        let total_cycles_minted_initial: u64 = nns_canisters
            .cycles_minting
            .query_("total_cycles_minted", protobuf, ())
            .await
            .unwrap();

        // Top-up the Governance canister
        let cycles_response = send_cycles(
            icpts,
            &nns_canisters.ledger,
            MEMO_TOP_UP_CANISTER,
            &subaccount,
        )
        .await;

        match cycles_response {
            CyclesResponse::ToppedUp(_) => (),
            _ => panic!("Failed to top up canister"),
        }

        // Assert that the correct amount of TEST_USER1's ICP was used to create cycles
        let final_balance: Tokens = nns_canisters
            .ledger
            .query_from_sender(
                "account_balance_pb",
                protobuf,
                AccountBalanceArgs { account },
                &Sender::from_keypair(&TEST_USER1_KEYPAIR),
            )
            .await
            .map(tokens_from_proto)
            .unwrap();

        let mut expected_final_balance = icpts;
        expected_final_balance = (expected_final_balance - Tokens::new(10, 0).unwrap()).unwrap();
        expected_final_balance = (expected_final_balance
            - (DEFAULT_TRANSFER_FEE + DEFAULT_TRANSFER_FEE).unwrap())
        .unwrap();
        assert_eq!(final_balance, expected_final_balance);

        let total_cycles_minted_final: u64 = nns_canisters
            .cycles_minting
            .query_("total_cycles_minted", protobuf, ())
            .await
            .unwrap();

        // Assert that the expected amount of cycles were minted
        assert_eq!(
            total_cycles_minted_final - total_cycles_minted_initial,
            20000000000000
        );

        Ok(())
    });
}

/// Sends 10 ICP from `TEST_USER1_PRINCIPAL`s Ledger account to the given
/// subaccount of the CMC, which then, depending on `memo`, either tries to
/// create a canister (aka a "cycles wallet") or top-up the canister whose
/// `CanisterId` corresponds to `subaccount`.
async fn send_cycles(
    initial_icpts: Tokens,
    ledger: &Canister<'_>,
    memo: Memo,
    subaccount: &Subaccount,
) -> CyclesResponse {
    let account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);

    let initial_balance: Tokens = ledger
        .query_from_sender(
            "account_balance_pb",
            protobuf,
            AccountBalanceArgs { account },
            &Sender::from_keypair(&TEST_USER1_KEYPAIR),
        )
        .await
        .map(tokens_from_proto)
        .unwrap();

    assert_eq!(initial_balance, initial_icpts);

    let send_args = SendArgs {
        memo,
        amount: Tokens::new(10, 0).unwrap(),
        fee: DEFAULT_TRANSFER_FEE,
        from_subaccount: None,
        to: AccountIdentifier::new(CYCLES_MINTING_CANISTER_ID.get(), Some(*subaccount)),
        created_at_time: None,
    };

    let block_height: BlockIndex = ledger
        .update_from_sender(
            "send_dfx",
            candid_one,
            send_args.clone(),
            &Sender::from_keypair(&TEST_USER1_KEYPAIR),
        )
        .await
        .unwrap();

    let after_send_balance: Tokens = ledger
        .query_from_sender(
            "account_balance_pb",
            protobuf,
            AccountBalanceArgs { account },
            &Sender::from_keypair(&TEST_USER1_KEYPAIR),
        )
        .await
        .map(tokens_from_proto)
        .unwrap();

    let mut expected_balance = initial_icpts;
    expected_balance = (expected_balance - Tokens::new(10, 0).unwrap()).unwrap();
    expected_balance = (expected_balance - DEFAULT_TRANSFER_FEE).unwrap();
    assert_eq!(after_send_balance, expected_balance);

    let notify_args = NotifyCanisterArgs::new_from_send(
        &send_args,
        block_height,
        CYCLES_MINTING_CANISTER_ID,
        Some(*subaccount),
    )
    .unwrap();

    let cycles_response: CyclesResponse = ledger
        .update_from_sender(
            "notify_dfx",
            candid_one,
            notify_args.clone(),
            &Sender::from_keypair(&TEST_USER1_KEYPAIR),
        )
        .await
        .unwrap();

    cycles_response
}

async fn update_subnet_type(nns: &NnsCanisters<'_>, payload: UpdateSubnetTypeArgs) {
    let proposal_id: ProposalId = submit_external_update_proposal(
        &nns.governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::UpdateSubnetType,
        payload.clone(),
        "<proposal created by update_subnet_type>".to_string(),
        "".to_string(),
    )
    .await;

    // Wait for the proposal to be accepted and executed.
    assert_eq!(
        wait_for_final_state(&nns.governance, proposal_id)
            .await
            .status(),
        ProposalStatus::Executed
    );
}

#[test]
fn test_update_subnet_type() {
    local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let payload = UpdateSubnetTypeArgs::Add("Fiduciary".to_string());

        update_subnet_type(&nns_canisters, payload).await;

        let response: SubnetTypesToSubnetsResponse = nns_canisters
            .cycles_minting
            .query_("get_subnet_types_to_subnets", candid_one, ())
            .await
            .unwrap();
        assert_eq!(
            response,
            SubnetTypesToSubnetsResponse {
                data: vec![("Fiduciary".to_string(), vec![])]
            }
        );

        Ok(())
    });
}

async fn change_subnet_type_assignment(
    nns: &NnsCanisters<'_>,
    payload: ChangeSubnetTypeAssignmentArgs,
) {
    let proposal_id: ProposalId = submit_external_update_proposal(
        &nns.governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::ChangeSubnetTypeAssignment,
        payload.clone(),
        "<proposal created by change_subnet_type_assignment>".to_string(),
        "".to_string(),
    )
    .await;

    // Wait for the proposal to be accepted and executed.
    assert_eq!(
        wait_for_final_state(&nns.governance, proposal_id)
            .await
            .status(),
        ProposalStatus::Executed
    );
}

#[test]
fn test_change_subnet_type_assignment() {
    local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let type1 = "Type1".to_string();
        let type2 = "Type2".to_string();
        update_subnet_type(&nns_canisters, UpdateSubnetTypeArgs::Add(type1.clone())).await;
        update_subnet_type(&nns_canisters, UpdateSubnetTypeArgs::Add(type2.clone())).await;

        let subnet1 = subnet_test_id(0);
        let subnet2 = subnet_test_id(1);
        let subnet3 = subnet_test_id(2);

        let payload = ChangeSubnetTypeAssignmentArgs::Add(SubnetListWithType {
            subnets: vec![subnet1, subnet2],
            subnet_type: type1.clone(),
        });
        change_subnet_type_assignment(&nns_canisters, payload).await;

        let payload = ChangeSubnetTypeAssignmentArgs::Add(SubnetListWithType {
            subnets: vec![subnet3],
            subnet_type: type2.clone(),
        });
        change_subnet_type_assignment(&nns_canisters, payload).await;

        let response: SubnetTypesToSubnetsResponse = nns_canisters
            .cycles_minting
            .query_("get_subnet_types_to_subnets", candid_one, ())
            .await
            .unwrap();
        assert_eq!(
            response,
            SubnetTypesToSubnetsResponse {
                data: vec![
                    (type1.clone(), vec![subnet1, subnet2]),
                    (type2.clone(), vec![subnet3])
                ]
            }
        );

        let payload = ChangeSubnetTypeAssignmentArgs::Remove(SubnetListWithType {
            subnets: vec![subnet2],
            subnet_type: type1.clone(),
        });
        change_subnet_type_assignment(&nns_canisters, payload).await;

        let response: SubnetTypesToSubnetsResponse = nns_canisters
            .cycles_minting
            .query_("get_subnet_types_to_subnets", candid_one, ())
            .await
            .unwrap();
        assert_eq!(
            response,
            SubnetTypesToSubnetsResponse {
                data: vec![(type1, vec![subnet1]), (type2, vec![subnet3])]
            }
        );

        Ok(())
    });
}
