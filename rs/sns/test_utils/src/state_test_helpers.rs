use crate::itest_helpers::populate_canister_ids;
use candid::{Decode, Encode};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ic00_types::CanisterInstallMode;
use ic_nervous_system_common::ExplosiveTokens;
use ic_nns_constants::{
    LEDGER_CANISTER_ID as ICP_LEDGER_CANISTER_ID, ROOT_CANISTER_ID as NNS_ROOT_CANISTER_ID,
};
use ic_nns_test_utils::sns_wasm::{
    build_governance_sns_wasm, build_index_sns_wasm, build_ledger_sns_wasm, build_root_sns_wasm,
    build_swap_sns_wasm,
};
use ic_nns_test_utils::state_test_helpers::set_controllers;
use ic_sns_governance::pb::v1::{ListNeurons, ListNeuronsResponse};
use ic_sns_init::SnsCanisterInitPayloads;
use ic_sns_root::pb::v1::{RegisterDappCanisterRequest, RegisterDappCanisterResponse};
use ic_sns_swap::pb::v1::{self as swap_pb, RefreshBuyerTokensRequest};
use ic_state_machine_tests::StateMachine;
use ic_types::ingress::WasmResult;
use icp_ledger::{AccountIdentifier, Memo, TransferArgs, DEFAULT_TRANSFER_FEE};

#[derive(Debug)]
pub struct SnsTestCanisterIds {
    pub root_canister_id: CanisterId,
    pub governance_canister_id: CanisterId,
    pub ledger_canister_id: CanisterId,
    pub swap_canister_id: CanisterId,
    pub index_canister_id: CanisterId,
}

pub fn setup_sns_canisters(
    state_machine: &StateMachine,
    mut payloads: SnsCanisterInitPayloads,
) -> SnsTestCanisterIds {
    let create_canister = || state_machine.create_canister(/* settings= */ None);
    let install_canister = |canister_id, wasm, payload| {
        state_machine
            .install_wasm_in_mode(canister_id, CanisterInstallMode::Install, wasm, payload)
            .unwrap()
    };

    let root_canister_id = create_canister();
    let governance_canister_id = create_canister();
    let ledger_canister_id = create_canister();
    let swap_canister_id = create_canister();
    let index_canister_id = create_canister();

    set_controllers(
        state_machine,
        PrincipalId::new_anonymous(),
        root_canister_id,
        vec![governance_canister_id.into()],
    );
    set_controllers(
        state_machine,
        PrincipalId::new_anonymous(),
        governance_canister_id,
        vec![root_canister_id.into()],
    );
    set_controllers(
        state_machine,
        PrincipalId::new_anonymous(),
        ledger_canister_id,
        vec![root_canister_id.into()],
    );
    set_controllers(
        state_machine,
        PrincipalId::new_anonymous(),
        swap_canister_id,
        vec![NNS_ROOT_CANISTER_ID.into(), swap_canister_id.into()],
    );
    set_controllers(
        state_machine,
        PrincipalId::new_anonymous(),
        index_canister_id,
        vec![root_canister_id.into()],
    );

    populate_canister_ids(
        root_canister_id,
        governance_canister_id,
        ledger_canister_id,
        swap_canister_id,
        index_canister_id,
        &mut payloads,
    );

    let SnsCanisterInitPayloads {
        governance,
        ledger,
        root,
        swap,
        index,
    } = payloads;

    install_canister(
        root_canister_id,
        build_root_sns_wasm().wasm,
        Encode!(&root).unwrap(),
    );
    install_canister(
        governance_canister_id,
        build_governance_sns_wasm().wasm,
        Encode!(&governance).unwrap(),
    );
    install_canister(
        ledger_canister_id,
        build_ledger_sns_wasm().wasm,
        Encode!(&ledger).unwrap(),
    );
    install_canister(
        swap_canister_id,
        build_swap_sns_wasm().wasm,
        Encode!(&swap).unwrap(),
    );
    install_canister(
        index_canister_id,
        build_index_sns_wasm().wasm,
        Encode!(&index).unwrap(),
    );

    SnsTestCanisterIds {
        root_canister_id,
        governance_canister_id,
        ledger_canister_id,
        swap_canister_id,
        index_canister_id,
    }
}

pub fn sns_governance_list_neurons(
    state_machine: &mut StateMachine,
    sns_governance_canister_id: CanisterId,
    request: &ListNeurons,
) -> ListNeuronsResponse {
    let result = state_machine
        .execute_ingress(
            sns_governance_canister_id,
            "list_neurons",
            Encode!(&request).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_state was rejected by the swap canister: {:#?}", reject)
        }
    };
    Decode!(&result, ListNeuronsResponse).unwrap()
}

pub fn participate_in_swap(
    state_machine: &mut StateMachine,
    swap_canister_id: CanisterId,
    participant_principal_id: PrincipalId,
    amount: ExplosiveTokens,
) {
    // First, transfer ICP to swap. Needs to go into a special subaccount...
    send_participation_funds(
        state_machine,
        swap_canister_id,
        participant_principal_id,
        amount,
    );

    // ... then, swap must be notified about that transfer.
    state_machine
        .execute_ingress(
            swap_canister_id,
            "refresh_buyer_tokens",
            Encode!(&RefreshBuyerTokensRequest {
                buyer: participant_principal_id.to_string(),
            })
            .unwrap(),
        )
        .unwrap();
}

pub fn send_participation_funds(
    state_machine: &mut StateMachine,
    swap_canister_id: CanisterId,
    participant_principal_id: PrincipalId,
    amount: ExplosiveTokens,
) {
    let subaccount = icp_ledger::Subaccount(ic_sns_swap::swap::principal_to_subaccount(
        &participant_principal_id,
    ));
    let request = Encode!(&TransferArgs {
        memo: Memo(0),
        amount: amount.into(),
        fee: DEFAULT_TRANSFER_FEE,
        from_subaccount: None,
        to: AccountIdentifier::new(swap_canister_id.into(), Some(subaccount)).to_address(),
        created_at_time: None,
    })
    .unwrap();
    state_machine
        .execute_ingress_as(
            participant_principal_id,
            ICP_LEDGER_CANISTER_ID,
            "transfer",
            request,
        )
        .unwrap();
}

pub fn swap_get_state(
    state_machine: &mut StateMachine,
    swap_canister_id: CanisterId,
    request: &swap_pb::GetStateRequest,
) -> swap_pb::GetStateResponse {
    let result = state_machine
        .execute_ingress(swap_canister_id, "get_state", Encode!(request).unwrap())
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_state was rejected by the swap canister: {:#?}", reject)
        }
    };
    Decode!(&result, swap_pb::GetStateResponse).unwrap()
}

pub fn sns_root_register_dapp_canister(
    state_machine: &mut StateMachine,
    target_canister_id: CanisterId,
    request: &RegisterDappCanisterRequest,
) -> RegisterDappCanisterResponse {
    let result = state_machine
        .execute_ingress(
            target_canister_id,
            "register_dapp_canister",
            Encode!(&request).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!(
                "register_dapp_canister was rejected by the swap canister: {:#?}",
                reject
            )
        }
    };
    Decode!(&result, RegisterDappCanisterResponse).unwrap()
}
