use crate::itest_helpers::{SnsTestsInitPayloadBuilder, populate_canister_ids};
use candid::{CandidType, Decode, Encode};
use canister_test::Project;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::Tokens;
use ic_management_canister_types_private::CanisterInstallMode;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord, canister_status::CanisterStatusResultV2,
};
use ic_nervous_system_common::ExplosiveTokens;
use ic_nervous_system_common_test_keys::TEST_USER1_PRINCIPAL;
use ic_nns_constants::{
    LEDGER_CANISTER_ID as ICP_LEDGER_CANISTER_ID, ROOT_CANISTER_ID as NNS_ROOT_CANISTER_ID,
};
use ic_nns_test_utils::{
    sns_wasm::{
        build_governance_sns_wasm, build_index_ng_sns_wasm, build_ledger_sns_wasm,
        build_root_sns_wasm, build_swap_sns_wasm,
    },
    state_test_helpers::set_controllers,
};
use ic_sns_governance::pb::v1::{
    ListNeurons, ListNeuronsResponse, ManageNeuron, ManageNeuronResponse, NervousSystemParameters,
    NeuronId, ProposalId, Vote,
    governance::Version,
    manage_neuron::{self, RegisterVote},
};
use ic_sns_init::SnsCanisterInitPayloads;
use ic_sns_root::{
    GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse,
    pb::v1::{
        RegisterDappCanisterRequest, RegisterDappCanisterResponse, RegisterDappCanistersRequest,
        RegisterDappCanistersResponse,
    },
};
use ic_sns_swap::pb::v1::{
    self as swap_pb, ErrorRefundIcpResponse, FinalizeSwapResponse, GetBuyerStateResponse,
    GetBuyersTotalResponse, GetLifecycleResponse, GetOpenTicketResponse, GetSaleParametersResponse,
    ListCommunityFundParticipantsResponse, NewSaleTicketResponse, NotifyPaymentFailureResponse,
    RefreshBuyerTokensRequest, RefreshBuyerTokensResponse, Ticket,
};
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_types::ingress::WasmResult;
use icp_ledger::{
    AccountIdentifier, BlockIndex, DEFAULT_TRANSFER_FEE, Memo, TransferArgs, TransferError,
};
use icrc_ledger_types::icrc1::account::Account;

pub fn state_machine_builder_for_sns_tests() -> StateMachineBuilder {
    StateMachineBuilder::new().with_current_time()
}

#[derive(Copy, Clone, Debug)]
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
        root_canister_id.get(),
        governance_canister_id.get(),
        ledger_canister_id.get(),
        swap_canister_id.get(),
        index_canister_id.get(),
        vec![],
        &mut payloads,
    );

    let SnsCanisterInitPayloads {
        mut governance,
        ledger,
        root,
        swap,
        index_ng,
    } = payloads;

    let (root_sns_wasm, governance_sns_wasm, ledger_sns_wasm, swap_sns_wasm, index_sns_wasm) = (
        build_root_sns_wasm(),
        build_governance_sns_wasm(),
        build_ledger_sns_wasm(),
        build_swap_sns_wasm(),
        build_index_ng_sns_wasm(),
    );

    let deployed_version = Version {
        root_wasm_hash: root_sns_wasm.sha256_hash().to_vec(),
        governance_wasm_hash: governance_sns_wasm.sha256_hash().to_vec(),
        ledger_wasm_hash: ledger_sns_wasm.sha256_hash().to_vec(),
        swap_wasm_hash: swap_sns_wasm.sha256_hash().to_vec(),
        archive_wasm_hash: vec![], // tests don't need it for now so we don't compile it.
        index_wasm_hash: index_sns_wasm.sha256_hash().to_vec(),
    };

    governance.deployed_version = Some(deployed_version);

    install_canister(
        root_canister_id,
        root_sns_wasm.wasm,
        Encode!(&root).unwrap(),
    );
    install_canister(
        governance_canister_id,
        governance_sns_wasm.wasm,
        Encode!(&governance).unwrap(),
    );
    install_canister(
        ledger_canister_id,
        ledger_sns_wasm.wasm,
        Encode!(&ledger).unwrap(),
    );
    install_canister(
        swap_canister_id,
        swap_sns_wasm.wasm,
        Encode!(&swap).unwrap(),
    );
    install_canister(
        index_canister_id,
        index_sns_wasm.wasm,
        Encode!(&index_ng.expect("Index payload was None")).unwrap(),
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
    state_machine: &StateMachine,
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
            panic!("list_neurons was rejected by the governance canister: {reject:#?}")
        }
    };
    Decode!(&result, ListNeuronsResponse).unwrap()
}

pub fn sns_governance_get_nervous_system_parameters(
    state_machine: &StateMachine,
    sns_governance_canister_id: CanisterId,
) -> NervousSystemParameters {
    let result = state_machine
        .execute_ingress(
            sns_governance_canister_id,
            "get_nervous_system_parameters",
            Encode!().unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!(
                "get_nervous_system_parameters was rejected by the governance canister: {reject:#?}"
            )
        }
    };
    Decode!(&result, NervousSystemParameters).unwrap()
}

#[must_use]
fn manage_neuron(
    state_machine: &StateMachine,
    sns_governance_canister_id: CanisterId,
    sender: PrincipalId,
    neuron_id: NeuronId,
    command: manage_neuron::Command,
) -> ManageNeuronResponse {
    let result = state_machine
        .execute_ingress_as(
            sender,
            sns_governance_canister_id,
            "manage_neuron",
            Encode!(&ManageNeuron {
                command: Some(command),
                subaccount: neuron_id.id,
            })
            .unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to manage_neuron failed: {s:#?}"),
    };

    Decode!(&result, ManageNeuronResponse).unwrap()
}

pub fn sns_cast_vote(
    state_machine: &StateMachine,
    sns_governance_canister_id: CanisterId,
    sender: PrincipalId,
    neuron_id: NeuronId,
    proposal_id: ProposalId,
    vote: Vote,
) -> ManageNeuronResponse {
    let command = manage_neuron::Command::RegisterVote(RegisterVote {
        proposal: Some(proposal_id),
        vote: vote as i32,
    });

    manage_neuron(
        state_machine,
        sns_governance_canister_id,
        sender,
        neuron_id,
        command,
    )
}

pub fn participate_in_swap(
    state_machine: &StateMachine,
    swap_canister_id: CanisterId,
    participant_principal_id: PrincipalId,
    amount: ExplosiveTokens,
) -> RefreshBuyerTokensResponse {
    // First, transfer ICP to swap. Needs to go into a special subaccount...
    send_participation_funds(
        state_machine,
        swap_canister_id,
        participant_principal_id,
        amount,
    );

    // ... then, swap must be notified about that transfer.
    let response = state_machine
        .execute_ingress(
            swap_canister_id,
            "refresh_buyer_tokens",
            Encode!(&RefreshBuyerTokensRequest {
                buyer: participant_principal_id.to_string(),
                confirmation_text: None,
            })
            .unwrap(),
        )
        .unwrap();
    let response = match response {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("refresh_buyer_tokens was rejected by the swap canister: {reject:#?}")
        }
    };

    Decode!(&response, RefreshBuyerTokensResponse).unwrap()
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum SnsCanisterType {
    Ledger,
    Root,
    Governance,
    Swap,
}

impl SnsCanisterType {
    fn get_wasm(self) -> Vec<u8> {
        let features = [];
        Project::cargo_bin_maybe_from_env(self.bin_name(), &features).bytes()
    }

    fn bin_name(self) -> &'static str {
        use SnsCanisterType::*;
        match self {
            Ledger => "ic-icrc1-ledger",

            Root => "sns-root-canister",
            Governance => "sns-governance-canister",
            Swap => "sns-swap-canister",
        }
    }
}

pub fn init_canister(
    state_machine: &StateMachine,
    canister_id: CanisterId,
    sns_canister_type: SnsCanisterType,
    init_argument: &impl CandidType,
) {
    let init_argument = Encode!(init_argument).unwrap();
    state_machine
        .install_wasm_in_mode(
            canister_id,
            CanisterInstallMode::Install,
            sns_canister_type.get_wasm(),
            init_argument,
        )
        .unwrap();
}

pub fn send_participation_funds(
    state_machine: &StateMachine,
    swap_canister_id: CanisterId,
    participant_principal_id: PrincipalId,
    amount: ExplosiveTokens,
) {
    let subaccount = icp_ledger::Subaccount(ic_sns_swap::swap::principal_to_subaccount(
        &participant_principal_id,
    ));
    let transfer_args = TransferArgs {
        memo: Memo(0),
        amount: amount.into(),
        fee: DEFAULT_TRANSFER_FEE,
        from_subaccount: None,
        to: AccountIdentifier::new(swap_canister_id.into(), Some(subaccount)).to_address(),
        created_at_time: None,
    };
    let request = Encode!(&transfer_args).unwrap();
    let response = state_machine
        .execute_ingress_as(
            participant_principal_id,
            ICP_LEDGER_CANISTER_ID,
            "transfer",
            request,
        )
        .unwrap();
    let _response = match response {
        WasmResult::Reply(reply) => Decode!(&reply, Result<BlockIndex, TransferError>)
            .expect("Failed to decode response")
            .expect("Failed to transfer participation funds"),
        WasmResult::Reject(reject) => {
            panic!("transfer was rejected by the ICP ledger canister: {reject:#?}")
        }
    };
}

pub fn swap_get_state(
    state_machine: &StateMachine,
    swap_canister_id: CanisterId,
    request: &swap_pb::GetStateRequest,
) -> swap_pb::GetStateResponse {
    let result = state_machine
        .execute_ingress(swap_canister_id, "get_state", Encode!(request).unwrap())
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_state was rejected by the swap canister: {reject:#?}")
        }
    };
    Decode!(&result, swap_pb::GetStateResponse).unwrap()
}

pub fn canister_status(
    state_machine: &StateMachine,
    sender: PrincipalId,
    request: &CanisterIdRecord,
) -> CanisterStatusResultV2 {
    let request = Encode!(&request).unwrap();
    let result = state_machine
        .execute_ingress_as(sender, CanisterId::ic_00(), "canister_status", request)
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_state was rejected by the swap canister: {reject:#?}")
        }
    };
    Decode!(&result, CanisterStatusResultV2).unwrap()
}

pub fn sns_root_register_dapp_canister(
    state_machine: &StateMachine,
    sns_root_canister_id: CanisterId,
    sns_governance_canister_id: CanisterId,
    dapp_canister_id: CanisterId,
) -> RegisterDappCanisterResponse {
    let request = RegisterDappCanisterRequest {
        canister_id: Some(dapp_canister_id.into()),
    };
    let result = state_machine
        .execute_ingress_as(
            sns_governance_canister_id.into(),
            sns_root_canister_id,
            "register_dapp_canister",
            Encode!(&request).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("register_dapp_canisters was rejected by the swap canister: {reject:#?}")
        }
    };
    Decode!(&result, RegisterDappCanisterResponse).unwrap()
}

pub fn sns_root_register_dapp_canisters(
    state_machine: &StateMachine,
    sns_root_canister_id: CanisterId,
    sns_governance_canister_id: CanisterId,
    dapp_canister_ids: Vec<CanisterId>,
) -> RegisterDappCanistersResponse {
    let request = RegisterDappCanistersRequest {
        canister_ids: dapp_canister_ids.into_iter().map(|id| id.into()).collect(),
    };
    let result = state_machine
        .execute_ingress_as(
            sns_governance_canister_id.into(),
            sns_root_canister_id,
            "register_dapp_canisters",
            Encode!(&request).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("register_dapp_canisters was rejected by the swap canister: {reject:#?}")
        }
    };
    Decode!(&result, RegisterDappCanistersResponse).unwrap()
}

pub struct Scenario {
    pub configuration: SnsCanisterInitPayloads,
    pub root_canister_id: CanisterId,
    pub governance_canister_id: CanisterId,
    pub ledger_canister_id: CanisterId,
    pub swap_canister_id: CanisterId,
    pub dapp_canister_ids: Vec<CanisterId>,
}
impl Scenario {
    /// Step 1: Creates canisters, but does not install code into them.
    ///
    /// Installation is performed separately using the init_all_canisters method.
    ///
    /// These two operations are performed separately in order to allow the user
    /// to customize the canisters. This can be done by modifying
    /// self.configuration before calling init_all_canisters.
    ///
    /// self.configuration is initialized with "bare-bones" values. More
    /// precisely, it builds upon SnsTestsInitPayloadBuilder::new().build(), but
    /// this makes two enhancements:
    ///
    ///   1. The swap canister is funded (with 100 SNS tokens).
    ///   2. The canister_id fields are populated.
    ///
    /// The dapp canister is owned by TEST_USER1.
    pub fn new(state_machine: &StateMachine, sns_tokens: Tokens) -> Self {
        let create_canister = || state_machine.create_canister(/* settings= */ None);

        let root_canister_id = create_canister();
        let governance_canister_id = create_canister();
        let ledger_canister_id = create_canister();
        let swap_canister_id = create_canister();
        let dapp_canister_id = create_canister();
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
            dapp_canister_id,
            vec![*TEST_USER1_PRINCIPAL],
        );
        set_controllers(
            state_machine,
            PrincipalId::new_anonymous(),
            index_canister_id,
            vec![root_canister_id.into()],
        );

        let swap_principal_id: PrincipalId = swap_canister_id.into();
        // Construct base configuration.
        let account_identifiers = vec![Account {
            owner: swap_principal_id.0,
            subaccount: None,
        }];
        let mut configuration = SnsTestsInitPayloadBuilder::new()
            .with_ledger_accounts(account_identifiers, sns_tokens)
            .build();

        populate_canister_ids(
            root_canister_id.get(),
            governance_canister_id.get(),
            ledger_canister_id.get(),
            swap_canister_id.get(),
            index_canister_id.get(),
            vec![],
            &mut configuration,
        );

        Self {
            root_canister_id,
            governance_canister_id,
            ledger_canister_id,
            swap_canister_id,
            dapp_canister_ids: vec![dapp_canister_id],
            configuration,
        }
    }

    /// Installs respective wasms into respective canisters, using the
    /// corresponding init payload, of course.
    ///
    /// (The dapp canister is not touched).
    pub fn init_all_canisters(&self, state_machine: &StateMachine) {
        init_canister(
            state_machine,
            self.root_canister_id,
            SnsCanisterType::Root,
            &self.configuration.root,
        );
        init_canister(
            state_machine,
            self.governance_canister_id,
            SnsCanisterType::Governance,
            &self.configuration.governance,
        );
        init_canister(
            state_machine,
            self.ledger_canister_id,
            SnsCanisterType::Ledger,
            &self.configuration.ledger.clone(),
        );
        init_canister(
            state_machine,
            self.swap_canister_id,
            SnsCanisterType::Swap,
            &self.configuration.swap,
        );
    }
}

pub fn get_open_ticket(
    env: &StateMachine,
    swap_id: CanisterId,
    sender: PrincipalId,
) -> GetOpenTicketResponse {
    let args = Encode!(&swap_pb::GetOpenTicketRequest {}).unwrap();
    let res = env
        .query_as(sender, swap_id, "get_open_ticket", args)
        .unwrap();
    Decode!(&res.bytes(), GetOpenTicketResponse).unwrap()
}

pub fn new_sale_ticket(
    env: &StateMachine,
    swap_id: CanisterId,
    sender: PrincipalId,
    amount_icp_e8s: u64,
    subaccount: Option<Vec<u8>>,
) -> Result<Ticket, swap_pb::new_sale_ticket_response::Err> {
    let args = Encode!(&swap_pb::NewSaleTicketRequest {
        amount_icp_e8s,
        subaccount,
    })
    .unwrap();
    let res = env
        .execute_ingress_as(sender, swap_id, "new_sale_ticket", args)
        .unwrap();
    Decode!(&res.bytes(), NewSaleTicketResponse)
        .unwrap()
        .ticket()
}

pub fn refresh_buyer_tokens(
    env: &StateMachine,
    swap_id: &CanisterId,
    sender: &PrincipalId,
    confirmation_text: Option<String>,
) -> Result<RefreshBuyerTokensResponse, String> {
    let args = Encode!(&RefreshBuyerTokensRequest {
        buyer: sender.to_string(),
        confirmation_text,
    })
    .unwrap();
    match env.execute_ingress_as(*sender, *swap_id, "refresh_buyer_tokens", args) {
        Ok(res) => Ok(Decode!(&res.bytes(), RefreshBuyerTokensResponse).unwrap()),
        Err(e) => Err(e.description().to_owned()),
    }
}

pub fn notify_payment_failure(
    env: &StateMachine,
    swap_id: &CanisterId,
    sender: &PrincipalId,
) -> NotifyPaymentFailureResponse {
    let args = Encode!(&swap_pb::NotifyPaymentFailureRequest {}).unwrap();
    let res = env
        .execute_ingress_as(*sender, *swap_id, "notify_payment_failure", args)
        .unwrap();
    Decode!(&res.bytes(), NotifyPaymentFailureResponse).unwrap()
}

pub fn get_buyer_state(
    env: &StateMachine,
    swap_id: &CanisterId,
    sender: &PrincipalId,
) -> GetBuyerStateResponse {
    let args = Encode!(&swap_pb::GetBuyerStateRequest {
        principal_id: Some(*sender)
    })
    .unwrap();
    let res = env
        .query_as(*sender, *swap_id, "get_buyer_state", args)
        .unwrap();
    Decode!(&res.bytes(), GetBuyerStateResponse).unwrap()
}

pub fn get_sns_sale_parameters(
    env: &StateMachine,
    swap_id: &CanisterId,
) -> GetSaleParametersResponse {
    let args = Encode!(&swap_pb::GetSaleParametersRequest {}).unwrap();
    let res = env.query(*swap_id, "get_sale_parameters", args).unwrap();
    Decode!(&res.bytes(), GetSaleParametersResponse).unwrap()
}

pub fn list_community_fund_participants(
    env: &StateMachine,
    swap_id: &CanisterId,
    sender: &PrincipalId,
    limit: &u32,
    offset: &u64,
) -> ListCommunityFundParticipantsResponse {
    let args = Encode!(&swap_pb::ListCommunityFundParticipantsRequest {
        limit: Some(*limit),
        offset: Some(*offset)
    })
    .unwrap();
    let res = env
        .query_as(*sender, *swap_id, "list_community_fund_participants", args)
        .unwrap();
    Decode!(&res.bytes(), ListCommunityFundParticipantsResponse).unwrap()
}

pub fn error_refund(
    env: &StateMachine,
    swap_id: &CanisterId,
    sender: &PrincipalId,
) -> ErrorRefundIcpResponse {
    let args = Encode!(&swap_pb::ErrorRefundIcpRequest {
        source_principal_id: Some(*sender)
    })
    .unwrap();
    let res = env
        .execute_ingress_as(*sender, *swap_id, "error_refund_icp", args)
        .unwrap();
    Decode!(&res.bytes(), ErrorRefundIcpResponse).unwrap()
}

pub fn get_lifecycle(env: &StateMachine, swap_id: &CanisterId) -> GetLifecycleResponse {
    let args = Encode!(&swap_pb::GetLifecycleRequest {}).unwrap();
    let res = env.query(*swap_id, "get_lifecycle", args).unwrap();
    Decode!(&res.bytes(), GetLifecycleResponse).unwrap()
}

pub fn finalize_swap(env: &StateMachine, swap_id: &CanisterId) -> FinalizeSwapResponse {
    let args = Encode!(&swap_pb::FinalizeSwapRequest {}).unwrap();
    let res = env
        .execute_ingress(*swap_id, "finalize_swap", args)
        .unwrap();
    Decode!(&res.bytes(), FinalizeSwapResponse).unwrap()
}

pub fn get_buyers_total(env: &StateMachine, swap_id: &CanisterId) -> GetBuyersTotalResponse {
    let args = Encode!(&swap_pb::GetBuyersTotalRequest {}).unwrap();
    let res = env
        .execute_ingress(*swap_id, "get_buyers_total", args)
        .unwrap();
    Decode!(&res.bytes(), GetBuyersTotalResponse).unwrap()
}

pub fn get_sns_canisters_summary(
    env: &StateMachine,
    root_id: &CanisterId,
) -> GetSnsCanistersSummaryResponse {
    let args = Encode!(&GetSnsCanistersSummaryRequest {
        update_canister_list: None
    })
    .unwrap();
    let response = env
        .execute_ingress(*root_id, "get_sns_canisters_summary", args)
        .unwrap();
    Decode!(&response.bytes(), GetSnsCanistersSummaryResponse).unwrap()
}
