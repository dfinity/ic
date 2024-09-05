use candid::{CandidType, Decode, Encode, Nat, Principal};
use ic_base_types::PrincipalId;
use ic_ledger_core::Tokens;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID};
use ic_nns_governance_api::pb::v1::{
    ListNeurons as ListNnsNeuronsReq, ListNeuronsResponse as ListNnsNeuronsRes,
};
use ic_nns_gtc::pb::v1::AccountState;
use ic_sns_governance::pb::v1::{
    GetMetadataRequest as GetMetadataReq, GetMetadataResponse as GetMetadataRes,
    GetMode as GetModeReq, GetModeResponse as GetModeRes, ListNeurons as ListSnsNeuronsReq,
    ListNeuronsResponse as ListSnsNeuronsRes, ManageNeuron as ManageSnsNeuronReq,
    ManageNeuronResponse as ManageSnsNeuronRes, NeuronId,
};
use ic_sns_root::{
    pb::v1::ListSnsCanistersResponse as ListSnsCanistersRes,
    GetSnsCanistersSummaryRequest as GetSnsCanistersSummaryReq,
    GetSnsCanistersSummaryResponse as GetSnsCanistersSummaryRes,
};
use ic_sns_swap::pb::v1::{
    FinalizeSwapRequest as FinalizeSwapReq, FinalizeSwapResponse,
    GetAutoFinalizationStatusRequest as GetAutoFinalizationStatusReq,
    GetAutoFinalizationStatusResponse as GetAutoFinalizationStatusRes,
    GetBuyerStateRequest as GetBuyerStateReq, GetBuyerStateResponse as GetBuyerStateRes,
    GetDerivedStateRequest as GetDerivedSwapStateReq,
    GetDerivedStateResponse as GetDerivedSwapStateRes, GetLifecycleRequest as GetLifecycleReq,
    GetLifecycleResponse as GetLifecycleRes, GetOpenTicketRequest as GetOpenTicketReq,
    GetOpenTicketResponse as GetOpenTicketRes, GetStateRequest as GetStateReq,
    GetStateResponse as GetStateRes, NewSaleTicketRequest as NewSaleTicketReq,
    NewSaleTicketResponse as NewSaleTicketRes, RefreshBuyerTokensRequest as RefreshBuyerTokensReq,
    RefreshBuyerTokensResponse as RefreshBuyerTokensRes,
};
use icp_ledger::Subaccount;
use icrc_ledger_types::{
    icrc::generic_metadata_value::MetadataValue as Value,
    icrc1::{
        account::Account,
        transfer::{TransferArg, TransferError},
    },
};

//nns/gtc/gen/ic_nns_gtc.pb.v1.rs
use ic_sns_wasm::pb::v1::{
    ListDeployedSnsesRequest as ListDeployedSnsesReq,
    ListDeployedSnsesResponse as ListDeployedSnsesRes, SnsCanisterIds,
};

use ic_utils::interfaces::http_request::HttpResponse;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    driver::test_env::{TestEnv, TestEnvAttribute},
    sns_client::SnsClient,
};

#[derive(Clone, Debug)]
pub enum CallMode {
    Query,
    Update,
    // update call without subsequent polling of the request state
    UpdateNoPolling,
}

pub trait Response: candid::CandidType + DeserializeOwned {}

impl<T: candid::CandidType + DeserializeOwned> Response for T {}

/// Fully defines a call to be executed against a canister.
/// An agent or a workload engine is needed to submit this request to a replica.
pub trait Request<T: Response> {
    fn mode(&self) -> CallMode;
    fn is_update(&self) -> bool {
        matches!(self.mode(), CallMode::Update | CallMode::UpdateNoPolling)
    }
    fn is_query(&self) -> bool {
        matches!(self.mode(), CallMode::Query)
    }
    fn canister_id(&self) -> Principal;
    fn method_name(&self) -> String;
    fn signature(&self) -> String {
        format!(
            "{}@{}[{}]",
            self.method_name(),
            self.canister_id(),
            if self.is_query() { "q" } else { "u" }
        )
    }
    fn payload(&self) -> Vec<u8>;
    fn parse_response(&self, raw_response: &[u8]) -> anyhow::Result<T> {
        let response = Decode!(raw_response, T)?;
        Ok(response)
    }
}

/// Please use this structure only for interacting with test canisters that are **not deployed to production**.
/// Responses to requests of this type cannot be decoded. Canisters that have external clients (outside of this repo) should be system tested
/// via an appropriate `Request<ResponseType>`, for which `ResponseType` <: `Response` is a Candid type that can be decoded.
///
/// Some examples of when this type is appropriate:
/// - Counter Canister (//rs/workload_generator:src/counter.wat)
/// - Universal Canister (//rs/universal_canister/lib)
#[derive(Clone)]
pub struct GenericRequest {
    canister: Principal,
    method: String,
    payload: Vec<u8>,
    mode: CallMode,
}

impl GenericRequest {
    pub fn new(canister: Principal, method: String, payload: Vec<u8>, mode: CallMode) -> Self {
        Self {
            canister,
            method,
            payload,
            mode,
        }
    }
}

impl Request<()> for GenericRequest {
    fn mode(&self) -> CallMode {
        self.mode.clone()
    }
    fn canister_id(&self) -> Principal {
        self.canister
    }
    fn method_name(&self) -> String {
        self.method.clone()
    }
    fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }
    fn parse_response(&self, _raw_response: &[u8]) -> anyhow::Result<()> {
        panic!("GenericRequest response cannot be parsed (use only for testing)")
    }
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
struct SimpleHttpHeader(String, String);

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
struct SimpleHttpRequest {
    url: String,
    method: String,
    headers: Vec<SimpleHttpHeader>,
    body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct CanisterHttpRequest {
    http_canister: Principal,
    /// The part of the URL after the domain name; starts with "/"
    relative_url: String,
}

impl Request<HttpResponse> for CanisterHttpRequest {
    fn mode(&self) -> CallMode {
        CallMode::Query
    }

    fn canister_id(&self) -> Principal {
        self.http_canister
    }

    fn method_name(&self) -> String {
        "http_request".to_string()
    }

    fn payload(&self) -> Vec<u8> {
        Encode!(&SimpleHttpRequest {
            url: self.relative_url.clone(),
            method: "GET".to_string(),
            headers: vec![],
            body: vec![],
        })
        .unwrap()
    }
}

impl CanisterHttpRequest {
    pub fn new(http_canister: Principal, relative_url: String) -> Self {
        Self {
            http_canister,
            relative_url,
        }
    }
}

#[derive(Copy, Clone)]
pub struct CanisterHttpRequestProvider {
    http_canister: Principal,
}

impl CanisterHttpRequestProvider {
    pub fn new(http_canister: Principal) -> Self {
        Self { http_canister }
    }

    pub fn http_request(
        &self,
        relative_url: String,
    ) -> impl Request<HttpResponse> + std::fmt::Debug + Clone + Sync + Send {
        CanisterHttpRequest::new(self.http_canister, relative_url)
    }
}

#[derive(Clone, Debug)]
pub struct GetAccountRequest {
    mode: CallMode,
    nns_dapp_canister: Principal,
    account_address: String,
}

pub type GetAccountResponse = Result<AccountState, String>;

impl Request<GetAccountResponse> for GetAccountRequest {
    fn mode(&self) -> CallMode {
        self.mode.clone()
    }

    fn canister_id(&self) -> Principal {
        self.nns_dapp_canister
    }

    fn method_name(&self) -> String {
        "get_account".to_string()
    }

    fn payload(&self) -> Vec<u8> {
        Encode!(&self.account_address).unwrap()
    }
}

impl GetAccountRequest {
    pub fn new(nns_dapp_canister: Principal, account_address: String, mode: CallMode) -> Self {
        Self {
            mode,
            nns_dapp_canister,
            account_address,
        }
    }
}

#[derive(Copy, Clone)]
pub struct NnsDappRequestProvider {
    nns_dapp_canister: Principal,
}

impl NnsDappRequestProvider {
    pub fn new(nns_dapp_canister: Principal) -> Self {
        Self { nns_dapp_canister }
    }

    pub fn get_account_request(
        &self,
        account_address: String,
        mode: CallMode,
    ) -> impl Request<GetAccountResponse> + std::fmt::Debug + Clone + Sync + Send {
        GetAccountRequest::new(self.nns_dapp_canister, account_address, mode)
    }

    pub fn http_request(
        &self,
        relative_url: String,
    ) -> impl Request<HttpResponse> + std::fmt::Debug + Clone + Sync + Send {
        CanisterHttpRequest::new(self.nns_dapp_canister, relative_url)
    }
}

#[derive(Clone, Debug)]
pub struct NewSaleTicketRequest {
    sale_canister: Principal,
    amount_icp_e8s: u64,
    subaccount: Option<Subaccount>,
}

impl Request<NewSaleTicketRes> for NewSaleTicketRequest {
    fn mode(&self) -> CallMode {
        CallMode::Update
    }
    fn canister_id(&self) -> Principal {
        self.sale_canister
    }
    fn method_name(&self) -> String {
        "new_sale_ticket".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&NewSaleTicketReq {
            amount_icp_e8s: self.amount_icp_e8s,
            subaccount: self.subaccount.map(|x| x.to_vec())
        })
        .unwrap()
    }
}

impl NewSaleTicketRequest {
    pub fn new(
        sale_canister: Principal,
        amount_icp_e8s: u64,
        subaccount: Option<Subaccount>,
    ) -> Self {
        Self {
            sale_canister,
            amount_icp_e8s,
            subaccount,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RefreshBuyerTokensRequest {
    sale_canister: Principal,
    buyer: Option<PrincipalId>,
    confirmation_text: Option<String>,
}

impl Request<RefreshBuyerTokensRes> for RefreshBuyerTokensRequest {
    fn mode(&self) -> CallMode {
        CallMode::Update
    }
    fn canister_id(&self) -> Principal {
        self.sale_canister
    }
    fn method_name(&self) -> String {
        "refresh_buyer_tokens".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&RefreshBuyerTokensReq {
            buyer: self.buyer.map(|p| p.to_string()).unwrap_or_default(),
            confirmation_text: self.confirmation_text.clone(),
        })
        .unwrap()
    }
}

impl RefreshBuyerTokensRequest {
    pub fn new(
        sale_canister: Principal,
        buyer: Option<PrincipalId>,
        confirmation_text: Option<String>,
    ) -> Self {
        Self {
            sale_canister,
            buyer,
            confirmation_text,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GetBuyerStateRequest {
    mode: CallMode,
    sale_canister: Principal,
    buyer: Option<PrincipalId>,
}

impl Request<GetBuyerStateRes> for GetBuyerStateRequest {
    fn mode(&self) -> CallMode {
        self.mode.clone()
    }
    fn canister_id(&self) -> Principal {
        self.sale_canister
    }
    fn method_name(&self) -> String {
        "get_buyer_state".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&GetBuyerStateReq {
            principal_id: self.buyer
        })
        .unwrap()
    }
}

impl GetBuyerStateRequest {
    pub fn new(sale_canister: Principal, buyer: Option<PrincipalId>, mode: CallMode) -> Self {
        Self {
            mode,
            sale_canister,
            buyer,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GetOpenTicketRequest {
    mode: CallMode,
    sale_canister: Principal,
}

impl Request<GetOpenTicketRes> for GetOpenTicketRequest {
    fn mode(&self) -> CallMode {
        self.mode.clone()
    }
    fn canister_id(&self) -> Principal {
        self.sale_canister
    }
    fn method_name(&self) -> String {
        "get_open_ticket".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&GetOpenTicketReq {}).unwrap()
    }
}

impl GetOpenTicketRequest {
    pub fn new(sale_canister: Principal, mode: CallMode) -> Self {
        Self {
            mode,
            sale_canister,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ListDeployedSnsesRequest {
    mode: CallMode,
    sns_wasm_canister: Principal,
}

impl Request<ListDeployedSnsesRes> for ListDeployedSnsesRequest {
    fn mode(&self) -> CallMode {
        self.mode.clone()
    }
    fn canister_id(&self) -> Principal {
        self.sns_wasm_canister
    }
    fn method_name(&self) -> String {
        "list_deployed_snses".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&ListDeployedSnsesReq {}).unwrap()
    }
}

impl ListDeployedSnsesRequest {
    pub fn new(sns_wasm_canister: Principal, mode: CallMode) -> Self {
        Self {
            mode,
            sns_wasm_canister,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ListSnsCanistersRequest {
    mode: CallMode,
    root_canister: Principal,
}

impl Request<ListSnsCanistersRes> for ListSnsCanistersRequest {
    fn mode(&self) -> CallMode {
        self.mode.clone()
    }
    fn canister_id(&self) -> Principal {
        self.root_canister
    }
    fn method_name(&self) -> String {
        "list_sns_canisters".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&GetOpenTicketReq {}).unwrap()
    }
}

impl ListSnsCanistersRequest {
    pub fn new(root_canister: Principal, mode: CallMode) -> Self {
        Self {
            mode,
            root_canister,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GetMetadataRequest {
    mode: CallMode,
    governance_canister: Principal,
}

impl Request<GetMetadataRes> for GetMetadataRequest {
    fn mode(&self) -> CallMode {
        self.mode.clone()
    }
    fn canister_id(&self) -> Principal {
        self.governance_canister
    }
    fn method_name(&self) -> String {
        "get_metadata".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&GetMetadataReq {}).unwrap()
    }
}

impl GetMetadataRequest {
    pub fn new(governance_canister: Principal, mode: CallMode) -> Self {
        Self {
            mode,
            governance_canister,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Icrc1TransferRequest {
    icrc1_canister: Principal,
    transfer_arg: TransferArg,
}

pub type Icrc1TransferResponse = Result<Nat, TransferError>;

impl Request<Icrc1TransferResponse> for Icrc1TransferRequest {
    fn mode(&self) -> CallMode {
        CallMode::Update
    }
    fn canister_id(&self) -> Principal {
        self.icrc1_canister
    }
    fn method_name(&self) -> String {
        "icrc1_transfer".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&self.transfer_arg).unwrap()
    }
}

impl Icrc1TransferRequest {
    pub fn new(icrc1_canister: Principal, transfer_arg: TransferArg) -> Self {
        Self {
            icrc1_canister,
            transfer_arg,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FinalizeSwapRequest {
    swap_canister: Principal,
}

impl Request<FinalizeSwapResponse> for FinalizeSwapRequest {
    fn mode(&self) -> CallMode {
        CallMode::Update
    }
    fn canister_id(&self) -> Principal {
        self.swap_canister
    }
    fn method_name(&self) -> String {
        "finalize_swap".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&FinalizeSwapReq {}).unwrap()
    }
}

impl FinalizeSwapRequest {
    pub fn new(swap_canister: Principal) -> Self {
        Self { swap_canister }
    }
}

#[derive(Clone, Debug)]
pub struct Icrc1MetadataRequest {
    mode: CallMode,
    icrc1_canister: Principal,
}

pub type Icrc1MetadataResponse = Vec<(String, Value)>;

impl Request<Icrc1MetadataResponse> for Icrc1MetadataRequest {
    fn mode(&self) -> CallMode {
        self.mode.clone()
    }
    fn canister_id(&self) -> Principal {
        self.icrc1_canister
    }
    fn method_name(&self) -> String {
        "icrc1_metadata".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!().unwrap()
    }
}

impl Icrc1MetadataRequest {
    pub fn new(icrc1_canister: Principal, mode: CallMode) -> Self {
        Self {
            mode,
            icrc1_canister,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Icrc1BalanceOfRequest {
    mode: CallMode,
    icrc1_canister: Principal,
    account: Account,
}

pub type Icrc1BalanceOfResponse = Tokens;

impl Request<Icrc1BalanceOfResponse> for Icrc1BalanceOfRequest {
    fn mode(&self) -> CallMode {
        self.mode.clone()
    }
    fn canister_id(&self) -> Principal {
        self.icrc1_canister
    }
    fn method_name(&self) -> String {
        "icrc1_balance_of".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&self.account).unwrap()
    }
}

impl Icrc1BalanceOfRequest {
    pub fn new(icrc1_canister: Principal, account: Account, mode: CallMode) -> Self {
        Self {
            mode,
            icrc1_canister,
            account,
        }
    }
}

#[derive(Copy, Clone)]
pub struct Icrc1RequestProvider {
    icrc1_canister: Principal,
}

impl Icrc1RequestProvider {
    pub fn new_icp_ledger_request_provider() -> Self {
        Self {
            icrc1_canister: Principal::from(LEDGER_CANISTER_ID.get()),
        }
    }

    pub fn icrc1_transfer_request(
        &self,
        transfer_arg: TransferArg,
    ) -> impl Request<Icrc1TransferResponse> + std::fmt::Debug + Clone + Sync + Send {
        Icrc1TransferRequest::new(self.icrc1_canister, transfer_arg)
    }

    pub fn icrc1_metadata_request(
        &self,
        mode: CallMode,
    ) -> impl Request<Icrc1MetadataResponse> + std::fmt::Debug + Clone + Sync + Send {
        Icrc1MetadataRequest::new(self.icrc1_canister, mode)
    }

    pub fn icrc1_balance_of_request(
        &self,
        account: Account,
        mode: CallMode,
    ) -> impl Request<Icrc1BalanceOfResponse> + std::fmt::Debug + Clone + Sync + Send {
        Icrc1BalanceOfRequest::new(self.icrc1_canister, account, mode)
    }
}

#[derive(Clone, Debug)]
pub struct ListSnsNeuronsRequest {
    mode: CallMode,
    sns_governance_canister: Principal,
    payload: ListSnsNeuronsReq,
}

impl Request<ListSnsNeuronsRes> for ListSnsNeuronsRequest {
    fn mode(&self) -> CallMode {
        self.mode.clone()
    }
    fn canister_id(&self) -> Principal {
        self.sns_governance_canister
    }
    fn method_name(&self) -> String {
        "list_neurons".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&self.payload).unwrap()
    }
}

impl ListSnsNeuronsRequest {
    pub fn new(
        governance_canister: Principal,
        limit: u32,
        start_page_at: Option<NeuronId>,
        of_principal: Option<PrincipalId>,
        mode: CallMode,
    ) -> Self {
        Self {
            mode,
            sns_governance_canister: governance_canister,
            payload: ListSnsNeuronsReq {
                limit,
                start_page_at,
                of_principal,
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct ListNnsNeuronsRequest {
    mode: CallMode,
    payload: ListNnsNeuronsReq,
}

impl Request<ListNnsNeuronsRes> for ListNnsNeuronsRequest {
    fn mode(&self) -> CallMode {
        self.mode.clone()
    }
    fn canister_id(&self) -> Principal {
        Principal::from(GOVERNANCE_CANISTER_ID)
    }
    fn method_name(&self) -> String {
        "list_neurons".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&self.payload).unwrap()
    }
}

impl ListNnsNeuronsRequest {
    pub fn new(
        neuron_ids: Vec<u64>,
        include_neurons_readable_by_caller: bool,
        mode: CallMode,
    ) -> Self {
        Self {
            mode,
            payload: ListNnsNeuronsReq {
                neuron_ids,
                include_neurons_readable_by_caller,
                include_empty_neurons_readable_by_caller: None,
                include_public_neurons_in_full_neurons: None,
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct ManageSnsNeuronRequest {
    sns_governance_canister: Principal,
    payload: ManageSnsNeuronReq,
}

impl Request<ManageSnsNeuronRes> for ManageSnsNeuronRequest {
    fn mode(&self) -> CallMode {
        CallMode::Update
    }
    fn canister_id(&self) -> Principal {
        self.sns_governance_canister
    }
    fn method_name(&self) -> String {
        "manage_neuron".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&self.payload).unwrap()
    }
}

impl ManageSnsNeuronRequest {
    pub fn new(
        governance_canister: Principal,
        subaccount: Vec<u8>,
        command: ic_sns_governance::pb::v1::manage_neuron::Command,
    ) -> Self {
        Self {
            sns_governance_canister: governance_canister,
            payload: ManageSnsNeuronReq {
                subaccount,
                command: Some(command),
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct GetStateRequest {
    mode: CallMode,
    sale_canister: Principal,
}

impl Request<GetStateRes> for GetStateRequest {
    fn mode(&self) -> CallMode {
        self.mode.clone()
    }
    fn canister_id(&self) -> Principal {
        self.sale_canister
    }
    fn method_name(&self) -> String {
        "get_state".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&GetStateReq {}).unwrap()
    }
}

impl GetStateRequest {
    pub fn new(sale_canister: Principal, mode: CallMode) -> Self {
        Self {
            mode,
            sale_canister,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GetLifecycleRequest {
    mode: CallMode,
    sale_canister: Principal,
}

impl Request<GetLifecycleRes> for GetLifecycleRequest {
    fn mode(&self) -> CallMode {
        self.mode.clone()
    }
    fn canister_id(&self) -> Principal {
        self.sale_canister
    }
    fn method_name(&self) -> String {
        "get_lifecycle".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&GetLifecycleReq {}).unwrap()
    }
}

impl GetLifecycleRequest {
    pub fn new(sale_canister: Principal, mode: CallMode) -> Self {
        Self {
            mode,
            sale_canister,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GetDerivedSwapStateRequest {
    mode: CallMode,
    sale_canister: Principal,
}

impl Request<GetDerivedSwapStateRes> for GetDerivedSwapStateRequest {
    fn mode(&self) -> CallMode {
        self.mode.clone()
    }
    fn canister_id(&self) -> Principal {
        self.sale_canister
    }
    fn method_name(&self) -> String {
        "get_derived_state".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&GetDerivedSwapStateReq {}).unwrap()
    }
}

impl GetDerivedSwapStateRequest {
    pub fn new(sale_canister: Principal, mode: CallMode) -> Self {
        Self {
            mode,
            sale_canister,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GetAutoFinalizationStatusRequest {
    mode: CallMode,
    sale_canister: Principal,
}

impl Request<GetAutoFinalizationStatusRes> for GetAutoFinalizationStatusRequest {
    fn mode(&self) -> CallMode {
        self.mode.clone()
    }
    fn canister_id(&self) -> Principal {
        self.sale_canister
    }
    fn method_name(&self) -> String {
        "get_auto_finalization_status".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&GetAutoFinalizationStatusReq {}).unwrap()
    }
}

impl GetAutoFinalizationStatusRequest {
    pub fn new(sale_canister: Principal, mode: CallMode) -> Self {
        Self {
            mode,
            sale_canister,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GetSnsCanistersSummaryRequest {
    sns_root_canister: Principal,
}

impl Request<GetSnsCanistersSummaryRes> for GetSnsCanistersSummaryRequest {
    fn mode(&self) -> CallMode {
        CallMode::Update
    }
    fn canister_id(&self) -> Principal {
        self.sns_root_canister
    }
    fn method_name(&self) -> String {
        "get_sns_canisters_summary".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&GetSnsCanistersSummaryReq {
            update_canister_list: Some(false)
        })
        .unwrap()
    }
}

impl GetSnsCanistersSummaryRequest {
    pub fn new(sns_root_canister: Principal) -> Self {
        Self { sns_root_canister }
    }
}

#[derive(Clone, Debug)]
pub struct GetModeRequest {
    sns_governance_canister: Principal,
}

impl Request<GetModeRes> for GetModeRequest {
    fn mode(&self) -> CallMode {
        CallMode::Update
    }
    fn canister_id(&self) -> Principal {
        self.sns_governance_canister
    }
    fn method_name(&self) -> String {
        "get_mode".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        Encode!(&GetModeReq {}).unwrap()
    }
}

impl GetModeRequest {
    pub fn new(sns_governance_canister: Principal) -> Self {
        Self {
            sns_governance_canister,
        }
    }
}

#[derive(Copy, Clone)]
pub struct SnsRequestProvider {
    pub sns_canisters: SnsCanisterIds,
    pub sns_wasm_canister_id: PrincipalId,
    sns_ledger_request_provider: Icrc1RequestProvider,
}

impl SnsRequestProvider {
    pub fn from_sns_client(sns_client: &SnsClient) -> Self {
        let sns_ledger_request_provider = Icrc1RequestProvider {
            icrc1_canister: sns_client.sns_canisters.ledger().get().into(),
        };
        Self {
            sns_canisters: sns_client.sns_canisters,
            sns_wasm_canister_id: sns_client.sns_wasm_canister_id,
            sns_ledger_request_provider,
        }
    }

    pub fn from_env(env: &TestEnv) -> Self {
        let sns_client = SnsClient::read_attribute(env);
        Self::from_sns_client(&sns_client)
    }

    pub fn new_sale_ticket(
        &self,
        amount_icp_e8s: u64,
        subaccount: Option<Subaccount>,
    ) -> impl Request<NewSaleTicketRes> + std::fmt::Debug + Clone + Sync + Send {
        let sale_canister = self.sns_canisters.swap().get().into();
        NewSaleTicketRequest::new(sale_canister, amount_icp_e8s, subaccount)
    }

    pub fn refresh_buyer_tokens(
        &self,
        buyer: Option<PrincipalId>,
        confirmation_text: Option<String>,
    ) -> impl Request<RefreshBuyerTokensRes> + std::fmt::Debug + Clone + Sync + Send {
        let sale_canister = self.sns_canisters.swap().get().into();
        RefreshBuyerTokensRequest::new(sale_canister, buyer, confirmation_text)
    }

    pub fn get_buyer_state(
        &self,
        buyer: Option<PrincipalId>,
        mode: CallMode,
    ) -> impl Request<GetBuyerStateRes> + std::fmt::Debug + Clone + Sync + Send {
        let sale_canister = self.sns_canisters.swap().get().into();
        GetBuyerStateRequest::new(sale_canister, buyer, mode)
    }

    pub fn get_open_ticket(
        &self,
        mode: CallMode,
    ) -> impl Request<GetOpenTicketRes> + std::fmt::Debug + Clone + Sync + Send {
        let sale_canister = self.sns_canisters.swap().get().into();
        GetOpenTicketRequest::new(sale_canister, mode)
    }

    pub fn finalize_swap(
        &self,
    ) -> impl Request<FinalizeSwapResponse> + std::fmt::Debug + Clone + Sync + Send {
        let sale_canister = self.sns_canisters.swap().get().into();
        FinalizeSwapRequest::new(sale_canister)
    }

    // The requests below are used by the aggregator canister

    pub fn list_deployed_snses(
        &self,
        mode: CallMode,
    ) -> impl Request<ListDeployedSnsesRes> + std::fmt::Debug + Clone + Sync + Send {
        let sns_wasm_canister = self.sns_wasm_canister_id.into();
        ListDeployedSnsesRequest::new(sns_wasm_canister, mode)
    }

    pub fn list_sns_canisters(
        &self,
        mode: CallMode,
    ) -> impl Request<ListSnsCanistersRes> + std::fmt::Debug + Clone + Sync + Send {
        let root_canister = self.sns_canisters.root().get().into();
        ListSnsCanistersRequest::new(root_canister, mode)
    }

    pub fn get_metadata(
        &self,
        mode: CallMode,
    ) -> impl Request<GetMetadataRes> + std::fmt::Debug + Clone + Sync + Send {
        let governance_canister = self.sns_canisters.governance().get().into();
        GetMetadataRequest::new(governance_canister, mode)
    }

    pub fn icrc1_metadata(
        &self,
        mode: CallMode,
    ) -> impl Request<Icrc1MetadataResponse> + std::fmt::Debug + Clone + Sync + Send {
        self.sns_ledger_request_provider
            .icrc1_metadata_request(mode)
    }

    pub fn metadata(
        &self,
        mode: CallMode,
    ) -> impl Request<GetMetadataRes> + std::fmt::Debug + Clone + Sync + Send {
        let governance_canister = self.sns_canisters.governance().get().into();
        GetMetadataRequest::new(governance_canister, mode)
    }

    pub fn get_state(
        &self,
        mode: CallMode,
    ) -> impl Request<GetStateRes> + std::fmt::Debug + Clone + Sync + Send {
        let swap_canister = self.sns_canisters.swap().get().into();
        GetStateRequest::new(swap_canister, mode)
    }

    pub fn get_lifecycle(
        &self,
        mode: CallMode,
    ) -> impl Request<GetLifecycleRes> + std::fmt::Debug + Clone + Sync + Send {
        let swap_canister = self.sns_canisters.swap().get().into();
        GetLifecycleRequest::new(swap_canister, mode)
    }

    pub fn get_derived_swap_state(
        &self,
        mode: CallMode,
    ) -> impl Request<GetDerivedSwapStateRes> + std::fmt::Debug + Clone + Sync + Send {
        let swap_canister = self.sns_canisters.swap().get().into();
        GetDerivedSwapStateRequest::new(swap_canister, mode)
    }

    pub fn get_auto_finalization_status(
        &self,
        mode: CallMode,
    ) -> impl Request<GetAutoFinalizationStatusRes> + std::fmt::Debug + Clone + Sync + Send {
        let swap_canister = self.sns_canisters.swap().get().into();
        GetAutoFinalizationStatusRequest::new(swap_canister, mode)
    }

    pub fn list_neurons(
        &self,
        limit: u32,
        start_page_at: Option<NeuronId>,
        of_principal: Option<PrincipalId>,
        mode: CallMode,
    ) -> impl Request<ListSnsNeuronsRes> + std::fmt::Debug + Clone + Sync + Send {
        let sns_governance_canister = self.sns_canisters.governance().get().into();
        ListSnsNeuronsRequest::new(
            sns_governance_canister,
            limit,
            start_page_at,
            of_principal,
            mode,
        )
    }

    pub fn manage_neuron(
        &self,
        subaccount: Vec<u8>,
        command: ic_sns_governance::pb::v1::manage_neuron::Command,
    ) -> impl Request<ManageSnsNeuronRes> + std::fmt::Debug + Clone + Sync + Send {
        let sns_governance_canister = self.sns_canisters.governance().get().into();
        ManageSnsNeuronRequest::new(sns_governance_canister, subaccount, command)
    }

    pub fn get_sns_canisters_summary(
        &self,
    ) -> impl Request<GetSnsCanistersSummaryRes> + std::fmt::Debug + Clone + Sync + Send {
        let sns_root_canister = self.sns_canisters.root().get().into();
        GetSnsCanistersSummaryRequest::new(sns_root_canister)
    }

    pub fn get_sns_governance_mode(
        &self,
    ) -> impl Request<GetModeRes> + std::fmt::Debug + Clone + Sync + Send {
        let sns_governance_canister = self.sns_canisters.governance().get().into();
        GetModeRequest::new(sns_governance_canister)
    }
}

#[derive(Copy, Clone, Default)]
pub struct NnsRequestProvider {}

impl NnsRequestProvider {
    pub fn list_neurons(
        &self,
        neuron_ids: Vec<u64>,
        include_neurons_readable_by_caller: bool,
        mode: CallMode,
    ) -> impl Request<ListNnsNeuronsRes> + std::fmt::Debug + Clone + Sync + Send {
        ListNnsNeuronsRequest::new(neuron_ids, include_neurons_readable_by_caller, mode)
    }
}
