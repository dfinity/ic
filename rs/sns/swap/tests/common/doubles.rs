use async_trait::async_trait;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::Tokens;
use ic_nervous_system_common::{ledger::ICRC1Ledger, NervousSystemError};
use ic_nervous_system_common_test_utils::SpyLedger;
use ic_sns_governance::pb::v1::{
    manage_neuron_response, manage_neuron_response::ClaimOrRefreshResponse,
    ClaimSwapNeuronsRequest, ClaimSwapNeuronsResponse, ManageNeuron, ManageNeuronResponse, SetMode,
    SetModeResponse,
};
use ic_sns_swap::{
    clients::{NnsGovernanceClient, SnsGovernanceClient, SnsRootClient},
    environment::CanisterClients,
    pb::v1::{
        set_dapp_controllers_request::CanisterIds, CanisterCallError, SetDappControllersRequest,
        SetDappControllersResponse, SettleNeuronsFundParticipationRequest,
        SettleNeuronsFundParticipationResponse,
    },
};
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

/// Expect that no SNS root calls will be made. Explode otherwise.
#[derive(Debug, Default)]
pub struct ExplodingSnsRootClient;

#[async_trait]
impl SnsRootClient for ExplodingSnsRootClient {
    async fn set_dapp_controllers(
        &mut self,
        _request: SetDappControllersRequest,
    ) -> Result<SetDappControllersResponse, CanisterCallError> {
        unimplemented!();
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(PartialEq, Debug)]
pub enum SnsRootClientCall {
    SetDappControllers(SetDappControllersRequest),
}

impl SnsRootClientCall {
    pub fn set_dapp_controllers(
        canisters: Option<Vec<CanisterId>>,
        controllers: Vec<PrincipalId>,
    ) -> Self {
        let request = SetDappControllersRequest {
            canister_ids: canisters.map(|canisters| CanisterIds {
                canister_ids: canisters.into_iter().map(|x| x.get()).collect(),
            }),
            controller_principal_ids: controllers,
        };
        SnsRootClientCall::SetDappControllers(request)
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(PartialEq, Debug)]
pub enum SnsRootClientReply {
    SetDappControllers(SetDappControllersResponse),
}

/// SnsRootClient that lets the test spy on the calls made
#[derive(Debug, Default)]
pub struct SpySnsRootClient {
    pub observed_calls: Vec<SnsRootClientCall>,
    pub replies: Vec<SnsRootClientReply>,
}

#[async_trait]
impl SnsRootClient for SpySnsRootClient {
    async fn set_dapp_controllers(
        &mut self,
        request: SetDappControllersRequest,
    ) -> Result<SetDappControllersResponse, CanisterCallError> {
        self.observed_calls
            .push(SnsRootClientCall::SetDappControllers(request));
        match self.replies.pop().unwrap() {
            SnsRootClientReply::SetDappControllers(reply) => Ok(reply),
        }
    }
}

impl SpySnsRootClient {
    pub fn new(replies: Vec<SnsRootClientReply>) -> Self {
        SpySnsRootClient {
            observed_calls: vec![],
            replies,
        }
    }
}

impl SnsRootClientReply {
    /// Useful function for creating an enum value with no failures.
    pub fn successful_set_dapp_controllers() -> Self {
        SnsRootClientReply::SetDappControllers(SetDappControllersResponse {
            failed_updates: vec![],
        })
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Debug)]
pub enum SnsGovernanceClientCall {
    ClaimSwapNeurons(ClaimSwapNeuronsRequest),
    ManageNeuron(ManageNeuron),
    SetMode(SetMode),
}

#[allow(clippy::large_enum_variant)]
#[derive(PartialEq, Debug)]
#[allow(unused)]
pub enum SnsGovernanceClientReply {
    ClaimSwapNeurons(ClaimSwapNeuronsResponse),
    ManageNeuron(ManageNeuronResponse),
    SetMode(SetModeResponse),
    CanisterCallError(CanisterCallError),
}

#[derive(Debug, Default)]
pub struct SpySnsGovernanceClient {
    pub calls: Vec<SnsGovernanceClientCall>,
    pub replies: VecDeque<SnsGovernanceClientReply>,
}

impl SpySnsGovernanceClient {
    pub fn new(replies: Vec<SnsGovernanceClientReply>) -> Self {
        SpySnsGovernanceClient {
            calls: vec![],
            replies: VecDeque::from(replies),
        }
    }

    pub fn push_reply(&mut self, reply: SnsGovernanceClientReply) {
        self.replies.push_back(reply)
    }

    pub fn get_calls_snapshot(&self) -> Vec<SnsGovernanceClientCall> {
        self.calls.clone()
    }
}

#[async_trait]
impl SnsGovernanceClient for SpySnsGovernanceClient {
    async fn manage_neuron(
        &mut self,
        request: ManageNeuron,
    ) -> Result<ManageNeuronResponse, CanisterCallError> {
        self.calls
            .push(SnsGovernanceClientCall::ManageNeuron(request));
        Ok(ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::ClaimOrRefresh(
                // Even an empty value can be used here, because it is not
                // actually used in this scenario (yet).
                ClaimOrRefreshResponse::default(),
            )),
        })
    }
    async fn set_mode(&mut self, request: SetMode) -> Result<SetModeResponse, CanisterCallError> {
        self.calls.push(SnsGovernanceClientCall::SetMode(request));
        match self
            .replies
            .pop_front()
            .expect("Expected there to be a reply in the SnsGovernanceClientCall queue")
        {
            SnsGovernanceClientReply::SetMode(reply) => Ok(reply),
            SnsGovernanceClientReply::CanisterCallError(error) => Err(error),
            unexpected_reply => panic!(
                "Unexpected reply in the SnsGovernanceClientCall queue. Expected SetMode | CanisterCallError: {:?}",
                unexpected_reply
            ),
        }
    }

    async fn claim_swap_neurons(
        &mut self,
        request: ClaimSwapNeuronsRequest,
    ) -> Result<ClaimSwapNeuronsResponse, CanisterCallError> {
        let payload = Encode!(&request).unwrap();
        assert!(payload.len() < 1000 * 1000 * 10, "Payload over 10 MiB: {}", payload.len());

        self.calls
            .push(SnsGovernanceClientCall::ClaimSwapNeurons(request));
        match self
            .replies
            .pop_front()
            .expect("Expected there to be a reply in the SnsGovernanceClientCall queue")
        {
            SnsGovernanceClientReply::ClaimSwapNeurons(reply) => Ok(reply),
            SnsGovernanceClientReply::CanisterCallError(error) => Err(error),
            unexpected_reply => panic!(
                "Unexpected reply in the SnsGovernanceClientCall queue: {:?}",
                unexpected_reply
            ),
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Debug)]
pub enum NnsGovernanceClientCall {
    SettleNeuronsFundParticipation(SettleNeuronsFundParticipationRequest),
}

#[derive(Clone, PartialEq, Debug)]
pub enum NnsGovernanceClientReply {
    SettleNeuronsFundParticipation(SettleNeuronsFundParticipationResponse),
    CanisterCallError(CanisterCallError),
}

/// NnsGovernanceClient that allows tests to spy on the calls made
#[derive(Clone, Debug, Default)]
pub struct SpyNnsGovernanceClient {
    pub calls: Vec<NnsGovernanceClientCall>,
    pub replies: Vec<NnsGovernanceClientReply>,
}

impl SpyNnsGovernanceClient {
    pub fn new(replies: Vec<NnsGovernanceClientReply>) -> Self {
        SpyNnsGovernanceClient {
            calls: vec![],
            replies,
        }
    }

    pub fn with_successful_replies() -> Self {
        SpyNnsGovernanceClient {
            calls: vec![],
            replies: vec![],
        }
    }
}

#[async_trait]
impl NnsGovernanceClient for SpyNnsGovernanceClient {
    async fn settle_neurons_fund_participation(
        &mut self,
        request: SettleNeuronsFundParticipationRequest,
    ) -> Result<SettleNeuronsFundParticipationResponse, CanisterCallError> {
        self.calls
            .push(NnsGovernanceClientCall::SettleNeuronsFundParticipation(
                request,
            ));

        match self
            .replies
            .pop()
            .expect("Expected there to be a reply in the NnsGovernanceClient queue")
        {
            NnsGovernanceClientReply::SettleNeuronsFundParticipation(reply) => Ok(reply),
            NnsGovernanceClientReply::CanisterCallError(err) => Err(err),
        }
    }
}

/// Expectation of one call on the mock Ledger.
#[derive(Copy, Clone, Debug)]
pub enum LedgerExpect {
    AccountBalance(Account, Result<Tokens, i32>),
    TransferFunds(u64, u64, Option<Subaccount>, Account, u64, Result<u64, i32>),
}

#[derive(Clone, Debug)]
pub struct MockLedger {
    pub expect: Arc<Mutex<Vec<LedgerExpect>>>,
}

impl MockLedger {
    fn pop(&self) -> Option<LedgerExpect> {
        (*self.expect).lock().unwrap().pop()
    }
}

#[async_trait]
impl ICRC1Ledger for MockLedger {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to: Account,
        memo: u64,
    ) -> Result<u64, NervousSystemError> {
        match self.pop() {
            Some(LedgerExpect::TransferFunds(
                amount_e8s_,
                fee_e8s_,
                from_subaccount_,
                to_,
                memo_,
                result,
            )) => {
                assert_eq!(amount_e8s_, amount_e8s);
                assert_eq!(fee_e8s_, fee_e8s);
                assert_eq!(from_subaccount_, from_subaccount);
                assert_eq!(to_, to);
                assert_eq!(memo_, memo);
                return result.map_err(|x| NervousSystemError::new_with_message(format!("{}", x)));
            }
            x => panic!(
                "Received transfer_funds({}, {}, {:?}, {}, {}), expected {:?}",
                amount_e8s, fee_e8s, from_subaccount, to, memo, x
            ),
        }
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        unimplemented!()
    }

    async fn account_balance(&self, account: Account) -> Result<Tokens, NervousSystemError> {
        match self.pop() {
            Some(LedgerExpect::AccountBalance(account_, result)) => {
                assert_eq!(account_, account);
                return result.map_err(|x| NervousSystemError::new_with_message(format!("{}", x)));
            }
            x => panic!("Received account_balance({}), expected {:?}", account, x),
        }
    }

    fn canister_id(&self) -> CanisterId {
        CanisterId::from_u64(1)
    }
}

pub fn spy_clients() -> CanisterClients<
    SpySnsRootClient,
    SpySnsGovernanceClient,
    SpyLedger,
    SpyLedger,
    SpyNnsGovernanceClient,
> {
    let sns_root = SpySnsRootClient::default();
    let sns_governance = SpySnsGovernanceClient::default();
    let sns_ledger = SpyLedger::default();
    let icp_ledger = SpyLedger::default();
    let nns_governance = SpyNnsGovernanceClient::with_successful_replies();

    CanisterClients {
        sns_root,
        sns_governance,
        sns_ledger,
        icp_ledger,
        nns_governance,
    }
}

pub fn spy_clients_exploding_root() -> CanisterClients<
    ExplodingSnsRootClient,
    SpySnsGovernanceClient,
    SpyLedger,
    SpyLedger,
    SpyNnsGovernanceClient,
> {
    let sns_root = ExplodingSnsRootClient;
    let sns_governance = SpySnsGovernanceClient::default();
    let sns_ledger = SpyLedger::default();
    let icp_ledger = SpyLedger::default();
    let nns_governance = SpyNnsGovernanceClient::with_successful_replies();

    CanisterClients {
        sns_root,
        sns_governance,
        sns_ledger,
        icp_ledger,
        nns_governance,
    }
}
