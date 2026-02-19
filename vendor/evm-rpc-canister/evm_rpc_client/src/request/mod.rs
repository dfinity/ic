#[cfg(feature = "alloy")]
pub(crate) mod alloy;

use crate::{retry, EvmRpcClient, Runtime};
use candid::CandidType;
use evm_rpc_types::{
    BlockTag, CallArgs, ConsensusStrategy, FeeHistoryArgs, GetLogsArgs, GetLogsRpcConfig,
    GetTransactionCountArgs, Hex, Hex20, Hex32, MultiRpcResult, Nat256, RpcConfig, RpcResult,
    RpcServices,
};
use ic_canister_runtime::IcError;
use serde::de::DeserializeOwned;
use std::fmt::{Debug, Formatter};
use strum::EnumIter;

#[derive(Debug, Clone)]
pub struct CallRequest(CallArgs);

impl CallRequest {
    pub fn new(params: CallArgs) -> Self {
        Self(params)
    }
}

impl EvmRpcRequest for CallRequest {
    type Config = RpcConfig;
    type Params = CallArgs;
    type CandidOutput = MultiRpcResult<Hex>;

    fn endpoint(&self) -> EvmRpcEndpoint {
        EvmRpcEndpoint::Call
    }

    fn params(self) -> Self::Params {
        self.0
    }
}

pub type CallRequestBuilder<R, C, P, Output> = RequestBuilder<
    R,
    C,
    P,
    <CallRequest as EvmRpcRequest>::Config,
    <CallRequest as EvmRpcRequest>::Params,
    <CallRequest as EvmRpcRequest>::CandidOutput,
    Output,
>;

impl<R, C, P, Output> CallRequestBuilder<R, C, P, Output> {
    /// Change the `block` parameter for an `eth_call` request.
    pub fn with_block(mut self, block: impl Into<BlockTag>) -> Self {
        self.request.params.block = Some(block.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct FeeHistoryRequest(FeeHistoryArgs);

impl FeeHistoryRequest {
    pub fn new(params: FeeHistoryArgs) -> Self {
        Self(params)
    }
}

impl EvmRpcRequest for FeeHistoryRequest {
    type Config = RpcConfig;
    type Params = FeeHistoryArgs;
    type CandidOutput = MultiRpcResult<evm_rpc_types::FeeHistory>;

    fn endpoint(&self) -> EvmRpcEndpoint {
        EvmRpcEndpoint::FeeHistory
    }

    fn params(self) -> Self::Params {
        self.0
    }
}

pub type FeeHistoryRequestBuilder<R, C, P, Output> = RequestBuilder<
    R,
    C,
    P,
    <FeeHistoryRequest as EvmRpcRequest>::Config,
    <FeeHistoryRequest as EvmRpcRequest>::Params,
    <FeeHistoryRequest as EvmRpcRequest>::CandidOutput,
    Output,
>;

impl<R, C, P, Output> FeeHistoryRequestBuilder<R, C, P, Output> {
    /// Change the `block_count` parameter for an `eth_feeHistory` request.
    pub fn with_block_count(mut self, block_count: impl Into<Nat256>) -> Self {
        self.request.params.block_count = block_count.into();
        self
    }

    /// Change the `newest_block` parameter for an `eth_feeHistory` request.
    pub fn with_newest_block(mut self, newest_block: impl Into<BlockTag>) -> Self {
        self.request.params.newest_block = newest_block.into();
        self
    }

    /// Change the `reward_percentiles` parameter for an `eth_feeHistory` request.
    pub fn with_reward_percentiles(mut self, reward_percentiles: impl Into<Vec<u8>>) -> Self {
        self.request.params.reward_percentiles = Some(reward_percentiles.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct GetBlockByNumberRequest(BlockTag);

impl GetBlockByNumberRequest {
    pub fn new(params: BlockTag) -> Self {
        Self(params)
    }
}

impl EvmRpcRequest for GetBlockByNumberRequest {
    type Config = RpcConfig;
    type Params = BlockTag;
    type CandidOutput = MultiRpcResult<evm_rpc_types::Block>;

    fn endpoint(&self) -> EvmRpcEndpoint {
        EvmRpcEndpoint::GetBlockByNumber
    }

    fn params(self) -> Self::Params {
        self.0
    }
}

pub type GetBlockByNumberRequestBuilder<R, C, P, Output> = RequestBuilder<
    R,
    C,
    P,
    <GetBlockByNumberRequest as EvmRpcRequest>::Config,
    <GetBlockByNumberRequest as EvmRpcRequest>::Params,
    <GetBlockByNumberRequest as EvmRpcRequest>::CandidOutput,
    Output,
>;

#[derive(Debug, Clone)]
pub struct GetLogsRequest(GetLogsArgs);

impl GetLogsRequest {
    pub fn new(params: GetLogsArgs) -> Self {
        Self(params)
    }
}

impl EvmRpcRequest for GetLogsRequest {
    type Config = GetLogsRpcConfig;
    type Params = GetLogsArgs;
    type CandidOutput = MultiRpcResult<Vec<evm_rpc_types::LogEntry>>;

    fn endpoint(&self) -> EvmRpcEndpoint {
        EvmRpcEndpoint::GetLogs
    }

    fn params(self) -> Self::Params {
        self.0
    }
}

pub type GetLogsRequestBuilder<R, C, P, Output> = RequestBuilder<
    R,
    C,
    P,
    <GetLogsRequest as EvmRpcRequest>::Config,
    <GetLogsRequest as EvmRpcRequest>::Params,
    <GetLogsRequest as EvmRpcRequest>::CandidOutput,
    Output,
>;

impl<R, C, P, Output> GetLogsRequestBuilder<R, C, P, Output> {
    /// Change the `from_block` parameter for an `eth_getLogs` request.
    pub fn with_from_block(mut self, from_block: impl Into<BlockTag>) -> Self {
        self.request.params.from_block = Some(from_block.into());
        self
    }

    /// Change the `to_block` parameter for an `eth_getLogs` request.
    pub fn with_to_block(mut self, to_block: impl Into<BlockTag>) -> Self {
        self.request.params.to_block = Some(to_block.into());
        self
    }

    /// Change the `addresses` parameter for an `eth_getLogs` request.
    pub fn with_addresses(mut self, addresses: Vec<impl Into<Hex20>>) -> Self {
        self.request.params.addresses = addresses.into_iter().map(Into::into).collect();
        self
    }

    /// Change the `topics` parameter for an `eth_getLogs` request.
    pub fn with_topics(mut self, topics: Vec<Vec<impl Into<Hex32>>>) -> Self {
        self.request.params.topics = Some(
            topics
                .into_iter()
                .map(|array| array.into_iter().map(Into::into).collect())
                .collect(),
        );
        self
    }
}

#[derive(Debug, Clone)]
pub struct GetTransactionCountRequest(GetTransactionCountArgs);

impl GetTransactionCountRequest {
    pub fn new(params: GetTransactionCountArgs) -> Self {
        Self(params)
    }
}

impl EvmRpcRequest for GetTransactionCountRequest {
    type Config = RpcConfig;
    type Params = GetTransactionCountArgs;
    type CandidOutput = MultiRpcResult<Nat256>;

    fn endpoint(&self) -> EvmRpcEndpoint {
        EvmRpcEndpoint::GetTransactionCount
    }

    fn params(self) -> Self::Params {
        self.0
    }
}

pub type GetTransactionCountRequestBuilder<R, C, P, Output> = RequestBuilder<
    R,
    C,
    P,
    <GetTransactionCountRequest as EvmRpcRequest>::Config,
    <GetTransactionCountRequest as EvmRpcRequest>::Params,
    <GetTransactionCountRequest as EvmRpcRequest>::CandidOutput,
    Output,
>;

impl<R, C, P, Output> GetTransactionCountRequestBuilder<R, C, P, Output> {
    /// Change the `address` parameter for an `eth_getTransactionCount` request.
    pub fn with_address(mut self, address: impl Into<Hex20>) -> Self {
        self.request.params.address = address.into();
        self
    }

    /// Change the `block` parameter for an `eth_getTransactionCount` request.
    pub fn with_block(mut self, block: impl Into<BlockTag>) -> Self {
        self.request.params.block = block.into();
        self
    }
}

#[derive(Debug, Clone)]
pub struct GetTransactionReceiptRequest(Hex32);

impl GetTransactionReceiptRequest {
    pub fn new(params: Hex32) -> Self {
        Self(params)
    }
}

impl EvmRpcRequest for GetTransactionReceiptRequest {
    type Config = RpcConfig;
    type Params = Hex32;
    type CandidOutput = MultiRpcResult<Option<evm_rpc_types::TransactionReceipt>>;

    fn endpoint(&self) -> EvmRpcEndpoint {
        EvmRpcEndpoint::GetTransactionReceipt
    }

    fn params(self) -> Self::Params {
        self.0
    }
}

pub type GetTransactionReceiptRequestBuilder<R, C, P, Output> = RequestBuilder<
    R,
    C,
    P,
    <GetTransactionReceiptRequest as EvmRpcRequest>::Config,
    <GetTransactionReceiptRequest as EvmRpcRequest>::Params,
    <GetTransactionReceiptRequest as EvmRpcRequest>::CandidOutput,
    Output,
>;

#[derive(Debug, Clone)]
pub struct JsonRequest(String);

impl TryFrom<serde_json::Value> for JsonRequest {
    type Error = String;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        serde_json::to_string(&value)
            .map(JsonRequest)
            .map_err(|e| e.to_string())
    }
}

impl EvmRpcRequest for JsonRequest {
    type Config = RpcConfig;
    type Params = String;
    type CandidOutput = MultiRpcResult<String>;

    fn endpoint(&self) -> EvmRpcEndpoint {
        EvmRpcEndpoint::MultiRequest
    }

    fn params(self) -> Self::Params {
        self.0
    }
}

pub type JsonRequestBuilder<R, C, P, Output> = RequestBuilder<
    R,
    C,
    P,
    <JsonRequest as EvmRpcRequest>::Config,
    <JsonRequest as EvmRpcRequest>::Params,
    <JsonRequest as EvmRpcRequest>::CandidOutput,
    Output,
>;

#[derive(Debug, Clone)]
pub struct SendRawTransactionRequest(Hex);

impl SendRawTransactionRequest {
    pub fn new(params: Hex) -> Self {
        Self(params)
    }
}

impl EvmRpcRequest for SendRawTransactionRequest {
    type Config = RpcConfig;
    type Params = Hex;
    type CandidOutput = MultiRpcResult<evm_rpc_types::SendRawTransactionStatus>;

    fn endpoint(&self) -> EvmRpcEndpoint {
        EvmRpcEndpoint::SendRawTransaction
    }

    fn params(self) -> Self::Params {
        self.0
    }
}

pub type SendRawTransactionRequestBuilder<R, C, P, Output> = RequestBuilder<
    R,
    C,
    P,
    <SendRawTransactionRequest as EvmRpcRequest>::Config,
    <SendRawTransactionRequest as EvmRpcRequest>::Params,
    <SendRawTransactionRequest as EvmRpcRequest>::CandidOutput,
    Output,
>;

/// Ethereum RPC endpoint supported by the EVM RPC canister.
pub trait EvmRpcRequest {
    /// Type of RPC config for that request.
    type Config;
    /// The type of parameters taken by this endpoint.
    type Params;
    /// The Candid type returned when executing this request which is then converted to [`Self::Output`].
    type CandidOutput;

    /// The name of the endpoint on the EVM RPC canister.
    fn endpoint(&self) -> EvmRpcEndpoint;

    /// Return the request parameters.
    fn params(self) -> Self::Params;
}

/// Endpoint on the EVM RPC canister triggering a call to EVM providers.
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, EnumIter)]
pub enum EvmRpcEndpoint {
    /// `eth_call` endpoint.
    Call,
    /// `eth_feeHistory` endpoint.
    FeeHistory,
    /// `eth_getBlockByNumber` endpoint.
    GetBlockByNumber,
    /// `eth_getLogs` endpoint.
    GetLogs,
    /// `eth_getTransactionCount` endpoint.
    GetTransactionCount,
    /// `eth_getTransactionReceipt` endpoint.
    GetTransactionReceipt,
    /// `multi_request` endpoint.
    MultiRequest,
    /// `eth_sendRawTransaction` endpoint.
    SendRawTransaction,
}

impl EvmRpcEndpoint {
    /// Method name on the EVM RPC canister
    pub fn rpc_method(&self) -> &'static str {
        match &self {
            Self::Call => "eth_call",
            Self::FeeHistory => "eth_feeHistory",
            Self::GetBlockByNumber => "eth_getBlockByNumber",
            Self::GetLogs => "eth_getLogs",
            Self::GetTransactionCount => "eth_getTransactionCount",
            Self::GetTransactionReceipt => "eth_getTransactionReceipt",
            Self::MultiRequest => "multi_request",
            Self::SendRawTransaction => "eth_sendRawTransaction",
        }
    }

    /// Method name on the EVM RPC canister to estimate the amount of cycles for that request.
    pub fn cycles_cost_method(&self) -> &'static str {
        match &self {
            Self::Call => "eth_callCyclesCost",
            Self::FeeHistory => "eth_feeHistoryCyclesCost",
            Self::GetBlockByNumber => "eth_getBlockByNumberCyclesCost",
            Self::GetLogs => "eth_getLogsCyclesCost",
            Self::GetTransactionCount => "eth_getTransactionCountCyclesCost",
            Self::GetTransactionReceipt => "eth_getTransactionReceiptCyclesCost",
            Self::MultiRequest => "multi_requestCyclesCost",
            Self::SendRawTransaction => "eth_sendRawTransactionCyclesCost",
        }
    }
}

/// A builder to construct a [`Request`].
///
/// To construct a [`RequestBuilder`], refer to the [`EvmRpcClient`] documentation.
#[must_use = "RequestBuilder does nothing until you 'send' it"]
pub struct RequestBuilder<Runtime, Converter, RetryPolicy, Config, Params, CandidOutput, Output> {
    client: EvmRpcClient<Runtime, Converter, RetryPolicy>,
    request: Request<Config, Params, CandidOutput, Output>,
}

impl<Runtime, Converter, RetryPolicy, Config: Clone, Params: Clone, CandidOutput, Output> Clone
    for RequestBuilder<Runtime, Converter, RetryPolicy, Config, Params, CandidOutput, Output>
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            request: self.request.clone(),
        }
    }
}

impl<
        Runtime: Debug,
        Converter: Debug,
        RetryPolicy: Debug,
        Config: Debug,
        Params: Debug,
        CandidOutput,
        Output,
    > Debug
    for RequestBuilder<Runtime, Converter, RetryPolicy, Config, Params, CandidOutput, Output>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let RequestBuilder { client, request } = &self;
        f.debug_struct("RequestBuilder")
            .field("client", client)
            .field("request", request)
            .finish()
    }
}

impl<Runtime, Converter, RetryPolicy, Config, Params, CandidOutput, Output>
    RequestBuilder<Runtime, Converter, RetryPolicy, Config, Params, CandidOutput, Output>
{
    pub(super) fn new<RpcRequest>(
        client: EvmRpcClient<Runtime, Converter, RetryPolicy>,
        rpc_request: RpcRequest,
        cycles: u128,
    ) -> Self
    where
        RpcRequest: EvmRpcRequest<Config = Config, Params = Params, CandidOutput = CandidOutput>,
        Config: From<RpcConfig>,
    {
        let endpoint = rpc_request.endpoint();
        let params = rpc_request.params();
        let request = Request {
            endpoint,
            rpc_services: client.config.rpc_services.clone(),
            rpc_config: client.config.rpc_config.clone().map(Config::from),
            params,
            cycles,
            _candid_marker: Default::default(),
            _output_marker: Default::default(),
        };
        RequestBuilder::<Runtime, Converter, RetryPolicy, Config, Params, CandidOutput, Output> {
            client,
            request,
        }
    }

    /// Query the cycles cost for that request
    pub fn request_cost(
        self,
    ) -> RequestCostBuilder<Runtime, Converter, RetryPolicy, Config, Params> {
        RequestCostBuilder {
            client: self.client,
            request: RequestCost {
                endpoint: self.request.endpoint,
                rpc_services: self.request.rpc_services,
                rpc_config: self.request.rpc_config,
                params: self.request.params,
                cycles: 0,
                _candid_marker: Default::default(),
                _output_marker: Default::default(),
            },
        }
    }

    /// Change the [`RpcServices`] for that request.
    pub fn with_rpc_sources(mut self, rpc_services: RpcServices) -> Self {
        self.request.rpc_services = rpc_services;
        self
    }

    /// Change the amount of cycles to send for that request.
    pub fn with_cycles(mut self, cycles: u128) -> Self {
        *self.request.cycles_mut() = cycles;
        self
    }

    /// Change the parameters to send for that request.
    pub fn with_params(mut self, params: impl Into<Params>) -> Self {
        *self.request.params_mut() = params.into();
        self
    }

    /// Modify current parameters to send for that request.
    pub fn modify_params<F>(mut self, mutator: F) -> Self
    where
        F: FnOnce(&mut Params),
    {
        mutator(self.request.params_mut());
        self
    }

    /// Change the RPC configuration to use for that request.
    pub fn with_rpc_config(mut self, rpc_config: impl Into<Config>) -> Self {
        *self.request.rpc_config_mut() = Some(rpc_config.into());
        self
    }
}

impl<R: Runtime, Converter, RetryPolicy, Config, Params, CandidOutput, Output>
    RequestBuilder<R, Converter, RetryPolicy, Config, Params, CandidOutput, Output>
{
    /// Constructs the [`Request`] and sends it using the [`EvmRpcClient`] returning the response.
    ///
    /// # Panics
    ///
    /// If the request was not successful.
    pub async fn send(self) -> Output
    where
        Config: CandidType + Clone + Send,
        Params: CandidType + Clone + Send,
        CandidOutput: Into<Output> + CandidType + DeserializeOwned,
        RetryPolicy: retry::RetryPolicy<Config, Params, CandidOutput, Output> + Clone,
    {
        self.client
            .execute_request::<Config, Params, CandidOutput, Output>(self.request)
            .await
    }

    /// Constructs the [`Request`] and sends it using the [`EvmRpcClient`]. This method returns
    /// either the request response or any error that occurs while sending the request.
    pub async fn try_send(self) -> Result<Output, IcError>
    where
        Config: CandidType + Clone + Send,
        Params: CandidType + Clone + Send,
        CandidOutput: Into<Output> + CandidType + DeserializeOwned,
        RetryPolicy: retry::RetryPolicy<Config, Params, CandidOutput, Output> + Clone,
    {
        self.client
            .try_execute_request::<Config, Params, CandidOutput, Output>(self.request)
            .await
    }
}

impl<Runtime, Converter, RetryPolicy, Params, CandidOutput, Output>
    RequestBuilder<Runtime, Converter, RetryPolicy, GetLogsRpcConfig, Params, CandidOutput, Output>
{
    /// Change the max block range error for `eth_getLogs` request.
    pub fn with_max_block_range(mut self, max_block_range: u32) -> Self {
        let config = self.request.rpc_config_mut().get_or_insert_default();
        config.max_block_range = Some(max_block_range);
        self
    }
}

/// Common behavior for the RPC config for EVM RPC canister endpoints.
pub trait EvmRpcConfig {
    /// Return a new RPC config with the given response size estimate.
    fn with_response_size_estimate(self, response_size_estimate: u64) -> Self;

    /// Return a new RPC config with the given response consensus.
    fn with_response_consensus(self, response_consensus: ConsensusStrategy) -> Self;
}

impl EvmRpcConfig for RpcConfig {
    fn with_response_size_estimate(self, response_size_estimate: u64) -> Self {
        Self {
            response_size_estimate: Some(response_size_estimate),
            ..self
        }
    }

    fn with_response_consensus(self, response_consensus: ConsensusStrategy) -> Self {
        Self {
            response_consensus: Some(response_consensus),
            ..self
        }
    }
}

impl EvmRpcConfig for GetLogsRpcConfig {
    fn with_response_size_estimate(self, response_size_estimate: u64) -> Self {
        Self {
            response_size_estimate: Some(response_size_estimate),
            ..self
        }
    }

    fn with_response_consensus(self, response_consensus: ConsensusStrategy) -> Self {
        Self {
            response_consensus: Some(response_consensus),
            ..self
        }
    }
}

impl<
        Runtime,
        Converter,
        RetryPolicy,
        Config: EvmRpcConfig + Default,
        Params,
        CandidOutput,
        Output,
    > RequestBuilder<Runtime, Converter, RetryPolicy, Config, Params, CandidOutput, Output>
{
    /// Change the response size estimate to use for that request.
    pub fn with_response_size_estimate(mut self, response_size_estimate: u64) -> Self {
        self.request.rpc_config = Some(
            self.request
                .rpc_config
                .unwrap_or_default()
                .with_response_size_estimate(response_size_estimate),
        );
        self
    }

    /// Change the consensus strategy to use for that request.
    pub fn with_response_consensus(mut self, response_consensus: ConsensusStrategy) -> Self {
        self.request.rpc_config = Some(
            self.request
                .rpc_config
                .unwrap_or_default()
                .with_response_consensus(response_consensus),
        );
        self
    }
}

/// A request which can be executed with `EvmRpcClient::execute_request` or `EvmRpcClient::execute_query_request`.
pub struct Request<Config, Params, CandidOutput, Output> {
    pub(super) endpoint: EvmRpcEndpoint,
    pub(super) rpc_services: RpcServices,
    pub(super) rpc_config: Option<Config>,
    pub(super) params: Params,
    pub(super) cycles: u128,
    pub(super) _candid_marker: std::marker::PhantomData<CandidOutput>,
    pub(super) _output_marker: std::marker::PhantomData<Output>,
}

impl<Config: Debug, Params: Debug, CandidOutput, Output> Debug
    for Request<Config, Params, CandidOutput, Output>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let Request {
            endpoint,
            rpc_services,
            rpc_config,
            params,
            cycles,
            _candid_marker,
            _output_marker,
        } = &self;
        f.debug_struct("Request")
            .field("endpoint", endpoint)
            .field("rpc_services", rpc_services)
            .field("rpc_config", rpc_config)
            .field("params", params)
            .field("cycles", cycles)
            .field("_candid_marker", _candid_marker)
            .field("_output_marker", _output_marker)
            .finish()
    }
}

impl<Config: PartialEq, Params: PartialEq, CandidOutput, Output> PartialEq
    for Request<Config, Params, CandidOutput, Output>
{
    fn eq(
        &self,
        Request {
            endpoint,
            rpc_services,
            rpc_config,
            params,
            cycles,
            _candid_marker,
            _output_marker,
        }: &Self,
    ) -> bool {
        &self.endpoint == endpoint
            && &self.rpc_services == rpc_services
            && &self.rpc_config == rpc_config
            && &self.params == params
            && &self.cycles == cycles
            && &self._candid_marker == _candid_marker
            && &self._output_marker == _output_marker
    }
}

impl<Config: Clone, Params: Clone, CandidOutput, Output> Clone
    for Request<Config, Params, CandidOutput, Output>
{
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            rpc_services: self.rpc_services.clone(),
            rpc_config: self.rpc_config.clone(),
            params: self.params.clone(),
            cycles: self.cycles,
            _candid_marker: self._candid_marker,
            _output_marker: self._output_marker,
        }
    }
}

impl<Config, Params, CandidOutput, Output> Request<Config, Params, CandidOutput, Output> {
    /// Get a mutable reference to the cycles.
    #[inline]
    pub fn cycles_mut(&mut self) -> &mut u128 {
        &mut self.cycles
    }

    /// Get a mutable reference to the RPC configuration.
    #[inline]
    pub fn rpc_config_mut(&mut self) -> &mut Option<Config> {
        &mut self.rpc_config
    }

    /// Get a mutable reference to the request parameters.
    #[inline]
    pub fn params_mut(&mut self) -> &mut Params {
        &mut self.params
    }
}

pub type RequestCost<Config, Params> = Request<Config, Params, RpcResult<u128>, RpcResult<u128>>;

#[must_use = "RequestCostBuilder does nothing until you 'send' it"]
pub struct RequestCostBuilder<Runtime, Converter, RetryPolicy, Config, Params> {
    client: EvmRpcClient<Runtime, Converter, RetryPolicy>,
    request: RequestCost<Config, Params>,
}

impl<R: Runtime, C, P, Config, Params> RequestCostBuilder<R, C, P, Config, Params> {
    /// Constructs the [`Request`] and send it using the [`EvmRpcClient`].
    pub async fn send(self) -> RpcResult<u128>
    where
        Config: CandidType + Send,
        Params: CandidType + Send,
    {
        self.client.execute_cycles_cost_request(self.request).await
    }
}

// This trait is not public, otherwise adding a new endpoint to the EVM RPC canister would be
// a breaking change since it would add a new associated type to this trait.
pub trait EvmRpcResponseConverter {
    type CallOutput;
    type FeeHistoryOutput;
    type GetBlockByNumberOutput;
    type GetLogsOutput;
    type GetTransactionCountOutput;
    type GetTransactionReceiptOutput;
    type JsonRequestOutput;
    type SendRawTransactionOutput;
}

/// Defines Candid response types.
pub struct CandidResponseConverter;

impl EvmRpcResponseConverter for CandidResponseConverter {
    type CallOutput = MultiRpcResult<Hex>;
    type FeeHistoryOutput = MultiRpcResult<evm_rpc_types::FeeHistory>;
    type GetBlockByNumberOutput = MultiRpcResult<evm_rpc_types::Block>;
    type GetLogsOutput = MultiRpcResult<Vec<evm_rpc_types::LogEntry>>;
    type GetTransactionCountOutput = MultiRpcResult<Nat256>;
    type GetTransactionReceiptOutput = MultiRpcResult<Option<evm_rpc_types::TransactionReceipt>>;
    type JsonRequestOutput = MultiRpcResult<String>;
    type SendRawTransactionOutput = MultiRpcResult<evm_rpc_types::SendRawTransactionStatus>;
}
