use async_trait::async_trait;
use candid::{CandidType, Nat};
use cycles_minting_canister::IcpXdrConversionRateCertifiedResponse;
use futures::join;
use ic_base_types::CanisterId;
use ic_nervous_system_common::{E8, UNITS_PER_PERMYRIAD};
use ic_nervous_system_runtime::{CdkRuntime, Runtime};
use ic_nervous_system_string::clamp_debug_len;
use ic_nns_constants::{CYCLES_MINTING_CANISTER_ID, LEDGER_CANISTER_ID as ICP_LEDGER_CANISTER_ID};
use ic_sns_swap_proto_library::pb::v1::{GetDerivedStateRequest, GetDerivedStateResponse};
use icrc_ledger_types::icrc1::account::Account;
use mockall::automock;
use rust_decimal::Decimal;
use std::{
    fmt::Debug,
    marker::PhantomData,
    time::{Duration, SystemTime},
};

pub async fn try_get_icp_balance_valuation(account: Account) -> Result<Valuation, ValuationError> {
    let timestamp = now();

    try_get_balance_valuation_factors(
        account,
        &mut LedgerCanister::<CdkRuntime>::new(ICP_LEDGER_CANISTER_ID),
        &mut IcpsPerIcpClient {},
        &mut new_standard_xdrs_per_icp_client::<CdkRuntime>(),
    )
    .await
    .map(|valuation_factors| Valuation {
        token: Token::Icp,
        account,
        timestamp,
        valuation_factors,
    })
}

pub async fn try_get_sns_token_balance_valuation(
    account: Account,
    sns_ledger_canister_id: CanisterId,
    swap_canister_id: CanisterId,
) -> Result<Valuation, ValuationError> {
    let timestamp = now();

    try_get_balance_valuation_factors(
        account,
        &mut LedgerCanister::<CdkRuntime>::new(sns_ledger_canister_id),
        &mut IcpsPerSnsTokenClient::<CdkRuntime>::new(swap_canister_id),
        &mut new_standard_xdrs_per_icp_client::<CdkRuntime>(),
    )
    .await
    .map(|valuation_factors| Valuation {
        token: Token::SnsToken,
        account,
        timestamp,
        valuation_factors,
    })
}

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_nanos(ic_cdk::api::time())
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum Token {
    Icp,

    /// The native token of the SNS.
    SnsToken,
}

impl Token {
    pub async fn assess_balance(
        self,
        sns_ledger_canister_id: CanisterId, // Not used when self = Icp.
        swap_canister_id: CanisterId,       // Not used when self = Icp.
        account: Account,
    ) -> Result<Valuation, ValuationError> {
        match self {
            Token::Icp => try_get_icp_balance_valuation(account).await,

            Token::SnsToken => {
                try_get_sns_token_balance_valuation(
                    account,
                    sns_ledger_canister_id,
                    swap_canister_id,
                )
                .await
            }
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct Valuation {
    pub token: Token,
    pub account: Account,
    pub timestamp: SystemTime,
    pub valuation_factors: ValuationFactors,
}

impl Valuation {
    pub fn to_xdr(&self) -> Decimal {
        self.valuation_factors.to_xdr()
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct ValuationFactors {
    pub tokens: Decimal,
    pub icps_per_token: Decimal,
    pub xdrs_per_icp: Decimal,
}

impl ValuationFactors {
    pub fn to_xdr(&self) -> Decimal {
        let Self {
            tokens,
            icps_per_token,
            xdrs_per_icp,
        } = self;

        tokens * icps_per_token * xdrs_per_icp
    }
}

/// Returns a valuation in XDR of the current balance in account.
///
/// # Arguments
/// * `account` - Where funds are held. In the case of an SNS's treasury, this is the default
///   subaccount of the SNS governance canister.
/// * `icrc1_client` - Reads the balance of `account`.
/// * `icps_per_token_client` - For conversion to ICP from whatever token the icrc1_client deals in.
///   Of course, in the case of ICP, this conversion is trivial, and is implemented by the
///   IcpsPerIcpClient in this crate.
/// * `xdrs_per_icp_client` - Supplies the ICP -> XDR conversion rate. This is probably the most
///   interesting of the clients used. A object suitable for production can be constructed by
///   calling new_standard_xdrs_per_icp_client::<DfnRuntime> with zero arguments.
async fn try_get_balance_valuation_factors(
    account: Account,
    icrc1_client: &mut dyn Icrc1Client,
    icps_per_token_client: &mut dyn IcpsPerTokenClient,
    xdrs_per_icp_client: &mut dyn XdrsPerIcpClient,
) -> Result<ValuationFactors, ValuationError> {
    // Fetch the three ingredients:
    //
    //     1. balance
    //     2. token -> ICP
    //     3. ICP -> XDR
    //
    // No await here. Instead, we use join (right after this).
    let balance_of_request = icrc1_client.icrc1_balance_of(account);
    let icps_per_token_request = icps_per_token_client.get();
    let xdrs_per_icp_request = xdrs_per_icp_client.get();

    // Make all (3) requests (concurrently).
    let (balance_of_response, icps_per_token_response, xdrs_per_icp_response) = join!(
        balance_of_request,
        icps_per_token_request,
        xdrs_per_icp_request,
    );

    // Unwrap/forward errors to the caller.
    let balance_of_response = balance_of_response.map_err(|err| {
        ValuationError::new_external(format!("Unable to obtain balance from ledger: {:?}", err))
    })?;
    let icps_per_token_response = icps_per_token_response.map_err(|err| {
        ValuationError::new_external(format!("Unable to determine ICPs per token: {:?}", err))
    })?;
    let xdrs_per_icp_response = xdrs_per_icp_response.map_err(|err| {
        ValuationError::new_external(format!("Unable to obtain XDR per ICP: {:?}", err))
    })?;

    // Extract and interpret the data we actually care about from the (Ok) responses.
    let tokens = Decimal::from(u128::try_from(balance_of_response.0).map_err(|err| {
        ValuationError::new_arithmetic(format!(
            "Balance of {:?} does not fit in u128: {:?}",
            account, err
        ))
    })?) / Decimal::from(E8);
    let icps_per_token = icps_per_token_response;
    let xdrs_per_icp = xdrs_per_icp_response;

    // Compose the fetched/interpretted data (i.e. multiply them) to construct the final result.
    Ok(ValuationFactors {
        tokens,
        icps_per_token,
        xdrs_per_icp,
    })
}

// ValuationError

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ValuationError {
    pub species: ValuationErrorSpecies,

    /// Human-readable. Ideally, explains what could not be done, proximate and prior causes, and
    /// includes breadcrumbs to help the reader figure out how to get what they wanted.
    pub message: String,
}

impl ValuationError {
    fn new_external(message: String) -> Self {
        Self {
            message,
            species: ValuationErrorSpecies::External,
        }
    }

    fn new_mismatch(message: String) -> Self {
        Self {
            message,
            species: ValuationErrorSpecies::Mismatch,
        }
    }

    fn new_arithmetic(message: String) -> Self {
        Self {
            message,
            species: ValuationErrorSpecies::Arithmetic,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ValuationErrorSpecies {
    /// Needed data from another canister, but was not able to get a reply.
    External,

    /// Got a reply from another canister, but the reply did not contain the needed data. This could
    /// be due to talking to an incompatible (more advanced?) version of the canister.
    Mismatch,

    /// E.g. overflow, underflow, divide by zero, etc.
    Arithmetic,
}

// Traits

#[automock]
#[async_trait]
trait Icrc1Client: Send {
    async fn icrc1_balance_of(&mut self, account: Account) -> Result<Nat, (i32, String)>;
}

#[automock]
#[async_trait]
trait IcpsPerTokenClient: Send {
    async fn get(&mut self) -> Result<Decimal, ValuationError>;
}

#[automock]
#[async_trait]
trait XdrsPerIcpClient: Send {
    async fn get(&mut self) -> Result<Decimal, ValuationError>;
}

// Trait Implementations Suitable For Production.

struct LedgerCanister<MyRuntime: Runtime + Send + Sync> {
    canister_id: CanisterId,
    _runtime: PhantomData<MyRuntime>,
}

impl<MyRuntime: Runtime + Send + Sync> LedgerCanister<MyRuntime> {
    fn new(canister_id: CanisterId) -> Self {
        Self {
            canister_id,
            _runtime: Default::default(),
        }
    }
}

#[async_trait]
impl<MyRuntime: Runtime + Send + Sync> Icrc1Client for LedgerCanister<MyRuntime> {
    async fn icrc1_balance_of(&mut self, account: Account) -> Result<Nat, (i32, String)> {
        let (result,): (Nat,) =
            MyRuntime::call_with_cleanup(self.canister_id, "icrc1_balance_of", (account,)).await?;

        Ok(result)
    }
}

struct IcpsPerIcpClient {}

#[async_trait]
impl IcpsPerTokenClient for IcpsPerIcpClient {
    async fn get(&mut self) -> Result<Decimal, ValuationError> {
        Ok(Decimal::from(1))
    }
}

struct IcpsPerSnsTokenClient<MyRuntime: Runtime + Send + Sync> {
    swap_canister_id: CanisterId,
    _runtime: PhantomData<MyRuntime>,
}

impl<MyRuntime: Runtime + Send + Sync> IcpsPerSnsTokenClient<MyRuntime> {
    pub fn new(swap_canister_id: CanisterId) -> Self {
        Self {
            swap_canister_id,
            _runtime: Default::default(),
        }
    }

    async fn fetch_icps_per_sns_token(&self) -> Result<Decimal, ValuationError> {
        // Fetch SNS token price from swap.
        let get_derived_state_response = self.call(GetDerivedStateRequest {}).await?;

        // Read the relevant field(s) out of the responses. Here, a floating point field is used. In
        // general, floating point should not be used for financial accounting, but it is ok here,
        // because we are using this to come up with a valuation, and valuations are not super
        // precise in the same way that (for example) a bank account balance is supposed to be.
        let sns_tokens_per_icp: f64 =
            get_derived_state_response
                .sns_tokens_per_icp
                .ok_or_else(|| {
                    ValuationError::new_mismatch(format!(
                        "Response from swap ({}) get_derived_state call did not \
                         contain sns_tokens_per_icp: {:#?}",
                        self.swap_canister_id, get_derived_state_response,
                    ))
                })?;

        // Convert data type.
        let sns_tokens_per_icp = Decimal::from_f64_retain(sns_tokens_per_icp).ok_or_else(|| {
            ValuationError::new_arithmetic(format!(
                "Unable to convert sns_tokens_per_icp {} (double precision \
                 floating point) to Decimal.",
                sns_tokens_per_icp,
            ))
        })?;

        // Flip the ratio from SNS tokens/ICP to ICPs/SNS token.
        Decimal::from(1)
            .checked_div(sns_tokens_per_icp)
            .ok_or_else(|| {
                ValuationError::new_arithmetic(format!(
                    "Unable to perform 1 / sns_tokens_per_icp (where sns_tokens_per_icp = {}).",
                    sns_tokens_per_icp,
                ))
            })
    }

    async fn call<MyRequest>(
        &self,
        request: MyRequest,
    ) -> Result<MyRequest::MyResponse, ValuationError>
    where
        MyRequest: Request + Debug + Clone + Sync,
        <MyRequest as Request>::MyResponse: CandidType,
    {
        call::<_, MyRuntime>(self.swap_canister_id, request.clone())
            .await
            .map_err(|err| {
                ValuationError::new_external(format!(
                    "Unable to determine ICPs per SNS token, because calling swap canister \
                     {} failed. Request:\n{}\nerr: {:?}",
                    self.swap_canister_id,
                    clamp_debug_len(request, /* max_len = */ 100),
                    err,
                ))
            })
    }
}

#[async_trait]
impl<R: Runtime + Send + Sync> IcpsPerTokenClient for IcpsPerSnsTokenClient<R> {
    async fn get(&mut self) -> Result<Decimal, ValuationError> {
        self.fetch_icps_per_sns_token().await
    }
}

// Here, "standard" just means that it is appropriate for production use.
fn new_standard_xdrs_per_icp_client<MyRuntime: Runtime + Send + Sync>() -> impl XdrsPerIcpClient {
    struct CmcBased30DayMovingAverageXdrsPerIcpClient<MyRuntime: Runtime + Send + Sync> {
        _runtime: PhantomData<MyRuntime>,
    }

    #[async_trait]
    impl<MyRuntime: Runtime + Send + Sync> XdrsPerIcpClient
        for CmcBased30DayMovingAverageXdrsPerIcpClient<MyRuntime>
    {
        async fn get(&mut self) -> Result<Decimal, ValuationError> {
            let (response,): (IcpXdrConversionRateCertifiedResponse,) =
                MyRuntime::call_with_cleanup(
                    CYCLES_MINTING_CANISTER_ID,
                    // This is not in the cmc.did file (yet).
                    "get_average_icp_xdr_conversion_rate",
                    ((),),
                )
                .await
                .map_err(|err| {
                    ValuationError::new_external(format!(
                        "Unable to determine XDRs per ICP, because the cycles minting canister \
                         did not reply to a get_average_icp_xdr_conversion_rate call: {:?}",
                        err,
                    ))
                })?;

            // No need to validate the cerificate in response, because query is not used in this
            // case (specifically, canister A in subnet X is calling (another) canister B in
            // (another) subnet Y).

            let xdr_per_icp =
                Decimal::from(response.data.xdr_permyriad_per_icp) * *UNITS_PER_PERMYRIAD;

            Ok(xdr_per_icp)
        }
    }

    CmcBased30DayMovingAverageXdrsPerIcpClient::<MyRuntime> {
        _runtime: Default::default(),
    }
}

// Generic Helpers (could be moved to more general place).

/// Associates a request type with method_name and response type.
///
/// This is based on the pattern where
///
/// ```candid
/// service : {
///     greet : (GreetRequest) -> (GreetResponse);
/// }
/// ```
///
/// Once you know one of the three pieces, you know the other two.
///
/// By implementing this trait, you are telling fn call how to deduce the method name and response
/// type from the request/argument type, which reduces quite a fair amount of redundancy.
// TODO: Implement #[derive(Request)]. This would replace the hand-crafted implementations below.
trait Request: CandidType + Send {
    const METHOD_NAME: &'static str;
    type MyResponse: for<'a> candid::Deserialize<'a>;
}

impl Request for GetDerivedStateRequest {
    const METHOD_NAME: &'static str = "get_derived_state";
    type MyResponse = GetDerivedStateResponse;
}

async fn call<MyRequest, MyRuntime>(
    destination_canister_id: CanisterId,
    request: MyRequest,
) -> Result<MyRequest::MyResponse, (i32, String)>
where
    MyRequest: Request + Sync,
    MyRuntime: Runtime,
    <MyRequest as Request>::MyResponse: CandidType,
{
    let (response,): (MyRequest::MyResponse,) =
        MyRuntime::call_with_cleanup(destination_canister_id, MyRequest::METHOD_NAME, (request,))
            .await?;

    Ok(response)
}

#[cfg(test)]
mod tests;
