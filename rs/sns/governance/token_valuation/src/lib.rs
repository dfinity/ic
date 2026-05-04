use async_trait::async_trait;
use candid::{CandidType, Nat};
use cycles_minting_canister::IcpXdrConversionRateCertifiedResponse;
use futures::join;
use ic_base_types::CanisterId;
use ic_nervous_system_common::{E8, UNITS_PER_PERMYRIAD, i2d};
use ic_nervous_system_initial_supply::{InitialSupplyOptions, initial_supply_e8s};
use ic_nervous_system_runtime::{CdkRuntime, Runtime};
use ic_nns_constants::{CYCLES_MINTING_CANISTER_ID, LEDGER_CANISTER_ID as ICP_LEDGER_CANISTER_ID};
use ic_sns_swap_proto_library::pb::v1::{GetDerivedStateRequest, GetDerivedStateResponse};
use icrc_ledger_types::icrc1::account::Account;
use mockall::automock;
use num_traits::cast::ToPrimitive;
use rust_decimal::Decimal;
#[cfg(target_arch = "wasm32")]
use std::time::Duration;
use std::{fmt::Debug, marker::PhantomData, time::SystemTime};

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
        &mut IcpsPerSnsTokenClient::<CdkRuntime>::new(swap_canister_id, sns_ledger_canister_id),
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
    #[cfg(target_arch = "wasm32")]
    return SystemTime::UNIX_EPOCH + Duration::from_nanos(ic_cdk::api::time());
    #[cfg(not(target_arch = "wasm32"))]
    SystemTime::now()
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
///   calling new_standard_xdrs_per_icp_client::<CdkRuntime> with zero arguments.
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
        ValuationError::new_external(format!("Unable to obtain balance from ledger: {err:?}"))
    })?;
    let icps_per_token_response = icps_per_token_response.map_err(|err| {
        ValuationError::new_external(format!("Unable to determine ICPs per token: {err:?}"))
    })?;
    let xdrs_per_icp_response = xdrs_per_icp_response.map_err(|err| {
        ValuationError::new_external(format!("Unable to obtain XDR per ICP: {err:?}"))
    })?;

    // Extract and interpret the data we actually care about from the (Ok) responses.
    let tokens = Decimal::from(u128::try_from(balance_of_response.0).map_err(|err| {
        ValuationError::new_arithmetic(format!(
            "Balance of {account:?} does not fit in u128: {err:?}"
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
    sns_token_ledger_canister_id: CanisterId,
    _runtime: PhantomData<MyRuntime>,
}

impl<MyRuntime: Runtime + Send + Sync> IcpsPerSnsTokenClient<MyRuntime> {
    pub fn new(
        swap_canister_id: CanisterId,
        // This is used to determine the amount of inflation since genesis/swap execution.
        sns_token_ledger_canister_id: CanisterId,
    ) -> Self {
        Self {
            swap_canister_id,
            sns_token_ledger_canister_id,
            _runtime: Default::default(),
        }
    }

    async fn fetch_icps_per_sns_token(&self) -> Result<Decimal, ValuationError> {
        // (Concurrently) fetch the various pieces that we need to sythensize the result:
        let (get_derived_state_result, initial_supply_e8s_result, current_supply_result) = join!(
            // 1. SNS token price from swap.
            call::<_, MyRuntime>(self.swap_canister_id, GetDerivedStateRequest {}),
            // 2. Initial SNS token supply.
            initial_supply_e8s::<MyRuntime>(
                self.sns_token_ledger_canister_id,
                InitialSupplyOptions::new()
            ),
            // 3. Current SNS token supply.
            MyRuntime::call_with_cleanup::<_, (Nat,)>(
                self.sns_token_ledger_canister_id,
                "icrc1_total_supply",
                ()
            ),
        );
        // (Factors 2 and 3 tell us how much inflation there has been. For
        // example, if the amount of tokens has doubled since the beginning,
        // then the current ICPs per SNS token should be half of what it was at
        // the time of the swap.)

        // Unwrap (intermediate) results.
        let get_derived_state_response = get_derived_state_result.map_err(|err| {
            ValuationError::new_external(format!(
                "Unable to obtain SNS token price at the time of the SNS initialization swap: {err:?}",
            ))
        })?;
        let initial_supply_e8s = initial_supply_e8s_result.map_err(|err| {
            ValuationError::new_external(format!(
                "Unable to determine the initial supply of SNS tokens: {err:?}",
            ))
        })?;
        let (current_supply_e8s,) = current_supply_result.map_err(|err| {
            ValuationError::new_external(format!(
                "Unable to obtain the current supply of SNS tokens: {err:?}",
            ))
        })?;

        // Read the relevant fields.

        // Here, a floating point field is used. This is ok, because we are just
        // using this to come up with a valuation, which isn't an exact science.
        let initial_sns_tokens_per_icp: f64 = get_derived_state_response
            .sns_tokens_per_icp
            .ok_or_else(|| {
                ValuationError::new_mismatch(format!(
                    "Response from swap ({}) get_derived_state call did not \
                     contain sns_tokens_per_icp: {:#?}",
                    self.swap_canister_id, get_derived_state_response,
                ))
            })?;

        // Convert all numbers to Decimal.

        let initial_sns_tokens_per_icp = Decimal::from_f64_retain(initial_sns_tokens_per_icp)
            .ok_or_else(|| {
                ValuationError::new_arithmetic(format!(
                    "Unable to convert sns_tokens_per_icp {initial_sns_tokens_per_icp} (double precision \
                     floating point) to Decimal.",
                ))
            })?;

        let initial_supply_e8s = i2d(initial_supply_e8s);

        let current_supply_e8s =
            Decimal::from(current_supply_e8s.0.to_u128().ok_or_else(|| {
                ValuationError::new_arithmetic(format!(
                    "Unable to convert current_supply_e8s ({current_supply_e8s}) from Nat to Decimal.",
                ))
            })?);

        // Do actual (simple) math.

        // Flip the ratio from SNS tokens per ICP to ICPs per SNS token.
        let initial_icps_per_sns_token = Decimal::from(1)
            .checked_div(initial_sns_tokens_per_icp)
            .ok_or_else(|| {
            ValuationError::new_arithmetic(format!(
                "Unable to perform 1 / sns_tokens_per_icp (where sns_tokens_per_icp = {initial_sns_tokens_per_icp}).",
            ))
        })?;

        let total_inflation = current_supply_e8s
            .checked_div(initial_supply_e8s)
            .ok_or_else(|| {
                ValuationError::new_arithmetic(format!(
                    "Unable to perform current_supply / initial_supply \
                     (where current_supply_e8s = {current_supply_e8s} and initial_supply_e8s = {initial_supply_e8s})",
                ))
            })?;

        // Finally, current price = initial price scaled down by inflation (or deflation).
        initial_icps_per_sns_token
            .checked_div(total_inflation)
            .ok_or_else(|| {
                ValuationError::new_arithmetic(format!(
                    "Unable to perform initial_icps_per_sns_token / total_inflation \
                     (where initial_icps_per_sns_token = {initial_icps_per_sns_token} and total_inflation = {total_inflation})",
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
                         did not reply to a get_average_icp_xdr_conversion_rate call: {err:?}",
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
