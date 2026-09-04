//! A canister for exercising HTTPS outcalls by hand.
//!
//! Deploy it on a testnet (or mainnet) and drive it from the Candid UI: every
//! endpoint takes flat, scalar arguments so that it can be filled in from a
//! browser without having to hand-write nested Candid values.
//!
//! What it offers:
//!  * [`http_request_fully_replicated`], [`http_request_non_replicated`] and
//!    [`flexible_http_request`] make outcalls of each replication kind, attaching
//!    however many of this canister's own cycles you ask for, and hand back what
//!    the management canister replied verbatim;
//!  * [`cost_http_request`] and [`cost_http_request_v2`] report what the two
//!    pricing versions say an outcall costs;
//!  * [`cycle_balance`] reads this canister's balance, which is where
//!    pay-as-you-go refunds land.
//!
//! Build it with
//! `bazel build //rs/rust_canisters/https_outcalls_test_canister` and install the
//! resulting `https_outcalls_test_canister.wasm.gz`. Top it up generously: the
//! cycles an outcall attaches come out of this canister's own balance, and under
//! legacy pricing a request that leaves `max_response_bytes` unset is charged for
//! the largest response it could ever get back.

use candid::{CandidType, Deserialize, Principal};
use ic_cdk::api::{canister_cycle_balance, canister_self, msg_cycles_refunded};
use ic_cdk::call::{Call, CallFailed};
use ic_cdk::{query, update};
use ic_management_canister_types_private::{
    BoundedHttpHeaders, CanisterHttpRequestArgs, CanisterHttpResponsePayload,
    FlexibleCanisterHttpRequestArgs, FlexibleHttpRequestResult, HttpHeader, HttpMethod,
    PRICING_VERSION_LEGACY, PRICING_VERSION_PAY_AS_YOU_GO, ReplicationCounts, TransformArgs,
    TransformContext, TransformFunc,
};

// ============================== Argument types ==============================
// Variants (rendered as dropdowns by the Candid UI) rather than magic strings,
// but no nested records: everything else is a scalar, an option or a list of
// strings.

/// Which pricing model the outcall asks to be charged under.
///
/// Leaving it out sends no `pricing_version` at all, which is what canisters that
/// predate the field do and what the replica falls back to.
#[derive(Clone, Copy, CandidType, Deserialize)]
pub enum PricingVersion {
    /// Charge the whole estimated cost up front and refund what is left over
    /// when the response is delivered.
    #[serde(rename = "legacy")]
    Legacy,
    /// Charge a base fee up front, then only what the outcall actually used,
    /// crediting the rest back to the balance afterwards.
    #[serde(rename = "pay_as_you_go")]
    PayAsYouGo,
}

impl PricingVersion {
    fn as_u32(self) -> u32 {
        match self {
            PricingVersion::Legacy => PRICING_VERSION_LEGACY,
            PricingVersion::PayAsYouGo => PRICING_VERSION_PAY_AS_YOU_GO,
        }
    }
}

/// Which of this canister's transform queries to run over the response.
///
/// A fully-replicated outcall only reaches consensus if every replica ends up
/// with byte-identical content, so anything that varies per replica — an httpbin
/// `Date` header, say — has to be transformed away first.
#[derive(Clone, Copy, CandidType, Deserialize)]
pub enum Transform {
    /// Return the response unchanged. Useful for *watching* a fully-replicated
    /// outcall fail to agree; fine for non-replicated ones.
    #[serde(rename = "identity")]
    Identity,
    /// Drop the headers, keep the status and body.
    #[serde(rename = "strip_headers")]
    StripHeaders,
    /// Drop the headers and replace the body with the transform context, which
    /// makes the response identical across replicas whatever the server said.
    #[serde(rename = "constant_body")]
    ConstantBody,
    /// Drop the headers and append the transform context to the body.
    #[serde(rename = "append_context")]
    AppendContext,
}

impl Transform {
    fn method_name(self) -> &'static str {
        match self {
            Transform::Identity => "identity",
            Transform::StripHeaders => "strip_headers",
            Transform::ConstantBody => "constant_body",
            Transform::AppendContext => "append_context",
        }
    }
}

/// The replication of the outcall whose price [`cost_http_request_v2`] reports.
///
/// Leaving it out prices a fully-replicated outcall, which is also what the
/// replica assumes when the field is absent.
#[derive(Clone, Copy, CandidType, Deserialize)]
pub enum OutcallType {
    #[serde(rename = "fully_replicated")]
    FullyReplicated,
    #[serde(rename = "non_replicated")]
    NonReplicated,
    #[serde(rename = "flexible")]
    Flexible,
}

// =============================== Result types ===============================
// Records and variants on the way out: the Candid UI renders them fine, and this
// is where staying faithful to what the management canister said matters.

/// Why a call to the management canister came back rejected.
#[derive(CandidType, Deserialize)]
pub struct CallReject {
    /// The reject code the system reported, or `0` if the call never reached the
    /// management canister and so has no code of its own.
    pub code: u32,
    pub message: String,
}

/// What an `http_request` came back with, plus what it cost.
#[derive(CandidType, Deserialize)]
pub struct HttpOutcome {
    /// Exactly what the management canister replied, or the reject it answered
    /// with.
    pub result: Result<CanisterHttpResponsePayload, CallReject>,
    /// The cycles that came back attached to the reply, or absent when the call
    /// never left this canister and so was never replied to at all.
    ///
    /// Under pay-as-you-go pricing most of the refund is instead credited to the
    /// balance a moment later, so query [`cycle_balance`] again to see the final
    /// cost.
    pub cycles_refunded: Option<u128>,
    /// The balance just before the call, and just after the reply arrived.
    pub balance_before: u128,
    pub balance_after: u128,
}

/// What a `flexible_http_request` came back with, plus what it cost.
///
/// Note the two nested layers of failure: `result` is `Err` when the *call* was
/// rejected (bad arguments, too few cycles to start), whereas
/// `Ok(FlexibleHttpRequestResult::Err)` is the outcall itself reporting that it
/// could not produce a response.
#[derive(CandidType, Deserialize)]
pub struct FlexibleOutcome {
    pub result: Result<FlexibleHttpRequestResult, CallReject>,
    /// See [`HttpOutcome::cycles_refunded`].
    pub cycles_refunded: Option<u128>,
    pub balance_before: u128,
    pub balance_after: u128,
}

// ================================= Outcalls =================================

/// Makes a fully-replicated outcall: every node of the subnet fetches the URL and
/// consensus only delivers a response they agree on byte for byte.
///
/// `is_replicated` is left absent, which the replica treats as replicated.
///
/// Arguments:
///  * `headers`: one `Name: Value` per entry.
///  * `body`: sent as UTF-8. Leave it out for no body at all.
///  * `max_response_bytes`: absent asks for the largest response allowed (2 MiB),
///    and is charged for accordingly under legacy pricing.
///  * `transform`/`transform_context`: which of this canister's transform queries
///    to run, and the context handed to it. A fully-replicated outcall to a
///    server that varies its response needs one — see [`Transform`].
///  * `cycles`: taken from this canister's own balance and attached to the call.
#[update]
#[allow(clippy::too_many_arguments)]
async fn http_request_fully_replicated(
    url: String,
    method: HttpMethod,
    headers: Vec<String>,
    body: Option<String>,
    max_response_bytes: Option<u64>,
    transform: Option<Transform>,
    transform_context: Option<String>,
    pricing_version: Option<PricingVersion>,
    cycles: u128,
) -> HttpOutcome {
    let args = http_request_args(
        url,
        method,
        headers,
        body,
        max_response_bytes,
        transform,
        transform_context,
        pricing_version,
        None,
    );
    http_request(args, cycles).await
}

/// Makes a non-replicated outcall: a single node fetches the URL and its response
/// is delivered without the other nodes having to agree on it.
///
/// Takes the same arguments as [`http_request_fully_replicated`], and sends
/// `is_replicated = false`.
#[update]
#[allow(clippy::too_many_arguments)]
async fn http_request_non_replicated(
    url: String,
    method: HttpMethod,
    headers: Vec<String>,
    body: Option<String>,
    max_response_bytes: Option<u64>,
    transform: Option<Transform>,
    transform_context: Option<String>,
    pricing_version: Option<PricingVersion>,
    cycles: u128,
) -> HttpOutcome {
    let args = http_request_args(
        url,
        method,
        headers,
        body,
        max_response_bytes,
        transform,
        transform_context,
        pricing_version,
        Some(false),
    );
    http_request(args, cycles).await
}

/// Makes a flexible outcall: `total_requests` nodes fetch the URL and between
/// `min_responses` and `max_responses` of their responses are delivered, so the
/// nodes need not all agree — or even all answer.
///
/// Flexible outcalls are always priced pay-as-you-go, hence no
/// `pricing_version`. The other arguments are as in
/// [`http_request_fully_replicated`], plus:
///  * `total_requests`, `min_responses`, `max_responses`: leave all three at `0`
///    to send no replication at all, which asks the replica for its defaults
///    (every node, `floor(2n/3) + 1` responses required, all of them accepted).
#[update]
#[allow(clippy::too_many_arguments)]
async fn flexible_http_request(
    url: String,
    method: HttpMethod,
    headers: Vec<String>,
    body: Option<String>,
    max_response_bytes: Option<u64>,
    transform: Option<Transform>,
    transform_context: Option<String>,
    total_requests: u32,
    min_responses: u32,
    max_responses: u32,
    cycles: u128,
) -> FlexibleOutcome {
    let replication = if (total_requests, min_responses, max_responses) == (0, 0, 0) {
        None
    } else {
        Some(ReplicationCounts {
            total_requests,
            min_responses,
            max_responses,
        })
    };
    let args = FlexibleCanisterHttpRequestArgs {
        url,
        max_response_bytes,
        headers: parse_headers(headers),
        body: body.map(String::into_bytes),
        method,
        transform: transform_context_for(transform, transform_context),
        replication,
    };

    let balance_before = canister_cycle_balance();
    let (result, cycles_refunded) =
        call_management_canister("flexible_http_request", args, cycles).await;
    FlexibleOutcome {
        result,
        cycles_refunded,
        balance_before,
        balance_after: canister_cycle_balance(),
    }
}

/// Assembles the management canister's `http_request` arguments out of the flat
/// ones the endpoints above take.
#[allow(clippy::too_many_arguments)]
fn http_request_args(
    url: String,
    method: HttpMethod,
    headers: Vec<String>,
    body: Option<String>,
    max_response_bytes: Option<u64>,
    transform: Option<Transform>,
    transform_context: Option<String>,
    pricing_version: Option<PricingVersion>,
    is_replicated: Option<bool>,
) -> CanisterHttpRequestArgs {
    CanisterHttpRequestArgs {
        url,
        max_response_bytes,
        headers: parse_headers(headers),
        body: body.map(String::into_bytes),
        method,
        transform: transform_context_for(transform, transform_context),
        is_replicated,
        pricing_version: pricing_version.map(PricingVersion::as_u32),
    }
}

async fn http_request(args: CanisterHttpRequestArgs, cycles: u128) -> HttpOutcome {
    let balance_before = canister_cycle_balance();
    let (result, cycles_refunded) = call_management_canister("http_request", args, cycles).await;
    HttpOutcome {
        result,
        cycles_refunded,
        balance_before,
        balance_after: canister_cycle_balance(),
    }
}

/// Calls `method` on the management canister with `cycles` of this canister's own
/// cycles attached, decodes the reply as `R`, and reports the cycles that came
/// back with it.
///
/// The refund is only reported when the call reached the management canister and
/// came back, because `ic0.msg_cycles_refunded` is only available in a reply or
/// reject callback and traps anywhere else — including where a call fails before
/// it is ever performed, as one asking for more cycles than this canister holds
/// does.
async fn call_management_canister<A, R>(
    method: &str,
    args: A,
    cycles: u128,
) -> (Result<R, CallReject>, Option<u128>)
where
    A: CandidType,
    R: CandidType + for<'de> Deserialize<'de>,
{
    match Call::unbounded_wait(Principal::management_canister(), method)
        .with_arg(args)
        .with_cycles(cycles)
        .await
    {
        // In a reply callback, so the refund is readable.
        Ok(response) => {
            let refunded = msg_cycles_refunded();
            let result = response.candid::<R>().map_err(|err| CallReject {
                code: 0,
                message: format!("the reply could not be decoded: {err}"),
            });
            (result, Some(refunded))
        }
        // In a reject callback, so the refund is readable here too.
        Err(CallFailed::CallRejected(rejected)) => (
            Err(CallReject {
                code: rejected.raw_reject_code(),
                message: rejected.reject_message().to_string(),
            }),
            Some(msg_cycles_refunded()),
        ),
        // The call never left this canister: there is neither a reject code of
        // its own nor a reply to have refunded anything.
        Err(other) => (
            Err(CallReject {
                code: 0,
                message: other.to_string(),
            }),
            None,
        ),
    }
}

/// Parses `Name: Value` entries into HTTP headers. An entry without a colon
/// becomes a header with an empty value.
fn parse_headers(headers: Vec<String>) -> BoundedHttpHeaders {
    BoundedHttpHeaders::new(
        headers
            .into_iter()
            .map(|header| match header.split_once(':') {
                Some((name, value)) => HttpHeader {
                    name: name.trim().to_string(),
                    value: value.trim().to_string(),
                },
                None => HttpHeader {
                    name: header.trim().to_string(),
                    value: String::new(),
                },
            })
            .collect(),
    )
}

/// Points the request at one of this canister's own transform queries.
fn transform_context_for(
    transform: Option<Transform>,
    context: Option<String>,
) -> Option<TransformContext> {
    transform.map(|transform| TransformContext {
        function: TransformFunc(candid::Func {
            principal: canister_self(),
            method: transform.method_name().to_string(),
        }),
        context: context.unwrap_or_default().into_bytes(),
    })
}

// ============================ Transform functions ============================
// Referenced by name from the outcalls above; see `Transform`.

#[query]
fn identity(args: TransformArgs) -> CanisterHttpResponsePayload {
    args.response
}

#[query]
fn strip_headers(args: TransformArgs) -> CanisterHttpResponsePayload {
    CanisterHttpResponsePayload {
        headers: vec![],
        ..args.response
    }
}

#[query]
fn constant_body(args: TransformArgs) -> CanisterHttpResponsePayload {
    CanisterHttpResponsePayload {
        headers: vec![],
        body: args.context,
        ..args.response
    }
}

#[query]
fn append_context(args: TransformArgs) -> CanisterHttpResponsePayload {
    let mut body = args.response.body;
    body.extend_from_slice(&args.context);
    CanisterHttpResponsePayload {
        headers: vec![],
        body,
        ..args.response
    }
}

// ============================== Cost functions ==============================

/// What legacy pricing says an outcall costs, via `ic0.cost_http_request`.
///
/// The whole amount is charged up front, whatever the outcall goes on to use.
///
///  * `request_bytes`: the size of the request's variable parts — URL, headers,
///    body and transform context.
///  * `max_response_bytes`: what the request asks for as its response limit;
///    pass 2_000_000 for a request that leaves it out.
#[query]
fn cost_http_request(request_bytes: u64, max_response_bytes: u64) -> u128 {
    ic_cdk::api::cost_http_request(request_bytes, max_response_bytes)
}

/// What pay-as-you-go pricing says an outcall costs, via
/// `ic0.cost_http_request_v2`.
///
/// Unlike [`cost_http_request`], this prices the resources an outcall actually
/// consumes, so it takes them all as arguments:
///  * `outcall_type`: the replication being priced. Absent prices a
///    fully-replicated outcall, as the replica assumes for callers that predate
///    the field.
///  * `total_requests`, `min_responses`, `max_responses`: only read for
///    `flexible`; leave all three at `0` to price the replica's defaults.
///  * `request_bytes`: the size of the request's variable parts.
///  * `http_roundtrip_time_ms`: how long a replica waits for the server.
///  * `raw_response_bytes`: what the server returns, before the transform.
///  * `transformed_response_bytes`: what the transform returns, which is what
///    gets put into a block.
///  * `transform_instructions`: what running the transform costs.
///
/// Nothing here is validated: asking for the price of an outcall that could never
/// be made simply reports a price nothing will ever be charged.
#[query]
#[allow(clippy::too_many_arguments)]
fn cost_http_request_v2(
    outcall_type: Option<OutcallType>,
    total_requests: u32,
    min_responses: u32,
    max_responses: u32,
    request_bytes: u64,
    http_roundtrip_time_ms: u64,
    raw_response_bytes: u64,
    transformed_response_bytes: u64,
    transform_instructions: u64,
) -> u128 {
    let counts = if (total_requests, min_responses, max_responses) == (0, 0, 0) {
        None
    } else {
        Some(ReplicationCounts {
            total_requests,
            min_responses,
            max_responses,
        })
    };
    let params = CostHttpRequestV2Params {
        request_bytes,
        http_roundtrip_time_ms,
        raw_response_bytes,
        transformed_response_bytes,
        transform_instructions,
        outcall_type: outcall_type.map(|outcall_type| match outcall_type {
            OutcallType::FullyReplicated => {
                CostHttpRequestOutcallType::FullyReplicated(candid::Reserved)
            }
            OutcallType::NonReplicated => {
                CostHttpRequestOutcallType::NonReplicated(candid::Reserved)
            }
            OutcallType::Flexible => CostHttpRequestOutcallType::Flexible(counts),
        }),
    };

    let encoded = candid::encode_one(&params).expect("encoding the cost parameters cannot fail");
    let mut cycles = [0_u8; 16];
    // SAFETY: `encoded` is a readable sequence of `encoded.len()` bytes and
    // `cycles` a writable sequence of the 16 bytes a cycles amount takes.
    unsafe {
        ic0::cost_http_request_v2(
            encoded.as_ptr() as usize,
            encoded.len(),
            cycles.as_mut_ptr() as usize,
        );
    }
    u128::from_le_bytes(cycles)
}

/// The parameters of `ic0.cost_http_request_v2`.
///
/// Mirrors the replica's own definition, which is private to the embedder — keep
/// the field names and order in step with it.
#[derive(CandidType, Deserialize)]
struct CostHttpRequestV2Params {
    request_bytes: u64,
    http_roundtrip_time_ms: u64,
    raw_response_bytes: u64,
    transformed_response_bytes: u64,
    transform_instructions: u64,
    outcall_type: Option<CostHttpRequestOutcallType>,
}

#[derive(CandidType, Deserialize)]
enum CostHttpRequestOutcallType {
    #[serde(rename = "fully_replicated")]
    FullyReplicated(candid::Reserved),
    #[serde(rename = "non_replicated")]
    NonReplicated(candid::Reserved),
    #[serde(rename = "flexible")]
    Flexible(Option<ReplicationCounts>),
}

/// Neither of these is in the `ic0` crate yet, so declare them here.
mod ic0 {
    #[cfg(target_family = "wasm")]
    #[link(wasm_import_module = "ic0")]
    unsafe extern "C" {
        pub fn cost_http_request_v2(params_src: usize, params_size: usize, dst: usize);
        pub fn subnet_self_node_count() -> u32;
    }

    #[cfg(not(target_family = "wasm"))]
    pub unsafe fn cost_http_request_v2(_params_src: usize, _params_size: usize, _dst: usize) {
        panic!("cost_http_request_v2 should only be called inside canisters.");
    }

    #[cfg(not(target_family = "wasm"))]
    pub unsafe fn subnet_self_node_count() -> u32 {
        panic!("subnet_self_node_count should only be called inside canisters.");
    }
}

// ================================ Subnet size ================================

/// How many nodes this subnet has, via `ic0.subnet_self_node_count`.
///
/// Every outcall fee scales with this, so it is what the cost functions above are
/// implicitly quoting against.
#[query]
fn subnet_node_count() -> u32 {
    // SAFETY: takes no arguments and returns a plain scalar.
    unsafe { ic0::subnet_self_node_count() }
}

// ================================== Balance ==================================

/// This canister's cycle balance.
///
/// The place to watch for pay-as-you-go refunds: they are credited here shortly
/// after the response is delivered, rather than returned on the reply.
#[query]
fn cycle_balance() -> u128 {
    canister_cycle_balance()
}

ic_cdk::export_candid!();

/// The Candid interface of this canister, as the checked-in `.did` file gives it.
const DID: &str = include_str!("../https_outcalls_test_canister.did");

/// Serves this canister's Candid interface as a plain query.
///
/// Tools read the interface from the `candid:service` metadata first and fall back
/// to this method, which `export_candid!` does not generate — the Candid UI, for
/// one, gives up with "Cannot fetch candid file" when neither is available. Unlike
/// the metadata, reading this needs no certified `read_state`, so it works
/// wherever a plain query does.
///
/// It serves the `.did` file rather than `__export_service()` so that both routes
/// yield the same interface: only the file names its parameters, and a UI that
/// fell back to the generated one would show them unlabelled. A test checks the
/// two stay structurally equal.
///
/// Hidden from the generated interface: it is plumbing, not part of what this
/// canister offers.
#[query(hidden = true, name = "__get_candid_interface_tmp_hack")]
fn candid_interface() -> String {
    DID.to_string()
}

/// The canister's entry points are the `#[query]`/`#[update]` exports above;
/// nothing runs on start-up.
fn main() {}

#[cfg(test)]
mod tests {
    use candid_parser::utils::{CandidSource, service_equal};

    /// The Candid interface embedded in the wasm — and so the one the Candid UI
    /// renders — is the checked-in `.did` file, not what the code generates. The
    /// file names its parameters, which `export_candid!` cannot do and which is
    /// the whole point of it being hand-written, so compare the two structurally:
    /// parameter names are not part of a Candid type.
    #[test]
    fn candid_interface_matches_the_did_file() {
        let declared = super::DID;
        let implemented = super::__export_service();
        service_equal(
            CandidSource::Text(declared),
            CandidSource::Text(&implemented),
        )
        .unwrap_or_else(|err| {
            panic!(
                "the checked-in .did file does not match the implemented interface: {err}\n\n\
                 implemented:\n{implemented}"
            )
        });
    }
}
