/*

TODO - REQUIRED
- Unit tests: WIP.
- Neuron creation: implement.
- Canister methods for token distributions.

TODO - OPTIONAL / SEMI-REQUIRED
- Introduce Min ICP.
- No participant can buy more than or equal to half (or X% for some config paramter X) of the tokens.
- Refine approach to fee handling.
- Address occurrences of TODO in the code.
- What if ICP target is reached but there is an insufficient number of participants?

 */

use async_trait::async_trait;
use candid::candid_method;
use dfn_candid::{candid_one, CandidOne};
use dfn_core::CanisterId;
use dfn_core::{
    api::{caller, id, now},
    over, over_async, over_init, println,
};
use ic_base_types::PrincipalId;
use ic_nervous_system_common::ledger::{Ledger, LedgerCanister};
use ic_nervous_system_common::stable_mem_utils::{
    BufferedStableMemReader, BufferedStableMemWriter,
};
use ic_sns_governance::pb::v1::{ManageNeuron, ManageNeuronResponse, SetMode, SetModeResponse};
use ic_sns_sale::pb::v1::{
    CanisterCallError, FinalizeSaleRequest, FinalizeSaleResponse, GetCanisterStatusRequest,
    GetCanisterStatusResponse, GetStateRequest, GetStateResponse, Init, OpenSaleRequest,
    OpenSaleResponse, RefreshBuyerTokensRequest, RefreshBuyerTokensResponse,
    RefreshSnsTokensRequest, RefreshSnsTokensResponse, Sale,
};
use ic_sns_sale::sale::{SnsGovernanceClient, LOG_PREFIX};

use std::str::FromStr;

// TODO: add canister methods for transferring tokens out.
// use ledger_canister::{AccountIdentifier, Subaccount, DEFAULT_TRANSFER_FEE};

use prost::Message;
use std::time::Duration;
use std::time::SystemTime;

/// Size of the buffer for stable memory reads and writes.
const STABLE_MEM_BUFFER_SIZE: u32 = 1024 * 1024; // 1MiB

// =============================================================================
// ===               Global state of the canister                            ===
// =============================================================================

/// The global state of the this canister.
static mut SALE: Option<Sale> = None;

/// Returns an immutable reference to the global state.
///
/// This should only be called once the global state has been initialized, which
/// happens in `canister_init` or `canister_post_upgrade`.
fn sale() -> &'static Sale {
    unsafe { SALE.as_ref().expect("Canister not initialized!") }
}

/// Returns a mutable reference to the global state.
///
/// This should only be called once the global state has been initialized, which
/// happens in `canister_init` or `canister_post_upgrade`.
fn sale_mut() -> &'static mut Sale {
    unsafe { SALE.as_mut().expect("Canister not initialized!") }
}

// =============================================================================
// ===               Canister's public interface                             ===
// =============================================================================

/// See `GetStateResponse`.
#[export_name = "canister_query get_state"]
fn get_state() {
    over(candid_one, get_state_)
}

/// See `GetStateResponse`.
#[candid_method(query, rename = "get_state")]
fn get_state_(_arg: GetStateRequest) -> GetStateResponse {
    GetStateResponse {
        sale: Some(sale().clone()),
        derived: Some(sale().derived_state()),
    }
}

/// The sale can only be opened by the NNS Governance canister. See
/// `Sale.open` for details.
#[export_name = "canister_update open_sale"]
fn open_sale() {
    over(candid_one, open_sale_)
}

/// See `open_sale`.
#[candid_method(update, rename = "open_sale")]
fn open_sale_(_: OpenSaleRequest) -> OpenSaleResponse {
    println!("{}open_sale", LOG_PREFIX);
    let allowed_canister = sale().init().nns_governance();
    if caller() != PrincipalId::from(allowed_canister) {
        panic!(
            "This method can only be called by canister {}",
            allowed_canister
        );
    }
    match sale_mut().open() {
        Ok(()) => OpenSaleResponse {},
        Err(msg) => panic!("{}", msg),
    }
}

/// See `Sale.refresh_sns_token_e8s`.
#[export_name = "canister_update refresh_sns_tokens"]
fn refresh_sns_tokens() {
    over_async(candid_one, refresh_sns_tokens_)
}

/// See `Sale.refresh_sns_token_e8`.
#[candid_method(update, rename = "refresh_sns_tokens")]
async fn refresh_sns_tokens_(_: RefreshSnsTokensRequest) -> RefreshSnsTokensResponse {
    println!("{}refresh_sns_tokens", LOG_PREFIX);
    let ledger_factory = &create_real_ledger;
    match sale_mut().refresh_sns_token_e8s(id(), ledger_factory).await {
        Ok(()) => RefreshSnsTokensResponse {},
        Err(msg) => panic!("{}", msg),
    }
}

/// See `Sale.refresh_buyer_token_e8`.
#[export_name = "canister_update refresh_buyer_tokens"]
fn refresh_buyer_tokens() {
    over_async(candid_one, refresh_buyer_tokens_)
}

/// See `Sale.refresh_buyer_token_e8`.
#[candid_method(update, rename = "refresh_buyer_tokens")]
async fn refresh_buyer_tokens_(arg: RefreshBuyerTokensRequest) -> RefreshBuyerTokensResponse {
    println!("{}refresh_buyer_tokens", LOG_PREFIX);
    let p: PrincipalId = if arg.buyer.is_empty() {
        caller()
    } else {
        PrincipalId::from_str(&arg.buyer).unwrap()
    };
    let ledger_factory = &create_real_ledger;
    match sale_mut()
        .refresh_buyer_token_e8s(p, id(), ledger_factory)
        .await
    {
        Ok(()) => RefreshBuyerTokensResponse {},
        Err(msg) => panic!("{}", msg),
    }
}

struct RealSnsGovernanceClient {
    canister_id: CanisterId,
}

impl RealSnsGovernanceClient {
    fn new(canister_id: CanisterId) -> Self {
        Self { canister_id }
    }
}

#[async_trait]
impl SnsGovernanceClient for RealSnsGovernanceClient {
    async fn manage_neuron(
        &mut self,
        request: ManageNeuron,
    ) -> Result<ManageNeuronResponse, CanisterCallError> {
        dfn_core::api::call(
            self.canister_id,
            "manage_neuron",
            dfn_candid::candid_one,
            request,
        )
        .await
        .map_err(CanisterCallError::from)
    }

    async fn set_mode(&mut self, request: SetMode) -> Result<SetModeResponse, CanisterCallError> {
        // TODO: Eliminate repetitive code. At least textually, the only
        // difference is the second argument that gets passed to
        // dfn_core::api::call (the name of the method).
        dfn_core::api::call(
            self.canister_id,
            "set_mode",
            dfn_candid::candid_one,
            request,
        )
        .await
        .map_err(CanisterCallError::from)
    }
}

/// See Sale.finalize.
#[export_name = "canister_update finalize_sale"]
fn finalize_sale() {
    over_async(candid_one, finalize_sale_)
}

/// See Sale.finalize.
#[candid_method(update, rename = "finalize_sale")]
async fn finalize_sale_(_arg: FinalizeSaleRequest) -> FinalizeSaleResponse {
    // Helpers.
    let mut sns_governance_client = RealSnsGovernanceClient::new(sale().init().sns_governance());
    let ledger_factory = create_real_ledger;

    sale_mut()
        .finalize(&mut sns_governance_client, ledger_factory)
        .await
}

trait Ic0 {
    fn canister_cycle_balance(&self) -> u64;
}

struct ProdIc0 {}

impl ProdIc0 {
    fn new() -> Self {
        Self {}
    }
}

impl Ic0 for ProdIc0 {
    fn canister_cycle_balance(&self) -> u64 {
        dfn_core::api::canister_cycle_balance()
    }
}

#[export_name = "canister_query get_canister_status"]
fn get_canister_status() {
    over(candid_one, get_canister_status_)
}

#[candid_method(update, rename = "get_canister_status")]
fn get_canister_status_(request: GetCanisterStatusRequest) -> GetCanisterStatusResponse {
    do_get_canister_status(request, &ProdIc0::new())
}

fn do_get_canister_status(
    _request: GetCanisterStatusRequest,
    ic0: &impl Ic0,
) -> GetCanisterStatusResponse {
    GetCanisterStatusResponse {
        canister_cycle_balance: ic0.canister_cycle_balance(),
    }
}

// =============================================================================
// ===               Canister helper & boilerplate methods                   ===
// =============================================================================

#[export_name = "canister_heartbeat"]
fn canister_heartbeat() {
    let now = now_seconds();
    if sale_mut().try_commit_or_abort(now) {
        println!("{}Sale committed/aborted at timestamp {}", LOG_PREFIX, now);
    }
}

fn now_seconds() -> u64 {
    now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Returns a function that (when passed the canister ID of a presumptive
/// Ledger) returns a Ledger implementation suitable for use in
/// production. I.e. calls out to another canister.
///
/// This function is a "Ledger factory" in that you call this, and a Ledger
/// object is returned. What distinguishes this from other possible Ledger
/// factories is that this produces objects that are suitable for use in
/// production.
fn create_real_ledger(id: CanisterId) -> Box<dyn Ledger> {
    Box::new(LedgerCanister::new(id))
}

#[export_name = "canister_init"]
fn canister_init() {
    over_init(|CandidOne(arg)| canister_init_(arg))
}

/// In contrast to canister_init(), this method does not do deserialization.
#[candid_method(init)]
fn canister_init_(init_payload: Init) {
    dfn_core::printer::hook();
    let sale = Sale::new(init_payload);
    unsafe {
        assert!(
            SALE.is_none(),
            "{}Trying to initialize an already initialized canister!",
            LOG_PREFIX
        );
        SALE = Some(sale);
    }
    println!("{}Initialized", LOG_PREFIX);
}

/// Serialize and write the state to stable memory so that it is
/// preserved during the upgrade and can be deserialised again in
/// `canister_post_upgrade`.
#[export_name = "canister_pre_upgrade"]
fn canister_pre_upgrade() {
    println!("{}Executing pre upgrade", LOG_PREFIX);
    let mut writer = BufferedStableMemWriter::new(STABLE_MEM_BUFFER_SIZE);
    sale()
        .encode(&mut writer)
        .expect("Error. Couldn't serialize canister pre-upgrade.");
    writer.flush();
}

/// Deserialise what has been written to stable memory in
/// canister_pre_upgrade and initialising the state with it.
#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
    println!("{}Executing post upgrade", LOG_PREFIX);
    let reader = BufferedStableMemReader::new(STABLE_MEM_BUFFER_SIZE);
    match Sale::decode(reader) {
        Err(err) => {
            panic!(
                "{}Error deserializing canister state post-upgrade. \
		 CANISTER HAS BROKEN STATE!!!!. Error: {:?}",
                LOG_PREFIX, err
            );
        }
        Ok(proto) => unsafe {
            assert!(
                SALE.is_none(),
                "{}Trying to post-upgrade an already initialized canister!",
                LOG_PREFIX
            );
            SALE = Some(proto);
        },
    }
}

/// When run on native, this prints the candid service definition of this
/// canister, from the methods annotated with `candid_method` above.
///
/// Note that `cargo test` calls `main`, and `export_service` (which defines
/// `__export_service` in the current scope) needs to be called exactly once. So
/// in addition to `not(target_arch = "wasm32")` we have a `not(test)` guard here
/// to avoid calling `export_service` in tests.
#[cfg(not(any(target_arch = "wasm32", test)))]
fn main() {
    // The line below generates did types and service definition from the
    // methods annotated with `candid_method` above. The definition is then
    // obtained with `__export_service()`.
    candid::export_service!();
    std::print!("{}", __export_service());
}

/// Empty main for test target.
#[cfg(any(target_arch = "wasm32", test))]
fn main() {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test that fails if the API was updated but the candid definition was not.
    #[test]
    fn check_sale_candid_file() {
        let governance_did =
            String::from_utf8(std::fs::read("canister/sale.did").unwrap()).unwrap();

        // See comments in main above
        candid::export_service!();
        let expected = __export_service();

        if governance_did != expected {
            panic!(
                "Generated candid definition does not match canister/sale.did. \
                 Run `cargo run --bin sns-sale-canister > canister/sale.did` in \
                 rs/sns/sale to update canister/sale.did."
            )
        }
    }

    struct StubIc0 {}

    impl Ic0 for StubIc0 {
        fn canister_cycle_balance(&self) -> u64 {
            42
        }
    }

    #[test]
    fn test_get_canister_status() {
        let response = do_get_canister_status(GetCanisterStatusRequest {}, &StubIc0 {});
        assert_eq!(
            response,
            GetCanisterStatusResponse {
                canister_cycle_balance: 42
            }
        );
    }
}
