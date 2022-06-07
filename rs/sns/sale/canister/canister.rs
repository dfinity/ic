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
use ic_sns_sale::pb::v1::{
    FinalizeSaleRequest, FinalizeSaleResponse, GetStateRequest, GetStateResponse, Init, Lifecycle,
    OpenSaleRequest, OpenSaleResponse, RefreshBuyerTokensRequest, RefreshBuyerTokensResponse,
    RefreshSnsTokensRequest, RefreshSnsTokensResponse, Sale, SweepResult,
};
use ic_sns_sale::sale::LOG_PREFIX;
use ledger_canister::DEFAULT_TRANSFER_FEE;

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
    match sale_mut().refresh_sns_token_e8s(id(), &ledger_stub()).await {
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
    match sale_mut()
        .refresh_buyer_token_e8s(p, id(), &ledger_stub())
        .await
    {
        Ok(()) => RefreshBuyerTokensResponse {},
        Err(msg) => panic!("{}", msg),
    }
}

#[export_name = "canister_update finalize_sale"]
fn finalize_sale() {
    over_async(candid_one, finalize_sale_)
}

/// TODO: Actually try to create neurons.
#[candid_method(update, rename = "finalize_sale")]
async fn finalize_sale_(_arg: FinalizeSaleRequest) -> FinalizeSaleResponse {
    let lifecycle = sale().state().lifecycle();
    assert!(
        lifecycle == Lifecycle::Committed || lifecycle == Lifecycle::Aborted,
        "Sale can only be finalized in the committed or aborted states - was {:?}",
        lifecycle
    );
    let sweep_icp = Some(
        sale_mut()
            .sweep_icp(DEFAULT_TRANSFER_FEE, &ledger_stub())
            .await,
    );
    if lifecycle != Lifecycle::Committed {
        return FinalizeSaleResponse {
            sweep_icp,
            sweep_sns: None,
            create_neuron: None,
        };
    }
    let sweep_sns = Some(
        sale_mut()
            .sweep_sns(DEFAULT_TRANSFER_FEE, &ledger_stub())
            .await,
    );
    let (skipped, ps) = sale().principals_for_create_neuron();
    let mut failure = 0;
    for p in ps {
        // TODO: Is there an interface akin to `Ledger` for SNS Governance?
        println!("TODO: create neuron for {}", p);
        failure += 1;
    }
    FinalizeSaleResponse {
        sweep_icp,
        sweep_sns,
        create_neuron: Some(SweepResult {
            success: 0,
            failure,
            skipped,
        }),
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

fn ledger_stub() -> impl Fn(CanisterId) -> Box<dyn Ledger> {
    |x| Box::new(LedgerCanister::new(x))
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
