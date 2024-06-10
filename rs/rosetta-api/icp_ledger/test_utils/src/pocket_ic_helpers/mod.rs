use candid::{CandidType, Decode, Encode, Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_nns_constants::ALL_NNS_CANISTER_IDS;
use pocket_ic::{CanisterSettings, PocketIc, WasmResult};
use serde::Deserialize;

pub mod index;
pub mod ledger;

const STARTING_CYCLES_PER_CANISTER: u128 = 2_000_000_000_000_000;

pub fn install_canister(
    pocket_ic: &PocketIc,
    name: &str,
    canister_id: CanisterId,
    arg: Vec<u8>,
    wasm_bytes: Vec<u8>,
    controller: Option<PrincipalId>,
) {
    let controller_principal = controller.map(|c| c.0);
    let memory_allocation = if ALL_NNS_CANISTER_IDS.contains(&&canister_id) {
        let memory_allocation_bytes = ic_nns_constants::memory_allocation_of(canister_id);
        Some(Nat::from(memory_allocation_bytes))
    } else {
        None
    };
    let settings = Some(CanisterSettings {
        memory_allocation,
        ..Default::default()
    });
    let canister_id = pocket_ic
        .create_canister_with_id(controller_principal, settings, canister_id.into())
        .unwrap();
    pocket_ic.install_canister(canister_id, wasm_bytes, arg, controller_principal);
    pocket_ic.add_cycles(canister_id, STARTING_CYCLES_PER_CANISTER);
    let subnet_id = pocket_ic.get_subnet(canister_id).unwrap();
    println!(
        "Installed the {} canister ({}) onto {}",
        name, canister_id, subnet_id
    );
}

// Panics if the canister is unreachable or it has rejected the query.
fn query_or_panic<I, O>(
    pocket_ic: &PocketIc,
    canister_id: Principal,
    caller: Principal,
    method: &str,
    arg: I,
) -> O
where
    I: CandidType,
    O: CandidType + for<'a> Deserialize<'a>,
{
    let arg = Encode!(&arg).unwrap();
    match pocket_ic.query_call(canister_id, caller, method, arg) {
        Err(err) => {
            panic!("{canister_id}.{method} query failed with error {err} (caller: {caller})");
        }
        Ok(WasmResult::Reject(err)) => {
            panic!("{canister_id}.{method} query rejected with error {err} (caller: {caller})");
        }
        Ok(WasmResult::Reply(res)) => Decode!(&res, O)
            .unwrap_or_else(|_| panic!("error decoding response to {} query", method)),
    }
}

// Panics if the canister is unreachable or it has rejected the update.
fn update_or_panic<I, O>(
    pocket_ic: &PocketIc,
    canister_id: Principal,
    caller: Principal,
    method: &str,
    arg: I,
) -> O
where
    I: CandidType,
    O: CandidType + for<'a> Deserialize<'a>,
{
    let arg = Encode!(&arg).unwrap();
    match pocket_ic.update_call(canister_id, caller, method, arg) {
        Err(err) => {
            panic!("{canister_id}.{method} failed with error {err} (caller: {caller})");
        }
        Ok(WasmResult::Reject(err)) => {
            panic!("{canister_id}.{method} rejected with error {err} (caller: {caller})");
        }
        Ok(WasmResult::Reply(res)) => Decode!(&res, O)
            .unwrap_or_else(|_| panic!("error decoding response to {} call", method)),
    }
}
