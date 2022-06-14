use bitcoin::AddressType;
use candid::{CandidType, Deserialize};
use ic_base_types::ic_types::Principal;
use ic_ckbtc_minter::runtime::Runtime;
use ic_ledger_types::{Subaccount, DEFAULT_SUBACCOUNT};
use serde::Serialize;

const SCHEMA_V1: u8 = 1;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct GetBtcAddressArgs {
    pub subaccount: Option<Subaccount>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct GetBtcAddressResult {
    pub address: String,
}

/// Return a valid BIP-32 derivation path from an account id (Principal + subaccount)
///
/// See [`derivation_path_schema()`] for the possible panics.
fn account_derivation_path(principal: Principal, subaccount: Option<Subaccount>) -> Vec<Vec<u8>> {
    let bytes = derivation_path_schema(principal, subaccount);
    ic_btc_library::address_management::get_derivation_path(&bytes)
}

/// Return a blob containing principal and subaccount.
///
/// Panics if the principal or the subaccount is not valid and if their length in bytes
/// is greater than or equal to 2^8 because we use only one byte to store the length.
fn derivation_path_schema(principal: Principal, subaccount: Option<Subaccount>) -> Vec<u8> {
    // The schema is the following:
    // * 1 byte to represent the version of the schema to support future changes
    // * 1 byte to store the length of principal
    // * the principal bytes
    // * 1 byte to store the length of subaccount
    // * the subaccount bytes
    let principal = principal.as_slice();
    if principal.len() >= 256 {
        panic!("principal.len() >= 256");
    }
    let subaccount = subaccount.unwrap_or(DEFAULT_SUBACCOUNT).0;
    let mut bytes = Vec::with_capacity(3 + principal.len() + subaccount.len());
    bytes.push(SCHEMA_V1); // version
    bytes.push(principal.len() as u8);
    bytes.extend_from_slice(principal);
    bytes.push(subaccount.len() as u8);
    bytes.extend_from_slice(&subaccount);
    bytes
}

pub fn get_btc_address(args: GetBtcAddressArgs, runtime: &dyn Runtime) -> GetBtcAddressResult {
    let caller = runtime.caller();
    let derivation_path = account_derivation_path(caller, args.subaccount);
    let address = runtime.address(derivation_path, &AddressType::P2pkh);
    GetBtcAddressResult { address }
}
