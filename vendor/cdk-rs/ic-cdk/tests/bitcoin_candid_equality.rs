//! This test checks that the generated candid interface is equal to the one in the bitcoin.did file.
//!
//! The bitcoin.did file comes from https://github.com/dfinity/bitcoin-canister/blob/master/canister/candid.did
//!
//! Following items in bitcoin.did are commented out because they are not implemented in the bitcoin_canister module:
//! - The init args `(init_config)`.
//! - The `*_query` methods. Calling them from inter-canister calls would result in "<_query> cannot be called in replicated mode" rejection.
//! - The `get_config` and `set_config` methods.

#![allow(unused)]
use candid::candid_method;
use ic_cdk::bitcoin_canister::*;

#[candid_method(update)]
fn bitcoin_get_balance(_: GetBalanceRequest) -> Satoshi {
    unimplemented!()
}

#[candid_method(update)]
fn bitcoin_get_utxos(_: GetUtxosRequest) -> GetUtxosResponse {
    unimplemented!()
}

#[candid_method(update)]
fn bitcoin_get_current_fee_percentiles(
    _: GetCurrentFeePercentilesRequest,
) -> Vec<MillisatoshiPerByte> {
    unimplemented!()
}

#[candid_method(update)]
fn bitcoin_get_block_headers(_: GetBlockHeadersRequest) -> GetBlockHeadersResponse {
    unimplemented!()
}

#[candid_method(update)]
fn bitcoin_send_transaction(_: SendTransactionRequest) {
    unimplemented!()
}

#[cfg(test)]
mod test {
    use candid_parser::utils::{CandidSource, service_equal};
    use ic_cdk::bitcoin_canister::*;

    #[test]
    fn candid_equality_test() {
        let declared_interface_str =
            std::fs::read_to_string("tests/bitcoin.did").expect("failed to read bitcoin.did file");
        let declared_interface = CandidSource::Text(&declared_interface_str);

        candid::export_service!();
        let implemented_interface_str = __export_service();
        let implemented_interface = CandidSource::Text(&implemented_interface_str);

        let result = service_equal(declared_interface, implemented_interface);
        assert!(result.is_ok(), "{:?}", result.unwrap_err());
    }
}
