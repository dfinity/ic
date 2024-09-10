use bitcoin::{Address, Network};
use ic_btc_interface::Txid;
use ic_btc_kyt::{
    blocklist_contains, check_transaction_inputs, CheckAddressArgs, CheckAddressResponse,
    CheckTransactionArgs, CheckTransactionResponse, CHECK_TRANSACTION_CYCLES_REQUIRED,
    CHECK_TRANSACTION_CYCLES_SERVICE_FEE,
};
use ic_cdk::api::management_canister::http_request::{HttpResponse, TransformArgs};
use std::str::FromStr;

#[ic_cdk::query]
/// Return `Passed` if the given bitcion address passed the KYT check, or
/// `Failed` otherwise.
/// May throw error (trap) if the given address is malformed or not a mainnet address.
fn check_address(args: CheckAddressArgs) -> CheckAddressResponse {
    let address = Address::from_str(args.address.trim())
        .unwrap_or_else(|err| ic_cdk::trap(&format!("Invalid bitcoin address: {}", err)))
        .require_network(Network::Bitcoin)
        .unwrap_or_else(|err| ic_cdk::trap(&format!("Not a bitcoin mainnet address: {}", err)));

    if blocklist_contains(&address) {
        CheckAddressResponse::Failed
    } else {
        CheckAddressResponse::Passed
    }
}

#[ic_cdk::update]
/// Return `Passed` if all input addresses of the transaction of the given
/// transaction id passed the KYT check, or `Failed` if any of them did not.
///
/// Every call to check_transaction must attach at least `CHECK_TRANSACTION_CYCLES_REQUIRED`
/// Return `NotEnoughCycles` if not enough cycles are attached.
///
/// The actual cycle cost may be well less than `CHECK_TRANSACTION_CYCLES_REQUIRED`, and
/// unspent cycles will be refunded back to the caller, minus a
/// `CHECK_TRANSACTION_CYCLES_SERVICE_FEE`, which is always deducted regardless.
///
/// In certain cases, it may also return `HighLoad` or `Pending` to indicate the
/// caller needs to call again (with at least `CHECK_TRANSACTION_CYCLES_REQUIRED` cycles)
/// in order to get the result.
///
/// If a permanent error occurred in the process, e.g, when a transaction data
/// fails to decode or its transaction id does not match, then `Error` is returned
/// together with a text description.
async fn check_transaction(args: CheckTransactionArgs) -> CheckTransactionResponse {
    ic_cdk::api::call::msg_cycles_accept128(CHECK_TRANSACTION_CYCLES_SERVICE_FEE);
    match Txid::try_from(args.txid.as_ref()) {
        Ok(txid) => {
            if ic_cdk::api::call::msg_cycles_available128() + CHECK_TRANSACTION_CYCLES_SERVICE_FEE
                < CHECK_TRANSACTION_CYCLES_REQUIRED
            {
                CheckTransactionResponse::NotEnoughCycles
            } else {
                check_transaction_inputs(txid).await
            }
        }
        Err(err) => CheckTransactionResponse::Error(format!("Invalid txid: {}", err)),
    }
}

#[ic_cdk::query(hidden = true)]
fn transform(raw: TransformArgs) -> HttpResponse {
    HttpResponse {
        status: raw.response.status.clone(),
        body: raw.response.body.clone(),
        headers: vec![],
    }
}

fn main() {}

#[test]
fn check_candid_interface_compatibility() {
    use candid_parser::utils::{service_equal, CandidSource};

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("btc_kyt_canister.did");

    service_equal(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .unwrap();
}
