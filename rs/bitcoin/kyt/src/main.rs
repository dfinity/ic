use bitcoin::Address;
use ic_btc_interface::Txid;
use ic_btc_kyt::{
    blocklist_contains, check_transaction_inputs, dashboard, get_config, set_config,
    CheckAddressArgs, CheckAddressResponse, CheckTransactionArgs,
    CheckTransactionIrrecoverableError, CheckTransactionResponse, CheckTransactionStatus, Config,
    KytArg, CHECK_TRANSACTION_CYCLES_REQUIRED, CHECK_TRANSACTION_CYCLES_SERVICE_FEE,
};
use ic_canisters_http_types as http;
use ic_cdk::api::management_canister::http_request::{HttpResponse, TransformArgs};
use std::str::FromStr;

#[ic_cdk::query]
/// Return `Passed` if the given bitcion address passed the KYT check, or
/// `Failed` otherwise.
/// May throw error (trap) if the given address is malformed or not a mainnet address.
fn check_address(args: CheckAddressArgs) -> CheckAddressResponse {
    let btc_network = get_config().btc_network;
    let address = Address::from_str(args.address.trim())
        .unwrap_or_else(|err| ic_cdk::trap(&format!("Invalid bitcoin address: {}", err)))
        .require_network(btc_network.into())
        .unwrap_or_else(|err| {
            ic_cdk::trap(&format!("Not a bitcoin {} address: {}", btc_network, err))
        });

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
/// Every call to check_transaction must attach at least `CHECK_TRANSACTION_CYCLES_REQUIRED`.
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
            if ic_cdk::api::call::msg_cycles_available128()
                .checked_add(CHECK_TRANSACTION_CYCLES_SERVICE_FEE)
                .unwrap()
                < CHECK_TRANSACTION_CYCLES_REQUIRED
            {
                CheckTransactionStatus::NotEnoughCycles.into()
            } else {
                check_transaction_inputs(txid).await
            }
        }
        Err(err) => CheckTransactionIrrecoverableError::InvalidTransaction(err.to_string()).into(),
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

#[ic_cdk::init]
fn init(arg: KytArg) {
    match arg {
        KytArg::InitArg(init_arg) => set_config(Config {
            btc_network: init_arg.btc_network,
        }),
        KytArg::UpgradeArg(_) => {
            ic_cdk::trap("cannot init canister state without init args");
        }
    }
}

#[ic_cdk::post_upgrade]
fn post_upgrade(arg: KytArg) {
    match arg {
        KytArg::UpgradeArg(_) => (),
        KytArg::InitArg(_) => ic_cdk::trap("cannot upgrade canister state without upgrade args"),
    }
}

#[ic_cdk::query(hidden = true)]
fn http_request(req: http::HttpRequest) -> http::HttpResponse {
    if req.path() == "/metrics" {
        // TODO(XC-205): Add metrics
        unimplemented!()
    } else if req.path() == "/dashboard" {
        use askama::Template;
        let dashboard = dashboard::dashboard().render().unwrap();
        http::HttpResponseBuilder::ok()
            .header("Content-Type", "text/html; charset=utf-8")
            .with_body_and_content_length(dashboard)
            .build()
    } else {
        http::HttpResponseBuilder::not_found().build()
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
        CandidSource::Text(dbg!(&new_interface)),
        CandidSource::File(old_interface.as_path()),
    )
    .unwrap();
}
