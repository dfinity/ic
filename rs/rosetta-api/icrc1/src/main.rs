use candid::candid_method;
use ic_cdk::api::stable::{StableReader, StableWriter};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query};
use ic_ledger_core::ledger::LedgerData;
use ic_ledger_icrc1::{InitArgs, Ledger};
use std::cell::RefCell;

thread_local! {
    static LEDGER: RefCell<Option<Ledger>> = RefCell::new(None);
}

fn with_ledger<F, R>(f: F) -> R
where
    F: FnOnce(&Ledger) -> R,
{
    LEDGER.with(|cell| {
        f(cell
            .borrow()
            .as_ref()
            .expect("ledger state not initialized"))
    })
}

#[init]
fn init(args: InitArgs) {
    LEDGER.with(|cell| *cell.borrow_mut() = Some(Ledger::from_init_args(args)))
}

#[pre_upgrade]
fn pre_upgrade() {
    with_ledger(|ledger| ciborium::ser::into_writer(ledger, StableWriter::default()))
        .expect("failed to encode ledger state");
}

#[post_upgrade]
fn post_upgrade() {
    LEDGER.with(|cell| {
        *cell.borrow_mut() = Some(
            ciborium::de::from_reader(StableReader::default())
                .expect("failed to decode ledger state"),
        );
    })
}

#[query]
#[candid_method(query)]
fn icrc1_symbol() -> String {
    with_ledger(|ledger| ledger.token_symbol().to_string())
}

#[query]
#[candid_method(query)]
fn icrc1_name() -> String {
    with_ledger(|ledger| ledger.token_name().to_string())
}

fn main() {}

#[test]
fn check_candid_interface() {
    use candid::utils::{service_compatible, CandidSource};
    use std::path::PathBuf;

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("icrc1.did");

    service_compatible(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .expect("the ledger interface is not compatible with icrc1.did");
}
