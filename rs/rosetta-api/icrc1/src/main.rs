use candid::candid_method;
use ic_base_types::PrincipalId;
use ic_cdk::api::stable::{StableReader, StableWriter};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_ledger_core::{
    block::BlockHeight,
    ledger::{apply_transaction, LedgerData, LedgerTransaction},
    timestamp::TimeStamp,
    tokens::Tokens,
};
use ic_ledger_icrc1::{
    endpoints::{TransferArg, TransferError},
    Account, InitArgs, Ledger, Transaction,
};
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

fn with_ledger_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut Ledger) -> R,
{
    LEDGER.with(|cell| {
        f(cell
            .borrow_mut()
            .as_mut()
            .expect("ledger state not initialized"))
    })
}

#[init]
fn init(args: InitArgs) {
    let now = TimeStamp::from_nanos_since_unix_epoch(ic_cdk::api::time());
    LEDGER.with(|cell| *cell.borrow_mut() = Some(Ledger::from_init_args(args, now)))
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

#[query(name = "icrc1_balanceOf")]
#[candid_method(query, rename = "icrc1_balanceOf")]
fn icrc1_balance_of(account: Account) -> u64 {
    with_ledger(|ledger| ledger.balances().account_balance(&account).get_e8s())
}

#[update]
#[candid_method(update)]
fn icrc1_transfer(arg: TransferArg) -> Result<BlockHeight, TransferError> {
    with_ledger_mut(|ledger| {
        let now = TimeStamp::from_nanos_since_unix_epoch(ic_cdk::api::time());
        let from_account = Account {
            of: PrincipalId::from(ic_cdk::api::caller()),
            subaccount: arg.from_subaccount,
        };
        let to_account = arg.to_account();
        let amount = Tokens::from_e8s(arg.amount);
        let fee = arg.fee.map(Tokens::from_e8s);

        let tx = if &to_account == ledger.minting_account() {
            if fee.is_some() && fee != Some(Tokens::ZERO) {
                return Err(TransferError::BadFee { expected_fee: 0 });
            }
            Transaction::burn(from_account, amount, now)
        } else if &from_account == ledger.minting_account() {
            if fee.is_some() && fee != Some(Tokens::ZERO) {
                return Err(TransferError::BadFee { expected_fee: 0 });
            }
            Transaction::mint(to_account, amount, now)
        } else {
            let expected_fee = ledger.transfer_fee();
            if fee.is_some() && fee != Some(expected_fee) {
                return Err(TransferError::BadFee {
                    expected_fee: expected_fee.get_e8s(),
                });
            }
            Transaction::transfer(from_account, to_account, amount, expected_fee, now)
        };

        // TODO(ROSETTA1-304): certify tip
        let (block_idx, _hash) = apply_transaction(ledger, tx, now)?;
        Ok(block_idx)
    })
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
