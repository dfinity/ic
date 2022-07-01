use candid::candid_method;
use ic_base_types::PrincipalId;
use ic_cdk::api::stable::{StableReader, StableWriter};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_icrc1::{Account, ApprovalId, Transaction};
use ic_icrc1_ledger::{
    endpoints::{
        ApprovalDetails, ApproveTransferArg, ApproveTransferError, ArchiveInfo, CommitTransferArg,
        CommitTransferError, RevokeApprovalError, TransferArg, TransferError, Value,
    },
    InitArgs, Ledger,
};
use ic_ledger_core::{
    block::BlockHeight,
    ledger::{apply_transaction, archive_blocks, LedgerAccess, LedgerData, LedgerTransaction},
    timestamp::TimeStamp,
    tokens::Tokens,
};
use std::cell::RefCell;

const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

thread_local! {
    static LEDGER: RefCell<Option<Ledger>> = RefCell::new(None);
}

struct Access;
impl LedgerAccess for Access {
    type Ledger = Ledger;

    fn with_ledger<R>(f: impl FnOnce(&Ledger) -> R) -> R {
        LEDGER.with(|cell| {
            f(cell
                .borrow()
                .as_ref()
                .expect("ledger state not initialized"))
        })
    }

    fn with_ledger_mut<R>(f: impl FnOnce(&mut Ledger) -> R) -> R {
        LEDGER.with(|cell| {
            f(cell
                .borrow_mut()
                .as_mut()
                .expect("ledger state not initialized"))
        })
    }
}

#[init]
fn init(args: InitArgs) {
    let now = TimeStamp::from_nanos_since_unix_epoch(ic_cdk::api::time());
    LEDGER.with(|cell| *cell.borrow_mut() = Some(Ledger::from_init_args(args, now)))
}

#[pre_upgrade]
fn pre_upgrade() {
    Access::with_ledger(|ledger| ciborium::ser::into_writer(ledger, StableWriter::default()))
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
fn icrc1_name() -> String {
    Access::with_ledger(|ledger| ledger.token_name().to_string())
}

#[query]
#[candid_method(query)]
fn icrc1_symbol() -> String {
    Access::with_ledger(|ledger| ledger.token_symbol().to_string())
}

#[query]
#[candid_method(query)]
fn icrc1_decimals() -> u32 {
    ic_ledger_core::tokens::DECIMAL_PLACES
}

#[query]
#[candid_method(query)]
fn icrc1_metadata() -> Vec<(String, Value)> {
    Access::with_ledger(|ledger| ledger.metadata())
}

#[query(name = "icrc1_balanceOf")]
#[candid_method(query, rename = "icrc1_balanceOf")]
fn icrc1_balance_of(account: Account) -> u64 {
    Access::with_ledger(|ledger| ledger.balances().account_balance(&account).get_e8s())
}

#[update]
#[candid_method(update)]
async fn icrc1_transfer(arg: TransferArg) -> Result<BlockHeight, TransferError> {
    let block_idx = Access::with_ledger_mut(|ledger| {
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
            let balance = ledger.balances().account_balance(&from_account);
            let min_burn_amount = ledger.transfer_fee().min(balance);
            if amount < min_burn_amount {
                return Err(TransferError::BadBurn {
                    min_burn_amount: min_burn_amount.get_e8s(),
                });
            }
            if amount == Tokens::ZERO {
                return Err(TransferError::BadBurn {
                    min_burn_amount: ledger.transfer_fee().get_e8s(),
                });
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

        let (block_idx, _) = apply_transaction(ledger, tx, now)?;
        Ok(block_idx)
    })?;

    // NB. we need to set the certified data before the first async call to make sure that the
    // blockchain state agrees with the certificate while archiving is in progress.
    ic_cdk::api::set_certified_data(&Access::with_ledger(Ledger::root_hash));

    archive_blocks::<Access>(MAX_MESSAGE_SIZE).await;
    Ok(block_idx)
}

#[update(name = "icrc1_approveTransfer")]
#[candid_method(update, rename = "icrc1_approveTransfer")]
fn icrc1_approve_transfer(_arg: ApproveTransferArg) -> Result<ApprovalId, ApproveTransferError> {
    unimplemented!()
}

#[query]
#[candid_method(query)]
fn icrc1_allowance(_approval_id: ApprovalId) -> Option<ApprovalDetails> {
    unimplemented!()
}

#[update(name = "icrc1_commitTransfer")]
#[candid_method(update, rename = "icrc1_commitTransfer")]
fn icrc1_commit_transfer(_arg: CommitTransferArg) -> Result<BlockHeight, CommitTransferError> {
    unimplemented!()
}

#[update(name = "icrc1_revokeApproval")]
#[candid_method(update, rename = "icrc1_revokeApproval")]
fn icrc1_revoke_approval(_approval_id: ApprovalId) -> Result<BlockHeight, RevokeApprovalError> {
    unimplemented!()
}

#[query]
fn archives() -> Vec<ArchiveInfo> {
    Access::with_ledger(|ledger| {
        ledger
            .blockchain()
            .archive
            .read()
            .unwrap()
            .as_ref()
            .iter()
            .flat_map(|archive| {
                archive
                    .index()
                    .into_iter()
                    .map(|((start, end), canister_id)| ArchiveInfo {
                        canister_id,
                        block_range_start: start,
                        block_range_end: end,
                    })
            })
            .collect()
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
