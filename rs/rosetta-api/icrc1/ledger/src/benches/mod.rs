use crate::{execute_transfer_not_async, post_upgrade, pre_upgrade, Access, Tokens};
use assert_matches::assert_matches;
use candid::{Nat, Principal};
use ic_canister_log::Sink;
use ic_ledger_canister_core::ledger::{
    blocks_to_archive, remove_archived_blocks, LedgerAccess, LedgerContext,
};
use ic_ledger_core::block::BlockIndex;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;

#[cfg(feature = "u256-tokens")]
mod benches_u256;
#[cfg(not(feature = "u256-tokens"))]
mod benches_u64;

pub const NUM_TRANSFERS: u32 = 10_000;

pub fn upgrade() {
    let _p = canbench_rs::bench_scope("upgrade");
    pre_upgrade();
    post_upgrade(None);
}

pub fn icrc1_transfer(
    from: Principal,
    arg: TransferArg,
) -> Result<BlockIndex, ic_ledger_canister_core::ledger::TransferError<Tokens>> {
    let from_account = Account {
        owner: from,
        subaccount: arg.from_subaccount,
    };
    execute_transfer_not_async(
        from_account,
        arg.to,
        None,
        arg.fee,
        arg.amount,
        arg.memo,
        arg.created_at_time,
    )
}

fn assert_has_num_balances(num_balances: u32) {
    Access::with_ledger(|ledger| {
        assert_eq!(ledger.balances().store.len() as u32, num_balances);
    });
}

pub fn max_length_principal(index: u32) -> Principal {
    const MAX_PRINCIPAL: [u8; 29] = [1_u8; 29];
    let mut principal = MAX_PRINCIPAL;
    for (i, byte) in index.to_be_bytes().iter().enumerate() {
        principal[i] = *byte;
    }
    Principal::from_slice(&principal)
}

fn mint_tokens<T: Into<Nat>>(minter: Principal, amount: T) -> Account {
    let account_with_tokens = Account {
        owner: max_length_principal(u32::MAX),
        subaccount: Some([255_u8; 32]),
    };
    assert_matches!(
        icrc1_transfer(
            minter,
            TransferArg {
                from_subaccount: None,
                to: account_with_tokens,
                fee: None,
                created_at_time: None,
                memo: None,
                amount: amount.into(),
            },
        ),
        Ok(_)
    );
    account_with_tokens
}

pub fn emulate_archive_blocks<LA: LedgerAccess>(sink: impl Sink + Clone) {
    use ic_ledger_canister_core::archive::ArchivingGuardError;

    let (archiving_guard, blocks_to_archive) = match blocks_to_archive::<LA>(&sink) {
        Ok((guard, blocks)) => (guard, blocks),
        Err(ArchivingGuardError::NoArchive) => {
            return; // Archiving not enabled
        }
        Err(ArchivingGuardError::AlreadyArchiving) => {
            return; // Ledger is currently archiving, skipping archive_blocks.
        }
    };

    if blocks_to_archive.is_empty() {
        return;
    }

    let num_blocks = blocks_to_archive.len();
    remove_archived_blocks::<LA>(archiving_guard, num_blocks, &sink, Ok(num_blocks))
}
