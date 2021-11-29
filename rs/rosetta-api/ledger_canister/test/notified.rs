use dfn_candid::{candid, candid_one};
use dfn_core::println;
use dfn_core::{
    api::{call_bytes, call_bytes_with_cleanup, id, Funds},
    endpoint::over_bytes,
    over, over_async, over_may_reject,
};
use dfn_protobuf::protobuf;
use ic_base_types::PrincipalId;
use lazy_static::lazy_static;
use ledger_canister::{Memo, Tokens, TransactionNotification};
use std::sync::RwLock;

// This is a canister that gets notified
lazy_static! {
    static ref COUNTER: RwLock<u32> = RwLock::new(0);

    // For the call tests
    pub static ref DIRTY_LOCK: RwLock<()> = RwLock::new(());
    pub static ref CLEAN_LOCK: RwLock<()> = RwLock::new(());
}

#[export_name = "canister_update transaction_notification_pb"]
fn transaction_notification_pb_() {
    over_may_reject(protobuf, transaction_notification)
}

#[export_name = "canister_update transaction_notification"]
fn transaction_notification_() {
    over_may_reject(candid_one, transaction_notification)
}

fn transaction_notification(tn: TransactionNotification) -> Result<(), String> {
    let count = *COUNTER.read().unwrap();
    let res = match count {
        0 => {
            println!("Rejecting");
            Err("Rejected".to_string())
        }
        // Succeeds
        1 => Ok(()),
        _ => Err("This should not be called a third time".to_string()),
    };
    let expected_tn = TransactionNotification {
        from_subaccount: None,
        from: PrincipalId::new_anonymous(),
        to_subaccount: None,
        amount: Tokens::from_tokens(1).unwrap(),
        memo: Memo(0),
        block_height: 3,
        to: id(),
    };

    // Cause the test to fail
    if tn != expected_tn {
        *COUNTER.write().unwrap() = 99;
    }

    *COUNTER.write().unwrap() = count.checked_add(1).unwrap();
    res
}

#[export_name = "canister_query check_counter"]
fn check_counter_() {
    fn check_counter() -> u32 {
        *COUNTER.read().unwrap()
    }
    over(candid, |()| check_counter())
}

fn main() {}

#[export_name = "canister_update do_nothing"]
fn do_nothing() {
    over_bytes(|_| Vec::new())
}

// This checks that call with cleanup actually releases the lock after panic
#[export_name = "canister_update dirty_call"]
fn dirty_call_() {
    async fn dirty_call() {
        let l = match DIRTY_LOCK.try_write() {
            Ok(l) => l,
            Err(_) => return,
        };
        call_bytes(id(), "do_nothing", &[], Funds::zero())
            .await
            .unwrap();
        // We mention l here to make sure it hasn't been dropped earlier
        panic!("Failed successfully {:?}", l);
    }
    over_async(candid, |()| dirty_call())
}

// This checks that call with cleanup actually releases the lock after panic
#[export_name = "canister_update clean_call"]
fn clean_call_() {
    async fn clean_call() {
        let l = match CLEAN_LOCK.try_write() {
            Ok(l) => l,
            Err(_) => return,
        };
        call_bytes_with_cleanup(id(), "do_nothing", &[], Funds::zero())
            .await
            .unwrap();
        // We mention l here to make sure it hasn't been dropped earlier
        panic!("Failed successfully {:?}", l);
    }
    over_async(candid, |()| clean_call())
}
