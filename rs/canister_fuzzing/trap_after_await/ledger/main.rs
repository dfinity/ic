use ic_principal::Principal;
use std::cell::RefCell;
use std::collections::BTreeMap;

thread_local! {
    pub static BALANCES: RefCell<BTreeMap<Principal, u64>> = RefCell::default();
}

#[ic_cdk::query]
fn get_balance(account: Principal) -> u64 {
    BALANCES
        .with_borrow(|local_balances| local_balances.get(&account).cloned())
        .unwrap_or_default()
}

#[ic_cdk::update]
fn update_balance(reduce: u64) {
    BALANCES.with_borrow_mut(|local_balances| {
        if let Some(balance) = local_balances.get_mut(&ic_cdk::caller()) {
            *balance = balance.saturating_sub(reduce);
        }
    });
}

// Admin method for testing
#[ic_cdk::update]
fn setup_balance(account: Principal, balance: u64) {
    BALANCES.with_borrow_mut(|local_balances| local_balances.insert(account, balance));
}

fn main() {}
