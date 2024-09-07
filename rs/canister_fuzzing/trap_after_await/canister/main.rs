use ic_principal::Principal;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::BTreeMap;

thread_local! {
    pub static LOCAL_BALANCES: RefCell<BTreeMap<Principal, u64>> = RefCell::default();
    pub static LEDGER_PRINCIPAL: Cell<Principal> = Cell::new(Principal::anonymous());
}

fn reset_balance() {
    LOCAL_BALANCES.with_borrow_mut(|local_balances| {
        local_balances.clear();
        local_balances.insert(Principal::anonymous(), 10_000_000);
    });
}

#[ic_cdk::init]
fn init(ledger_principal: Principal) {
    LEDGER_PRINCIPAL.replace(ledger_principal);
    reset_balance();
}

#[ic_cdk::post_upgrade]
fn post_upgrade(ledger_principal: Principal) {
    LEDGER_PRINCIPAL.replace(ledger_principal);
    reset_balance();
}

#[ic_cdk::update]
fn update_balance() {
    reset_balance();
}

#[ic_cdk::query]
fn get_total_balance() -> u64 {
    LOCAL_BALANCES.with_borrow(|local_balances| local_balances.values().sum())
}

#[ic_cdk::update]
async fn refund_balance(trap: u64) {
    let caller = ic_cdk::caller();

    let balance = LOCAL_BALANCES.with_borrow(|local_balance| local_balance.get(&caller).cloned());

    if let Some(balance) = balance {
        if balance > trap {
            let callee = LEDGER_PRINCIPAL.get();
            let _result: () = ic_cdk::call(callee, "update_balance", (trap,))
                .await
                .unwrap();

            LOCAL_BALANCES
                .with_borrow_mut(|local_balance| local_balance.insert(caller, balance - trap));

            if trap == 3278_u64 {
                panic!("Triggering a trap");
            }
        }
    }
}

fn main() {}
