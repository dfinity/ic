use ic_principal::Principal;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

thread_local! {
    pub static LOCAL_BALANCES: RefCell<BTreeMap<Principal, u64>> = RefCell::default();
    pub static LEDGER_PRINCIPAL: Cell<Principal> = Cell::new(Principal::anonymous());
    pub static GUARDS: RefCell<BTreeSet<Principal>> = RefCell::default();
}

pub struct CallerGuard {
    principal: Principal,
}

impl CallerGuard {
    pub fn new(principal: Principal) -> Result<Self, String> {
        GUARDS.with_borrow_mut(|guard| {
            if guard.contains(&principal) {
                return Err(format!(
                    "Already processing a request for principal {:?}",
                    &principal
                ));
            }
            guard.insert(principal);
            Ok(Self { principal })
        })
    }
}

impl Drop for CallerGuard {
    fn drop(&mut self) {
        GUARDS.with_borrow_mut(|guard| {
            guard.remove(&self.principal);
        })
    }
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

    if let Ok(_principal) = CallerGuard::new(caller) {
        let balance =
            LOCAL_BALANCES.with_borrow(|local_balance| local_balance.get(&caller).cloned());
        if let Some(balance) = balance {
            if balance > trap {
                let callee = LEDGER_PRINCIPAL.get();
                let _result: () = ic_cdk::call(callee, "update_balance", (trap,))
                    .await
                    .unwrap();

                LOCAL_BALANCES
                    .with_borrow_mut(|local_balance| local_balance.insert(caller, balance - trap));

                // assume trap == 3278 creates a panic
                // Single branch; directly equality check
                // Not good for coverage

                // if trap == 3278_u64 {
                //     panic!("Triggering a trap");
                // }

                // Multiple branch; byte equality check
                // Good for coverage guided fuzzers
                let trap_slice = trap.to_le_bytes();
                if trap_slice[0] == 206 {
                    if trap_slice[1] == 12 {
                        if trap_slice[2..8].iter().all(|x| *x == 0) {
                            panic!("Triggering a trap");
                        }
                    }
                }
            }
        }
    }
}

fn main() {}
