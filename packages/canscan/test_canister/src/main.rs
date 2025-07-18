use candid::{Nat, Principal};
use ic_cdk::{query, update};

#[query(name = "getBalance")]
pub async fn get_balance(_owner: Option<Principal>) -> Nat {
    Nat::from(0u64)
}

#[update(name = "send")]
pub async fn send(_sender: Option<Principal>, _recipient: Principal, _amount: Nat) -> bool {
    true
}

#[update(name = "setApiKey", hidden = true)]
pub async fn set_api_key(_api_key: Option<String>) -> bool {
    true
}

fn main() {}
