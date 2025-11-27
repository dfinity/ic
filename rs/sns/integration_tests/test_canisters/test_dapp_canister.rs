use dfn_candid::candid_one;
use dfn_core::{over, println};

fn main() {}

#[unsafe(export_name = "canister_query test_dapp_method_validate")]
fn test_dapp_method_validate() {
    over(candid_one, test_dapp_method_validate_);
}

fn test_dapp_method_validate_(payload: i64) -> Result<String, String> {
    if payload > 10 {
        Ok(format!("Value is {payload}. Valid!"))
    } else {
        Err("Value < 10. Invalid!".to_string())
    }
}

#[unsafe(export_name = "canister_update test_dapp_method")]
fn test_dapp_method() {
    over(candid_one, test_dapp_method_);
}

fn test_dapp_method_(payload: i64) {
    println!("Executed with value: {}", payload);
}
