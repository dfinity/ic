use dfn_core::{api, call, over_async};
use on_wire::bytes;

fn main() {}

#[export_name = "canister_update call_nonexistent_method"]
fn call_nonexistent_method() {
    over_async(bytes, |_: Vec<u8>| async move {
        let res = call(
            api::id(),
            "this_method_does_not_exists",
            bytes,
            Vec::<u8>::new(),
        )
        .await;
        match res {
            Ok(_) => b"inter-canister call worked".to_vec(),
            Err(_) => b"inter-canister call did not work".to_vec(),
        }
    });
}
