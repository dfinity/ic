use dfn_core::endpoint::{bytes, over};

#[export_name = "canister_query reverse"]
fn reverse() {
    over(bytes, |mut arg| {
        arg.reverse();
        arg
    })
}

#[export_name = "canister_update set_certified_data"]
fn set_certified_data() {
    over(bytes, |bytes| {
        dfn_core::api::set_certified_data(&bytes[..]);
        bytes
    })
}

#[export_name = "canister_query get_certificate"]
fn get_certificate() {
    over(bytes, |_| dfn_core::api::data_certificate().unwrap())
}

fn main() {}
