use candid::{
    CandidType,
};
use dfn_candid::{
    CandidOne,
};
use dfn_core::{
    over_init,
};
use serde::{
    Deserialize,
    Serialize,
};

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct CyclesCanisterInitPayload {
    i: u64,
}

#[export_name = "canister_post_upgrade"]
fn post_upgrade_() {
    over_init(|CandidOne(args)| post_upgrade(args))
}

fn post_upgrade(maybe_args: Option<CyclesCanisterInitPayload>) {
    panic!("\n\nBEGIN\n{:#?}\nEND\n\n", maybe_args);
}

fn main() {}
