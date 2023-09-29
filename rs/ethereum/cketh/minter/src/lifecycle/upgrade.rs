use crate::endpoints::CandidBlockTag;
use crate::logs::INFO;
use crate::state::audit::{process_event, EventType};
use crate::state::mutate_state;
use crate::state::STATE;
use candid::{CandidType, Deserialize, Nat};
use ic_canister_log::log;
use minicbor::{Decode, Encode};

#[derive(
    CandidType, serde::Serialize, Deserialize, Clone, Debug, Default, Encode, Decode, PartialEq, Eq,
)]
pub struct UpgradeArg {
    #[cbor(n(0), with = "crate::cbor::nat::option")]
    pub next_transaction_nonce: Option<Nat>,
    #[cbor(n(1), with = "crate::cbor::nat::option")]
    pub minimum_withdrawal_amount: Option<Nat>,
    #[n(2)]
    pub ethereum_contract_address: Option<String>,
    #[n(3)]
    pub ethereum_block_height: Option<CandidBlockTag>,
}

pub fn post_upgrade(upgrade_args: Option<UpgradeArg>) {
    let start = ic_cdk::api::instruction_counter();

    STATE.with(|cell| {
        *cell.borrow_mut() = Some(crate::storage::decode_state());
    });
    if let Some(args) = upgrade_args {
        mutate_state(|s| process_event(s, EventType::Upgrade(args)))
    }

    let end = ic_cdk::api::instruction_counter();

    log!(
        INFO,
        "[upgrade]: upgrade consumed {} instructions",
        end - start
    );
}
