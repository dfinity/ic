use crate::endpoints::CandidBlockTag;
use crate::logs::INFO;
use crate::state::STATE;
use crate::state::audit::{EventType, process_event, replay_events};
use crate::state::mutate_state;
use crate::storage::total_event_count;
use crate::time::TimeProvider;
use candid::{CandidType, Deserialize, Nat, Principal};
use ic_canister_log::log;
use minicbor::{Decode, Encode};

#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Decode, Deserialize, Encode)]
pub struct UpgradeArg {
    #[cbor(n(0), with = "icrc_cbor::nat::option")]
    pub next_transaction_nonce: Option<Nat>,
    #[cbor(n(1), with = "icrc_cbor::nat::option")]
    pub minimum_withdrawal_amount: Option<Nat>,
    #[n(2)]
    pub ethereum_contract_address: Option<String>,
    #[n(3)]
    pub ethereum_block_height: Option<CandidBlockTag>,
    #[cbor(n(4), with = "icrc_cbor::principal::option")]
    pub ledger_suite_orchestrator_id: Option<Principal>,
    #[n(5)]
    pub erc20_helper_contract_address: Option<String>,
    #[cbor(n(6), with = "icrc_cbor::nat::option")]
    pub last_erc20_scraped_block_number: Option<Nat>,
    #[cbor(n(7), with = "icrc_cbor::principal::option")]
    pub evm_rpc_id: Option<Principal>,
    #[n(8)]
    pub deposit_with_subaccount_helper_contract_address: Option<String>,
    #[cbor(n(9), with = "icrc_cbor::nat::option")]
    pub last_deposit_with_subaccount_scraped_block_number: Option<Nat>,
    #[n(10)]
    pub ethereum_sweeper_contract_address: Option<String>,
    /// Next transaction nonce of the dedicated sweeper address, on its own nonce sequence.
    /// Mirrors `next_transaction_nonce` for the main address.
    #[cbor(n(11), with = "icrc_cbor::nat::option")]
    pub next_sweeper_transaction_nonce: Option<Nat>,
}

pub fn post_upgrade<T: TimeProvider>(upgrade_args: Option<UpgradeArg>, time_provider: &T) {
    let start = ic_cdk::api::instruction_counter();

    STATE.with(|cell| {
        *cell.borrow_mut() = Some(replay_events());
    });
    if let Some(args) = upgrade_args {
        mutate_state(|s| process_event(s, EventType::Upgrade(args), time_provider))
    }

    let end = ic_cdk::api::instruction_counter();

    let event_count = total_event_count();
    let instructions_consumed = end - start;

    log!(
        INFO,
        "[upgrade]: replaying {event_count} events consumed {instructions_consumed} instructions ({} instructions per event on average)",
        instructions_consumed / event_count
    );
}
