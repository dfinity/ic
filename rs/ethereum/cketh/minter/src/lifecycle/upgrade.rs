use crate::eth_rpc::BlockTag;
use crate::logs::INFO;
use crate::state::mutate_state;
use crate::state::STATE;
use candid::{CandidType, Deserialize, Nat};
use ic_canister_log::log;
use ic_cdk::api::stable::StableReader;

#[derive(CandidType, Deserialize, Clone, Debug, Default)]
pub struct UpgradeArg {
    pub next_transaction_nonce: Option<Nat>,
    pub minimum_withdrawal_amount: Option<Nat>,
    pub ethereum_contract_address: Option<String>,
    pub ethereum_block_height: Option<BlockTag>,
}

pub fn post_upgrade(upgrade_args: Option<UpgradeArg>) {
    let start = ic_cdk::api::instruction_counter();

    STATE.with(|cell| {
        *cell.borrow_mut() = Some(
            ciborium::de::from_reader(StableReader::default())
                .expect("failed to decode ledger state"),
        );
    });
    if let Some(args) = upgrade_args {
        mutate_state(|s| s.upgrade(args).expect("ERROR: failed to upgrade state"))
    }

    let end = ic_cdk::api::instruction_counter();

    log!(
        INFO,
        "[upgrade]: upgrade consumed {} instructions",
        end - start
    );
}
