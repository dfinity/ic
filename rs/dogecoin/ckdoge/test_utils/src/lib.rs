mod minter;

use candid::{Encode, Principal};
use ic_ckdoge_minter::lifecycle::init::Mode;
use ic_ckdoge_minter::lifecycle::init::{InitArgs, MinterArg, Network};
use ic_icrc1_ledger::ArchiveOptions;
use ic_management_canister_types::{CanisterId, CanisterSettings};
use icrc_ledger_types::icrc1::account::Account;
use pocket_ic::ErrorCode;
use pocket_ic::RejectCode;
use pocket_ic::{PocketIc, PocketIcBuilder, RejectResponse};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

pub use crate::minter::MinterCanister;

pub const NNS_ROOT_PRINCIPAL: Principal = Principal::from_slice(&[0_u8]);
pub const DOGECOIN_CANISTER: Principal =
    Principal::from_slice(&[0_u8, 0, 0, 0, 1, 160, 0, 7, 1, 1]);
pub const USER_PRINCIPAL: Principal = Principal::from_slice(&[0_u8, 42]);
pub const DOGECOIN_ADDRESS_1: &str = "DJfU2p6woQ9GiBdiXsWZWJnJ9uDdZfSSNC";
pub const RETRIEVE_DOGE_MIN_AMOUNT: u64 = 100_000_000;

pub struct Setup {
    env: Arc<PocketIc>,
    minter: CanisterId,
    _ledger: CanisterId,
}

impl Setup {
    pub fn new() -> Self {
        let env = Arc::new(
            PocketIcBuilder::new()
                .with_bitcoin_subnet()
                .with_fiduciary_subnet()
                .build(),
        );
        let fiduciary_subnet = env.topology().get_fiduciary().unwrap();

        let minter = env.create_canister_on_subnet(
            None,
            Some(CanisterSettings {
                controllers: Some(vec![NNS_ROOT_PRINCIPAL]),
                ..Default::default()
            }),
            fiduciary_subnet,
        );
        env.add_cycles(minter, u128::MAX);

        let ledger = env.create_canister_on_subnet(
            None,
            Some(CanisterSettings {
                controllers: Some(vec![NNS_ROOT_PRINCIPAL]),
                ..Default::default()
            }),
            fiduciary_subnet,
        );
        env.add_cycles(ledger, u128::MAX);

        {
            let minter_init_args = MinterArg::Init(InitArgs {
                doge_network: Network::Mainnet,
                ecdsa_key_name: "key_1".into(),
                retrieve_doge_min_amount: RETRIEVE_DOGE_MIN_AMOUNT,
                ledger_id: ledger,
                max_time_in_queue_nanos: Duration::from_secs(10).as_nanos() as u64,
                min_confirmations: Some(60),
                mode: Mode::GeneralAvailability,
                get_utxos_cache_expiration_seconds: Some(Duration::from_secs(60).as_secs()),
            });
            env.install_canister(
                minter,
                minter_wasm(),
                Encode!(&minter_init_args).unwrap(),
                Some(NNS_ROOT_PRINCIPAL),
            );
        }

        {
            let ledger_init_args = ic_icrc1_ledger::InitArgs {
                minting_account: minter.into(),
                fee_collector_account: Some(Account {
                    owner: DOGECOIN_CANISTER,
                    subaccount: Some([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0x0f, 0xee,
                    ]),
                }),
                initial_balances: vec![],
                // 0.1 DOGE, ca 0.02 USD (2025.09.06)
                transfer_fee: 10_000_000_u32.into(),
                decimals: Some(8),
                token_name: "ckDOGE".to_string(),
                token_symbol: "ckDOGE".to_string(),
                metadata: vec![],
                archive_options: ArchiveOptions {
                    trigger_threshold: 2_000,
                    num_blocks_to_archive: 1_0000,
                    node_max_memory_size_bytes: Some(3_221_225_472),
                    max_message_size_bytes: None,
                    controller_id: NNS_ROOT_PRINCIPAL.into(),
                    more_controller_ids: None,
                    cycles_for_archive_creation: Some(100_000_000_000_000),
                    max_transactions_per_response: None,
                },
                max_memo_length: Some(80),
                feature_flags: None,
                index_principal: None,
            };
            env.install_canister(
                ledger,
                ledger_wasm(),
                Encode!(&ic_icrc1_ledger::LedgerArgument::Init(ledger_init_args)).unwrap(),
                Some(NNS_ROOT_PRINCIPAL),
            );
        }

        Self {
            env,
            minter,
            _ledger: ledger,
        }
    }

    pub fn minter(&self) -> MinterCanister {
        MinterCanister {
            env: self.env.clone(),
            id: self.minter,
        }
    }
}

impl Default for Setup {
    fn default() -> Self {
        Self::new()
    }
}

fn minter_wasm() -> Vec<u8> {
    let wasm_path = std::env::var("IC_CKDOGE_MINTER_WASM_PATH").unwrap();
    std::fs::read(wasm_path).unwrap()
}

fn ledger_wasm() -> Vec<u8> {
    let wasm_path = std::env::var("IC_ICRC1_LEDGER_WASM_PATH").unwrap();
    std::fs::read(wasm_path).unwrap()
}

pub fn assert_trap<T: Debug>(result: Result<T, RejectResponse>, message: &str) {
    assert_matches::assert_matches!(
        result,
        Err(RejectResponse {reject_code, reject_message, error_code, ..}) if
            reject_code == RejectCode::CanisterError &&
            reject_message.contains(message) &&
            error_code == ErrorCode::CanisterCalledTrap
    );
}

#[cfg(test)]
mod tests {
    use crate::DOGECOIN_CANISTER;

    #[test]
    fn should_have_correct_principal() {
        assert_eq!(DOGECOIN_CANISTER.to_string(), "gordg-fyaaa-aaaan-aaadq-cai");
    }
}
