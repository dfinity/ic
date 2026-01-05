mod dogecoin;
mod events;
pub mod flow;
mod ledger;
mod minter;

use crate::dogecoin::{DogecoinCanister, DogecoinDaemon};
use crate::flow::{deposit::DepositFlowStart, withdrawal::WithdrawalFlowStart};
use crate::ledger::LedgerCanister;
pub use crate::{dogecoin::DogecoinUsers, minter::MinterCanister};
use bitcoin::TxOut;
use bitcoin::dogecoin::Network as DogeNetwork;
use candid::{Encode, Principal};
use ic_bitcoin_canister_mock::{OutPoint, Utxo};
use ic_btc_adapter_test_utils::bitcoind::Daemon;
use ic_ckdoge_minter::{
    Txid, get_dogecoin_canister_id,
    lifecycle::{
        MinterArg,
        init::{InitArgs, Mode, Network},
    },
};
use ic_icrc1_ledger::ArchiveOptions;
use ic_management_canister_types::{CanisterId, CanisterSettings};
use icrc_ledger_types::icrc1::account::Account;
use pocket_ic::ErrorCode;
use pocket_ic::RejectCode;
use pocket_ic::common::rest::{IcpFeatures, IcpFeaturesConfig};
use pocket_ic::{PocketIc, PocketIcBuilder, RejectResponse};
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

pub const NNS_ROOT_PRINCIPAL: Principal = Principal::from_slice(&[0_u8]);
pub const USER_PRINCIPAL: Principal = Principal::from_slice(&[0_u8, 42]);
pub const DOGECOIN_ADDRESS_1: &str = "DJfU2p6woQ9GiBdiXsWZWJnJ9uDdZfSSNC";
pub const DOGE: u64 = 100_000_000;
pub const RETRIEVE_DOGE_MIN_AMOUNT: u64 = 50 * DOGE;
/// Realistic median transaction fee in millikoinus/byte.
///
/// [Average transaction fee](https://bitinfocharts.com/dogecoin/)
/// was around `0.00084 DOGE/byte` on 26.11.2025 which translates to
/// * `84_000 koinus/byte`
/// * `84_000_000 millikoinus/byte`
pub const MEDIAN_TRANSACTION_FEE: u64 = 50_000_000;
// 0.01 DOGE, ca 0.002 USD (2025.09.06)
pub const LEDGER_TRANSFER_FEE: u64 = DOGE / 100;
const MAX_TIME_IN_QUEUE: Duration = Duration::from_secs(10);
pub const MIN_CONFIRMATIONS: u32 = 60;
pub const BLOCK_TIME: Duration = Duration::from_secs(60);

pub struct Setup {
    pub env: Arc<PocketIc>,
    doge_network: Network,
    dogecoin: Option<CanisterId>,
    minter: CanisterId,
    ledger: CanisterId,
    dogecoind: Option<Arc<Daemon<DogeNetwork>>>,
}

impl Setup {
    pub fn new(doge_network: Network) -> Self {
        let dogecoind = match doge_network {
            Network::Mainnet => None,
            Network::Regtest => {
                let dogecoind_path = std::env::var("DOGECOIND_BIN")
                    .expect("Missing DOGECOIND_BIN (path to dogecoind executable) in env.");
                Some(Arc::new(Daemon::new(
                    &dogecoind_path,
                    DogeNetwork::Regtest,
                    ic_btc_adapter_test_utils::bitcoind::Conf {
                        p2p: true,
                        ..Default::default()
                    },
                )))
            }
        };
        let env = match &dogecoind {
            Some(daemon) => {
                let icp_features = IcpFeatures {
                    dogecoin: Some(IcpFeaturesConfig::DefaultConfig),
                    ..Default::default()
                };
                let pic = PocketIcBuilder::new()
                    .with_bitcoin_subnet()
                    .with_fiduciary_subnet()
                    .with_dogecoind_addrs(vec![daemon.p2p_socket().unwrap().into()])
                    .with_icp_features(icp_features)
                    .build();
                pic.set_time(SystemTime::now().into());
                Arc::new(pic)
            }
            None => Arc::new(
                PocketIcBuilder::new()
                    .with_bitcoin_subnet()
                    .with_fiduciary_subnet()
                    .build(),
            ),
        };

        let mock_dogecoin_canister = match &dogecoind {
            Some(_) => None,
            None => {
                let dogecoin = env
                    .create_canister_with_id(
                        None,
                        Some(CanisterSettings {
                            controllers: Some(vec![NNS_ROOT_PRINCIPAL]),
                            ..Default::default()
                        }),
                        get_dogecoin_canister_id(&doge_network),
                    )
                    .unwrap();
                env.install_canister(
                    dogecoin,
                    bitcoin_canister_mock_wasm(),
                    Encode!(&ic_bitcoin_canister_mock::Network::Mainnet).unwrap(),
                    Some(NNS_ROOT_PRINCIPAL),
                );
                env.update_call(
                    dogecoin,
                    NNS_ROOT_PRINCIPAL,
                    "set_tip_height",
                    Encode!(&MIN_CONFIRMATIONS).unwrap(),
                )
                .unwrap();
                Some(dogecoin)
            }
        };

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
                doge_network,
                ecdsa_key_name: "key_1".into(),
                retrieve_doge_min_amount: RETRIEVE_DOGE_MIN_AMOUNT,
                ledger_id: ledger,
                max_time_in_queue_nanos: MAX_TIME_IN_QUEUE.as_nanos() as u64,
                min_confirmations: Some(MIN_CONFIRMATIONS),
                mode: Mode::GeneralAvailability,
                get_utxos_cache_expiration_seconds: Some(Duration::from_secs(60).as_secs()),
                utxo_consolidation_threshold: Some(10_000),
                max_num_inputs_in_transaction: Some(500),
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
                    owner: minter,
                    subaccount: Some([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0x0f, 0xee,
                    ]),
                }),
                initial_balances: vec![],
                transfer_fee: LEDGER_TRANSFER_FEE.into(),
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
            doge_network,
            dogecoin: mock_dogecoin_canister,
            minter,
            ledger,
            dogecoind,
        }
    }

    pub fn dogecoin(&self) -> DogecoinCanister {
        DogecoinCanister {
            env: self.env.clone(),
            id: self.dogecoin.expect("BUG: mock not available for Regtest"),
        }
    }

    pub fn dogecoind(&self) -> DogecoinDaemon {
        DogecoinDaemon {
            env: self.env.clone(),
            daemon: self
                .dogecoind
                .as_ref()
                .expect("BUG: mock not available for Mainnet")
                .clone(),
        }
    }

    pub fn minter(&self) -> MinterCanister {
        MinterCanister {
            env: self.env.clone(),
            id: self.minter,
        }
    }

    pub fn ledger(&self) -> LedgerCanister {
        LedgerCanister {
            env: self.env.clone(),
            id: self.ledger,
        }
    }

    pub fn network(&self) -> Network {
        self.doge_network
    }

    pub fn deposit_flow(&self) -> DepositFlowStart<&Setup> {
        DepositFlowStart::new(self)
    }

    pub fn withdrawal_flow(&self) -> WithdrawalFlowStart<&Setup> {
        WithdrawalFlowStart::new(self)
    }

    pub fn parse_dogecoin_address(&self, address: impl Into<String>) -> bitcoin::dogecoin::Address {
        let address = address.into();
        address
            .parse::<bitcoin::dogecoin::Address<_>>()
            .unwrap()
            .require_network(into_rust_dogecoin_network(self.network()))
            .unwrap()
    }

    /// Use the given median fee in millikoinu/byte.
    pub fn with_median_fee_percentile(self, median_fee: u64) -> Self {
        let fee_percentiles = [median_fee; 101];
        self.dogecoin().set_fee_percentiles(fee_percentiles);
        self.env.advance_time(Duration::from_secs(60 * 6 + 1));
        self.env.tick();
        self.env.tick();
        self.env.tick();

        self.minter()
            .assert_that_metrics()
            .assert_contains_metric_matching(format!(
                "ckbtc_minter_median_fee_per_vbyte {median_fee}"
            ));

        self
    }
}

impl Default for Setup {
    fn default() -> Self {
        Self::new(Network::Mainnet)
    }
}

impl AsRef<Setup> for Setup {
    fn as_ref(&self) -> &Setup {
        self
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

fn bitcoin_canister_mock_wasm() -> Vec<u8> {
    let wasm_path = std::env::var("IC_BITCOIN_CANISTER_MOCK_WASM_PATH").unwrap();
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

pub fn txid(bytes: [u8; 32]) -> Txid {
    Txid::from(bytes)
}

pub fn utxo_with_value(value: u64) -> Utxo {
    Utxo {
        height: 0,
        outpoint: OutPoint {
            txid: txid([42u8; 32]),
            vout: 1,
        },
        value,
    }
}

pub fn utxos_with_value(values: &[u64]) -> BTreeSet<Utxo> {
    assert!(
        values.len() < u16::MAX as usize,
        "Adapt logic below to create more unique UTXOs!"
    );
    let utxos = values
        .iter()
        .enumerate()
        .map(|(i, &value)| {
            let mut txid = [0; 32];
            txid[0] = (i % 256) as u8;
            txid[1] = (i / 256) as u8;
            Utxo {
                height: 0,
                outpoint: OutPoint {
                    txid: Txid::from(txid),
                    vout: 1,
                },
                value,
            }
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(values.len(), utxos.len());
    utxos
}

pub fn into_outpoint(
    value: ic_ckdoge_minter::OutPoint,
) -> bitcoin::blockdata::transaction::OutPoint {
    use bitcoin::hashes::Hash;

    bitcoin::blockdata::transaction::OutPoint {
        txid: bitcoin::blockdata::transaction::Txid::from_slice(value.txid.as_ref()).unwrap(),
        vout: value.vout,
    }
}

pub fn parse_dogecoin_address(network: Network, tx_out: &TxOut) -> bitcoin::dogecoin::Address {
    bitcoin::dogecoin::Address::from_script(
        tx_out.script_pubkey.as_script(),
        into_rust_dogecoin_network(network),
    )
    .unwrap_or_else(|e| {
        panic!(
            "BUG: invalid Dogecoin address from script '{}': {e}",
            tx_out.script_pubkey
        )
    })
}

pub fn into_rust_dogecoin_network(network: Network) -> bitcoin::dogecoin::Network {
    match network {
        Network::Mainnet => bitcoin::dogecoin::Network::Dogecoin,
        Network::Regtest => bitcoin::dogecoin::Network::Regtest,
    }
}

/// Expect exactly one element on anything that can be turn into an iterator.
pub fn only_one<T, I: IntoIterator<Item = T>>(iter: I) -> T {
    let mut iter = iter.into_iter();
    let result = iter.next().expect("BUG: expected exactly one item, got 0.");
    assert!(
        iter.next().is_none(),
        "BUG: expected exactly one item, got at least 2"
    );
    result
}
