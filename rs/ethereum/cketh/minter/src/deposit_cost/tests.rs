use crate::BALANCE_SCAN_INTERVAL;
use crate::balance_scan::MAX_CALLS_PER_BATCH;
use crate::balance_scan::batcher::{BalanceOfCall, encode_balance_batch};
use crate::deposit_address::DepositAddress;
use crate::eth_rpc_client::HEADER_SIZE_LIMIT;
use crate::numeric::GasAmount;
use crate::state::automatic_deposits::SCAN_GAP_SECS;
use crate::state::transactions::{AuthorizedSweepItem, sweep_gas_limit};
use crate::sweep::MAX_DEPOSITS_PER_SWEEP;
use crate::sweeper_contract::SweepItem;
use crate::tx::TransactionSignature;
use candid::Principal;
use ethnum::u256;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::time::Duration;

#[test]
fn should_compute_deposit_cost_in_usd() {
    for scenario in scenarios() {
        let cost = deposit_cost_usd(&scenario.conditions);

        assert_eq!(
            (
                usd(cost.gas),
                usd(cost.threshold_ecdsa),
                usd(cost.https_outcalls),
                usd(cost.total()),
            ),
            (
                scenario.gas_usd.to_string(),
                scenario.threshold_ecdsa_usd.to_string(),
                scenario.https_outcalls_usd.to_string(),
                scenario.total_usd.to_string(),
            ),
            "scenario '{}' (gas, threshold ECDSA, HTTPS outcalls, total)",
            scenario.name
        );
    }
}

struct ScenarioBuilder {
    name: &'static str,
    balance_scan: Vec<BalanceScanStep>,
    sweep: SweepTransactionStep,
    market: MarketConditions,
}

impl ScenarioBuilder {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            balance_scan: Vec::new(),
            sweep: SweepTransactionStep::new(1),
            market: Default::default(),
        }
    }

    pub fn with_balance_scans<I: IntoIterator<Item = u32>>(mut self, batch_size: I) -> Self {
        let batches: Vec<_> = batch_size.into_iter().map(BalanceScanStep::new).collect();
        assert!(
            batches.len() <= SCAN_GAP_SECS.len(),
            "BUG: Too many balance scans scheduled"
        );
        self.balance_scan = batches;
        self
    }

    pub fn with_sweep_of_size(mut self, sweep_size: u32) -> Self {
        self.sweep = SweepTransactionStep::new(sweep_size);
        self
    }

    pub fn with_market_conditions(mut self, market_conditions: MarketConditions) -> Self {
        self.market = market_conditions;
        self
    }
}

struct BalanceScanStep {
    batch_size: u32,
    num_providers: u32,
}

impl BalanceScanStep {
    pub fn new(batch_size: u32) -> Self {
        assert!(0 < batch_size && batch_size as usize <= MAX_CALLS_PER_BATCH);
        Self {
            batch_size,
            num_providers: 4,
        }
    }

    fn request_size_bytes(&self) -> usize {
        let input = encode_balance_batch(&scanned_pairs(self.batch_size));
        HEADER_SIZE_LIMIT as usize + hex_encoded_len(input.len())
    }

    fn response_size_bytes(&self) -> usize {
        let balance_words = 32 * self.batch_size as usize;
        HEADER_SIZE_LIMIT as usize + hex_encoded_len(balance_words)
    }

    fn request_cycles_cost(&self) -> u128 {
        let per_provider = HTTPS_OUTCALL_BASE_CYCLES
            + HTTPS_OUTCALL_REQUEST_CYCLES_PER_BYTE * self.request_size_bytes() as u128
            + HTTPS_OUTCALL_RESPONSE_CYCLES_PER_BYTE * self.response_size_bytes() as u128;
        self.num_providers as u128 * per_provider
    }

    fn amortized_cost_usd(&self, market: &MarketConditions) -> AmortizedCostUsd {
        AmortizedCostUsd {
            internet_computer: market.cycles_to_usd(self.request_cycles_cost())
                / self.batch_size as f64,
            ..Default::default()
        }
    }
}

struct SweepTransactionStep {
    batch_size: u32,
    with_attestation: bool,
    with_authorization: bool,
}

impl SweepTransactionStep {
    pub fn new(batch_size: u32) -> Self {
        assert!(0 < batch_size && batch_size as usize <= MAX_DEPOSITS_PER_SWEEP);
        Self {
            batch_size,
            with_attestation: true,
            with_authorization: true,
        }
    }

    fn signature_cycles_cost(&self) -> u128 {
        const THRESHOLD_ECDSA_FIDUCIARY_CYCLES_COST: u128 = 26_153_846_153;
        let mut num_signatures = 1; //for the overall Ethereum transaction;
        if self.with_attestation {
            num_signatures += self.batch_size;
        }
        if self.with_authorization {
            num_signatures += self.batch_size;
        }
        num_signatures as u128 * THRESHOLD_ECDSA_FIDUCIARY_CYCLES_COST
    }

    fn gas_cost(&self) -> GasAmount {
        const FIXED_GAS_COST: u128 = 26_000;
        const PER_ITEM_GAS_COST: u128 = 65_400;
        GasAmount::new(FIXED_GAS_COST + self.batch_size as u128 * PER_ITEM_GAS_COST)
    }

    fn amortized_cost_usd(&self, market: &MarketConditions) -> AmortizedCostUsd {
        AmortizedCostUsd {
            ethereum: market.gas_to_usd(&self.gas_cost()) / self.batch_size as f64,
            internet_computer: market.cycles_to_usd(self.signature_cycles_cost())
                / self.batch_size as f64,
        }
    }
}

struct MarketConditions {
    eth_usd: f64,
    gas_price_gwei: f64,
    xdr_usd: f64,
}

impl Default for MarketConditions {
    fn default() -> Self {
        Self {
            eth_usd: 3000.0,
            gas_price_gwei: 2.0,
            xdr_usd: 1.33,
        }
    }
}

impl MarketConditions {
    fn cycles_to_usd(&self, cycles: u128) -> f64 {
        const TCYCLES_XDR: f64 = 1e12;
        (cycles as f64 * self.xdr_usd) / TCYCLES_XDR
    }

    fn gas_to_usd(&self, gas: &GasAmount) -> f64 {
        const GWEI: f64 = 1e9;
        gas.as_f64() * self.gas_price_gwei * self.eth_usd / GWEI
    }
}

/// Cost in USD for 1 deposit.
#[derive(Default)]
struct AmortizedCostUsd {
    ethereum: f64,
    internet_computer: f64,
}

fn scanned_pairs(count: u32) -> Vec<BalanceOfCall> {
    (0..count)
        .map(|_| BalanceOfCall {
            token: Address::new([0xaa; 20]),
            holder: DepositAddress::new(Address::new([0xbb; 20])),
        })
        .collect()
}

fn hex_encoded_len(bytes: usize) -> usize {
    "0x".len() + 2 * bytes
}

struct Scenario {
    name: &'static str,
    conditions: DepositConditions,
    gas_usd: &'static str,
    threshold_ecdsa_usd: &'static str,
    https_outcalls_usd: &'static str,
    total_usd: &'static str,
}

fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "calm gas, lone deposit",
            conditions: conditions(4_500.0, 0.5, 1, 1.0),
            gas_usd: "0.5062",
            threshold_ecdsa_usd: "0.1044",
            https_outcalls_usd: "0.0080",
            total_usd: "0.6186",
        },
        Scenario {
            name: "calm gas, full batch",
            conditions: conditions(4_500.0, 0.5, 10, 1.0),
            gas_usd: "0.3848",
            threshold_ecdsa_usd: "0.0730",
            https_outcalls_usd: "0.0020",
            total_usd: "0.4598",
        },
        Scenario {
            name: "typical gas, lone deposit",
            conditions: conditions(4_500.0, 2.0, 1, 1.0),
            gas_usd: "2.0250",
            threshold_ecdsa_usd: "0.1044",
            https_outcalls_usd: "0.0080",
            total_usd: "2.1373",
        },
        Scenario {
            name: "typical gas, full batch",
            conditions: conditions(4_500.0, 2.0, 10, 1.0),
            gas_usd: "1.5390",
            threshold_ecdsa_usd: "0.0730",
            https_outcalls_usd: "0.0020",
            total_usd: "1.6140",
        },
        Scenario {
            name: "congested gas, lone deposit",
            conditions: conditions(4_500.0, 10.0, 1, 1.0),
            gas_usd: "10.1250",
            threshold_ecdsa_usd: "0.1044",
            https_outcalls_usd: "0.0080",
            total_usd: "10.2373",
        },
        Scenario {
            name: "gas spike, lone deposit",
            conditions: conditions(4_500.0, 100.0, 1, 1.0),
            gas_usd: "101.2500",
            threshold_ecdsa_usd: "0.1044",
            https_outcalls_usd: "0.0080",
            total_usd: "101.3623",
        },
        Scenario {
            name: "bear market ether, typical gas",
            conditions: conditions(2_000.0, 2.0, 1, 1.0),
            gas_usd: "0.9000",
            threshold_ecdsa_usd: "0.1044",
            https_outcalls_usd: "0.0080",
            total_usd: "1.0123",
        },
        Scenario {
            name: "bull market ether, typical gas",
            conditions: conditions(10_000.0, 2.0, 1, 1.0),
            gas_usd: "4.5000",
            threshold_ecdsa_usd: "0.1044",
            https_outcalls_usd: "0.0080",
            total_usd: "4.6123",
        },
        Scenario {
            name: "deposit scanned 100 times before landing",
            conditions: conditions(4_500.0, 2.0, 1, 100.0),
            gas_usd: "2.0250",
            threshold_ecdsa_usd: "0.1044",
            https_outcalls_usd: "0.1396",
            total_usd: "2.2690",
        },
        Scenario {
            name: "lone deposit scanned alone for 24h",
            conditions: conditions(
                4_500.0,
                2.0,
                1,
                balance_scan_outcalls_during(Duration::from_secs(24 * 60 * 60)),
            ),
            gas_usd: "2.0250",
            threshold_ecdsa_usd: "0.1044",
            https_outcalls_usd: "3.8371",
            total_usd: "5.9664",
        },
    ]
}

fn balance_scan_outcalls_during(scanning: Duration) -> f64 {
    scanning.as_secs_f64() / BALANCE_SCAN_INTERVAL.as_secs_f64()
}

fn conditions(
    eth_usd: f64,
    gas_price_gwei: f64,
    deposits_per_sweep: usize,
    balance_scan_outcalls_per_deposit: f64,
) -> DepositConditions {
    DepositConditions {
        eth_usd,
        gas_price_gwei,
        deposits_per_sweep,
        balance_scan_outcalls_per_deposit,
    }
}

fn usd(amount: f64) -> String {
    format!("{amount:.4}")
}

const USD_PER_XDR: f64 = 1.33;
const CYCLES_PER_XDR: f64 = 1e12;
const WEI_PER_ETH: f64 = 1e18;
const WEI_PER_GWEI: f64 = 1e9;

const ECDSA_SIGNATURE_CYCLES: f64 = 26_153_846_153.0;
const ECDSA_SIGNATURES_PER_DEPOSIT: f64 = 2.0;
const ECDSA_SIGNATURES_PER_SWEEP: f64 = 1.0;

const NODES_IN_FIDUCIARY_SUBNET: u128 = 34;
const HTTPS_OUTCALL_BASE_CYCLES: u128 =
    (3_000_000 + 60_000 * NODES_IN_FIDUCIARY_SUBNET) * NODES_IN_FIDUCIARY_SUBNET;
const HTTPS_OUTCALL_REQUEST_CYCLES_PER_BYTE: u128 = 400 * NODES_IN_FIDUCIARY_SUBNET;
const HTTPS_OUTCALL_RESPONSE_CYCLES_PER_BYTE: u128 = 800 * NODES_IN_FIDUCIARY_SUBNET;

const HTTPS_OUTCALL_CYCLES: f64 = 250_000_000.0;
const RPC_PROVIDERS_PER_CALL: f64 = 4.0;
const SWEEP_PIPELINE_RPC_CALLS: f64 = 5.0;

struct DepositConditions {
    eth_usd: f64,
    gas_price_gwei: f64,
    deposits_per_sweep: usize,
    balance_scan_outcalls_per_deposit: f64,
}

struct DepositCostUsd {
    gas: f64,
    threshold_ecdsa: f64,
    https_outcalls: f64,
}

impl DepositCostUsd {
    fn total(&self) -> f64 {
        self.gas + self.threshold_ecdsa + self.https_outcalls
    }
}

fn deposit_cost_usd(conditions: &DepositConditions) -> DepositCostUsd {
    DepositCostUsd {
        gas: gas_cost_usd(conditions),
        threshold_ecdsa: threshold_ecdsa_cost_usd(conditions),
        https_outcalls: https_outcalls_cost_usd(conditions),
    }
}

fn gas_cost_usd(conditions: &DepositConditions) -> f64 {
    let gas_per_deposit = sweep_gas_limit(&sweep_items(conditions.deposits_per_sweep)).as_f64()
        / conditions.deposits_per_sweep as f64;
    gas_per_deposit * conditions.gas_price_gwei * WEI_PER_GWEI / WEI_PER_ETH * conditions.eth_usd
}

fn threshold_ecdsa_cost_usd(conditions: &DepositConditions) -> f64 {
    let signatures_per_deposit = ECDSA_SIGNATURES_PER_DEPOSIT
        + ECDSA_SIGNATURES_PER_SWEEP / conditions.deposits_per_sweep as f64;
    cycles_to_usd(signatures_per_deposit * ECDSA_SIGNATURE_CYCLES)
}

fn https_outcalls_cost_usd(conditions: &DepositConditions) -> f64 {
    let rpc_calls_per_deposit = conditions.balance_scan_outcalls_per_deposit
        + SWEEP_PIPELINE_RPC_CALLS / conditions.deposits_per_sweep as f64;
    cycles_to_usd(rpc_calls_per_deposit * RPC_PROVIDERS_PER_CALL * HTTPS_OUTCALL_CYCLES)
}

fn cycles_to_usd(cycles: f64) -> f64 {
    cycles / CYCLES_PER_XDR * USD_PER_XDR
}

fn sweep_items(deposits: usize) -> Vec<AuthorizedSweepItem> {
    (1..=deposits)
        .map(|deposit| {
            let seed = u8::try_from(deposit).expect("deposits per sweep fits in a u8");
            AuthorizedSweepItem {
                item: SweepItem {
                    deposit: DepositAddress::new(Address::new([seed; 20])),
                    account: Account {
                        owner: Principal::management_canister(),
                        subaccount: Some([seed; 32]),
                    },
                    attestation: TransactionSignature {
                        signature_y_parity: false,
                        r: u256::from(seed),
                        s: u256::from(seed),
                    },
                },
                authorization: None,
            }
        })
        .collect()
}
