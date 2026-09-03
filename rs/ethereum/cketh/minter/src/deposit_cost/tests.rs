use crate::balance_scan::MAX_CALLS_PER_BATCH;
use crate::balance_scan::batcher::{BalanceOfCall, encode_balance_batch};
use crate::deposit_address::DepositAddress;
use crate::eth_rpc_client::HEADER_SIZE_LIMIT;
use crate::numeric::GasAmount;
use crate::state::automatic_deposits::SCAN_GAP_SECS;
use crate::sweep::MAX_DEPOSITS_PER_SWEEP;
use ic_ethereum_types::Address;
use std::ops::Add;

#[test]
fn should_compute_deposit_cost_in_usd() {
    for scenario in scenarios() {
        assert_eq!(
            (
                usd(scenario.cost.ethereum),
                usd(scenario.cost.internet_computer),
                usd(scenario.cost.total()),
            ),
            (
                scenario.ethereum_usd.to_string(),
                scenario.internet_computer_usd.to_string(),
                scenario.total_usd.to_string(),
            ),
            "scenario '{}' (Ethereum, Internet Computer, total)",
            scenario.name
        );
    }
}

fn scenarios() -> Vec<Scenario> {
    vec![
        ScenarioBuilder::new("calm gas, lone deposit")
            .with_balance_scans([1])
            .with_market_conditions(MarketConditions {
                gas_price_gwei: 0.5,
                ..Default::default()
            })
            .expecting("0.1371", "0.1058", "0.2429"),
        ScenarioBuilder::new("calm gas, full batch")
            .with_balance_scans([10])
            .with_sweep_of_size(10)
            .with_market_conditions(MarketConditions {
                gas_price_gwei: 0.5,
                ..Default::default()
            })
            .expecting("0.1020", "0.0732", "0.1752"),
        ScenarioBuilder::new("typical gas, lone deposit")
            .with_balance_scans([1])
            .expecting("0.5484", "0.1058", "0.6542"),
        ScenarioBuilder::new("typical gas, full batch")
            .with_balance_scans([10])
            .with_sweep_of_size(10)
            .expecting("0.4080", "0.0732", "0.4812"),
        ScenarioBuilder::new("congested gas, lone deposit")
            .with_balance_scans([1])
            .with_market_conditions(MarketConditions {
                gas_price_gwei: 10.0,
                ..Default::default()
            })
            .expecting("2.7420", "0.1058", "2.8478"),
        ScenarioBuilder::new("gas spike, lone deposit")
            .with_balance_scans([1])
            .with_market_conditions(MarketConditions {
                gas_price_gwei: 100.0,
                ..Default::default()
            })
            .expecting("27.4200", "0.1058", "27.5258"),
        ScenarioBuilder::new("bear market ether, typical gas")
            .with_balance_scans([1])
            .with_market_conditions(MarketConditions {
                eth_usd: 2_000.0,
                ..Default::default()
            })
            .expecting("0.3656", "0.1058", "0.4714"),
        ScenarioBuilder::new("bull market ether, typical gas")
            .with_balance_scans([1])
            .with_market_conditions(MarketConditions {
                eth_usd: 10_000.0,
                ..Default::default()
            })
            .expecting("1.8280", "0.1058", "1.9338"),
        ScenarioBuilder::new("scanned alone through the full 24h schedule")
            .with_balance_scans([1; SCAN_GAP_SECS.len()])
            .expecting("0.5484", "0.1507", "0.6991"),
        ScenarioBuilder::new("scanned through the full 24h schedule in full calls")
            .with_balance_scans([MAX_CALLS_PER_BATCH as u32; SCAN_GAP_SECS.len()])
            .expecting("0.5484", "0.1050", "0.6534"),
    ]
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

    pub fn expecting(
        self,
        ethereum_usd: &'static str,
        internet_computer_usd: &'static str,
        total_usd: &'static str,
    ) -> Scenario {
        Scenario {
            name: self.name,
            cost: self.cost_usd(),
            ethereum_usd,
            internet_computer_usd,
            total_usd,
        }
    }

    fn cost_usd(&self) -> AmortizedCostUsd {
        self.balance_scan
            .iter()
            .map(|scan| scan.amortized_cost_usd(&self.market))
            .fold(self.sweep.amortized_cost_usd(&self.market), Add::add)
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

impl AmortizedCostUsd {
    fn total(&self) -> f64 {
        self.ethereum + self.internet_computer
    }
}

impl Add for AmortizedCostUsd {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            ethereum: self.ethereum + rhs.ethereum,
            internet_computer: self.internet_computer + rhs.internet_computer,
        }
    }
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
    cost: AmortizedCostUsd,
    ethereum_usd: &'static str,
    internet_computer_usd: &'static str,
    total_usd: &'static str,
}

fn usd(amount: f64) -> String {
    format!("{amount:.4}")
}

const NODES_IN_FIDUCIARY_SUBNET: u128 = 34;
const HTTPS_OUTCALL_BASE_CYCLES: u128 =
    (3_000_000 + 60_000 * NODES_IN_FIDUCIARY_SUBNET) * NODES_IN_FIDUCIARY_SUBNET;
const HTTPS_OUTCALL_REQUEST_CYCLES_PER_BYTE: u128 = 400 * NODES_IN_FIDUCIARY_SUBNET;
const HTTPS_OUTCALL_RESPONSE_CYCLES_PER_BYTE: u128 = 800 * NODES_IN_FIDUCIARY_SUBNET;
