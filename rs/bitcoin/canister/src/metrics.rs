use ic_metrics::MetricsRegistry;
use prometheus::IntGaugeVec;

pub struct BitcoinCanisterMetrics {
    pub chain_height: IntGaugeVec,
    pub utxos_length: IntGaugeVec,
    pub address_to_outpoints_length: IntGaugeVec,
}

impl BitcoinCanisterMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            chain_height: metrics_registry.int_gauge_vec(
                "bitcoin_canister_chain_height",
                "The height of the bitcoin chain known to the bitcoin canister.",
                &["network"],
            ),
            utxos_length: metrics_registry.int_gauge_vec(
                "bitcoin_canister_utxos_length",
                "The size of UTXO set stored by the bitcoin canister.",
                &["network"],
            ),
            address_to_outpoints_length: metrics_registry.int_gauge_vec(
                "bitcoin_canister_address_outpoints_length",
                "The size of address to outpoints map stored by the bitcoin canister.",
                &["network"],
            ),
        }
    }

    pub fn observe_chain_height(&self, chain_height: u32, network_label: &str) {
        self.chain_height
            .with_label_values(&[network_label])
            .set(chain_height as i64);
    }

    pub fn observe_utxos_length(&self, utxos_length: u64, network_label: &str) {
        self.utxos_length
            .with_label_values(&[network_label])
            .set(utxos_length as i64);
    }

    pub fn observe_address_to_outpoints_length(
        &self,
        address_to_outpoints_length: u64,
        network_label: &str,
    ) {
        self.address_to_outpoints_length
            .with_label_values(&[network_label])
            .set(address_to_outpoints_length as i64);
    }
}
