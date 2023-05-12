use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AdaptersConfig {
    pub bitcoin_mainnet_uds_path: Option<PathBuf>,
    pub bitcoin_mainnet_uds_metrics_path: Option<PathBuf>,
    pub bitcoin_testnet_uds_path: Option<PathBuf>,
    pub bitcoin_testnet_uds_metrics_path: Option<PathBuf>,
    pub https_outcalls_uds_path: Option<PathBuf>,
    pub https_outcalls_uds_metrics_path: Option<PathBuf>,
    #[serde(default = "enable_onchain_observability_grpc_server_default")]
    pub onchain_observability_enable_grpc_server: bool,
    pub onchain_observability_uds_metrics_path: Option<PathBuf>,
}

fn enable_onchain_observability_grpc_server_default() -> bool {
    false
}
