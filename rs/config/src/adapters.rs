use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct AdaptersConfig {
    pub bitcoin_mainnet_uds_path: Option<PathBuf>,
    pub bitcoin_mainnet_uds_metrics_path: Option<PathBuf>,
    pub bitcoin_testnet_uds_path: Option<PathBuf>,
    pub bitcoin_testnet_uds_metrics_path: Option<PathBuf>,
    pub dogecoin_mainnet_uds_path: Option<PathBuf>,
    pub dogecoin_mainnet_uds_metrics_path: Option<PathBuf>,
    pub dogecoin_testnet_uds_path: Option<PathBuf>,
    pub dogecoin_testnet_uds_metrics_path: Option<PathBuf>,
    pub https_outcalls_uds_path: Option<PathBuf>,
    pub https_outcalls_uds_metrics_path: Option<PathBuf>,
}
