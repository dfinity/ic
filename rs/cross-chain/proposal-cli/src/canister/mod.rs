#[cfg(test)]
mod tests;

use std::fmt::Display;
use std::path::PathBuf;
use std::str::FromStr;
use strum_macros::EnumIter;

#[derive(Debug, EnumIter, Clone, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub enum TargetCanister {
    CkBtcArchive,
    CkBtcIndex,
    CkBtcKyt,
    CkBtcLedger,
    CkBtcMinter,
    CkEthArchive,
    CkEthIndex,
    CkEthLedger,
    CkEthMinter,
    IcpArchive1,
    IcpArchive2,
    IcpIndex,
    IcpLedger,
    LedgerSuiteOrchestrator,
}

impl TargetCanister {
    pub fn canister_name(&self) -> &str {
        match self {
            TargetCanister::CkBtcArchive | TargetCanister::CkEthArchive => "archive",
            TargetCanister::CkBtcIndex | TargetCanister::CkEthIndex => "index",
            TargetCanister::CkBtcKyt => "kyt",
            TargetCanister::CkBtcLedger | TargetCanister::CkEthLedger => "ledger",
            TargetCanister::CkBtcMinter | TargetCanister::CkEthMinter => "minter",
            TargetCanister::IcpArchive1 => "icp-archive1",
            TargetCanister::IcpArchive2 => "icp-archive2",
            TargetCanister::IcpIndex => "icp-index",
            TargetCanister::IcpLedger => "icp-ledger",
            TargetCanister::LedgerSuiteOrchestrator => "orchestrator",
        }
    }

    pub fn candid_file(&self) -> PathBuf {
        match &self {
            TargetCanister::CkBtcArchive | TargetCanister::CkEthArchive => {
                PathBuf::from("rs/rosetta-api/icrc1/archive/archive.did")
            }
            TargetCanister::CkBtcIndex | TargetCanister::CkEthIndex => {
                PathBuf::from("rs/rosetta-api/icrc1/index-ng/index-ng.did")
            }
            TargetCanister::CkBtcLedger | TargetCanister::CkEthLedger => {
                PathBuf::from("rs/rosetta-api/icrc1/ledger/ledger.did")
            }
            TargetCanister::CkBtcKyt => PathBuf::from("rs/bitcoin/ckbtc/kyt/kyt.did"),
            TargetCanister::CkBtcMinter => {
                PathBuf::from("rs/bitcoin/ckbtc/minter/ckbtc_minter.did")
            }
            TargetCanister::CkEthMinter => {
                PathBuf::from("rs/ethereum/cketh/minter/cketh_minter.did")
            }
            TargetCanister::IcpArchive1 | TargetCanister::IcpArchive2 => {
                PathBuf::from("rs/rosetta-api/icp_ledger/ledger_archive.did")
            }
            TargetCanister::IcpIndex => PathBuf::from("rs/rosetta-api/icp_ledger/index/index.did"),
            TargetCanister::IcpLedger => PathBuf::from("rs/rosetta-api/icp_ledger/ledger.did"),
            TargetCanister::LedgerSuiteOrchestrator => {
                PathBuf::from("rs/ethereum/ledger-suite-orchestrator/ledger_suite_orchestrator.did")
            }
        }
    }

    pub fn repo_dir(&self) -> PathBuf {
        self.candid_file().parent().unwrap().to_path_buf()
    }

    pub fn git_log_dirs(&self) -> Vec<PathBuf> {
        match &self {
            TargetCanister::IcpArchive1 | TargetCanister::IcpArchive2 => {
                vec![
                    PathBuf::from("packages/icrc-ledger_types"),
                    PathBuf::from("rs/rosetta-api/icp_ledger/archive"),
                    PathBuf::from("rs/rosetta-api/icp_ledger/src"),
                    PathBuf::from("rs/rosetta-api/ledger_canister_core"),
                    PathBuf::from("rs/rosetta-api/ledger_core"),
                ]
            }
            TargetCanister::IcpIndex => {
                vec![
                    PathBuf::from("packages/icrc-ledger_types"),
                    PathBuf::from("rs/rosetta-api/icp_ledger/index"),
                    PathBuf::from("rs/rosetta-api/icp_ledger/src"),
                    PathBuf::from("rs/rosetta-api/ledger_canister_core/src"),
                    PathBuf::from("rs/rosetta-api/ledger_core"),
                    PathBuf::from("rs/rust_canisters/http_types"),
                    PathBuf::from("rs/rust_canisters/canister_log"),
                ]
            }
            TargetCanister::IcpLedger => {
                vec![
                    PathBuf::from("packages/icrc-ledger_types"),
                    PathBuf::from("rs/rosetta-api/icp_ledger/ledger/src"),
                    PathBuf::from("rs/rosetta-api/icp_ledger/src"),
                    PathBuf::from("rs/rosetta-api/ledger_canister_core/src"),
                    PathBuf::from("rs/rosetta-api/ledger_core/src"),
                ]
            }
            _ => {
                vec![self.repo_dir()]
            }
        }
    }

    pub fn artifact(&self) -> PathBuf {
        PathBuf::from("artifacts/canisters").join(self.artifact_file_name())
    }

    pub fn artifact_file_name(&self) -> &str {
        match &self {
            TargetCanister::CkBtcArchive => "ic-icrc1-archive.wasm.gz",
            TargetCanister::CkBtcIndex => "ic-icrc1-index.wasm.gz",
            TargetCanister::CkBtcKyt => "ic-ckbtc-kyt.wasm.gz",
            TargetCanister::CkBtcLedger => "ic-icrc1-ledger.wasm.gz",
            TargetCanister::CkBtcMinter => "ic-ckbtc-minter.wasm.gz",
            TargetCanister::CkEthArchive => "ic-icrc1-archive-u256.wasm.gz",
            TargetCanister::CkEthIndex => "ic-icrc1-index-ng-u256.wasm.gz",
            TargetCanister::CkEthLedger => "ic-icrc1-ledger-u256.wasm.gz",
            TargetCanister::CkEthMinter => "ic-cketh-minter.wasm.gz",
            TargetCanister::IcpArchive1 | TargetCanister::IcpArchive2 => {
                "ledger-archive-node-canister.wasm.gz"
            }
            TargetCanister::IcpIndex => "ic-icp-index-canister.wasm.gz",
            TargetCanister::IcpLedger => "ledger-canister_notify-method.wasm.gz",
            TargetCanister::LedgerSuiteOrchestrator => {
                "ic-ledger-suite-orchestrator-canister.wasm.gz"
            }
        }
    }

    pub fn canister_ids_json_file(&self) -> PathBuf {
        match self {
            TargetCanister::CkBtcArchive
            | TargetCanister::CkBtcIndex
            | TargetCanister::CkBtcKyt
            | TargetCanister::CkBtcLedger
            | TargetCanister::CkBtcMinter => {
                PathBuf::from("rs/bitcoin/ckbtc/mainnet/canister_ids.json")
            }
            TargetCanister::CkEthArchive
            | TargetCanister::CkEthIndex
            | TargetCanister::CkEthLedger
            | TargetCanister::CkEthMinter
            | TargetCanister::LedgerSuiteOrchestrator => {
                PathBuf::from("rs/ethereum/cketh/mainnet/canister_ids.json")
            }
            TargetCanister::IcpArchive1
            | TargetCanister::IcpArchive2
            | TargetCanister::IcpIndex
            | TargetCanister::IcpLedger => {
                PathBuf::from("rs/rosetta-api/icp_ledger/canister_ids.json")
            }
        }
    }

    pub fn default_upgrade_args(&self) -> String {
        const EMPTY_UPGRADE_ARGS: &str = "()";
        EMPTY_UPGRADE_ARGS.to_string()
    }
}

impl FromStr for TargetCanister {
    type Err = String;

    fn from_str(canister: &str) -> Result<Self, Self::Err> {
        let canonicalized_canister = canister.to_ascii_lowercase();
        let parts: Vec<&str> = canonicalized_canister.split('-').collect();
        match &parts.as_slice() {
            ["ckbtc", "archive"] => Ok(TargetCanister::CkBtcArchive),
            ["ckbtc", "index"] => Ok(TargetCanister::CkBtcIndex),
            ["ckbtc", "kyt"] => Ok(TargetCanister::CkBtcKyt),
            ["ckbtc", "ledger"] => Ok(TargetCanister::CkBtcLedger),
            ["ckbtc", "minter"] => Ok(TargetCanister::CkBtcMinter),
            ["cketh", "archive"] => Ok(TargetCanister::CkEthArchive),
            ["cketh", "index"] => Ok(TargetCanister::CkEthIndex),
            ["cketh", "ledger"] => Ok(TargetCanister::CkEthLedger),
            ["cketh", "minter"] => Ok(TargetCanister::CkEthMinter),
            ["ckerc20", "orchestrator"] => Ok(TargetCanister::LedgerSuiteOrchestrator),
            ["icp", "archive1"] => Ok(TargetCanister::IcpArchive1),
            ["icp", "archive2"] => Ok(TargetCanister::IcpArchive2),
            ["icp", "index"] => Ok(TargetCanister::IcpIndex),
            ["icp", "ledger"] => Ok(TargetCanister::IcpLedger),
            _ => Err(format!("Unknown canister name: {}", canister)),
        }
    }
}

impl Display for TargetCanister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetCanister::CkBtcArchive => write!(f, "ckBTC archive"),
            TargetCanister::CkBtcIndex => write!(f, "ckBTC index"),
            TargetCanister::CkBtcKyt => write!(f, "ckBTC KYT"),
            TargetCanister::CkBtcLedger => write!(f, "ckBTC ledger"),
            TargetCanister::CkBtcMinter => write!(f, "ckBTC minter"),
            TargetCanister::CkEthArchive => write!(f, "ckETH archive"),
            TargetCanister::CkEthIndex => write!(f, "ckETH index"),
            TargetCanister::CkEthLedger => write!(f, "ckETH ledger"),
            TargetCanister::CkEthMinter => write!(f, "ckETH minter"),
            TargetCanister::IcpArchive1 => write!(f, "ICP archive1"),
            TargetCanister::IcpArchive2 => write!(f, "ICP archive2"),
            TargetCanister::IcpIndex => write!(f, "ICP index"),
            TargetCanister::IcpLedger => write!(f, "ICP ledger"),
            TargetCanister::LedgerSuiteOrchestrator => write!(f, "ledger suite orchestrator"),
        }
    }
}
