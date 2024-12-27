#[cfg(test)]
mod tests;

use std::fmt::Display;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use strum_macros::EnumIter;

#[derive(Clone, Eq, PartialEq, Debug, Ord, PartialOrd, EnumIter)]
#[allow(clippy::enum_variant_names)]
pub enum TargetCanister {
    BtcChecker,
    CkBtcArchive,
    CkBtcIndex,
    CkBtcLedger,
    CkBtcMinter,
    CkEthArchive,
    CkEthIndex,
    CkEthLedger,
    CkEthMinter,
    IcpArchive1,
    IcpArchive2,
    IcpArchive3,
    IcpIndex,
    IcpLedger,
    LedgerSuiteOrchestrator,
    EvmRpc,
    CyclesLedger,
    ExchangeRateCanister,
}

impl TargetCanister {
    pub fn canister_name(&self) -> &str {
        match self {
            TargetCanister::BtcChecker => "btc_checker",
            TargetCanister::CkBtcArchive | TargetCanister::CkEthArchive => "archive",
            TargetCanister::CkBtcIndex | TargetCanister::CkEthIndex => "index",
            TargetCanister::CkBtcLedger | TargetCanister::CkEthLedger => "ledger",
            TargetCanister::CkBtcMinter | TargetCanister::CkEthMinter => "minter",
            TargetCanister::IcpArchive1 => "icp-archive1",
            TargetCanister::IcpArchive2 => "icp-archive2",
            TargetCanister::IcpArchive3 => "icp-archive3",
            TargetCanister::IcpIndex => "icp-index",
            TargetCanister::IcpLedger => "icp-ledger",
            TargetCanister::LedgerSuiteOrchestrator => "orchestrator",
            TargetCanister::EvmRpc => "evm_rpc",
            TargetCanister::CyclesLedger => "cycles-ledger",
            TargetCanister::ExchangeRateCanister => "xrc",
        }
    }

    pub fn git_repository_url(&self) -> &str {
        match &self {
            TargetCanister::BtcChecker
            | TargetCanister::CkBtcArchive
            | TargetCanister::CkBtcIndex
            | TargetCanister::CkBtcLedger
            | TargetCanister::CkBtcMinter
            | TargetCanister::CkEthArchive
            | TargetCanister::CkEthIndex
            | TargetCanister::CkEthLedger
            | TargetCanister::CkEthMinter
            | TargetCanister::IcpArchive1
            | TargetCanister::IcpArchive2
            | TargetCanister::IcpArchive3
            | TargetCanister::IcpIndex
            | TargetCanister::IcpLedger
            | TargetCanister::LedgerSuiteOrchestrator => "https://github.com/dfinity/ic.git",
            TargetCanister::EvmRpc => {
                "https://github.com/internet-computer-protocol/evm-rpc-canister.git"
            }
            TargetCanister::CyclesLedger => "https://github.com/dfinity/cycles-ledger.git",
            TargetCanister::ExchangeRateCanister => {
                "https://github.com/dfinity/exchange-rate-canister.git"
            }
        }
    }

    pub fn candid_file(&self) -> PathBuf {
        match &self {
            TargetCanister::BtcChecker => {
                PathBuf::from("rs/bitcoin/checker/btc_checker_canister.did")
            }
            TargetCanister::CkBtcArchive | TargetCanister::CkEthArchive => {
                PathBuf::from("rs/ledger_suite/icrc1/archive/archive.did")
            }
            TargetCanister::CkBtcIndex | TargetCanister::CkEthIndex => {
                PathBuf::from("rs/ledger_suite/icrc1/index-ng/index-ng.did")
            }
            TargetCanister::CkBtcLedger | TargetCanister::CkEthLedger => {
                PathBuf::from("rs/ledger_suite/icrc1/ledger/ledger.did")
            }
            TargetCanister::CkBtcMinter => {
                PathBuf::from("rs/bitcoin/ckbtc/minter/ckbtc_minter.did")
            }
            TargetCanister::CkEthMinter => {
                PathBuf::from("rs/ethereum/cketh/minter/cketh_minter.did")
            }
            TargetCanister::IcpArchive1
            | TargetCanister::IcpArchive2
            | TargetCanister::IcpArchive3 => {
                PathBuf::from("rs/ledger_suite/icp/ledger_archive.did")
            }
            TargetCanister::IcpIndex => PathBuf::from("rs/ledger_suite/icp/index/index.did"),
            TargetCanister::IcpLedger => PathBuf::from("rs/ledger_suite/icp/ledger.did"),
            TargetCanister::LedgerSuiteOrchestrator => {
                PathBuf::from("rs/ethereum/ledger-suite-orchestrator/ledger_suite_orchestrator.did")
            }
            TargetCanister::EvmRpc => PathBuf::from("candid/evm_rpc.did"),
            TargetCanister::CyclesLedger => PathBuf::from("cycles-ledger/cycles-ledger.did"),
            TargetCanister::ExchangeRateCanister => PathBuf::from("src/xrc/xrc.did"),
        }
    }

    pub fn repo_dir(&self) -> Option<PathBuf> {
        match &self {
            TargetCanister::BtcChecker
            | TargetCanister::CkBtcArchive
            | TargetCanister::CkBtcIndex
            | TargetCanister::CkBtcLedger
            | TargetCanister::CkBtcMinter
            | TargetCanister::CkEthArchive
            | TargetCanister::CkEthIndex
            | TargetCanister::CkEthLedger
            | TargetCanister::CkEthMinter
            | TargetCanister::IcpArchive1
            | TargetCanister::IcpArchive2
            | TargetCanister::IcpArchive3
            | TargetCanister::IcpIndex
            | TargetCanister::IcpLedger
            | TargetCanister::LedgerSuiteOrchestrator => {
                Some(self.candid_file().parent().unwrap().to_path_buf())
            }
            TargetCanister::EvmRpc
            | TargetCanister::CyclesLedger
            | TargetCanister::ExchangeRateCanister => None,
        }
    }

    pub fn git_log_dirs(&self) -> Vec<PathBuf> {
        match &self {
            TargetCanister::IcpArchive1
            | TargetCanister::IcpArchive2
            | TargetCanister::IcpArchive3 => {
                vec![
                    PathBuf::from("packages/icrc-ledger_types"),
                    PathBuf::from("rs/ledger_suite/icp/archive"),
                    PathBuf::from("rs/ledger_suite/icp/src"),
                    PathBuf::from("rs/ledger_suite/common/ledger_canister_core"),
                    PathBuf::from("rs/ledger_suite/common/ledger_core"),
                ]
            }
            TargetCanister::IcpIndex => {
                vec![
                    PathBuf::from("packages/icrc-ledger_types"),
                    PathBuf::from("rs/ledger_suite/icp/index"),
                    PathBuf::from("rs/ledger_suite/icp/src"),
                    PathBuf::from("rs/ledger_suite/common/ledger_canister_core/src"),
                    PathBuf::from("rs/ledger_suite/common/ledger_core"),
                    PathBuf::from("rs/rust_canisters/http_types"),
                    PathBuf::from("rs/rust_canisters/canister_log"),
                ]
            }
            TargetCanister::IcpLedger => {
                vec![
                    PathBuf::from("packages/icrc-ledger_types"),
                    PathBuf::from("rs/ledger_suite/icp/ledger/src"),
                    PathBuf::from("rs/ledger_suite/icp/src"),
                    PathBuf::from("rs/ledger_suite/common/ledger_canister_core/src"),
                    PathBuf::from("rs/ledger_suite/common/ledger_core/src"),
                ]
            }
            TargetCanister::BtcChecker
            | TargetCanister::CkBtcArchive
            | TargetCanister::CkBtcIndex
            | TargetCanister::CkBtcLedger
            | TargetCanister::CkBtcMinter
            | TargetCanister::CkEthArchive
            | TargetCanister::CkEthIndex
            | TargetCanister::CkEthLedger
            | TargetCanister::CkEthMinter
            | TargetCanister::LedgerSuiteOrchestrator
            | TargetCanister::EvmRpc
            | TargetCanister::CyclesLedger
            | TargetCanister::ExchangeRateCanister => self.repo_dir().into_iter().collect(),
        }
    }

    pub fn artifact(&self) -> PathBuf {
        match &self {
            TargetCanister::BtcChecker
            | TargetCanister::CkBtcArchive
            | TargetCanister::CkBtcIndex
            | TargetCanister::CkBtcLedger
            | TargetCanister::CkBtcMinter
            | TargetCanister::CkEthArchive
            | TargetCanister::CkEthIndex
            | TargetCanister::CkEthLedger
            | TargetCanister::CkEthMinter
            | TargetCanister::IcpArchive1
            | TargetCanister::IcpArchive2
            | TargetCanister::IcpArchive3
            | TargetCanister::IcpIndex
            | TargetCanister::IcpLedger
            | TargetCanister::LedgerSuiteOrchestrator => {
                PathBuf::from("artifacts/canisters").join(self.artifact_file_name())
            }
            TargetCanister::EvmRpc
            | TargetCanister::CyclesLedger
            | TargetCanister::ExchangeRateCanister => PathBuf::from(self.artifact_file_name()),
        }
    }

    pub fn artifact_file_name(&self) -> &str {
        match &self {
            TargetCanister::BtcChecker => "ic-btc-checker.wasm.gz",
            TargetCanister::CkBtcArchive => "ic-icrc1-archive.wasm.gz",
            TargetCanister::CkBtcIndex => "ic-icrc1-index-ng.wasm.gz",
            TargetCanister::CkBtcLedger => "ic-icrc1-ledger.wasm.gz",
            TargetCanister::CkBtcMinter => "ic-ckbtc-minter.wasm.gz",
            TargetCanister::CkEthArchive => "ic-icrc1-archive-u256.wasm.gz",
            TargetCanister::CkEthIndex => "ic-icrc1-index-ng-u256.wasm.gz",
            TargetCanister::CkEthLedger => "ic-icrc1-ledger-u256.wasm.gz",
            TargetCanister::CkEthMinter => "ic-cketh-minter.wasm.gz",
            TargetCanister::IcpArchive1
            | TargetCanister::IcpArchive2
            | TargetCanister::IcpArchive3 => "ledger-archive-node-canister.wasm.gz",
            TargetCanister::IcpIndex => "ic-icp-index-canister.wasm.gz",
            TargetCanister::IcpLedger => "ledger-canister_notify-method.wasm.gz",
            TargetCanister::LedgerSuiteOrchestrator => {
                "ic-ledger-suite-orchestrator-canister.wasm.gz"
            }
            TargetCanister::EvmRpc => "evm_rpc.wasm.gz",
            TargetCanister::CyclesLedger => "cycles-ledger.wasm.gz",
            TargetCanister::ExchangeRateCanister => "xrc.wasm.gz",
        }
    }

    pub fn build_artifact(&self) -> Command {
        match &self {
            TargetCanister::BtcChecker
            | TargetCanister::CkBtcArchive
            | TargetCanister::CkBtcIndex
            | TargetCanister::CkBtcLedger
            | TargetCanister::CkBtcMinter
            | TargetCanister::CkEthArchive
            | TargetCanister::CkEthIndex
            | TargetCanister::CkEthLedger
            | TargetCanister::CkEthMinter
            | TargetCanister::IcpArchive1
            | TargetCanister::IcpArchive2
            | TargetCanister::IcpArchive3
            | TargetCanister::IcpIndex
            | TargetCanister::IcpLedger
            | TargetCanister::LedgerSuiteOrchestrator => {
                let mut cmd = Command::new("./ci/container/build-ic.sh");
                cmd.arg("--canisters");
                cmd
            }
            TargetCanister::EvmRpc | TargetCanister::CyclesLedger => {
                Command::new("./scripts/docker-build")
            }
            TargetCanister::ExchangeRateCanister => {
                let mut cmd = Command::new("./scripts/docker-build");
                cmd.env("IP_SUPPORT", "ipv4");
                cmd
            }
        }
    }

    pub fn build_artifact_as_str(&self) -> String {
        format!("{:?}", self.build_artifact())
    }

    pub fn canister_ids_json_file(&self) -> PathBuf {
        match self {
            TargetCanister::BtcChecker
            | TargetCanister::CkBtcArchive
            | TargetCanister::CkBtcIndex
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
            | TargetCanister::IcpArchive3
            | TargetCanister::IcpIndex
            | TargetCanister::IcpLedger => PathBuf::from("rs/ledger_suite/icp/canister_ids.json"),
            TargetCanister::EvmRpc
            | TargetCanister::CyclesLedger
            | TargetCanister::ExchangeRateCanister => PathBuf::from("canister_ids.json"),
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
            ["btc", "checker"] => Ok(TargetCanister::BtcChecker),
            ["ckbtc", "archive"] => Ok(TargetCanister::CkBtcArchive),
            ["ckbtc", "index"] => Ok(TargetCanister::CkBtcIndex),
            ["ckbtc", "ledger"] => Ok(TargetCanister::CkBtcLedger),
            ["ckbtc", "minter"] => Ok(TargetCanister::CkBtcMinter),
            ["cketh", "archive"] => Ok(TargetCanister::CkEthArchive),
            ["cketh", "index"] => Ok(TargetCanister::CkEthIndex),
            ["cketh", "ledger"] => Ok(TargetCanister::CkEthLedger),
            ["cketh", "minter"] => Ok(TargetCanister::CkEthMinter),
            ["ckerc20", "orchestrator"] => Ok(TargetCanister::LedgerSuiteOrchestrator),
            ["icp", "archive1"] => Ok(TargetCanister::IcpArchive1),
            ["icp", "archive2"] => Ok(TargetCanister::IcpArchive2),
            ["icp", "archive3"] => Ok(TargetCanister::IcpArchive3),
            ["icp", "index"] => Ok(TargetCanister::IcpIndex),
            ["icp", "ledger"] => Ok(TargetCanister::IcpLedger),
            ["evm", "rpc"] => Ok(TargetCanister::EvmRpc),
            ["cycles", "ledger"] => Ok(TargetCanister::CyclesLedger),
            ["exchange", "rate"] => Ok(TargetCanister::ExchangeRateCanister),
            _ => Err(format!("Unknown canister name: {}", canister)),
        }
    }
}

impl Display for TargetCanister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetCanister::BtcChecker => write!(f, "BTC Checker"),
            TargetCanister::CkBtcArchive => write!(f, "ckBTC archive"),
            TargetCanister::CkBtcIndex => write!(f, "ckBTC index"),
            TargetCanister::CkBtcLedger => write!(f, "ckBTC ledger"),
            TargetCanister::CkBtcMinter => write!(f, "ckBTC minter"),
            TargetCanister::CkEthArchive => write!(f, "ckETH archive"),
            TargetCanister::CkEthIndex => write!(f, "ckETH index"),
            TargetCanister::CkEthLedger => write!(f, "ckETH ledger"),
            TargetCanister::CkEthMinter => write!(f, "ckETH minter"),
            TargetCanister::IcpArchive1 => write!(f, "ICP archive1"),
            TargetCanister::IcpArchive2 => write!(f, "ICP archive2"),
            TargetCanister::IcpArchive3 => write!(f, "ICP archive3"),
            TargetCanister::IcpIndex => write!(f, "ICP index"),
            TargetCanister::IcpLedger => write!(f, "ICP ledger"),
            TargetCanister::LedgerSuiteOrchestrator => write!(f, "ledger suite orchestrator"),
            TargetCanister::EvmRpc => write!(f, "EVM RPC"),
            TargetCanister::CyclesLedger => write!(f, "cycles ledger"),
            TargetCanister::ExchangeRateCanister => write!(f, "exchange rate canister"),
        }
    }
}
