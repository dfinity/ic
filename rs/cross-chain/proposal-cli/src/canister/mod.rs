#[cfg(test)]
mod tests;

use candid::Principal;
use std::fmt::Display;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use strum_macros::{EnumCount, EnumIter};

#[derive(Clone, Eq, PartialEq, Debug, Ord, PartialOrd, EnumIter, EnumCount)]
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
    IcpArchive4,
    IcpIndex,
    IcpLedger,
    LedgerSuiteOrchestrator,
    EvmRpc,
    CyclesLedger,
    CyclesIndex,
    ExchangeRateCanister,
    SolRpc,
    Bitcoin,
    BtcWatchdog,
    Dogecoin,
}

impl TargetCanister {
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
            | TargetCanister::CyclesIndex
            | TargetCanister::IcpArchive1
            | TargetCanister::IcpArchive2
            | TargetCanister::IcpArchive3
            | TargetCanister::IcpArchive4
            | TargetCanister::IcpIndex
            | TargetCanister::IcpLedger
            | TargetCanister::LedgerSuiteOrchestrator => "https://github.com/dfinity/ic.git",
            TargetCanister::EvmRpc => "https://github.com/dfinity/evm-rpc-canister.git",
            TargetCanister::CyclesLedger => "https://github.com/dfinity/cycles-ledger.git",
            TargetCanister::ExchangeRateCanister => {
                "https://github.com/dfinity/exchange-rate-canister.git"
            }
            TargetCanister::SolRpc => "https://github.com/dfinity/sol-rpc-canister.git",
            TargetCanister::Bitcoin | TargetCanister::BtcWatchdog => {
                "https://github.com/dfinity/bitcoin-canister.git"
            }
            TargetCanister::Dogecoin => "https://github.com/dfinity/dogecoin-canister.git",
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
            TargetCanister::CkBtcIndex
            | TargetCanister::CkEthIndex
            | TargetCanister::CyclesIndex => {
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
            | TargetCanister::IcpArchive3
            | TargetCanister::IcpArchive4 => {
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
            TargetCanister::SolRpc => PathBuf::from("canister/sol_rpc_canister.did"),
            TargetCanister::Bitcoin => PathBuf::from("canister/candid.did"),
            TargetCanister::BtcWatchdog => PathBuf::from("watchdog/candid.did"),
            TargetCanister::Dogecoin => PathBuf::from("canister/candid.did"),
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
            | TargetCanister::CyclesIndex
            | TargetCanister::IcpArchive1
            | TargetCanister::IcpArchive2
            | TargetCanister::IcpArchive3
            | TargetCanister::IcpArchive4
            | TargetCanister::IcpIndex
            | TargetCanister::IcpLedger
            | TargetCanister::LedgerSuiteOrchestrator => {
                Some(self.candid_file().parent().unwrap().to_path_buf())
            }
            TargetCanister::EvmRpc
            | TargetCanister::CyclesLedger
            | TargetCanister::ExchangeRateCanister
            | TargetCanister::SolRpc
            | TargetCanister::Bitcoin
            | TargetCanister::BtcWatchdog
            | TargetCanister::Dogecoin => None,
        }
    }

    pub fn git_log_dirs(&self) -> Vec<PathBuf> {
        match &self {
            TargetCanister::CyclesIndex => {
                vec![
                    PathBuf::from("packages/icrc-ledger-types"),
                    PathBuf::from("rs/ledger_suite/common/ledger_canister_core"),
                    PathBuf::from("rs/ledger_suite/common/ledger_core"),
                    PathBuf::from("rs/ledger_suite/icrc1/index-ng"),
                    PathBuf::from("rs/ledger_suite/icrc1/tokens_u256"),
                ]
            }
            TargetCanister::IcpArchive1
            | TargetCanister::IcpArchive2
            | TargetCanister::IcpArchive3
            | TargetCanister::IcpArchive4 => {
                vec![
                    PathBuf::from("packages/icrc-ledger-types"),
                    PathBuf::from("rs/ledger_suite/icp/archive"),
                    PathBuf::from("rs/ledger_suite/icp/src"),
                    PathBuf::from("rs/ledger_suite/common/ledger_canister_core"),
                    PathBuf::from("rs/ledger_suite/common/ledger_core"),
                ]
            }
            TargetCanister::IcpIndex => {
                vec![
                    PathBuf::from("packages/icrc-ledger-types"),
                    PathBuf::from("packages/ic-http-types"),
                    PathBuf::from("rs/ledger_suite/icp/index"),
                    PathBuf::from("rs/ledger_suite/icp/src"),
                    PathBuf::from("rs/ledger_suite/common/ledger_canister_core/src"),
                    PathBuf::from("rs/ledger_suite/common/ledger_core"),
                    PathBuf::from("rs/rust_canisters/canister_log"),
                ]
            }
            TargetCanister::IcpLedger => {
                vec![
                    PathBuf::from("packages/icrc-ledger-types"),
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
            | TargetCanister::ExchangeRateCanister
            | TargetCanister::SolRpc => self.repo_dir().into_iter().collect(),
            TargetCanister::Bitcoin => vec![PathBuf::from("canister")],
            TargetCanister::BtcWatchdog => vec![PathBuf::from("watchdog")],
            TargetCanister::Dogecoin => vec![PathBuf::from("canister")],
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
            | TargetCanister::CyclesIndex
            | TargetCanister::IcpArchive1
            | TargetCanister::IcpArchive2
            | TargetCanister::IcpArchive3
            | TargetCanister::IcpArchive4
            | TargetCanister::IcpIndex
            | TargetCanister::IcpLedger
            | TargetCanister::LedgerSuiteOrchestrator => {
                PathBuf::from("artifacts/canisters").join(self.artifact_file_name())
            }
            TargetCanister::EvmRpc
            | TargetCanister::CyclesLedger
            | TargetCanister::ExchangeRateCanister
            | TargetCanister::Bitcoin
            | TargetCanister::BtcWatchdog
            | TargetCanister::Dogecoin => PathBuf::from(self.artifact_file_name()),
            TargetCanister::SolRpc => PathBuf::from("wasms").join(self.artifact_file_name()),
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
            TargetCanister::CkEthIndex | TargetCanister::CyclesIndex => {
                "ic-icrc1-index-ng-u256.wasm.gz"
            }
            TargetCanister::CkEthLedger => "ic-icrc1-ledger-u256.wasm.gz",
            TargetCanister::CkEthMinter => "ic-cketh-minter.wasm.gz",
            TargetCanister::IcpArchive1
            | TargetCanister::IcpArchive2
            | TargetCanister::IcpArchive3
            | TargetCanister::IcpArchive4 => "ledger-archive-node-canister.wasm.gz",
            TargetCanister::IcpIndex => "ic-icp-index-canister.wasm.gz",
            TargetCanister::IcpLedger => "ledger-canister.wasm.gz",
            TargetCanister::LedgerSuiteOrchestrator => {
                "ic-ledger-suite-orchestrator-canister.wasm.gz"
            }
            TargetCanister::EvmRpc => "evm_rpc.wasm.gz",
            TargetCanister::CyclesLedger => "cycles-ledger.wasm.gz",
            TargetCanister::ExchangeRateCanister => "xrc.wasm.gz",
            TargetCanister::SolRpc => "sol_rpc_canister.wasm.gz",
            TargetCanister::Bitcoin => "ic-btc-canister.wasm.gz",
            TargetCanister::BtcWatchdog => "watchdog.wasm.gz",
            TargetCanister::Dogecoin => "ic-doge-canister.wasm.gz",
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
            | TargetCanister::CyclesIndex
            | TargetCanister::IcpArchive1
            | TargetCanister::IcpArchive2
            | TargetCanister::IcpArchive3
            | TargetCanister::IcpArchive4
            | TargetCanister::IcpIndex
            | TargetCanister::IcpLedger
            | TargetCanister::LedgerSuiteOrchestrator => {
                let mut cmd = Command::new("./ci/container/build-ic.sh");
                cmd.arg("--canisters");
                cmd
            }
            TargetCanister::EvmRpc | TargetCanister::CyclesLedger | TargetCanister::SolRpc => {
                Command::new("./scripts/docker-build")
            }
            TargetCanister::Bitcoin => {
                let mut cmd = Command::new("./scripts/docker-build");
                cmd.arg("ic-btc-canister");
                cmd
            }
            TargetCanister::BtcWatchdog => {
                let mut cmd = Command::new("./scripts/docker-build");
                cmd.arg("watchdog");
                cmd
            }
            TargetCanister::Dogecoin => {
                let mut cmd = Command::new("./scripts/docker-build");
                cmd.arg("ic-doge-canister");
                cmd
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

    pub fn canister_id(&self) -> Principal {
        let principal = match self {
            TargetCanister::BtcChecker => "oltsj-fqaaa-aaaar-qal5q-cai",
            TargetCanister::CkBtcArchive => "nbsys-saaaa-aaaar-qaaga-cai",
            TargetCanister::CkBtcIndex => "n5wcd-faaaa-aaaar-qaaea-cai",
            TargetCanister::CkBtcLedger => "mxzaz-hqaaa-aaaar-qaada-cai",
            TargetCanister::CkBtcMinter => "mqygn-kiaaa-aaaar-qaadq-cai",
            TargetCanister::CkEthArchive => "xob7s-iqaaa-aaaar-qacra-cai",
            TargetCanister::CkEthIndex => "s3zol-vqaaa-aaaar-qacpa-cai",
            TargetCanister::CkEthLedger => "ss2fx-dyaaa-aaaar-qacoq-cai",
            TargetCanister::CkEthMinter => "sv3dd-oaaaa-aaaar-qacoa-cai",
            TargetCanister::IcpArchive1 => "qjdve-lqaaa-aaaaa-aaaeq-cai",
            TargetCanister::IcpArchive2 => "qsgjb-riaaa-aaaaa-aaaga-cai",
            TargetCanister::IcpArchive3 => "q4eej-kyaaa-aaaaa-aaaha-cai",
            TargetCanister::IcpArchive4 => "q3fc5-haaaa-aaaaa-aaahq-cai",
            TargetCanister::IcpIndex => "qhbym-qaaaa-aaaaa-aaafq-cai",
            TargetCanister::IcpLedger => "ryjl3-tyaaa-aaaaa-aaaba-cai",
            TargetCanister::LedgerSuiteOrchestrator => "vxkom-oyaaa-aaaar-qafda-cai",
            TargetCanister::EvmRpc => "7hfb6-caaaa-aaaar-qadga-cai",
            TargetCanister::CyclesLedger => "um5iw-rqaaa-aaaaq-qaaba-cai",
            TargetCanister::CyclesIndex => "ul4oc-4iaaa-aaaaq-qaabq-cai",
            TargetCanister::ExchangeRateCanister => "uf6dk-hyaaa-aaaaq-qaaaq-cai",
            TargetCanister::SolRpc => "tghme-zyaaa-aaaar-qarca-cai",
            TargetCanister::Bitcoin => "ghsi2-tqaaa-aaaan-aaaca-cai",
            TargetCanister::BtcWatchdog => "gatoo-6iaaa-aaaan-aaacq-cai",
            TargetCanister::Dogecoin => "gordg-fyaaa-aaaan-aaadq-cai",
        };
        Principal::from_text(principal).unwrap()
    }

    pub fn find_by_id(canister_id: &Principal) -> Option<Self> {
        use strum::IntoEnumIterator;
        TargetCanister::iter().find(|c| &c.canister_id() == canister_id)
    }

    pub fn default_upgrade_args(&self) -> String {
        const EMPTY_UPGRADE_ARGS: &str = "()";
        EMPTY_UPGRADE_ARGS.to_string()
    }

    pub fn forum_discussion(&self) -> &str {
        const NNS_UPDATES_AGGREGATION_THREAD_URL: &str =
            "https://forum.dfinity.org/t/nns-updates-aggregation-thread/23551";

        match self {
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
            | TargetCanister::ExchangeRateCanister
            | TargetCanister::SolRpc
            | TargetCanister::Bitcoin
            | TargetCanister::BtcWatchdog
            | TargetCanister::Dogecoin => "",
            TargetCanister::CyclesLedger
            | TargetCanister::CyclesIndex
            | TargetCanister::IcpArchive1
            | TargetCanister::IcpArchive2
            | TargetCanister::IcpArchive3
            | TargetCanister::IcpArchive4
            | TargetCanister::IcpIndex
            | TargetCanister::IcpLedger => NNS_UPDATES_AGGREGATION_THREAD_URL,
        }
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
            ["icp", "archive4"] => Ok(TargetCanister::IcpArchive4),
            ["icp", "index"] => Ok(TargetCanister::IcpIndex),
            ["icp", "ledger"] => Ok(TargetCanister::IcpLedger),
            ["evm", "rpc"] => Ok(TargetCanister::EvmRpc),
            ["cycles", "ledger"] => Ok(TargetCanister::CyclesLedger),
            ["cycles", "index"] => Ok(TargetCanister::CyclesIndex),
            ["exchange", "rate"] => Ok(TargetCanister::ExchangeRateCanister),
            ["sol", "rpc"] => Ok(TargetCanister::SolRpc),
            ["bitcoin"] => Ok(TargetCanister::Bitcoin),
            ["btc", "watchdog"] => Ok(TargetCanister::BtcWatchdog),
            ["dogecoin"] => Ok(TargetCanister::Dogecoin),
            _ => Err(format!("Unknown canister name: {canister}")),
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
            TargetCanister::IcpArchive4 => write!(f, "ICP archive4"),
            TargetCanister::IcpIndex => write!(f, "ICP index"),
            TargetCanister::IcpLedger => write!(f, "ICP ledger"),
            TargetCanister::LedgerSuiteOrchestrator => write!(f, "ledger suite orchestrator"),
            TargetCanister::EvmRpc => write!(f, "EVM RPC"),
            TargetCanister::CyclesLedger => write!(f, "cycles ledger"),
            TargetCanister::CyclesIndex => write!(f, "cycles index"),
            TargetCanister::ExchangeRateCanister => write!(f, "exchange rate canister"),
            TargetCanister::SolRpc => write!(f, "SOL RPC"),
            TargetCanister::Bitcoin => write!(f, "Bitcoin canister"),
            TargetCanister::BtcWatchdog => write!(f, "Bitcoin watchdog"),
            TargetCanister::Dogecoin => write!(f, "Dogecoin canister"),
        }
    }
}
