//! Wraps the shared [`crate::ckerc20::CkErc20Setup`] fixture — itself built on the shared
//! [`crate::CkEthSetup`] fixture — into a harness for the ckERC20 balance scan, driving *real*
//! canister outcalls against a local anvil node that [`LiveBalanceScanSetup`] owns (see
//! [`crate::anvil`]).
//!
//! The whole fixture — minter, EVM RPC canister, ledger-suite-orchestrator, and the ckUSDC/ckUSDT
//! ledger and index canisters the orchestrator spawns — is built on an ordinary (non-live) PocketIC
//! instance, exactly as [`crate::ckerc20::CkErc20Setup`]'s mocked fixture is: `await_call` ticks
//! deterministically, and every setup call completes in a bounded number of rounds. Only once
//! construction is complete does [`LiveBalanceScanSetup::new_live`] switch the instance to
//! auto-progress, so the EVM RPC canister's outcalls reach anvil for real from that point on.
//! Building the fixture itself against an auto-progressing (wall-clock-paced) instance instead made
//! every setup call race a round deadline it did not control, which reproducibly failed under CPU
//! contention.
//!
//! Nothing gets lost in the switch: the minter's startup timers already schedule outcalls during
//! that non-live phase, but PocketIC's auto-progress dispatch (`ProcessCanisterHttpInternal`)
//! re-scans every canister's current `canister_http_request_contexts()` each round and sends
//! whichever of them it has not already handed to the adapter, so outcalls created before
//! [`auto_progress`](pocket_ic::PocketIc::auto_progress) starts are simply picked up and answered
//! for real on its first round rather than dropped.
//!
//! The EVM RPC canister is installed with an `overrideProvider` that rewrites every provider URL to
//! the harness' anvil node (reached over HTTP, mirroring the `evm_rpc_local` configuration of the
//! EVM RPC canister), so the minter reads real Ethereum state from anvil once live: minter → EVM RPC
//! canister → anvil.

use candid::{Decode, Encode, Principal};
use ic_base_types::PrincipalId;
use ic_cketh_minter::endpoints::{
    DepositErc20Arg, DepositErc20Error, DepositErc20Response, DepositMode, DepositStatus,
};
use ic_cketh_minter::numeric::Erc20Value;
use ic_ethereum_types::Address;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::anvil::{
    Anvil, DEV_ACCOUNT, address_from_hex, deploy_mock_erc20, erc20_balance_slot, u256_be,
};
use crate::ckerc20::CkErc20Setup;
use crate::{CkEthSetup, EthereumBackend, USDC_ERC20_CONTRACT_ADDRESS};

/// USDT's mainnet address, the second token registered so the scan reads more than one token per
/// address. Matches the ckUSDT contract the minter prices in `balance_scan::MIN_DEPOSITS`.
pub const USDT_ERC20_CONTRACT_ADDRESS: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";

/// A supported ckERC20 token the live scan reads, sitting at its real mainnet contract address.
#[derive(Clone, Copy)]
pub enum SupportedToken {
    CkUsdc,
    CkUsdt,
}

impl SupportedToken {
    const ALL: [SupportedToken; 2] = [SupportedToken::CkUsdc, SupportedToken::CkUsdt];

    pub fn contract(self) -> Address {
        let address = match self {
            SupportedToken::CkUsdc => USDC_ERC20_CONTRACT_ADDRESS,
            SupportedToken::CkUsdt => USDT_ERC20_CONTRACT_ADDRESS,
        };
        Address::from_str(address).expect("BUG: hard-coded token address is invalid")
    }
}

/// A balance to place on the owned anvil node: `amount` of `token` credited to the `deposit`
/// address, so the scan reads a real balance for that (address, token) pair.
pub struct Holding {
    pub deposit: Address,
    pub token: SupportedToken,
    pub amount: u128,
}

/// Wraps the shared [`CkErc20Setup`] fixture — built against an owned anvil node — with the
/// balance-scan test's own state: the anvil node itself, kept alive for the harness' lifetime.
///
/// `ckerc20` is declared first so it drops first: the PocketIC instance goes away, and only then
/// does the node its canisters were calling out to.
pub struct LiveBalanceScanSetup {
    ckerc20: CkErc20Setup,
    anvil: Arc<Anvil>,
}

impl LiveBalanceScanSetup {
    /// Starts a local anvil node and builds the full [`CkErc20Setup`] fixture against it — minter,
    /// EVM RPC canister, orchestrator, and the ckUSDC/ckUSDT ledger and index canisters it spawns —
    /// on an ordinary (non-live) PocketIC instance, then switches that instance to live outcalls
    /// now that construction is complete, so the EVM RPC canister's outcalls reach anvil for real
    /// from this point on.
    pub fn new_live() -> Self {
        let anvil = Arc::new(Anvil::start());
        let cketh = CkEthSetup::new(EthereumBackend::Anvil(Arc::clone(&anvil)));
        let ckerc20 = CkErc20Setup::with_cketh(cketh).add_supported_erc20_tokens();

        ckerc20.env.auto_progress();

        Self { ckerc20, anvil }
    }

    /// A distinct non-anonymous depositing principal for `seed`, so a test can register several
    /// independent deposit addresses.
    pub fn depositor(&self, seed: u64) -> Principal {
        PrincipalId::new_user_test_id(seed).into()
    }

    /// Registers a `(caller/subaccount, token)` deposit and returns the Ethereum address the minter
    /// derived for it (shared across the caller's tokens).
    pub fn register_deposit_address(
        &self,
        caller: Principal,
        subaccount: [u8; 32],
        token: SupportedToken,
    ) -> Address {
        Address::from_str(&self.deposit_erc20(caller, subaccount, token).address)
            .expect("BUG: minter returned an invalid deposit address")
    }

    /// Calls `deposit_erc20` as `caller`, which registers (idempotently) that user's
    /// `(address, token)` pair for balance scanning and reports its scan progress.
    pub fn deposit_erc20(
        &self,
        caller: Principal,
        subaccount: [u8; 32],
        token: SupportedToken,
    ) -> DepositErc20Response {
        let arg = DepositErc20Arg {
            erc20_contract_address: token.contract().to_string(),
            mode: DepositMode::Unsponsored {
                subaccount: Some(subaccount),
            },
        };
        let reply = self
            .ckerc20
            .env
            .update_call(
                self.ckerc20.cketh.minter_id,
                caller,
                "deposit_erc20",
                Encode!(&arg).unwrap(),
            )
            .expect("BUG: deposit_erc20 was rejected");
        Decode!(&reply, Result<DepositErc20Response, DepositErc20Error>)
            .unwrap()
            .expect("BUG: deposit_erc20 returned an error")
    }

    /// Places both supported ERC-20s (ckUSDC, ckUSDT) at their real mainnet addresses on the owned
    /// anvil node and credits each holding by writing its `balanceOf` mapping slot directly.
    ///
    /// Every balance is written *before* any token gets code. The fail-loud batcher only returns a
    /// (scan-advancing) result once every token has code — by which point all balances are already
    /// in place — so a concurrent scan can never observe a partially-credited state.
    pub fn credit_deposits(&self, holdings: &[Holding]) {
        let dev = address_from_hex(DEV_ACCOUNT);
        // Reuse MockUSDT's deployed bytecode to give each token a working `balanceOf`.
        let runtime = self.anvil.code(&deploy_mock_erc20(&self.anvil, &dev));

        for holding in holdings {
            self.anvil.set_storage_at(
                &holding.token.contract(),
                &erc20_balance_slot(&holding.deposit),
                &u256_be(holding.amount),
            );
        }
        // Every token appearing in a registered pair is read in the shared batch, so a token
        // without code would revert the whole scan even for pairs that do not hold it.
        for token in SupportedToken::ALL {
            self.anvil.set_code(&token.contract(), &runtime);
        }
        for holding in holdings {
            assert_eq!(
                self.anvil
                    .erc20_balance(&holding.token.contract(), &holding.deposit),
                Erc20Value::from(holding.amount),
                "the deposit balance should be readable on anvil"
            );
        }
    }

    /// Waits until the minter's periodic balance scan has scanned `caller`'s deposit address —
    /// observed through `deposit_erc20`'s own status — and returns that response. An address counts
    /// as scanned once its status is `Scanning` with `scan_count >= 1` (a below-minimum address,
    /// advanced in place) or `AwaitingSweep` (a funded address, detected and queued). Either proves
    /// the `eth_call` against anvil succeeded and decoded, since a failing batch never advances or
    /// queues an address. Panics if no scan completes within `deadline`.
    pub fn await_scan(
        &self,
        caller: Principal,
        subaccount: [u8; 32],
        token: SupportedToken,
        deadline: Duration,
    ) -> DepositErc20Response {
        let start = Instant::now();
        loop {
            let progress = self.deposit_erc20(caller, subaccount, token);
            let scanned = match &progress.status {
                DepositStatus::Scanning { scan_count, .. } => *scan_count >= 1,
                DepositStatus::AwaitingSweep(_) => true,
            };
            if scanned {
                return progress;
            }
            assert!(
                start.elapsed() <= deadline,
                "the deposit address was not scanned within {deadline:?}"
            );
            std::thread::sleep(Duration::from_secs(2));
        }
    }
}
