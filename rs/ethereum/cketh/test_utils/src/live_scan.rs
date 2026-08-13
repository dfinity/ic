//! Wraps the shared [`crate::CkEthSetup`] fixture, built in live mode, into a harness for the
//! ckERC20 balance scan, driving *real* canister outcalls against a local anvil node that
//! [`LiveBalanceScanSetup`] owns (see [`crate::anvil`]).
//!
//! Unlike [`crate::ckerc20::CkErc20Setup`] — which also runs on PocketIC but answers the EVM RPC
//! canister's JSON-RPC outcalls with canned canister-http mocks ([`crate::mock::MockJsonRpcProviders`])
//! — this harness runs PocketIC in *live* mode so the EVM RPC canister makes genuine outcalls
//! through the IC's HTTPS-outcalls feature, and installs it with an `overrideProvider` that
//! rewrites every provider URL to the harness' anvil node (reached over HTTP, mirroring the
//! `evm_rpc_local` configuration of the EVM RPC canister). The minter therefore reads real
//! Ethereum state from anvil, exercising the balance scan end to end: minter → EVM RPC canister →
//! anvil.
//!
//! Only the minter and the EVM RPC canister are installed. The full ckERC20 feature is activated by
//! pointing the minter's ledger-suite-orchestrator id at a principal this harness controls, so
//! supported tokens can be registered directly via `add_ckerc20_token` without a real orchestrator
//! or any spawned ledgers — the balance scan only needs the token contract addresses in the
//! minter's state.

use candid::{Decode, Encode, Nat, Principal};
use ic_base_types::PrincipalId;
use ic_cketh_minter::endpoints::{
    AddCkErc20Token, DepositErc20Arg, DepositErc20Error, DepositErc20Response, DepositMode,
};
use ic_cketh_minter::lifecycle::MinterArg;
use ic_cketh_minter::lifecycle::upgrade::UpgradeArg;
use ic_cketh_minter::numeric::Erc20Value;
use ic_ethereum_types::Address;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::anvil::{
    Anvil, DEV_ACCOUNT, address_from_hex, deploy_mock_erc20, erc20_balance_slot, u256_be,
};
use crate::{
    CkEthSetup, ERC20_HELPER_CONTRACT_ADDRESS, EthereumBackend, USDC_ERC20_CONTRACT_ADDRESS,
    live_controller, minter_wasm,
};

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

    fn contract(self) -> Address {
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

/// Wraps the shared [`CkEthSetup`] fixture — built in live mode against an owned anvil node — with
/// the balance-scan test's own state: the anvil node itself, kept alive for the harness' lifetime.
///
/// `cketh` is declared first so it drops first: the PocketIC instance goes away, and only then does
/// the node its canisters were calling out to.
pub struct LiveBalanceScanSetup {
    cketh: CkEthSetup,
    anvil: Arc<Anvil>,
}

impl LiveBalanceScanSetup {
    /// Starts a local anvil node and builds the shared [`CkEthSetup`] fixture in live mode against
    /// it (installing only the minter and EVM RPC canister), then activates the ckERC20 feature and
    /// registers ckUSDC/ckUSDT so the EVM RPC canister's outcalls reach anvil for real.
    pub fn new_live() -> Self {
        let anvil = Arc::new(Anvil::start());
        let cketh = CkEthSetup::builder()
            .with_ethereum_backend(EthereumBackend::Anvil(Arc::clone(&anvil)))
            .build();
        activate_ckerc20(&cketh);
        register_supported_tokens(&cketh);

        Self { cketh, anvil }
    }

    /// A distinct non-anonymous depositing principal for `seed`, so a test can register several
    /// independent deposit addresses.
    pub fn depositor(&self, seed: u64) -> Principal {
        PrincipalId::new_user_test_id(seed).into()
    }

    /// Registers a deposit address for `caller`'s `subaccount` and returns the Ethereum address the
    /// minter derived for it.
    pub fn register_deposit_address(&self, caller: Principal, subaccount: [u8; 32]) -> Address {
        Address::from_str(&self.deposit_erc20(caller, subaccount).address)
            .expect("BUG: minter returned an invalid deposit address")
    }

    /// Calls `deposit_erc20` as `caller`, which registers (idempotently) that user's deposit
    /// address for balance scanning and reports its scan progress.
    pub fn deposit_erc20(&self, caller: Principal, subaccount: [u8; 32]) -> DepositErc20Response {
        let arg = DepositErc20Arg {
            mode: DepositMode::Unsponsored {
                subaccount: Some(subaccount),
            },
        };
        let reply = self
            .cketh
            .env
            .update_call(
                self.cketh.minter_id,
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
        // Every registered address is scanned against both tokens, so a token without code would
        // revert the whole scan even for addresses that do not hold it.
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
    /// observed through `deposit_erc20`'s own scan progress — and returns that progress. A failing
    /// batch never advances an address, so `scan_count >= 1` already proves the `eth_call` against
    /// anvil succeeded and decoded. Panics if no scan completes within `deadline`.
    ///
    /// Whether the address' balance made it a deposit *candidate* is not surfaced by
    /// `deposit_erc20`; read that from [`Self::balance_scan_candidates`].
    pub fn await_scan(
        &self,
        caller: Principal,
        subaccount: [u8; 32],
        deadline: Duration,
    ) -> DepositErc20Response {
        let start = Instant::now();
        loop {
            let progress = self.deposit_erc20(caller, subaccount);
            if progress.scan_count >= 1 {
                return progress;
            }
            assert!(
                start.elapsed() <= deadline,
                "the deposit address was not scanned within {deadline:?}"
            );
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    /// The greatest number of deposit candidates any balance scan reported, parsed from the
    /// minter's `[balance_scan]` logs — the scan only logs the count, it is not otherwise exposed.
    /// `deposit_erc20` reports that an address was scanned but not whether its balance cleared the
    /// candidate threshold. `0` if no scan has logged a count yet.
    pub fn balance_scan_candidates(&self) -> u64 {
        // Canister logs are controller-only by default, so query them as the controller.
        self.cketh
            .env
            .fetch_canister_logs(self.cketh.minter_id, live_controller())
            .expect("BUG: fetching the minter's canister logs failed")
            .into_iter()
            .filter_map(|record| candidates_in_log(&String::from_utf8_lossy(&record.content)))
            .max()
            .unwrap_or(0)
    }
}

/// Extracts `N` from a `[balance_scan]: ... found N candidate(s) ...` log line, or `None` for any
/// other line.
fn candidates_in_log(line: &str) -> Option<u64> {
    if !line.contains("[balance_scan]") {
        return None;
    }
    line.split("found ")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Activates the ckERC20 feature by pointing the minter's orchestrator id at [`live_controller`]
/// (so this harness can register tokens) and setting the ERC-20 deposit helper contract.
fn activate_ckerc20(cketh: &CkEthSetup) {
    let upgrade = UpgradeArg {
        ledger_suite_orchestrator_id: Some(live_controller()),
        erc20_helper_contract_address: Some(ERC20_HELPER_CONTRACT_ADDRESS.to_string()),
        ..Default::default()
    };
    cketh
        .env
        .upgrade_canister(
            cketh.minter_id,
            minter_wasm(),
            Encode!(&MinterArg::UpgradeArg(upgrade)).unwrap(),
            Some(live_controller()),
        )
        .expect("BUG: failed to activate the ckERC20 feature");
}

fn register_supported_tokens(cketh: &CkEthSetup) {
    for (address, symbol) in [
        (USDC_ERC20_CONTRACT_ADDRESS, "ckUSDC"),
        (USDT_ERC20_CONTRACT_ADDRESS, "ckUSDT"),
    ] {
        let arg = AddCkErc20Token {
            chain_id: Nat::from(1_u8),
            address: address.to_string(),
            ckerc20_token_symbol: symbol.to_string(),
            // A distinct placeholder ledger per token: the minter rejects duplicate ledger ids and
            // never calls these on the balance-scan path.
            ckerc20_ledger_id: cketh.env.create_canister(),
        };
        cketh
            .add_ckerc20_token(live_controller(), &arg)
            .expect("BUG: add_ckerc20_token was rejected");
    }
}
