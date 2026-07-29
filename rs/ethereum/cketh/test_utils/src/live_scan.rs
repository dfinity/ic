//! A live [`PocketIc`] harness for the ckERC20 balance scan, driving *real* HTTPS outcalls against
//! a local anvil node that the harness owns (see [`crate::anvil`]).
//!
//! Unlike [`crate::ckerc20::CkErc20Setup`] — which runs on `StateMachine` and answers the EVM RPC
//! canister's JSON-RPC outcalls with canned mocks ([`crate::mock::MockJsonRpcProviders`]) — this
//! harness runs PocketIC in *live* mode so the EVM RPC canister issues genuine HTTPS outcalls, and
//! installs it with an `overrideProvider` that rewrites every provider URL to the harness' anvil
//! node (mirroring the `evm_rpc_local` configuration of the EVM RPC canister). The minter therefore
//! reads real Ethereum state from anvil, exercising the balance scan end to end: minter → EVM RPC
//! canister → anvil.
//!
//! Only the minter and the EVM RPC canister are installed. The full ckERC20 feature is activated by
//! pointing the minter's ledger-suite-orchestrator id at a principal this harness controls, so
//! supported tokens can be registered directly via `add_ckerc20_token` without a real orchestrator
//! or any spawned ledgers — the balance scan only needs the token contract addresses in the
//! minter's state.

use candid::{Decode, Encode, Nat, Principal};
use evm_rpc_types::{InstallArgs, OverrideProvider, RegexSubstitution};
use ic_base_types::PrincipalId;
use ic_cketh_minter::endpoints::{
    AddCkErc20Token, DepositErc20Arg, DepositErc20Error, DepositErc20Response, DepositMode,
};
use ic_cketh_minter::lifecycle::upgrade::UpgradeArg;
use ic_cketh_minter::lifecycle::{EthereumNetwork, MinterArg, init::InitArg as MinterInitArgs};
use ic_cketh_minter::numeric::Erc20Value;
use ic_ethereum_types::Address;
use ic_http_types::{HttpRequest, HttpResponse};
use pocket_ic::{CanisterSettings, PocketIc, PocketIcBuilder};
use serde_bytes::ByteBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};

use crate::anvil::{
    Anvil, DEV_ACCOUNT, address_from_hex, deploy_mock_erc20, erc20_balance_slot, u256_be,
};
use crate::{
    CKETH_MINIMUM_WITHDRAWAL_AMOUNT, DEFAULT_PRINCIPAL_ID, ERC20_HELPER_CONTRACT_ADDRESS,
    ETH_HELPER_CONTRACT_ADDRESS, USDC_ERC20_CONTRACT_ADDRESS, evm_rpc_wasm, minter_wasm,
};

/// USDT's mainnet address, the second token registered so the scan reads more than one token per
/// address. Matches the ckUSDT contract the minter prices in `balance_scan::MIN_DEPOSITS`.
pub const USDT_ERC20_CONTRACT_ADDRESS: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";

/// PocketIC's fiduciary subnet holds the secp256k1 test key named `key_1`, the key the minter
/// derives deposit addresses from.
const ECDSA_KEY_NAME: &str = "key_1";

pub struct CkErc20LiveScanSetup {
    env: PocketIc,
    anvil: Anvil,
    minter_id: Principal,
    /// The default depositing user, matching [`crate::ckerc20::CkErc20Setup`]'s caller.
    caller: Principal,
}

impl CkErc20LiveScanSetup {
    /// Starts a local anvil node, installs the minter and EVM RPC canister (the latter routed to
    /// anvil via `overrideProvider`), registers ckUSDC/ckUSDT, and switches PocketIC to live mode so
    /// the EVM RPC canister's outcalls reach anvil for real.
    pub fn new_live() -> Self {
        let anvil = Anvil::start();

        let mut env = PocketIcBuilder::new()
            .with_nns_subnet() // make_live requires an NNS subnet.
            .with_fiduciary_subnet() // holds the secp256k1 `key_1` used by the minter.
            .build();

        let controller = Principal::from_slice(&[0x0a; 10]);
        let settings = CanisterSettings {
            controllers: Some(vec![controller]),
            ..Default::default()
        };

        // A placeholder ckETH ledger: the minter stores its id at init but never calls it on the
        // balance-scan path, so it is left uninstalled.
        let ledger_id = env.create_canister();
        let evm_rpc_id =
            env.create_canister_with_settings(Some(controller), Some(settings.clone()));
        env.add_cycles(evm_rpc_id, u128::from(u64::MAX));
        install_evm_rpc(&env, evm_rpc_id, controller, anvil.url());

        let minter_id = env.create_canister_with_settings(Some(controller), Some(settings));
        env.add_cycles(minter_id, u128::from(u64::MAX));

        // Go live *before* installing the minter: its install schedules immediate refresh and
        // balance-scan timers that issue HTTPS outcalls, which would stall (holding the task guards)
        // if they fired while the outcalls could not be answered.
        let _gateway = env.make_live(None);

        install_minter(&env, minter_id, ledger_id, evm_rpc_id, controller);
        activate_ckerc20(&env, minter_id, controller);
        register_supported_tokens(&env, minter_id, controller);

        Self {
            env,
            anvil,
            minter_id,
            caller: PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID).into(),
        }
    }

    /// The default depositing user, matching [`crate::ckerc20::CkErc20Setup`]'s caller.
    pub fn caller(&self) -> Principal {
        self.caller
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
            .env
            .update_call(
                self.minter_id,
                caller,
                "deposit_erc20",
                Encode!(&arg).unwrap(),
            )
            .expect("BUG: deposit_erc20 was rejected");
        Decode!(&reply, Result<DepositErc20Response, DepositErc20Error>)
            .unwrap()
            .expect("BUG: deposit_erc20 returned an error")
    }

    /// Places the supported ERC-20s (ckUSDC, ckUSDT) at their real mainnet addresses on the owned
    /// anvil node and credits `deposit` with `amount` of each, so the scan reads real,
    /// above-threshold balances. Both tokens get code, or the fail-loud batcher would revert the
    /// whole scan.
    pub fn credit_deposit(&self, deposit: &Address, amount: u128) {
        let dev = address_from_hex(DEV_ACCOUNT);
        // Reuse MockUSDT's deployed bytecode to give each token a working `balanceOf`, and credit the
        // deposit address by writing the `balanceOf` mapping slot directly.
        let runtime = self.anvil.code(&deploy_mock_erc20(&self.anvil, &dev));
        let tokens = [USDC_ERC20_CONTRACT_ADDRESS, USDT_ERC20_CONTRACT_ADDRESS]
            .map(|address| Address::from_str(address).unwrap());

        // Write every balance *before* placing any code. The fail-loud batcher only returns a
        // (scan-advancing) result once every token has code — by which point all balances are
        // already in place — so a concurrent scan can never observe a partially-credited address.
        for token in &tokens {
            self.anvil
                .set_storage_at(token, &erc20_balance_slot(deposit), &u256_be(amount));
        }
        for token in &tokens {
            self.anvil.set_code(token, &runtime);
        }
        for token in &tokens {
            assert_eq!(
                self.anvil.erc20_balance(token, deposit),
                Erc20Value::from(amount),
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

    /// The number of deposit candidates the minter's most recent balance scan found, read from its
    /// metrics — `deposit_erc20` reports that an address was scanned but not whether its balance
    /// cleared the candidate threshold. `0` if no scan has recorded statistics yet.
    pub fn balance_scan_candidates(&self) -> u64 {
        gauge(&self.metrics(), "cketh_minter_balance_scan_candidates").unwrap_or(0.0) as u64
    }

    fn metrics(&self) -> String {
        let request = HttpRequest {
            method: "GET".to_string(),
            url: "/metrics".to_string(),
            headers: vec![],
            body: ByteBuf::default(),
        };
        let reply = self
            .env
            .query_call(
                self.minter_id,
                Principal::anonymous(),
                "http_request",
                Encode!(&request).unwrap(),
            )
            .expect("BUG: the metrics query was rejected");
        let response = Decode!(&reply, HttpResponse).unwrap();
        String::from_utf8(response.body.into_vec()).expect("BUG: metrics are not valid UTF-8")
    }
}

fn install_evm_rpc(env: &PocketIc, evm_rpc_id: Principal, controller: Principal, anvil_url: &str) {
    let args = InstallArgs {
        override_provider: Some(OverrideProvider {
            override_url: Some(RegexSubstitution {
                pattern: ".*".into(),
                replacement: anvil_url.to_string(),
            }),
        }),
        ..Default::default()
    };
    env.install_canister(
        evm_rpc_id,
        evm_rpc_wasm(),
        Encode!(&args).unwrap(),
        Some(controller),
    );
}

fn install_minter(
    env: &PocketIc,
    minter_id: Principal,
    ledger_id: Principal,
    evm_rpc_id: Principal,
    controller: Principal,
) {
    let args = MinterInitArgs {
        ethereum_network: EthereumNetwork::Mainnet,
        ecdsa_key_name: ECDSA_KEY_NAME.to_string(),
        ethereum_contract_address: Some(ETH_HELPER_CONTRACT_ADDRESS.to_string()),
        ledger_id,
        // anvil is a fresh chain with no finalized blocks, so track its "latest" head.
        ethereum_block_height: ic_cketh_minter::endpoints::CandidBlockTag::Latest,
        minimum_withdrawal_amount: Nat::from(CKETH_MINIMUM_WITHDRAWAL_AMOUNT),
        next_transaction_nonce: Nat::from(0_u8),
        last_scraped_block_number: Nat::from(0_u8),
        evm_rpc_id: Some(evm_rpc_id),
    };
    env.install_canister(
        minter_id,
        minter_wasm(),
        Encode!(&MinterArg::InitArg(args)).unwrap(),
        Some(controller),
    );
}

/// Activates the ckERC20 feature by pointing the minter's orchestrator id at `controller` (so this
/// harness can register tokens) and setting the ERC-20 deposit helper contract.
fn activate_ckerc20(env: &PocketIc, minter_id: Principal, controller: Principal) {
    let upgrade = UpgradeArg {
        ledger_suite_orchestrator_id: Some(controller),
        erc20_helper_contract_address: Some(ERC20_HELPER_CONTRACT_ADDRESS.to_string()),
        ..Default::default()
    };
    env.upgrade_canister(
        minter_id,
        minter_wasm(),
        Encode!(&MinterArg::UpgradeArg(upgrade)).unwrap(),
        Some(controller),
    )
    .expect("BUG: failed to activate the ckERC20 feature");
}

fn register_supported_tokens(env: &PocketIc, minter_id: Principal, controller: Principal) {
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
            ckerc20_ledger_id: env.create_canister(),
        };
        env.update_call(
            minter_id,
            controller,
            "add_ckerc20_token",
            Encode!(&arg).unwrap(),
        )
        .expect("BUG: add_ckerc20_token was rejected");
    }
}

/// Reads the value of a Prometheus gauge line `"<name> <value> [timestamp]"`, or `None` if the
/// metric is absent (e.g. no balance scan has run yet).
fn gauge(metrics: &str, name: &str) -> Option<f64> {
    metrics.lines().find_map(|line| {
        let rest = line.strip_prefix(name)?;
        rest.strip_prefix(' ')?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}
