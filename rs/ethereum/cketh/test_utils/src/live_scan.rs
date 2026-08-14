//! A live [`PocketIc`] harness for the ckERC20 balance scan, driving *real* canister outcalls
//! against a local anvil node that the harness owns (see [`crate::anvil`]).
//!
//! Unlike [`crate::ckerc20::CkErc20Setup`] — which runs on `StateMachine` and answers the EVM RPC
//! canister's JSON-RPC outcalls with canned mocks ([`crate::mock::MockJsonRpcProviders`]) — this
//! harness runs PocketIC in *live* mode so the EVM RPC canister makes genuine outcalls through the
//! IC's HTTPS-outcalls feature, and installs it with an `overrideProvider` that rewrites every
//! provider URL to the harness' anvil node (reached over HTTP, mirroring the `evm_rpc_local`
//! configuration of the EVM RPC canister). The minter therefore reads real Ethereum state from
//! anvil, exercising the balance scan end to end: minter → EVM RPC canister → anvil.
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
    DepositStatus,
};
use ic_cketh_minter::lifecycle::upgrade::UpgradeArg;
use ic_cketh_minter::lifecycle::{EthereumNetwork, MinterArg, init::InitArg as MinterInitArgs};
use ic_cketh_minter::numeric::Erc20Value;
use ic_ethereum_types::Address;
use pocket_ic::{CanisterSettings, PocketIc, PocketIcBuilder};
use std::str::FromStr;
use std::time::{Duration, Instant};

use crate::anvil::{
    Anvil, DEV_ACCOUNT, address_from_hex, deploy_mock_erc20, erc20_balance_slot, u256_be,
};
use crate::{
    CKETH_MINIMUM_WITHDRAWAL_AMOUNT, ERC20_HELPER_CONTRACT_ADDRESS, ETH_HELPER_CONTRACT_ADDRESS,
    USDC_ERC20_CONTRACT_ADDRESS, evm_rpc_wasm, minter_wasm,
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

/// PocketIC's fiduciary subnet holds the secp256k1 test key named `key_1`, the key the minter
/// derives deposit addresses from.
const ECDSA_KEY_NAME: &str = "key_1";

/// A fixed non-anonymous principal used as the canisters' controller and as the minter's stand-in
/// ledger-suite-orchestrator id, so this harness can register supported tokens itself.
fn controller() -> Principal {
    Principal::from_slice(&[0x0a; 10])
}

pub struct CkErc20LiveScanSetup {
    env: PocketIc,
    anvil: Anvil,
    minter_id: Principal,
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

        let settings = CanisterSettings {
            controllers: Some(vec![controller()]),
            ..Default::default()
        };

        // A placeholder ckETH ledger: the minter stores its id at init but never calls it on the
        // balance-scan path, so it is left uninstalled.
        let ledger_id = env.create_canister();
        let evm_rpc_id =
            env.create_canister_with_settings(Some(controller()), Some(settings.clone()));
        env.add_cycles(evm_rpc_id, u128::from(u64::MAX));
        install_evm_rpc(&env, evm_rpc_id, anvil.url());

        let minter_id = env.create_canister_with_settings(Some(controller()), Some(settings));
        env.add_cycles(minter_id, u128::from(u64::MAX));

        // Go live *before* installing the minter: its install schedules immediate refresh and
        // balance-scan timers that issue HTTPS outcalls, which would stall (holding the task guards)
        // if they fired while the outcalls could not be answered.
        let _gateway = env.make_live(None);

        install_minter(&env, minter_id, ledger_id, evm_rpc_id);
        activate_ckerc20(&env, minter_id);
        register_supported_tokens(&env, minter_id);

        Self {
            env,
            anvil,
            minter_id,
        }
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

fn install_evm_rpc(env: &PocketIc, evm_rpc_id: Principal, anvil_url: &str) {
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
        Some(controller()),
    );
}

fn install_minter(
    env: &PocketIc,
    minter_id: Principal,
    ledger_id: Principal,
    evm_rpc_id: Principal,
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
        Some(controller()),
    );
}

/// Activates the ckERC20 feature by pointing the minter's orchestrator id at [`controller`] (so
/// this harness can register tokens) and setting the ERC-20 deposit helper contract.
fn activate_ckerc20(env: &PocketIc, minter_id: Principal) {
    let upgrade = UpgradeArg {
        ledger_suite_orchestrator_id: Some(controller()),
        erc20_helper_contract_address: Some(ERC20_HELPER_CONTRACT_ADDRESS.to_string()),
        ..Default::default()
    };
    env.upgrade_canister(
        minter_id,
        minter_wasm(),
        Encode!(&MinterArg::UpgradeArg(upgrade)).unwrap(),
        Some(controller()),
    )
    .expect("BUG: failed to activate the ckERC20 feature");
}

fn register_supported_tokens(env: &PocketIc, minter_id: Principal) {
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
            controller(),
            "add_ckerc20_token",
            Encode!(&arg).unwrap(),
        )
        .expect("BUG: add_ckerc20_token was rejected");
    }
}
