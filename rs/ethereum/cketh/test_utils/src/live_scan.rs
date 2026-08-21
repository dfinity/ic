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
    Anvil, DEV_ACCOUNT, SweepContracts, address_from_hex, deploy_mock_erc20,
    deploy_sweep_contracts, erc20_balance_slot, u256_be,
};
use crate::ckerc20::{CkErc20Setup, Erc20Token};
use crate::{CkEthSetup, EthereumBackend, MINTER_ADDRESS};

/// A balance to place on the owned anvil node: `amount` of `token` credited to the `deposit`
/// address, so the scan reads a real balance for that (address, token) pair.
pub struct Holding<'a> {
    pub deposit: Address,
    pub token: &'a Erc20Token,
    pub amount: u128,
}

/// `token.contract.address`, parsed: every canister and anvil call the harness makes needs an
/// [`Address`], not the raw string the orchestrator registered the token with.
fn contract_address(token: &Erc20Token) -> Address {
    Address::from_str(&token.contract.address)
        .expect("BUG: registered token has an invalid contract address")
}

/// Wraps the shared [`CkErc20Setup`] fixture — built against an owned anvil node — with the
/// balance-scan test's own state: the anvil node itself, kept alive for the harness' lifetime.
///
/// `ckerc20` is declared first so it drops first: the PocketIC instance goes away, and only then
/// does the node its canisters were calling out to.
pub struct LiveBalanceScanSetup {
    ckerc20: CkErc20Setup,
    anvil: Arc<Anvil>,
    sweep_contracts: Option<SweepContracts>,
}

impl LiveBalanceScanSetup {
    /// Starts a local anvil node and builds the full [`CkErc20Setup`] fixture against it — minter,
    /// EVM RPC canister, orchestrator, and the ckUSDC/ckUSDT ledger and index canisters it spawns —
    /// on an ordinary (non-live) PocketIC instance, then switches that instance to live outcalls
    /// now that construction is complete, so the EVM RPC canister's outcalls reach anvil for real
    /// from this point on.
    pub fn new_live() -> Self {
        Self::build(None)
    }

    /// Like [`Self::new_live`], but with the real deposit helper and the attested sweeper delegate
    /// deployed on the node first, so the minter is installed knowing both, and with the minter's
    /// dedicated sweeper address pre-funded with `sweeper_gas_wei` of ETH.
    ///
    /// Funding the sweeper directly is a shortcut: in production its gas comes from a ckETH burn out
    /// of the minter's fee account, which is a separate pipeline from sweeping.
    pub fn new_live_with_sweeping(sweeper: &Address, sweeper_gas_wei: u128) -> Self {
        let setup = Self::build(Some(sweeper));
        setup.anvil.set_balance(sweeper, sweeper_gas_wei);
        setup
    }

    fn build(sweeper: Option<&Address>) -> Self {
        let anvil = Arc::new(Anvil::start());
        let sweep_contracts = sweeper.map(|_| {
            // The helper pays out to the minter's main address, which the minter derives from the
            // same key as the sweeper address, so the fixture cannot know it before installing the
            // minter. It is only ever read back out of the helper event, never by the helper itself,
            // so the deployment can name the address the test asserts against.
            deploy_sweep_contracts(&anvil, &address_from_hex(MINTER_ADDRESS))
        });
        let cketh = CkEthSetup::new(EthereumBackend::Anvil {
            anvil: Arc::clone(&anvil),
            sweep_contracts,
        });
        let ckerc20 = CkErc20Setup::with_cketh(cketh).add_supported_erc20_tokens();
        let ckerc20 = match sweep_contracts {
            Some(contracts) => ckerc20.add_support_for_subaccount_helper(contracts.helper),
            None => ckerc20,
        };

        ckerc20.env.auto_progress();

        Self {
            ckerc20,
            anvil,
            sweep_contracts,
        }
    }

    /// The contracts the sweep goes through, if this harness deployed them.
    pub fn sweep_contracts(&self) -> SweepContracts {
        self.sweep_contracts
            .expect("BUG: this harness was built without sweeping")
    }

    /// The owned anvil node, so a test can read balances and code straight off the chain.
    pub fn anvil(&self) -> &Anvil {
        &self.anvil
    }

    /// A distinct non-anonymous depositing principal for `seed`, so a test can register several
    /// independent deposit addresses.
    pub fn depositor(&self, seed: u64) -> Principal {
        PrincipalId::new_user_test_id(seed).into()
    }

    /// The tokens the orchestrator actually registered, in registration order — the same set
    /// [`Self::credit_deposits`] gives code on anvil, by construction rather than by convention.
    pub fn supported_erc20_tokens(&self) -> &[Erc20Token] {
        &self.ckerc20.supported_erc20_tokens
    }

    /// Registers a `(caller/subaccount, token)` deposit and returns the Ethereum address the minter
    /// derived for it (shared across the caller's tokens).
    pub fn register_deposit_address(
        &self,
        caller: Principal,
        subaccount: [u8; 32],
        token: &Erc20Token,
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
        token: &Erc20Token,
    ) -> DepositErc20Response {
        let arg = DepositErc20Arg {
            erc20_contract_address: token.contract.address.clone(),
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

    /// Places every token [`Self::supported_erc20_tokens`] returns at its real mainnet address on
    /// the owned anvil node, and credits each holding by writing its `balanceOf` mapping slot
    /// directly.
    ///
    /// Every balance is written *before* any token gets code. The fail-loud batcher only returns a
    /// (scan-advancing) result once every token has code — by which point all balances are already
    /// in place — so a concurrent scan can never observe a partially-credited state.
    pub fn credit_deposits(&self, holdings: &[Holding<'_>]) {
        let dev = address_from_hex(DEV_ACCOUNT);
        // Reuse MockUSDT's deployed bytecode to give each token a working `balanceOf`.
        let runtime = self.anvil.code(&deploy_mock_erc20(&self.anvil, &dev));

        for holding in holdings {
            self.anvil.set_storage_at(
                &contract_address(holding.token),
                &erc20_balance_slot(&holding.deposit),
                &u256_be(holding.amount),
            );
        }
        // Every registered token is read in the shared batch, so a token without code would revert
        // the whole scan even for holdings that do not involve it.
        for token in self.supported_erc20_tokens() {
            self.anvil.set_code(&contract_address(token), &runtime);
        }
        for holding in holdings {
            assert_eq!(
                self.anvil
                    .erc20_balance(&contract_address(holding.token), &holding.deposit),
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
        token: &Erc20Token,
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
