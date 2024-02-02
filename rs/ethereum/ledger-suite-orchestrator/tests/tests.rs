use candid::{Decode, Encode, Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_ledger::FeatureFlags as LedgerFeatureFlags;
use ic_ledger_suite_orchestrator::candid::{
    AddErc20Arg, Erc20Contract, InitArg, LedgerInitArg, ManagedCanisterIds, OrchestratorArg,
};
use ic_ledger_suite_orchestrator::state::{Wasm, WasmHash};
use ic_state_machine_tests::{
    CanisterStatusResultV2, Cycles, StateMachine, StateMachineBuilder, WasmResult,
};
use ic_test_utilities_load_wasm::load_wasm;
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue as LedgerMetadataValue;
use icrc_ledger_types::icrc1::account::Account as LedgerAccount;
use std::str::FromStr;

const MAX_TICKS: usize = 10;

#[test]
fn should_install_orchestrator_and_add_supported_erc20_tokens() {
    let mut orchestrator = LedgerSuiteOrchestrator::new();
    let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();

    for token in supported_erc20_tokens(embedded_ledger_wasm_hash, embedded_index_wasm_hash) {
        orchestrator = orchestrator
            .add_erc20_token(token)
            .expect_new_ledger_and_index_canisters()
            .assert_all_controlled_by_orchestrator()
            .assert_ledger_icrc1_total_supply(0_u8)
            .assert_index_has_correct_ledger_id()
            .setup;
    }
}

#[test]
fn should_spawn_ledger_with_correct_init_args() {
    const CKETH_TOKEN_LOGO: &str = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTQ2IiBoZWlnaHQ9IjE0NiIgdmlld0JveD0iMCAwIDE0NiAxNDYiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSIxNDYiIGhlaWdodD0iMTQ2IiByeD0iNzMiIGZpbGw9IiMzQjAwQjkiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xNi4zODM3IDc3LjIwNTJDMTguNDM0IDEwNS4yMDYgNDAuNzk0IDEyNy41NjYgNjguNzk0OSAxMjkuNjE2VjEzNS45NEMzNy4zMDg3IDEzMy44NjcgMTIuMTMzIDEwOC42OTEgMTAuMDYwNSA3Ny4yMDUySDE2LjM4MzdaIiBmaWxsPSJ1cmwoI3BhaW50MF9saW5lYXJfMTEwXzU4NikiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik02OC43NjQ2IDE2LjM1MzRDNDAuNzYzOCAxOC40MDM2IDE4LjQwMzcgNDAuNzYzNyAxNi4zNTM1IDY4Ljc2NDZMMTAuMDMwMyA2OC43NjQ2QzEyLjEwMjcgMzcuMjc4NCAzNy4yNzg1IDEyLjEwMjYgNjguNzY0NiAxMC4wMzAyTDY4Ljc2NDYgMTYuMzUzNFoiIGZpbGw9IiMyOUFCRTIiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xMjkuNjE2IDY4LjczNDNDMTI3LjU2NiA0MC43MzM0IDEwNS4yMDYgMTguMzczMyA3Ny4yMDUxIDE2LjMyMzFMNzcuMjA1MSA5Ljk5OTk4QzEwOC42OTEgMTIuMDcyNCAxMzMuODY3IDM3LjI0ODEgMTM1LjkzOSA2OC43MzQzTDEyOS42MTYgNjguNzM0M1oiIGZpbGw9InVybCgjcGFpbnQxX2xpbmVhcl8xMTBfNTg2KSIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTc3LjIzNTQgMTI5LjU4NkMxMDUuMjM2IDEyNy41MzYgMTI3LjU5NiAxMDUuMTc2IDEyOS42NDcgNzcuMTc0OUwxMzUuOTcgNzcuMTc0OUMxMzMuODk3IDEwOC42NjEgMTA4LjcyMiAxMzMuODM3IDc3LjIzNTQgMTM1LjkwOUw3Ny4yMzU0IDEyOS41ODZaIiBmaWxsPSIjMjlBQkUyIi8+CjxwYXRoIGQ9Ik03My4xOTA0IDMxVjYxLjY4MThMOTkuMTIzIDczLjI2OTZMNzMuMTkwNCAzMVoiIGZpbGw9IndoaXRlIiBmaWxsLW9wYWNpdHk9IjAuNiIvPgo8cGF0aCBkPSJNNzMuMTkwNCAzMUw0Ny4yNTQ0IDczLjI2OTZMNzMuMTkwNCA2MS42ODE4VjMxWiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTczLjE5MDQgOTMuMTUyM1YxMTRMOTkuMTQwMyA3OC4wOTg0TDczLjE5MDQgOTMuMTUyM1oiIGZpbGw9IndoaXRlIiBmaWxsLW9wYWNpdHk9IjAuNiIvPgo8cGF0aCBkPSJNNzMuMTkwNCAxMTRWOTMuMTQ4OEw0Ny4yNTQ0IDc4LjA5ODRMNzMuMTkwNCAxMTRaIiBmaWxsPSJ3aGl0ZSIvPgo8cGF0aCBkPSJNNzMuMTkwNCA4OC4zMjY5TDk5LjEyMyA3My4yNjk2TDczLjE5MDQgNjEuNjg4N1Y4OC4zMjY5WiIgZmlsbD0id2hpdGUiIGZpbGwtb3BhY2l0eT0iMC4yIi8+CjxwYXRoIGQ9Ik00Ny4yNTQ0IDczLjI2OTZMNzMuMTkwNCA4OC4zMjY5VjYxLjY4ODdMNDcuMjU0NCA3My4yNjk2WiIgZmlsbD0id2hpdGUiIGZpbGwtb3BhY2l0eT0iMC42Ii8+CjxkZWZzPgo8bGluZWFyR3JhZGllbnQgaWQ9InBhaW50MF9saW5lYXJfMTEwXzU4NiIgeDE9IjUzLjQ3MzYiIHkxPSIxMjIuNzkiIHgyPSIxNC4wMzYyIiB5Mj0iODkuNTc4NiIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPgo8c3RvcCBvZmZzZXQ9IjAuMjEiIHN0b3AtY29sb3I9IiNFRDFFNzkiLz4KPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjNTIyNzg1Ii8+CjwvbGluZWFyR3JhZGllbnQ+CjxsaW5lYXJHcmFkaWVudCBpZD0icGFpbnQxX2xpbmVhcl8xMTBfNTg2IiB4MT0iMTIwLjY1IiB5MT0iNTUuNjAyMSIgeDI9IjgxLjIxMyIgeTI9IjIyLjM5MTQiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIj4KPHN0b3Agb2Zmc2V0PSIwLjIxIiBzdG9wLWNvbG9yPSIjRjE1QTI0Ii8+CjxzdG9wIG9mZnNldD0iMC42ODQxIiBzdG9wLWNvbG9yPSIjRkJCMDNCIi8+CjwvbGluZWFyR3JhZGllbnQ+CjwvZGVmcz4KPC9zdmc+Cg==";

    // Adapted from ckETH ledger init args https://dashboard.internetcomputer.org/proposal/126309
    let realistic_usdc_ledger_init_arg = LedgerInitArg {
        minting_account: LedgerAccount {
            owner: Principal::from_str("sv3dd-oaaaa-aaaar-qacoa-cai").unwrap(),
            subaccount: None,
        },
        fee_collector_account: Some(LedgerAccount {
            owner: Principal::from_str("sv3dd-oaaaa-aaaar-qacoa-cai").unwrap(),
            subaccount: Some([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0xf, 0xe, 0xe,
            ]),
        }),
        initial_balances: vec![],
        transfer_fee: 2_000_000_000_000_u64.into(),
        decimals: Some(6),
        token_name: "USD Coin".to_string(),
        token_symbol: "USDC".to_string(),
        token_logo: CKETH_TOKEN_LOGO.to_string(),
        max_memo_length: Some(80),
        feature_flags: Some(LedgerFeatureFlags { icrc2: true }),
        maximum_number_of_accounts: None,
        accounts_overflow_trim_quantity: None,
    };

    let orchestrator = LedgerSuiteOrchestrator::new();
    let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();
    orchestrator
        .add_erc20_token(AddErc20Arg {
            contract: usdc_erc20_contract(),
            ledger_init_arg: realistic_usdc_ledger_init_arg,
            ledger_compressed_wasm_hash: embedded_ledger_wasm_hash.to_string(),
            index_compressed_wasm_hash: embedded_index_wasm_hash.to_string(),
        })
        .expect_new_ledger_and_index_canisters()
        .assert_ledger_icrc1_fee(2_000_000_000_000_u64)
        .assert_ledger_icrc1_decimals(6_u8)
        .assert_ledger_icrc1_name("USD Coin")
        .assert_ledger_icrc1_symbol("USDC")
        .assert_ledger_icrc1_total_supply(0_u8)
        .assert_ledger_icrc1_minting_account(LedgerAccount {
            owner: Principal::from_str("sv3dd-oaaaa-aaaar-qacoa-cai").unwrap(),
            subaccount: None,
        })
        .assert_ledger_icrc1_metadata(vec![
            (
                "icrc1:logo".to_string(),
                LedgerMetadataValue::from(CKETH_TOKEN_LOGO),
            ),
            (
                "icrc1:decimals".to_string(),
                LedgerMetadataValue::from(6_u64),
            ),
            (
                "icrc1:name".to_string(),
                LedgerMetadataValue::from("USD Coin"),
            ),
            (
                "icrc1:symbol".to_string(),
                LedgerMetadataValue::from("USDC"),
            ),
            (
                "icrc1:fee".to_string(),
                LedgerMetadataValue::from(2_000_000_000_000_u64),
            ),
            (
                "icrc1:max_memo_length".to_string(),
                LedgerMetadataValue::from(80_u64),
            ),
        ]);
}

pub struct LedgerSuiteOrchestrator {
    pub env: StateMachine,
    pub ledger_suite_orchestrator_id: CanisterId,
    pub embedded_ledger_wasm_hash: WasmHash,
    pub embedded_index_wasm_hash: WasmHash,
}

impl Default for LedgerSuiteOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl LedgerSuiteOrchestrator {
    pub fn new() -> Self {
        let env = StateMachineBuilder::new()
            .with_default_canister_range()
            .build();
        let ledger_suite_orchestrator_id =
            env.create_canister_with_cycles(None, Cycles::new(u128::MAX), None);
        install_ledger_orchestrator(&env, ledger_suite_orchestrator_id);
        Self {
            env,
            ledger_suite_orchestrator_id,
            embedded_ledger_wasm_hash: ledger_wasm().hash().clone(),
            embedded_index_wasm_hash: index_wasm().hash().clone(),
        }
    }

    fn upgrade_ledger_suite_orchestrator(self, upgrade_arg: &OrchestratorArg) -> Self {
        self.env.tick(); //tick before upgrade to finish current timers which are reset afterwards
        self.env
            .upgrade_canister(
                self.ledger_suite_orchestrator_id,
                ledger_suite_orchestrator_wasm(),
                Encode!(upgrade_arg).unwrap(),
            )
            .expect("Failed to upgrade ledger suite orchestrator");
        self
    }

    pub fn add_erc20_token(self, params: AddErc20Arg) -> AddErc20TokenFlow {
        let setup =
            self.upgrade_ledger_suite_orchestrator(&OrchestratorArg::AddErc20Arg(params.clone()));
        AddErc20TokenFlow { setup, params }
    }

    pub fn call_orchestrator_canister_ids(
        &self,
        contract: &Erc20Contract,
    ) -> Option<ManagedCanisterIds> {
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress(
                        self.ledger_suite_orchestrator_id,
                        "canister_ids",
                        Encode!(contract).unwrap()
                    )
                    .expect("failed to execute token transfer")
            ),
            Option<ManagedCanisterIds>
        )
        .unwrap()
    }

    pub fn canister_status_of(&self, controlled_canister_id: CanisterId) -> CanisterStatusResultV2 {
        self.env
            .canister_status_as(
                self.ledger_suite_orchestrator_id.into(),
                controlled_canister_id,
            )
            .unwrap()
            .unwrap()
    }
}

fn install_ledger_orchestrator(env: &StateMachine, ledger_suite_orchestrator_id: CanisterId) {
    let args = OrchestratorArg::InitArg(InitArg {});
    env.install_existing_canister(
        ledger_suite_orchestrator_id,
        ledger_suite_orchestrator_wasm(),
        Encode!(&args).unwrap(),
    )
    .unwrap();
}

fn ledger_suite_orchestrator_wasm() -> Vec<u8> {
    load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ledger_suite_orchestrator",
        &[],
    )
}

fn ledger_wasm() -> Wasm {
    Wasm::from(load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ledger_canister",
        &[],
    ))
}

fn index_wasm() -> Wasm {
    Wasm::from(load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "index_canister",
        &[],
    ))
}
fn supported_erc20_tokens(
    ledger_compressed_wasm_hash: WasmHash,
    index_compressed_wasm_hash: WasmHash,
) -> Vec<AddErc20Arg> {
    vec![
        usdc(
            ledger_compressed_wasm_hash.clone(),
            index_compressed_wasm_hash.clone(),
        ),
        usdt(ledger_compressed_wasm_hash, index_compressed_wasm_hash),
    ]
}

fn usdc(
    ledger_compressed_wasm_hash: WasmHash,
    index_compressed_wasm_hash: WasmHash,
) -> AddErc20Arg {
    AddErc20Arg {
        contract: usdc_erc20_contract(),
        ledger_init_arg: ledger_init_arg("USD Coin", "USDC"),
        ledger_compressed_wasm_hash: ledger_compressed_wasm_hash.to_string(),
        index_compressed_wasm_hash: index_compressed_wasm_hash.to_string(),
    }
}

fn usdc_erc20_contract() -> Erc20Contract {
    Erc20Contract {
        chain_id: Nat::from(1_u8),
        address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
    }
}

fn usdt(
    ledger_compressed_wasm_hash: WasmHash,
    index_compressed_wasm_hash: WasmHash,
) -> AddErc20Arg {
    AddErc20Arg {
        contract: Erc20Contract {
            chain_id: Nat::from(1_u8),
            address: "0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string(),
        },
        ledger_init_arg: ledger_init_arg("Tether USD", "USDT"),
        ledger_compressed_wasm_hash: ledger_compressed_wasm_hash.to_string(),
        index_compressed_wasm_hash: index_compressed_wasm_hash.to_string(),
    }
}

fn ledger_init_arg<U: Into<String>, V: Into<String>>(
    token_name: U,
    token_symbol: V,
) -> LedgerInitArg {
    LedgerInitArg {
        minting_account: LedgerAccount {
            owner: Principal::anonymous(),
            subaccount: None,
        },
        fee_collector_account: None,
        initial_balances: vec![],
        transfer_fee: 10_000_u32.into(),
        decimals: None,
        token_name: token_name.into(),
        token_symbol: token_symbol.into(),
        token_logo: "".to_string(),
        max_memo_length: None,
        feature_flags: None,
        maximum_number_of_accounts: None,
        accounts_overflow_trim_quantity: None,
    }
}

pub struct AddErc20TokenFlow {
    setup: LedgerSuiteOrchestrator,
    params: AddErc20Arg,
}

impl AddErc20TokenFlow {
    pub fn expect_new_ledger_and_index_canisters(self) -> ManagedCanistersAssert {
        for _ in 0..MAX_TICKS {
            self.setup.env.tick();
        }

        let canister_ids = self
            .setup
            .call_orchestrator_canister_ids(&self.params.contract)
            .unwrap_or_else(|| {
                panic!(
                    "No managed canister IDs found for contract {:?}",
                    self.params.contract
                )
            });

        assert_ne!(
            canister_ids.ledger, canister_ids.index,
            "BUG: ledger and index canister IDs MUST be different"
        );

        ManagedCanistersAssert {
            setup: self.setup,
            canister_ids,
        }
    }
}

pub struct ManagedCanistersAssert {
    setup: LedgerSuiteOrchestrator,
    canister_ids: ManagedCanisterIds,
}

impl ManagedCanistersAssert {
    pub fn assert_all_controlled_by_orchestrator(self) -> Self {
        for canister_id in self.all_canister_ids() {
            assert_eq!(
                self.setup
                    .canister_status_of(canister_id)
                    .settings()
                    .controllers(),
                vec![self.setup.ledger_suite_orchestrator_id.get()],
                "BUG: unexpected controller for canister {}",
                canister_id
            );
        }
        self
    }

    pub fn assert_index_has_correct_ledger_id(self) -> Self {
        assert_eq!(
            self.call_index_ledger_id(),
            self.canister_ids.ledger.unwrap()
        );
        self
    }

    fn call_index_ledger_id(&self) -> Principal {
        Decode!(
            &assert_reply(
                self.setup
                    .env
                    .query(self.index_canister_id(), "ledger_id", Encode!().unwrap())
                    .expect("failed to query get_transactions on the ledger")
            ),
            Principal
        )
        .unwrap()
    }
    fn ledger_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(PrincipalId::from(self.canister_ids.ledger.unwrap()))
    }

    fn index_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(PrincipalId::from(self.canister_ids.index.unwrap()))
    }

    fn archive_canister_ids(&self) -> Vec<CanisterId> {
        self.canister_ids
            .archives
            .iter()
            .map(|p| CanisterId::unchecked_from_principal(PrincipalId::from(*p)))
            .collect()
    }

    fn all_canister_ids(&self) -> Vec<CanisterId> {
        vec![self.ledger_canister_id(), self.index_canister_id()]
            .into_iter()
            .chain(self.archive_canister_ids())
            .collect()
    }
}

macro_rules! assert_ledger {
    ($name:expr, $ty:ty) => {
        impl ManagedCanistersAssert {
            paste::paste! {
                fn [<call_ledger_$name:snake >](&self) -> $ty {
                    candid::Decode!(
                        &assert_reply(
                            self.setup
                                .env
                                .query(self.ledger_canister_id(), $name, candid::Encode!().unwrap())
                                .expect("failed to query on the ledger")
                        ),
                        $ty
                    )
                    .unwrap()
                }

                fn [<assert_ledger_$name:snake>]<T: Into<$ty>>(self, expected: T) -> Self {
                    assert_eq!(self.[<call_ledger_$name:snake >](), expected.into(), "BUG: unexpected value for ledger {}", stringify!($name));
                    self
                }
            }
        }
    };
}

assert_ledger!("icrc1_name", String);
assert_ledger!("icrc1_symbol", String);
assert_ledger!("icrc1_decimals", u8);
assert_ledger!("icrc1_total_supply", Nat);
assert_ledger!("icrc1_fee", Nat);
assert_ledger!("icrc1_minting_account", Option<LedgerAccount>);
assert_ledger!("icrc1_metadata", Vec<(String, LedgerMetadataValue)>);

fn assert_reply(result: WasmResult) -> Vec<u8> {
    match result {
        WasmResult::Reply(bytes) => bytes,
        WasmResult::Reject(reject) => {
            panic!("Expected a successful reply, got a reject: {}", reject)
        }
    }
}
