use candid::{Decode, Encode, Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_suite_orchestrator::candid::{
    AddErc20Arg, Erc20Contract, InitArg, ManagedCanisterIds, OrchestratorArg,
};
use ic_state_machine_tests::{
    CanisterStatusResultV2, Cycles, StateMachine, StateMachineBuilder, WasmResult,
};
use ic_test_utilities_load_wasm::load_wasm;
use std::path::PathBuf;

const MAX_TICKS: usize = 10;

#[test]
fn should_install_orchestrator_and_add_supported_erc20_tokens() {
    let mut orchestrator = LedgerSuiteOrchestrator::new();

    for contract in supported_erc20_tokens() {
        orchestrator = orchestrator
            .add_erc20_token(AddErc20Arg { contract })
            .expect_new_ledger_and_index_canisters()
            .assert_all_controlled_by_orchestrator()
            .assert_ledger_icrc1_total_supply_is(0_u8)
            .assert_index_has_correct_ledger_id()
            .setup;
    }
}

pub struct LedgerSuiteOrchestrator {
    pub env: StateMachine,
    pub ledger_suite_orchestrator_id: CanisterId,
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
    let args = OrchestratorArg::InitArg(InitArg {
        ledger_wasm: ledger_wasm(),
        index_wasm: index_wasm(),
        archive_wasm: archive_wasm(),
    });
    env.install_existing_canister(
        ledger_suite_orchestrator_id,
        ledger_suite_orchestrator_wasm(),
        Encode!(&args).unwrap(),
    )
    .unwrap();
}

fn ledger_wasm() -> Vec<u8> {
    load_wasm(icrc1_path().join("ledger"), "ic-icrc1-ledger", &[])
}

fn index_wasm() -> Vec<u8> {
    load_wasm(icrc1_path().join("index-ng"), "ic-icrc1-index-ng", &[])
}

fn icrc1_path() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("rosetta-api")
        .join("icrc1")
}

fn archive_wasm() -> Vec<u8> {
    //TODO: remove archive wasm from init args
    vec![]
}

fn ledger_suite_orchestrator_wasm() -> Vec<u8> {
    load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ledger_suite_orchestrator",
        &[],
    )
}

fn supported_erc20_tokens() -> Vec<Erc20Contract> {
    vec![usdc(), usdt()]
}

fn usdc() -> Erc20Contract {
    Erc20Contract {
        chain_id: Nat::from(1_u8),
        address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
    }
}

fn usdt() -> Erc20Contract {
    Erc20Contract {
        chain_id: Nat::from(1_u8),
        address: "0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string(),
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

    pub fn assert_ledger_icrc1_total_supply_is<T: Into<Nat>>(self, expected: T) -> Self {
        assert!(self.call_ledger_icrc1_total_supply() == expected.into());
        self
    }

    pub fn assert_index_has_correct_ledger_id(self) -> Self {
        assert_eq!(self.call_index_ledger_id(), self.canister_ids.ledger);
        self
    }

    fn call_ledger_icrc1_total_supply(&self) -> Nat {
        Decode!(
            &assert_reply(
                self.setup
                    .env
                    .query(
                        self.ledger_canister_id(),
                        "icrc1_total_supply",
                        Encode!().unwrap()
                    )
                    .expect("failed to query get_transactions on the ledger")
            ),
            Nat
        )
        .unwrap()
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
        CanisterId::unchecked_from_principal(PrincipalId::from(self.canister_ids.ledger))
    }

    fn index_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(PrincipalId::from(self.canister_ids.index))
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

fn assert_reply(result: WasmResult) -> Vec<u8> {
    match result {
        WasmResult::Reply(bytes) => bytes,
        WasmResult::Reject(reject) => {
            panic!("Expected a successful reply, got a reject: {}", reject)
        }
    }
}
