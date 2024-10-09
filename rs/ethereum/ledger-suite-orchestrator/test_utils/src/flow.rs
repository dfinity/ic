use crate::metrics::MetricsAssert;
use crate::universal_canister::UniversalCanister;
use crate::{
    assert_reply, out_of_band_upgrade, stop_canister, LedgerAccount, LedgerMetadataValue,
    LedgerSuiteOrchestrator, MAX_TICKS, MINTER_PRINCIPAL,
};
use candid::{Decode, Encode, Nat, Principal};
use ic_cdk::api::management_canister::main::{CanisterId, CanisterStatusResponse};
use ic_ledger_suite_orchestrator::candid::{AddErc20Arg, ManagedCanisterIds};
use ic_ledger_suite_orchestrator::state::{IndexWasm, LedgerWasm};
use ic_management_canister_types::CanisterInfoResponse;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use icrc_ledger_types::icrc3::archive::ArchiveInfo;
use icrc_ledger_types::icrc3::blocks::{GetBlocksRequest, GetBlocksResult};
use pocket_ic::PocketIc;
use std::collections::BTreeSet;

pub struct AddErc20TokenFlow {
    pub setup: LedgerSuiteOrchestrator,
    pub params: AddErc20Arg,
}

impl AddErc20TokenFlow {
    pub fn expect_new_ledger_and_index_canisters(self) -> ManagedCanistersAssert {
        for _ in 0..MAX_TICKS {
            self.setup.env.tick();
        }
        self.setup.assert_managed_canisters(&self.params.contract)
    }
}

pub struct ManagedCanistersAssert {
    pub setup: LedgerSuiteOrchestrator,
    pub canister_ids: ManagedCanisterIds,
}

impl AsRef<PocketIc> for ManagedCanistersAssert {
    fn as_ref(&self) -> &PocketIc {
        self.setup.env.as_ref()
    }
}

impl ManagedCanistersAssert {
    pub fn assert_all_controlled_by(self, expected_controllers: &[Principal]) -> Self {
        for canister_id in self.all_canister_ids() {
            assert_eq!(
                self.setup
                    .canister_status_of(canister_id)
                    .settings
                    .controllers
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
                expected_controllers
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>(), // convert to set to ignore order
                "BUG: unexpected controller for canister {} in managed canisters {}",
                canister_id,
                self.canister_ids
            );
        }
        self
    }

    pub fn check_metrics(self) -> MetricsAssert<Self> {
        let canister_id = self.setup.ledger_suite_orchestrator_id;
        MetricsAssert::from_querying_metrics(self, canister_id)
    }

    pub fn trigger_creation_of_archive(self) -> Self {
        const ARCHIVE_TRIGGER_THRESHOLD: u64 = 2_000;

        let archive_ids_before: BTreeSet<_> = self
            .call_ledger_archives()
            .into_iter()
            .map(|info| info.canister_id)
            .collect();

        for _i in 0..ARCHIVE_TRIGGER_THRESHOLD {
            let from = MINTER_PRINCIPAL;
            let to = Principal::management_canister();
            self.call_ledger_icrc1_transfer(
                from,
                &TransferArg {
                    from_subaccount: None,
                    to: to.into(),
                    fee: None,
                    created_at_time: None,
                    memo: None,
                    amount: Nat::from(1_u8),
                },
            )
            .expect("BUG: fail to make a transfer to trigger archive creation");
        }

        let archive_ids_after: BTreeSet<_> = self
            .call_ledger_archives()
            .into_iter()
            .map(|info| info.canister_id)
            .collect();
        assert_eq!(
            archive_ids_after.len(),
            archive_ids_before.len() + 1,
            "BUG: expected one more archive canister"
        );
        assert!(archive_ids_before.is_subset(&archive_ids_after));

        Self {
            setup: self.setup,
            canister_ids: ManagedCanisterIds {
                ledger: self.canister_ids.ledger,
                index: self.canister_ids.index,
                archives: Vec::from_iter(archive_ids_after),
            },
        }
    }

    pub fn assert_ledger_canister_info_satisfy<P: FnOnce(&CanisterInfoResponse) -> bool>(
        self,
        caller: &UniversalCanister,
        predicate: P,
    ) -> Self {
        let canister_info = caller.canister_info(self.ledger_canister_id());
        assert!(
            predicate(&canister_info),
            "BUG: ledger canister info does not satisfy predicate. Canister info: {:?}",
            canister_info
        );
        self
    }

    pub fn assert_index_canister_info_satisfy<P: FnOnce(&CanisterInfoResponse) -> bool>(
        self,
        caller: &UniversalCanister,
        predicate: P,
    ) -> Self {
        let canister_info = caller.canister_info(self.index_canister_id());
        assert!(
            predicate(&canister_info),
            "BUG: index canister info does not satisfy predicate. Canister info: {:?}",
            canister_info
        );
        self
    }

    pub fn assert_all_archive_canister_info_satisfy<P: Fn(&CanisterInfoResponse) -> bool>(
        self,
        caller: &UniversalCanister,
        predicate: P,
    ) -> Self {
        assert!(
            !self.canister_ids.archives.is_empty(),
            "BUG: no archive canisters"
        );
        for archive in self.archive_canister_ids() {
            let canister_info = caller.canister_info(archive);
            assert!(
                predicate(&canister_info),
                "BUG: archive canister info does not satisfy predicate. Canister info: {:?}",
                canister_info
            );
        }
        self
    }

    pub fn stop_ledger(self) -> Self {
        stop_canister(
            &self,
            self.setup.ledger_suite_orchestrator_id,
            self.ledger_canister_id(),
        );
        self
    }

    pub fn stop_index(self) -> Self {
        stop_canister(
            &self,
            self.setup.ledger_suite_orchestrator_id,
            self.index_canister_id(),
        );
        self
    }

    pub fn ledger_out_of_band_upgrade<T: Into<Principal>>(
        self,
        controller: T,
        wasm: LedgerWasm,
    ) -> Self {
        out_of_band_upgrade(
            &self,
            controller.into(),
            self.ledger_canister_id(),
            wasm.to_bytes(),
        )
        .expect("failed to upgrade ledger canister");
        self
    }

    pub fn index_out_of_band_upgrade<T: Into<Principal>>(
        self,
        controller: T,
        wasm: IndexWasm,
    ) -> Self {
        out_of_band_upgrade(
            &self,
            controller.into(),
            self.index_canister_id(),
            wasm.to_bytes(),
        )
        .expect("failed to upgrade index canister");
        self
    }

    pub fn call_ledger_icrc1_transfer(
        &self,
        from: Principal,
        arg: &TransferArg,
    ) -> Result<Nat, TransferError> {
        Decode!(
            &assert_reply(
            self.setup.env.update_call(
                self.ledger_canister_id(),
                from,
                "icrc1_transfer",
                Encode!(arg).unwrap()
            )
            .expect("failed to transfer funds")
            ),
            Result<Nat, TransferError>
        )
        .unwrap()
    }

    pub fn call_ledger_icrc3_get_blocks(&self, request: &Vec<GetBlocksRequest>) -> GetBlocksResult {
        Decode!(
            &assert_reply(
                self.setup
                    .env
                    .query_call(
                        self.ledger_canister_id(),
                        Principal::anonymous(),
                        "icrc3_get_blocks",
                        Encode!(request).unwrap()
                    )
                    .expect("failed to call icrc3_get_blocks")
            ),
            GetBlocksResult
        )
        .expect("failed to decode icrc3_get_blocks response")
    }

    fn call_ledger_archives(&self) -> Vec<ArchiveInfo> {
        Decode!(
            &assert_reply(
                self.setup
                    .env
                    .query_call(
                        self.ledger_canister_id(),
                        Principal::anonymous(),
                        "archives",
                        Encode!().unwrap()
                    )
                    .expect("failed to query archives")
            ),
            Vec<ArchiveInfo>
        )
        .expect("failed to decode archives response")
    }

    pub fn assert_index_has_correct_ledger_id(self) -> Self {
        assert_eq!(
            self.call_index_ledger_id(),
            self.canister_ids.ledger.unwrap()
        );
        self
    }

    pub fn ledger_canister_status(&self) -> CanisterStatusResponse {
        self.setup.canister_status_of(self.ledger_canister_id())
    }

    pub fn assert_ledger_has_cycles_close_to(self, expected: u128) -> Self {
        let canister_id = self.ledger_canister_id();
        self.assert_has_cycles_close_to(canister_id, expected);
        self
    }

    pub fn assert_index_has_cycles_close_to(self, expected: u128) -> Self {
        let canister_id = self.index_canister_id();
        self.assert_has_cycles_close_to(canister_id, expected);
        self
    }

    pub fn assert_all_archives_have_cycles_close_to(self, expected: u128) -> Self {
        assert!(
            !self.archive_canister_ids().is_empty(),
            "BUG: no archive canisters"
        );
        for archive in self.archive_canister_ids() {
            self.assert_has_cycles_close_to(archive, expected);
        }
        self
    }

    fn assert_has_cycles_close_to(&self, canister_id: Principal, expected: u128) {
        let actual = self.setup.cycles_of(canister_id);
        assert_approx_eq(actual, expected);
    }

    pub fn assert_ledger_has_wasm_hash<T: AsRef<[u8]>>(self, expected: T) -> Self {
        assert_eq!(
            self.ledger_canister_status().module_hash,
            Some(expected.as_ref().to_vec()),
            "BUG: unexpected wasm hash for ledger canister"
        );
        self
    }

    pub fn assert_index_has_wasm_hash<T: AsRef<[u8]>>(self, expected: T) -> Self {
        assert_eq!(
            self.setup
                .canister_status_of(self.index_canister_id())
                .module_hash,
            Some(expected.as_ref().to_vec()),
            "BUG: unexpected wasm hash for index canister"
        );
        self
    }

    fn call_index_ledger_id(&self) -> Principal {
        Decode!(
            &assert_reply(
                self.setup
                    .env
                    .query_call(
                        self.index_canister_id(),
                        Principal::anonymous(),
                        "ledger_id",
                        Encode!().unwrap()
                    )
                    .expect("failed to query get_transactions on the ledger")
            ),
            Principal
        )
        .unwrap()
    }
    pub fn ledger_canister_id(&self) -> CanisterId {
        self.canister_ids.ledger.unwrap()
    }

    pub fn index_canister_id(&self) -> CanisterId {
        self.canister_ids.index.unwrap()
    }

    pub fn archive_canister_ids(&self) -> Vec<CanisterId> {
        self.canister_ids.archives.clone()
    }

    fn all_canister_ids(&self) -> Vec<CanisterId> {
        vec![self.ledger_canister_id(), self.index_canister_id()]
            .into_iter()
            .chain(self.archive_canister_ids())
            .collect()
    }
}

pub fn assert_approx_eq<U: Into<u128>, V: Into<u128>>(actual: U, expected: V) {
    let actual = actual.into();
    let expected = expected.into();
    let max_diff = expected / 100; // tolerate 1% difference
    assert!(
        actual.abs_diff(expected) <= max_diff,
        "BUG: unexpected amount. Expected {}, got {} but maximum tolerated difference is {}",
        expected,
        actual,
        max_diff
    );
}

macro_rules! assert_ledger {
    ($name:expr, $ty:ty) => {
        paste::paste! {
            pub fn [<call_ledger_$name:snake >](env: &pocket_ic::PocketIc, ledger_canister_id: candid::Principal) -> $ty {
                candid::Decode!(
                    &assert_reply(
                            env
                            .query_call(ledger_canister_id, candid::Principal::anonymous(), $name, candid::Encode!().unwrap())
                            .expect("failed to query on the ledger")
                    ),
                    $ty
                )
                .unwrap()
            }
            impl ManagedCanistersAssert {
                pub fn [<assert_ledger_$name:snake>]<T: Into<$ty>>(self, expected: T) -> Self {
                    assert_eq!([<call_ledger_$name:snake >](&self.setup.env, self.ledger_canister_id()), expected.into(), "BUG: unexpected value for ledger {}", stringify!($name));
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
