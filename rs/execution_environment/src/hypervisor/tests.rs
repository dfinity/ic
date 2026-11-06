//! Matrix tests for the Wasm memory validation performed when a new execution
//! state is created (`Hypervisor::create_execution_state`).
//!
//! A scenario describes an existing Wasm memory (of a canister or of a canister
//! snapshot), the Wasm memory declared by the canister module that this Wasm
//! memory is installed with, and the expected outcome of validating the former
//! against the latter (once for each Wasm execution mode of the canister
//! module). Every scenario is run for every Wasm execution mode of the canister
//! module (Wasm32 and Wasm64) and for every operation that installs an existing
//! Wasm memory into a new execution state: upgrading a canister with the
//! `wasm_memory_persistence: opt keep` upgrade option (which keeps the
//! canister's Wasm memory) and loading a canister snapshot uploaded via its
//! metadata (which restores the snapshot's Wasm memory).
//!
//! Metadata upload is also checked at and above the global Wasm memory cap,
//! independently of the execution mode of the currently installed module.

use candid::{Decode, Encode};
use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::{
    CanisterSettingsArgsBuilder, CanisterSnapshotDataOffset, CanisterUpgradeOptions,
    LoadCanisterSnapshotArgs, Payload, UploadCanisterSnapshotDataArgs,
    UploadCanisterSnapshotMetadataArgs, UploadCanisterSnapshotMetadataResponse,
    WasmMemoryPersistence,
};
use ic_replicated_state::canister_state::WASM_PAGE_SIZE_IN_BYTES;
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder};
use ic_types::{
    CanisterId, MAX_WASM_MEMORY_IN_BYTES, MAX_WASM64_MEMORY_IN_BYTES, SnapshotId,
    ingress::WasmResult,
};
use ic_types_cycles::Cycles;

const CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);

/// The maximum Wasm memory (in Wasm pages) of a canister module in Wasm32 mode.
const MAX_WASM_MEMORY_PAGES: u64 = MAX_WASM_MEMORY_IN_BYTES / WASM_PAGE_SIZE_IN_BYTES as u64;

/// The maximum Wasm memory (in Wasm pages) of a canister module in Wasm64 mode.
/// It is higher than the maximum for Wasm32 mode, i.e. a Wasm memory that is
/// valid for a canister module in Wasm64 mode can be too large for one in
/// Wasm32 mode.
const MAX_WASM64_MEMORY_PAGES: u64 = MAX_WASM64_MEMORY_IN_BYTES / WASM_PAGE_SIZE_IN_BYTES as u64;

/// Converts a number of Wasm pages into a number of bytes.
fn bytes(wasm_memory_pages: u64) -> u64 {
    wasm_memory_pages * WASM_PAGE_SIZE_IN_BYTES as u64
}

/// The Wasm execution mode of a canister module.
#[derive(Copy, Clone, Debug)]
enum WasmMode {
    Wasm32,
    Wasm64,
}

impl WasmMode {
    /// The maximum Wasm memory (in Wasm pages) allowed for this Wasm execution mode.
    fn max_wasm_memory_pages(&self) -> u64 {
        match self {
            WasmMode::Wasm32 => MAX_WASM_MEMORY_PAGES,
            WasmMode::Wasm64 => MAX_WASM64_MEMORY_PAGES,
        }
    }
}

/// The Wasm memory declared by a canister module.
#[derive(Copy, Clone, Debug)]
enum DeclaredWasmMemory {
    /// The canister module declares no Wasm memory.
    None,
    /// The canister module declares a Wasm memory of the given minimum size
    /// (in Wasm pages).
    Min(u64),
}

impl DeclaredWasmMemory {
    /// The minimum size (in Wasm pages) of the declared Wasm memory,
    /// `None` if the canister module declares no Wasm memory.
    fn min_wasm_memory_pages(&self) -> Option<u64> {
        match self {
            DeclaredWasmMemory::None => None,
            DeclaredWasmMemory::Min(pages) => Some(*pages),
        }
    }

    /// The Wasm execution mode of a canister module declaring this Wasm memory
    /// for the given Wasm execution mode: the Wasm execution mode is determined
    /// by the declared Wasm memory and thus a canister module declaring no Wasm
    /// memory always runs in Wasm32 mode.
    fn wasm_mode(&self, wasm_mode: WasmMode) -> WasmMode {
        match self {
            DeclaredWasmMemory::None => WasmMode::Wasm32,
            DeclaredWasmMemory::Min(_) => wasm_mode,
        }
    }

    /// Returns a canister module declaring this Wasm memory for the given Wasm
    /// execution mode. The module supports enhanced orthogonal persistence,
    /// which is required by the `wasm_memory_persistence: opt keep` upgrade
    /// option and irrelevant otherwise.
    fn wasm_module(&self, wasm_mode: WasmMode) -> Vec<u8> {
        let memory = match (self, self.wasm_mode(wasm_mode)) {
            (DeclaredWasmMemory::None, _) => "".to_string(),
            (DeclaredWasmMemory::Min(pages), WasmMode::Wasm32) => format!("(memory {pages})"),
            (DeclaredWasmMemory::Min(pages), WasmMode::Wasm64) => format!("(memory i64 {pages})"),
        };
        let wat = format!(
            r#"
            (module
                {memory}
                (@custom "icp:private enhanced-orthogonal-persistence" "")
            )
            "#
        );
        wat::parse_str(wat).unwrap()
    }
}

/// The expected outcome of validating the Wasm memory of a scenario.
#[derive(Copy, Clone, Debug)]
enum Expected {
    /// The Wasm memory matches the canister module.
    Valid,
    /// The Wasm memory exceeds the maximum Wasm memory allowed for the Wasm
    /// execution mode of the canister module.
    ExceedsMaximum,
    /// The canister module declares no Wasm memory, but the Wasm memory is not empty.
    NotEmpty,
    /// The Wasm memory is smaller than the minimum Wasm memory declared by the
    /// canister module.
    TooSmall,
}

#[derive(Copy, Clone, Debug)]
struct Scenario {
    /// The Wasm memory declared by the canister module that the Wasm memory
    /// is installed with.
    declared_wasm_memory: DeclaredWasmMemory,
    /// The size (in Wasm pages) of the Wasm memory installed into the new
    /// execution state. It never exceeds `MAX_WASM64_MEMORY_PAGES` because
    /// no canister (and hence no canister snapshot) can have a larger Wasm
    /// memory in the first place.
    wasm_memory_pages: u64,
    /// The expected outcome if the canister module runs in Wasm32 mode.
    expected_wasm32: Expected,
    /// The expected outcome if the canister module runs in Wasm64 mode.
    expected_wasm64: Expected,
}

impl Scenario {
    /// The Wasm execution mode of the canister module in this scenario
    /// if the scenario is run for the given Wasm execution mode.
    fn wasm_mode(&self, wasm_mode: WasmMode) -> WasmMode {
        self.declared_wasm_memory.wasm_mode(wasm_mode)
    }

    /// The expected outcome if the scenario is run for the given Wasm
    /// execution mode.
    fn expected(&self, wasm_mode: WasmMode) -> Expected {
        match self.wasm_mode(wasm_mode) {
            WasmMode::Wasm32 => self.expected_wasm32,
            WasmMode::Wasm64 => self.expected_wasm64,
        }
    }

    /// The error message expected from the operation under test,
    /// `None` if the operation is expected to succeed.
    fn expected_error(&self, wasm_mode: WasmMode) -> Option<String> {
        let wasm_memory = bytes(self.wasm_memory_pages);
        let message = match self.expected(wasm_mode) {
            Expected::Valid => return None,
            Expected::ExceedsMaximum => {
                let max_wasm_memory = bytes(self.wasm_mode(wasm_mode).max_wasm_memory_pages());
                format!(
                    "the Wasm memory ({wasm_memory} bytes) exceeds the maximum Wasm memory \
                     ({max_wasm_memory} bytes) allowed for the Wasm execution mode of the \
                     canister module."
                )
            }
            Expected::NotEmpty => format!(
                "the Wasm memory ({wasm_memory} bytes) is not empty although the canister \
                 module declares no Wasm memory."
            ),
            Expected::TooSmall => {
                let min_wasm_memory =
                    bytes(self.declared_wasm_memory.min_wasm_memory_pages().unwrap());
                format!(
                    "the Wasm memory ({wasm_memory} bytes) is smaller than the minimum Wasm \
                     memory ({min_wasm_memory} bytes) declared by the canister module."
                )
            }
        };
        Some(format!(
            "Canister Wasm memory is incompatible with its Wasm module: {message}"
        ))
    }
}

const SCENARIOS: [Scenario; 10] = [
    // The canister module declares no Wasm memory: the Wasm memory must be empty.
    // Such a canister module always runs in Wasm32 mode, so its scenarios have
    // the same outcome in both Wasm execution modes.
    Scenario {
        declared_wasm_memory: DeclaredWasmMemory::None,
        wasm_memory_pages: 0,
        expected_wasm32: Expected::Valid,
        expected_wasm64: Expected::Valid,
    },
    Scenario {
        declared_wasm_memory: DeclaredWasmMemory::None,
        wasm_memory_pages: 1,
        expected_wasm32: Expected::NotEmpty,
        expected_wasm64: Expected::NotEmpty,
    },
    // The canister module declares an empty Wasm memory: every Wasm memory is
    // at least as large as the declared minimum.
    Scenario {
        declared_wasm_memory: DeclaredWasmMemory::Min(0),
        wasm_memory_pages: 0,
        expected_wasm32: Expected::Valid,
        expected_wasm64: Expected::Valid,
    },
    Scenario {
        declared_wasm_memory: DeclaredWasmMemory::Min(0),
        wasm_memory_pages: 1,
        expected_wasm32: Expected::Valid,
        expected_wasm64: Expected::Valid,
    },
    // The canister module declares a non-empty Wasm memory: the Wasm memory
    // must be at least as large as the declared minimum.
    Scenario {
        declared_wasm_memory: DeclaredWasmMemory::Min(2),
        wasm_memory_pages: 1,
        expected_wasm32: Expected::TooSmall,
        expected_wasm64: Expected::TooSmall,
    },
    Scenario {
        declared_wasm_memory: DeclaredWasmMemory::Min(2),
        wasm_memory_pages: 2,
        expected_wasm32: Expected::Valid,
        expected_wasm64: Expected::Valid,
    },
    Scenario {
        declared_wasm_memory: DeclaredWasmMemory::Min(2),
        wasm_memory_pages: 3,
        expected_wasm32: Expected::Valid,
        expected_wasm64: Expected::Valid,
    },
    // The Wasm memory is at and beyond the maximum Wasm memory for the Wasm
    // execution mode of the canister module: the very same Wasm memory can be
    // too large for a canister module in Wasm32 mode, but not for one in
    // Wasm64 mode, whose maximum Wasm memory is higher.
    Scenario {
        declared_wasm_memory: DeclaredWasmMemory::Min(2),
        wasm_memory_pages: MAX_WASM_MEMORY_PAGES,
        expected_wasm32: Expected::Valid,
        expected_wasm64: Expected::Valid,
    },
    Scenario {
        declared_wasm_memory: DeclaredWasmMemory::Min(2),
        wasm_memory_pages: MAX_WASM_MEMORY_PAGES + 1,
        expected_wasm32: Expected::ExceedsMaximum,
        expected_wasm64: Expected::Valid,
    },
    Scenario {
        declared_wasm_memory: DeclaredWasmMemory::Min(2),
        wasm_memory_pages: MAX_WASM64_MEMORY_PAGES,
        expected_wasm32: Expected::ExceedsMaximum,
        expected_wasm64: Expected::Valid,
    },
];

/// Installs a canister so that its Wasm memory has the given size (in Wasm pages).
fn install_canister_with_wasm_memory(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    wasm_memory_pages: u64,
) {
    // Only a canister module in Wasm64 mode may declare a Wasm memory
    // exceeding the maximum Wasm memory for Wasm32 mode.
    let wasm_mode = if wasm_memory_pages > MAX_WASM_MEMORY_PAGES {
        WasmMode::Wasm64
    } else {
        WasmMode::Wasm32
    };
    let declared_wasm_memory = DeclaredWasmMemory::Min(wasm_memory_pages);
    test.install_canister(canister_id, declared_wasm_memory.wasm_module(wasm_mode))
        .unwrap();
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size.get() as u64,
        wasm_memory_pages
    );
}

/// Uploads a canister snapshot consisting of the given canister module and a
/// Wasm memory of the given size (in Wasm pages) via
/// `upload_canister_snapshot_metadata` and `upload_canister_snapshot_data`,
/// and returns the ID of the uploaded snapshot.
fn upload_snapshot_from_metadata(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    wasm_module: Vec<u8>,
    wasm_memory_pages: u64,
) -> SnapshotId {
    let md_upload_args = UploadCanisterSnapshotMetadataArgs::new(
        canister_id,
        None,                     /* replace_snapshot */
        wasm_module.len() as u64, /* wasm_module_size */
        vec![],                   /* globals */
        bytes(wasm_memory_pages), /* wasm_memory_size */
        0,                        /* stable_memory_size */
        vec![],                   /* certified_data */
        None,                     /* global_timer */
        None,                     /* on_low_wasm_memory_hook_status */
    );
    let WasmResult::Reply(bytes) = test
        .subnet_message("upload_canister_snapshot_metadata", md_upload_args.encode())
        .unwrap()
    else {
        panic!("expected WasmResult::Reply")
    };
    let snapshot_id = Decode!(&bytes, UploadCanisterSnapshotMetadataResponse)
        .unwrap()
        .get_snapshot_id();
    let args = UploadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataOffset::WasmModule { offset: 0 },
        wasm_module,
    );
    test.subnet_message("upload_canister_snapshot_data", Encode!(&args).unwrap())
        .unwrap();
    snapshot_id
}

#[test]
fn snapshot_metadata_validates_global_wasm_memory_cap() {
    for wasm_mode in [WasmMode::Wasm32, WasmMode::Wasm64] {
        let mut test = ExecutionTestBuilder::new().build();
        let canister_id = test.create_canister(CYCLES);
        let wasm_module = DeclaredWasmMemory::Min(0).wasm_module(wasm_mode);
        test.install_canister(canister_id, wasm_module.clone())
            .unwrap();

        // A page-aligned size one page above the global cap must be rejected
        // during metadata upload, before any snapshot data is uploaded or loaded.
        let args = UploadCanisterSnapshotMetadataArgs::new(
            canister_id,
            None,                               /* replace_snapshot */
            wasm_module.len() as u64,           /* wasm_module_size */
            vec![],                             /* globals */
            bytes(MAX_WASM64_MEMORY_PAGES + 1), /* wasm_memory_size */
            0,                                  /* stable_memory_size */
            vec![],                             /* certified_data */
            None,                               /* global_timer */
            None,                               /* on_low_wasm_memory_hook_status */
        );
        let error = test
            .subnet_message("upload_canister_snapshot_metadata", args.encode())
            .expect_err("metadata above the global Wasm memory cap must be rejected");
        assert_eq!(
            error.code(),
            ErrorCode::InvalidManagementPayload,
            "{wasm_mode:?}"
        );
        assert_eq!(
            error.description(),
            "Snapshot Metadata contains invalid data: WasmMemoryTooLarge",
            "{wasm_mode:?}"
        );
        assert_eq!(test.canister_state(canister_id).canister_snapshots.len(), 0);

        // The global cap itself is accepted, even if the current module is
        // Wasm32. Compatibility with the snapshot's module is checked on load.
        upload_snapshot_from_metadata(&mut test, canister_id, wasm_module, MAX_WASM64_MEMORY_PAGES);
        assert_eq!(test.canister_state(canister_id).canister_snapshots.len(), 1);
    }
}

/// The operations installing an existing Wasm memory into a new execution state.
#[derive(Copy, Clone, Debug)]
enum Operation {
    /// Upgrading a canister with the `wasm_memory_persistence: opt keep`
    /// upgrade option, which keeps the canister's Wasm memory.
    UpgradeKeepingWasmMemory,
    /// Loading a canister snapshot uploaded via its metadata,
    /// which restores the snapshot's Wasm memory.
    LoadCanisterSnapshot,
}

impl Operation {
    /// Runs the operation for the given scenario and Wasm execution mode and
    /// returns the canister it ran on together with the size of the canister's
    /// Wasm memory (in Wasm pages) after the operation, or the error of the
    /// operation.
    fn run(self, scenario: &Scenario, wasm_mode: WasmMode) -> (CanisterId, Result<u64, UserError>) {
        let mut test = ExecutionTestBuilder::new().build();
        // The canister's Wasm memory limit is a canister setting that is
        // unrelated to the maximum Wasm memory under test, so it is raised
        // to the highest Wasm memory a canister can have.
        let settings = CanisterSettingsArgsBuilder::new()
            .with_wasm_memory_limit(MAX_WASM64_MEMORY_IN_BYTES)
            .build();
        let canister_id = test
            .create_canister_with_settings(CYCLES, settings)
            .unwrap();
        let new_wasm_module = scenario.declared_wasm_memory.wasm_module(wasm_mode);
        let wasm_memory_pages = scenario.wasm_memory_pages;
        let result = match self {
            Operation::UpgradeKeepingWasmMemory => {
                // The upgrade keeps the Wasm memory of the canister.
                install_canister_with_wasm_memory(&mut test, canister_id, wasm_memory_pages);
                test.upgrade_canister_v2(
                    canister_id,
                    new_wasm_module,
                    CanisterUpgradeOptions {
                        skip_pre_upgrade: None,
                        wasm_memory_persistence: Some(WasmMemoryPersistence::Keep),
                    },
                )
            }
            Operation::LoadCanisterSnapshot => {
                // The Wasm module and Wasm memory of the canister are
                // irrelevant: loading the snapshot replaces both.
                test.install_canister(
                    canister_id,
                    DeclaredWasmMemory::None.wasm_module(WasmMode::Wasm32),
                )
                .unwrap();
                let snapshot_id = upload_snapshot_from_metadata(
                    &mut test,
                    canister_id,
                    new_wasm_module,
                    wasm_memory_pages,
                );
                let args = LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, None);
                test.subnet_message("load_canister_snapshot", args.encode())
                    .map(|_| ())
            }
        };
        let wasm_memory_pages =
            result.map(|()| test.execution_state(canister_id).wasm_memory.size.get() as u64);
        (canister_id, wasm_memory_pages)
    }
}

#[test]
fn create_execution_state_validates_wasm_memory() {
    for wasm_mode in [WasmMode::Wasm32, WasmMode::Wasm64] {
        for scenario in SCENARIOS {
            for operation in [
                Operation::UpgradeKeepingWasmMemory,
                Operation::LoadCanisterSnapshot,
            ] {
                let (canister_id, result) = operation.run(&scenario, wasm_mode);
                match scenario.expected_error(wasm_mode) {
                    None => assert_eq!(
                        result.unwrap(),
                        scenario.wasm_memory_pages,
                        "unexpected Wasm memory after {operation:?} for {scenario:?} in {wasm_mode:?}"
                    ),
                    Some(message) => {
                        let error = result.expect_err(&format!(
                            "expected {operation:?} to fail for {scenario:?} in {wasm_mode:?}"
                        ));
                        assert_eq!(
                            error.code(),
                            ErrorCode::CanisterContractViolation,
                            "unexpected error code of {operation:?} for {scenario:?} in {wasm_mode:?}"
                        );
                        assert_eq!(
                            error.description(),
                            format!("Error from Canister {canister_id}: {message}"),
                            "unexpected error of {operation:?} for {scenario:?} in {wasm_mode:?}"
                        );
                    }
                }
            }
        }
    }
}
