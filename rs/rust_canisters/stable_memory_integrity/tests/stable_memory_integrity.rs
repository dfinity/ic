use assert_matches::assert_matches;
use candid::{Decode, Encode};
use proptest::prelude::*;

use ic_base_types::CanisterId;
use ic_stable_memory_integrity::StableOperationResult;
use ic_state_machine_tests::StateMachine;
use ic_types::{Cycles, MAX_STABLE_MEMORY_IN_BYTES, ingress::WasmResult};

const KB: u64 = 1024;
const WASM_PAGE_SIZE_IN_BYTES: usize = 64 * KB as usize;

lazy_static::lazy_static! {
    static ref STABLE_MEMORY_INTEGRITY_WASM: Vec<u8> =
        canister_test::Project::cargo_bin_maybe_from_env("stable_memory_integrity_canister", &[]).bytes();
}

#[derive(Clone, Debug, Default)]
struct StableState {
    contents: Vec<u8>,
}

impl StableState {
    /// Checks if a stable read/write operation would trap.
    fn is_valid_read_write(&self, start: u64, length: u64, require_32_bit: bool) -> bool {
        if require_32_bit && self.contents.len() > u32::MAX as usize {
            return false;
        }
        if length == 0 {
            return true;
        }
        let (end, overflow) = start.overflowing_add(length);
        !overflow && end <= self.contents.len() as u64
    }

    /// Returns error if the operation would trap.
    fn get_operation_result(&self, op: &StableOperation) -> Result<StableOperationResult, ()> {
        match op {
            StableOperation::Size => Ok(StableOperationResult::Size(
                self.contents.len() as u64 / WASM_PAGE_SIZE_IN_BYTES as u64,
            )),
            StableOperation::Grow(new_pages) => {
                let current_pages = (self.contents.len() / WASM_PAGE_SIZE_IN_BYTES) as u64;
                let result = if current_pages
                    .saturating_add(*new_pages)
                    .saturating_mul(WASM_PAGE_SIZE_IN_BYTES as u64)
                    <= MAX_STABLE_MEMORY_IN_BYTES
                {
                    Ok(current_pages)
                } else {
                    Err(())
                };
                Ok(StableOperationResult::Grow {
                    new_pages: *new_pages,
                    result,
                })
            }
            StableOperation::Read { start, length } => {
                if self.is_valid_read_write(*start, *length, false) {
                    let result = if *length == 0 {
                        vec![]
                    } else {
                        self.contents[*start as usize..(start + length) as usize].to_vec()
                    };
                    Ok(StableOperationResult::Read {
                        start: *start,
                        result,
                    })
                } else {
                    Err(())
                }
            }
            StableOperation::Write { start, contents } => {
                if self.is_valid_read_write(*start, contents.len() as u64, false) {
                    Ok(StableOperationResult::Write {
                        start: *start,
                        contents: contents.clone(),
                    })
                } else {
                    Err(())
                }
            }
        }
    }

    fn apply_operation(&mut self, op: &StableOperation) {
        match op {
            StableOperation::Size | StableOperation::Read { .. } => {}
            StableOperation::Grow(new_pages) => {
                if new_pages
                    .saturating_mul(WASM_PAGE_SIZE_IN_BYTES as u64)
                    .saturating_add(self.contents.len() as u64)
                    <= MAX_STABLE_MEMORY_IN_BYTES
                {
                    self.grow(*new_pages as usize * WASM_PAGE_SIZE_IN_BYTES);
                }
            }
            StableOperation::Write { start, contents } => {
                if !contents.is_empty() {
                    self.contents[*start as usize..*start as usize + contents.len()]
                        .copy_from_slice(contents)
                }
            }
        }
    }

    fn grow(&mut self, bytes: usize) {
        self.contents.resize(self.contents.len() + bytes, 0);
    }

    fn apply_operations(&mut self, operations: &Operations) {
        if !operations.last_operation_traps {
            for op in &operations.ops {
                self.apply_operation(&op.into())
            }
        }
    }

    fn check_final_size(&self, canister_id: CanisterId, env: &StateMachine) {
        let result = match env
            .query(canister_id, "final_size", Encode!(&()).unwrap())
            .unwrap()
        {
            WasmResult::Reply(bytes) => bytes,
            WasmResult::Reject(err) => panic!("Failed to get stable memory size: {err}"),
        };

        assert_eq!(
            (self.contents.len() / WASM_PAGE_SIZE_IN_BYTES) as u64,
            Decode!(&result, u64).unwrap()
        );
    }

    fn is_nonzero(chunk: &[u8]) -> bool {
        let (prefix, middle, suffix) = unsafe { chunk.align_to::<u128>() };
        for b in prefix {
            if *b != 0 {
                return true;
            }
        }
        for i in middle {
            if *i != 0 {
                return true;
            }
        }
        for b in suffix {
            if *b != 0 {
                return true;
            }
        }
        false
    }

    fn check_memory_state(&self, canister_id: CanisterId, env: &StateMachine) {
        for (inx, chunk) in self.contents.chunks((KB * KB) as usize).enumerate() {
            if Self::is_nonzero(chunk) {
                let start = inx as u64 * KB * KB;
                let result = match env
                    .query(
                        canister_id,
                        "read",
                        Encode!(&start, &(chunk.len() as u64)).unwrap(),
                    )
                    .unwrap()
                {
                    WasmResult::Reply(bytes) => bytes,
                    WasmResult::Reject(err) => {
                        panic!("Failed to read stable memory contents: {err}")
                    }
                };
                assert_eq!(chunk, &Decode!(&result, Vec<u8>).unwrap());
            }
        }
    }
}

enum StableOperationType {
    Size,
    Grow,
    Read,
    Write,
}

impl StableOperationType {
    /// 5% size
    /// 15% grow
    /// 40% read
    /// 40% write
    fn random(rng: &mut impl Rng) -> Self {
        let val = rng.random_range(0.0..1.0);
        if val < 0.05 {
            Self::Size
        } else if val < 0.2 {
            Self::Grow
        } else if val < 0.6 {
            Self::Read
        } else {
            Self::Write
        }
    }
}

#[derive(Clone, Debug)]
enum StableOperation {
    Size,
    Grow(u64),
    Read { start: u64, length: u64 },
    Write { start: u64, contents: Vec<u8> },
}

impl From<StableOperation> for StableOperationResult {
    fn from(op: StableOperation) -> Self {
        match op {
            StableOperation::Size => StableOperationResult::Size(0),
            StableOperation::Grow(new_pages) => StableOperationResult::Grow {
                new_pages,
                result: Err(()),
            },
            StableOperation::Read { start, length } => StableOperationResult::Read {
                start,
                result: vec![0; length as usize],
            },
            StableOperation::Write { start, contents } => {
                StableOperationResult::Write { start, contents }
            }
        }
    }
}

impl From<&StableOperationResult> for StableOperation {
    fn from(value: &StableOperationResult) -> Self {
        match value {
            StableOperationResult::Size(_) => StableOperation::Size,
            StableOperationResult::Grow {
                new_pages,
                result: _,
            } => StableOperation::Grow(*new_pages),
            StableOperationResult::Read { start, result } => StableOperation::Read {
                start: *start,
                length: result.len() as u64,
            },
            StableOperationResult::Write { start, contents } => StableOperation::Write {
                start: *start,
                contents: contents.clone(),
            },
        }
    }
}

#[derive(Clone, Debug)]
struct Operations {
    ops: Vec<StableOperationResult>,
    last_operation_traps: bool,
}

struct OperationsTree {
    all_operations: Vec<Operations>,
}

impl proptest::strategy::ValueTree for OperationsTree {
    type Value = Vec<Operations>;
    fn current(&self) -> Vec<Operations> {
        self.all_operations.clone()
    }
    // We'll use proptest to easily record our test cases, but won't support
    // shrinking failures.
    fn simplify(&mut self) -> bool {
        false
    }
    fn complicate(&mut self) -> bool {
        false
    }
}

#[derive(Copy, Clone, Debug)]
struct OperationsStrategy;

impl proptest::strategy::Strategy for OperationsStrategy {
    type Tree = OperationsTree;
    type Value = Vec<Operations>;

    fn new_tree(
        &self,
        runner: &mut proptest::test_runner::TestRunner,
    ) -> proptest::strategy::NewTree<Self> {
        let rng = runner.rng();
        let mut all_operations = vec![];
        let mut state = StableState::default();

        // Execute 20 messages.
        for _ in 0..20 {
            let allow_invalid = rng.random_bool(0.2);
            let concentrate_ops = rng.random_bool(0.5);
            let ops = generate_random_ops(allow_invalid, concentrate_ops, rng, &mut state);
            all_operations.push(ops);
        }
        Ok(OperationsTree { all_operations })
    }
}

fn generate_random_ops(
    allow_invalid: bool,
    concentrate_ops: bool,
    rng: &mut impl Rng,
    state: &mut StableState,
) -> Operations {
    let count = rng.random_range(0..100);
    let mut result = Vec::with_capacity(count);
    let initial_state = state.clone();
    for _ in 0..count {
        let op = generate_operation(allow_invalid, concentrate_ops, rng, state);
        let op_result = state.get_operation_result(&op);
        match op_result {
            Ok(op_result) => {
                state.apply_operation(&op);
                result.push(op_result);
            }
            Err(()) => {
                result.push(op.into());
                *state = initial_state;
                return Operations {
                    ops: result,
                    last_operation_traps: true,
                };
            }
        }
    }
    Operations {
        ops: result,
        last_operation_traps: false,
    }
}

fn generate_operation(
    // Include out-of-bounds operations which will trap.
    allow_invalid: bool,
    // Don't grow and perform all operations within the last wasm page to get
    // overlapping reads/writes.
    concentrate_ops: bool,
    rng: &mut impl Rng,
    state: &StableState,
) -> StableOperation {
    let mut ty = StableOperationType::random(rng);
    // If we are concentrating reads/writes to the last page, then don't grow so
    // the operations remain overlapping.
    if concentrate_ops && !state.contents.is_empty() {
        ty = match ty {
            StableOperationType::Size => StableOperationType::Write,
            StableOperationType::Grow => StableOperationType::Read,
            StableOperationType::Read => StableOperationType::Read,
            StableOperationType::Write => StableOperationType::Write,
        }
    }
    let range_start = if concentrate_ops {
        state.contents.len().saturating_sub(WASM_PAGE_SIZE_IN_BYTES)
    } else {
        0
    };
    if allow_invalid && rng.random_bool(0.1) {
        return generate_invalid_operation(rng, state, ty);
    }
    match ty {
        StableOperationType::Size => StableOperation::Size,
        StableOperationType::Grow => {
            let new_pages = rng.random_range(0..100);
            StableOperation::Grow(new_pages)
        }
        StableOperationType::Read => {
            let length = if state.contents.is_empty() {
                0
            } else {
                rng.random_range(0..4 * KB)
            };
            let start = rng.random_range(
                range_start as u64..(state.contents.len() as u64).saturating_sub(length).max(1),
            );
            StableOperation::Read { start, length }
        }
        StableOperationType::Write => {
            let write_size = if state.contents.is_empty() {
                0
            } else {
                rng.random_range(0..4 * KB)
            };
            let mut contents = vec![0; write_size as usize];
            rng.fill(&mut contents[..]);
            let start = rng.random_range(
                range_start as u64
                    ..(state.contents.len() as u64)
                        .saturating_sub(write_size)
                        .max(1),
            );
            StableOperation::Write { start, contents }
        }
    }
}

fn generate_invalid_operation(
    rng: &mut impl Rng,
    state: &StableState,
    ty: StableOperationType,
) -> StableOperation {
    match ty {
        StableOperationType::Size => StableOperation::Size,
        StableOperationType::Grow => {
            let max_pages_to_grow = (MAX_STABLE_MEMORY_IN_BYTES - state.contents.len() as u64)
                / WASM_PAGE_SIZE_IN_BYTES as u64;
            StableOperation::Grow(max_pages_to_grow.saturating_add(rng.r#gen::<u64>()))
        }
        StableOperationType::Read => {
            let length = rng.random_range(0..4 * KB);
            let start = rng.random_range(
                (state.contents.len() as u64).saturating_sub(length)
                    ..(state.contents.len()) as u64 + 10,
            );
            StableOperation::Read { start, length }
        }
        StableOperationType::Write => {
            let write_size = rng.random_range(0..4 * KB);
            let contents = vec![0; write_size as usize];
            let start = rng.random_range(
                (state.contents.len() as u64).saturating_sub(write_size)
                    ..(state.contents.len()) as u64 + 10,
            );
            StableOperation::Write { start, contents }
        }
    }
}

fn run_operations_on_canister(
    env: &StateMachine,
    canister_id: CanisterId,
    all_operations: &[Operations],
) {
    env.reinstall_canister(canister_id, STABLE_MEMORY_INTEGRITY_WASM.clone(), vec![])
        .unwrap();
    let mut state = StableState::default();

    for ops in all_operations {
        let result = env.execute_ingress(
            canister_id,
            "perform_and_check_ops",
            Encode!(&ops.ops).unwrap(),
        );
        if ops.last_operation_traps {
            assert_matches!(result, Err(_))
        } else {
            assert_matches!(result, Ok(_))
        }
        state.apply_operations(ops);
    }
    state.check_final_size(canister_id, env);
    state.check_memory_state(canister_id, env);
}

#[test]
fn stable_memory_integrity_test() {
    // Even with only 10 test cases, this test still takes over 1 minute.
    let config = prop::test_runner::Config::with_cases(10);
    let algorithm = config.rng_algorithm;
    let mut runner = prop::test_runner::TestRunner::new_with_rng(
        config,
        prop::test_runner::TestRng::deterministic_rng(algorithm),
    );
    let env = StateMachine::new();
    let canister_id = env.create_canister_with_cycles(None, Cycles::from(1_u128 << 64), None);
    runner
        .run(&OperationsStrategy, |all_operations| {
            run_operations_on_canister(&env, canister_id, &all_operations);
            Ok(())
        })
        .unwrap();
}
