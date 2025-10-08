use ic_base_types::CanisterId;
use ic_management_canister_types_private::{
    CanisterStatusResultV2, Method, Payload, TakeCanisterSnapshotArgs,
};
use ic_test_utilities::universal_canister::{UNIVERSAL_CANISTER_WASM, wasm};
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder, get_reply};
use ic_types::Cycles;

const T: u128 = 1_000_000_000_000;

struct Runbook<F> {
    memory_allocation: u64,
    op: Option<F>,
}

struct Checklist {
    canister_status: bool,
    subnet_available_memory: bool,
}

fn test_memory_allocation<F>(runbook_1: Runbook<F>, runbook_2: Runbook<F>, checklist: Checklist)
where
    F: Fn(&mut ExecutionTest, CanisterId),
{
    let run = |runbook: Runbook<F>| -> (CanisterStatusResultV2, i64) {
        let mut test = ExecutionTestBuilder::new().build();
        let initial_subnet_available_memory = test.subnet_available_memory();
        let canister_id = test
            .create_canister_with_allocation(
                Cycles::from(100 * T),
                None,
                Some(runbook.memory_allocation),
            )
            .unwrap();
        test.install_canister(canister_id, UNIVERSAL_CANISTER_WASM.to_vec())
            .unwrap();
        if let Some(op) = runbook.op {
            op(&mut test, canister_id);
        }
        println!(
            "memory usage: {}",
            test.canister_state(canister_id)
                .memory_allocated_bytes()
                .get()
        );
        assert_eq!(
            test.subnet_available_memory().get_execution_memory()
                + test
                    .canister_state(canister_id)
                    .memory_allocated_bytes()
                    .get() as i64,
            initial_subnet_available_memory.get_execution_memory()
        );
        let res = test.canister_status(canister_id);
        let bytes = get_reply(res);
        (
            CanisterStatusResultV2::decode(&bytes).unwrap(),
            test.subnet_available_memory().get_execution_memory(),
        )
    };

    let (alloc_status_1, alloc_available_memory_1) = run(runbook_1);
    let (alloc_status_2, alloc_available_memory_2) = run(runbook_2);

    if checklist.canister_status {
        assert_eq!(alloc_status_1.memory_size(), alloc_status_2.memory_size());
        assert_eq!(alloc_status_1.cycles(), alloc_status_2.cycles());
        assert_eq!(
            alloc_status_1.reserved_cycles(),
            alloc_status_2.reserved_cycles()
        );
    }
    if checklist.subnet_available_memory {
        assert_eq!(alloc_available_memory_1, alloc_available_memory_2);
    }
}

fn test_memory_allocation_suite<F>(op: F)
where
    F: Fn(&mut ExecutionTest, CanisterId) + Copy,
{
    // very low memory allocation (exceeded already before executing `op`)
    println!("low memory allocation");
    let runbook_1 = Runbook {
        memory_allocation: 0,
        op: Some(op),
    };
    let runbook_2 = Runbook {
        memory_allocation: 1,
        op: Some(op),
    };
    let checklist = Checklist {
        canister_status: true,
        subnet_available_memory: true,
    };
    test_memory_allocation(runbook_1, runbook_2, checklist);

    // moderate memory allocation (exceeded while executing `op`)
    println!("moderate memory allocation");
    let runbook_1 = Runbook {
        memory_allocation: 0,
        op: Some(op),
    };
    let runbook_2 = Runbook {
        memory_allocation: 100 << 20,
        op: Some(op),
    };
    let checklist = Checklist {
        canister_status: true,
        subnet_available_memory: true,
    };
    test_memory_allocation(runbook_1, runbook_2, checklist);

    // large memory allocation (not exceeded even after executing `op`)
    println!("large memory allocation I");
    let runbook_1 = Runbook {
        memory_allocation: 0,
        op: Some(op),
    };
    let runbook_2 = Runbook {
        memory_allocation: 100 << 30,
        op: Some(op),
    };
    let checklist = Checklist {
        canister_status: true,
        subnet_available_memory: false,
    };
    test_memory_allocation(runbook_1, runbook_2, checklist);

    // large memory allocation (not exceeded even after executing `op`)
    println!("large memory allocation II");
    let runbook_1 = Runbook {
        memory_allocation: 100 << 30,
        op: None,
    };
    let runbook_2 = Runbook {
        memory_allocation: 100 << 30,
        op: Some(op),
    };
    let checklist = Checklist {
        canister_status: false,
        subnet_available_memory: true,
    };
    test_memory_allocation(runbook_1, runbook_2, checklist);
}

#[test]
fn test_memory_allocation_suite_grow_wasm_memory() {
    let op = |test: &mut ExecutionTest, canister_id| {
        test.ingress(
            canister_id,
            "update",
            wasm().push_equal_bytes(42, 1 << 30).reply().build(),
        )
        .unwrap();
    };
    test_memory_allocation_suite(op);
}

#[test]
fn test_memory_allocation_suite_grow_stable_memory() {
    let op = |test: &mut ExecutionTest, canister_id| {
        test.ingress(
            canister_id,
            "update",
            wasm().stable64_grow((1 << 30) >> 16).reply().build(),
        )
        .unwrap();
    };
    test_memory_allocation_suite(op);
}

#[test]
fn test_memory_allocation_suite_take_snapshot() {
    let op = |test: &mut ExecutionTest, canister_id| {
        test.ingress(
            canister_id,
            "update",
            wasm().stable64_grow((60 << 20) >> 16).reply().build(),
        )
        .unwrap();
        let take_canister_snapshot_args = TakeCanisterSnapshotArgs::new(canister_id, None);
        test.subnet_message(
            Method::TakeCanisterSnapshot,
            take_canister_snapshot_args.encode(),
        )
        .unwrap();
    };
    test_memory_allocation_suite(op);
}
