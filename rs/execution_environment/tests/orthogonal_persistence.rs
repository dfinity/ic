use ic_config::execution_environment::Config;
use ic_execution_environment::{Hypervisor, QueryExecutionType};
use ic_interfaces::{
    execution_environment::{ExecutionParameters, SubnetAvailableMemory},
    messages::RequestOrIngress,
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CallContextAction, CanisterState};
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder, mock_time, state::SystemStateBuilder,
    types::ids::subnet_test_id, types::ids::user_test_id, types::messages::IngressBuilder,
    with_test_replica_logger,
};
use ic_types::{
    ingress::WasmResult, CanisterId, ComputeAllocation, Cycles, NumBytes, NumInstructions, SubnetId,
};
use maplit::btreemap;
use proptest::prelude::*;
use std::{collections::BTreeMap, sync::Arc};

fn execution_parameters() -> ExecutionParameters {
    ExecutionParameters {
        instruction_limit: NumInstructions::new(1_000_000_000),
        canister_memory_limit: NumBytes::new(u64::MAX / 2),
        subnet_available_memory: SubnetAvailableMemory::new(i64::MAX / 2),
        compute_allocation: ComputeAllocation::default(),
        subnet_type: SubnetType::Application,
    }
}

struct HypervisorTest {
    hypervisor: Hypervisor,
    canister: CanisterState,
    routing_table: Arc<RoutingTable>,
    subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
}

impl HypervisorTest {
    fn init(wast: &str, log: ReplicaLogger) -> Self {
        let subnet_id = subnet_test_id(1);
        let subnet_type = SubnetType::Application;
        let routing_table = Arc::new(RoutingTable::new(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => subnet_id,
        }));
        let subnet_records = Arc::new(btreemap! {
            subnet_id => subnet_type,
        });
        let registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let hypervisor = Hypervisor::new(
            Config::default(),
            1,
            &registry,
            subnet_id,
            subnet_type,
            log,
            cycles_account_manager,
        );
        let wasm_binary = wabt::wat2wasm(wast).unwrap();
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let system_state = SystemStateBuilder::default()
            .memory_allocation(NumBytes::new(8 * 1024 * 1024 * 1024)) // 8GiB
            .build();
        let execution_state = hypervisor
            .create_execution_state(
                wasm_binary,
                tmpdir.path().to_path_buf(),
                system_state.canister_id(),
            )
            .unwrap();

        let canister = CanisterState {
            system_state,
            execution_state: Some(execution_state),
            scheduler_state: Default::default(),
        };

        Self {
            hypervisor,
            canister,
            routing_table,
            subnet_records,
        }
    }

    fn update(&mut self, method_name: &str, method_payload: Vec<u8>) -> CallContextAction {
        let ingress = IngressBuilder::new()
            .method_name(method_name.to_string())
            .method_payload(method_payload)
            .source(user_test_id(24))
            .build();

        let (canister, _, action, _) = self.hypervisor.execute_update(
            self.canister.clone(),
            RequestOrIngress::Ingress(ingress),
            mock_time(),
            Arc::clone(&self.routing_table),
            self.subnet_records.clone(),
            execution_parameters(),
        );
        self.canister = canister;
        action
    }

    fn query(&mut self, method_name: &str, method_payload: Vec<u8>) -> Option<WasmResult> {
        let (canister, _, result) = self.hypervisor.execute_query(
            QueryExecutionType::Replicated,
            method_name,
            method_payload.as_slice(),
            user_test_id(24).get(),
            self.canister.clone(),
            None,
            mock_time(),
            execution_parameters(),
        );

        self.canister = canister;
        result.unwrap()
    }
}

fn make_module_wat(heap_size: usize) -> String {
    format!(
        r#"
    (module
      (import "ic0" "msg_reply" (func $msg_reply))
      (import "ic0" "msg_reply_data_append"
        (func $msg_reply_data_append (param i32) (param i32)))
      (import "ic0" "msg_arg_data_copy"
        (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
      (import "ic0" "msg_arg_data_size"
        (func $ic0_msg_arg_data_size (result i32)))

      (func $memory_grow
        ;; copy the i32 `delta` to heap[0;4]
        (call $ic0_msg_arg_data_copy
          (i32.const 0) ;; dst
          (i32.const 0) ;; off
          (i32.const 4) ;; len
        )
        (drop (memory.grow (i32.load (i32.const 0))))
      )

      (func $dump_heap
        (call $msg_reply_data_append (i32.const 0) (i32.mul (memory.size) (i32.const 0x10000)))
        (call $msg_reply)
      )

      ;; write to memory
      (func $write_bytes
        ;; copy the i32 `addr` to heap[0;4]
        (call $ic0_msg_arg_data_copy
          (i32.const 0) ;; dst
          (i32.const 0) ;; off
          (i32.const 4) ;; len
        )
        ;; copy the remainder of the payload to the heap[addr;size]
        (call $ic0_msg_arg_data_copy
          ;; addr
          (i32.load (i32.const 0))
          ;; offset
          (i32.const 4)
          ;; size
          (i32.sub
            (call $ic0_msg_arg_data_size)
            (i32.const 4)
          )
        )
        (call $msg_reply)
      )

      (memory $memory {})
      (export "canister_query dump_heap" (func $dump_heap))
      (export "canister_update memory_grow" (func $memory_grow))
      (export "canister_update write_bytes" (func $write_bytes))
    )"#,
        heap_size
    )
}

#[derive(Debug)]
pub struct Write {
    dst: u32,
    bytes: Vec<u8>,
}

fn random_writes(heap_size: usize, num_writes: usize) -> impl Strategy<Value = Vec<Write>> {
    let write_strategy = (0..heap_size).prop_flat_map(move |dst| {
        let dst = dst as u32;
        // up to 128 bytes
        let remain = (heap_size - dst as usize) % 128;
        prop::collection::vec(any::<u8>(), 0..=remain).prop_map(move |bytes| Write { dst, bytes })
    });
    prop::collection::vec(write_strategy, 1..num_writes)
}

fn write_bytes(t: &mut HypervisorTest, dst: u32, bytes: &[u8]) {
    println!("write_bytes(dst: {}, bytes: {:?})", dst, bytes);
    let mut payload = dst.to_le_bytes().to_vec();
    payload.extend(bytes.iter());
    let action = t.update("write_bytes", payload);
    assert_eq!(
        action,
        CallContextAction::Reply {
            payload: vec![],
            refund: Cycles::from(0),
        }
    );
}

fn dump_heap(t: &mut HypervisorTest) -> Vec<u8> {
    println!("dump_heap()");
    if let Some(WasmResult::Reply(canister_heap)) = t.query("dump_heap", vec![]) {
        canister_heap
    } else {
        panic!("expected a payload")
    }
}

fn buf_apply_write(heap: &mut Vec<u8>, write: &Write) {
    // match the behavior of write_bytes: copy the i32 `addr` to heap[0;4]
    heap[0..4].copy_from_slice(&write.dst.to_le_bytes());
    heap[write.dst as usize..(write.dst as usize + write.bytes.len() as usize)]
        .copy_from_slice(&write.bytes)
}

const TEST_HEAP_SIZE_BYTES: usize = WASM_PAGE_SIZE_BYTES * TEST_NUM_PAGES;
// This limit is reduced to 32 pages to ensure that the maximum query response
// is not larger than 2MB. This is required because currently the size of the
// query response is bounded by the MAX_INTER_CANISTER_MESSAGE_IN_BYTES. To fix
// this, we could try one of the following two approaches: - Make the test dump
// the heap using multiple messages. - Set a different limit for query
// responses.
//const TEST_NUM_PAGES: usize = 400;
const TEST_NUM_PAGES: usize = 32;
const TEST_NUM_WRITES: usize = 20;
const WASM_PAGE_SIZE_BYTES: usize = 65536;

proptest! {
    #![proptest_config(ProptestConfig { cases: 20, .. ProptestConfig::default() })]
    #[test]
    // generate multiple writes of varying size to random memory locations, apply them both to a
    // canister and a simple Vec buffer and compare the results.
    fn test_orthogonal_persistence(writes in random_writes(TEST_HEAP_SIZE_BYTES, TEST_NUM_WRITES)) {
        with_test_replica_logger(|log| {
            let mut heap = vec![0;TEST_HEAP_SIZE_BYTES];
            let wat = make_module_wat(TEST_NUM_PAGES);
            let mut t = HypervisorTest::init(&wat, log);

            for w in &writes {
                buf_apply_write(&mut heap, w);
                write_bytes(&mut t, w.dst, &w.bytes);
                // verify the heap
                let canister_heap = dump_heap(&mut t);
                assert_eq!(heap[..], canister_heap[..])
            }
        });
    }
}
