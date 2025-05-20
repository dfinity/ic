use candid::Encode;
use canister_test::{CanisterInstallMode, InstallCodeArgs, WasmResult};
use ic_test_utilities_execution_environment::ExecutionTestBuilder;
use ic_types::Cycles;

#[test]
fn test_memory_loader() {
    let wat = r#"(module
		(import "ic0" "msg_reply" (func $ic0_msg_reply))
		(memory 1)
		(func $go (export "canister_query go")
			(drop (i32.load (i32.const 10)))
			(call $ic0_msg_reply)
		)
	)"#;
    let wasm = wat::parse_str(wat).unwrap();
    let mut test = ExecutionTestBuilder::new().build();

    let canister_id = test.create_canister(Cycles::from(1_u128 << 64));
    let args = InstallCodeArgs::new(
        CanisterInstallMode::Install,
        canister_id,
        wasm,
        vec![],
        None,
        None,
    );
    let result = test.install_code(args).unwrap();
    println!("Installation completed");
    if let WasmResult::Reject(s) = result {
        panic!("Installation rejected: {}", s)
    }

    // Execute a message to sync the new memory so that time isn't included in
    // benchmarks.
    test.ingress(canister_id, "go", Encode!(&()).unwrap())
        .unwrap();
}
