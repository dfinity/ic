#[test]
fn wasm_api_hello() {
    use wasm_api::*;

    let engine = Engine::new();
    let store = Store::new(&engine);
    let module = Module::new(
        &store,
        std::fs::read_to_string("tests/hello.wasm")
            .expect("read wasm module file")
            .as_ref(),
    );
    let memory = Memory::new(&store, 2, 3);
    let instance = Instance::new(&store, &module, &[memory.as_extern()]);
    let exports = instance.exports();
    assert!(!exports.is_empty(), "at least one export");
    let run_func = Func::new(&exports[0]);
    let result = run_func.call(&[WasmVal::I32(100)]);
    assert_eq!(result, WasmVal::I32(142));
    // fetch 4 bytes from memory
    let from_memory = unsafe { *(memory.data()[10..14].as_ptr() as *const i32) };
    assert_eq!(from_memory, 42);
    println!(
        "> result: {:?}, memory_min: {}, memory_max: {}, memory[10..14]: {}",
        result,
        memory.min(),
        memory.max(),
        from_memory
    );
}
