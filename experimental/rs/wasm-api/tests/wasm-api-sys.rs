#[test]
fn wasm_api_sys_hello() {
    use wasm_api_sys::*;

    unsafe {
        let engine: *mut wasm_engine_t = wasm_engine_new();
        let store: *mut wasm_store_t = wasm_store_new(engine);

        let file_name = "tests/hello.wasm";
        let file_conents = std::fs::read_to_string(file_name).unwrap();
        let file_size = file_conents.len();
        println!(
            "> module file name: {:?}, size: {} bytes",
            file_name, file_size
        );
        let module = {
            let mut bytes = wasm_byte_vec_t::default();
            wasm_byte_vec_new(
                &mut bytes,
                file_size,
                file_conents.as_ptr() as *const std::os::raw::c_char,
            );
            let module = wasm_module_new(store, &bytes);
            assert!(!module.is_null());
            wasm_byte_vec_delete(&mut bytes);
            module
        };

        let memory = {
            let mut limits = wasm_limits_t::default();
            limits.min = 2;
            limits.max = 3;
            let memory_type = wasm_memorytype_new(&limits);
            wasm_memory_new(store, memory_type)
        };
        let imports: [*const wasm_extern_t; 1] = [wasm_memory_as_extern(memory)];
        let instance = wasm_instance_new(store, module, imports.as_ptr());
        assert!(!instance.is_null());

        let exports: &[*mut wasm_extern_t] = {
            let mut exports = wasm_extern_vec_t::default();
            wasm_instance_exports(instance, &mut exports);
            assert!(exports.size > 0, "at least one export");
            std::slice::from_raw_parts(exports.data, exports.size)
        };

        let run: *const wasm_func_t = wasm_extern_as_func(exports[0]);
        assert!(!run.is_null());

        let args = &[{
            let mut v = wasm_val_t::default();
            v.kind = wasm_valkind_enum_WASM_I32 as u8;
            v.of.i32 = 100;
            v
        }];
        let mut result: [wasm_val_t; 1] = Default::default();
        let trap: *mut wasm_trap_t = wasm_func_call(run, args.as_ptr(), result.as_mut_ptr());
        assert!(trap.is_null(), "call succeeded. no trap");
        let (mem_min, mem_max) = {
            let limits = wasm_memorytype_limits(wasm_memory_type(memory));
            ((*limits).min, (*limits).max)
        };
        let from_memory = *((wasm_memory_data(memory) as u64 + 10) as *const i32);
        println!(
            "> result: {}, memory_min: {}, memory_max: {}, memory[10..14]: {}",
            result[0].of.i32, mem_min, mem_max, from_memory
        );
    }
}
