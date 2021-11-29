use wasm_api_sys::*;

pub struct Engine(*mut wasm_engine_t);

impl Engine {
    pub fn new() -> Self {
        unsafe { Engine(wasm_engine_new()) }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe { wasm_engine_delete(self.0) }
    }
}

pub struct Store(*mut wasm_store_t);

impl Store {
    pub fn new(engine: &Engine) -> Self {
        unsafe { Store(wasm_store_new(engine.0)) }
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        unsafe { wasm_store_delete(self.0) }
    }
}

pub struct Module(*mut wasm_module_t);

impl Module {
    pub fn new(store: &Store, bytes: &[u8]) -> Self {
        unsafe {
            let mut byte_vec = wasm_byte_vec_t::default();
            wasm_byte_vec_new(
                &mut byte_vec,
                bytes.len(),
                bytes.as_ptr() as *const std::os::raw::c_char,
            );
            let module = wasm_module_new(store.0, &byte_vec);
            assert!(!module.is_null());
            wasm_byte_vec_delete(&mut byte_vec);
            Module(module)
        }
    }
}

impl Drop for Module {
    fn drop(&mut self) {
        unsafe { wasm_module_delete(self.0) }
    }
}

// Extern keeps the original object alive.
pub struct Extern(*mut wasm_extern_t, Option<Box<dyn std::any::Any>>);

pub struct Instance(*mut wasm_instance_t);

impl Instance {
    pub fn new(store: &Store, module: &Module, imports: &[Extern]) -> Self {
        let imports: Vec<*const wasm_extern_t> = imports
            .iter()
            .map(|x| x.0 as *const wasm_extern_t)
            .collect();
        unsafe { Instance(wasm_instance_new(store.0, module.0, imports.as_ptr())) }
    }

    pub fn exports(&self) -> Vec<Extern> {
        unsafe {
            let mut exports = wasm_extern_vec_t::default();
            wasm_instance_exports(self.0, &mut exports);
            let exports = std::slice::from_raw_parts(exports.data, exports.size);
            exports.iter().map(|x| Extern(*x, None)).collect()
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum WasmVal {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
}

impl WasmVal {
    // only used internally
    fn new(v: wasm_val_t) -> Self {
        let kind = u32::from(v.kind);
        if kind == wasm_valkind_enum_WASM_I32 {
            WasmVal::I32(unsafe { v.of.i32 })
        } else if kind == wasm_valkind_enum_WASM_I64 {
            WasmVal::I64(unsafe { v.of.i64 })
        } else if kind == wasm_valkind_enum_WASM_F32 {
            WasmVal::F32(unsafe { v.of.f32 })
        } else if kind == wasm_valkind_enum_WASM_F64 {
            WasmVal::F64(unsafe { v.of.f64 })
        } else if kind == wasm_valkind_enum_WASM_ANYREF {
            panic!("TODO")
        } else if kind == wasm_valkind_enum_WASM_FUNCREF {
            panic!("TODO")
        } else {
            panic!("WasmVal::new()")
        }
    }
}

pub struct Func(*const wasm_func_t);

impl Func {
    pub fn new(ext: &Extern) -> Self {
        unsafe {
            let ptr = wasm_extern_as_func(ext.0);
            assert!(!ptr.is_null());
            Func(ptr)
        }
    }

    pub fn call(&self, args: &[WasmVal]) -> WasmVal {
        unsafe {
            let wasm_args: Vec<wasm_val_t> = args
                .iter()
                .map(|x| {
                    let mut result = wasm_val_t::default();
                    match x {
                        WasmVal::I32(x) => {
                            result.of.i32 = *x;
                            result.kind = wasm_valkind_enum_WASM_I32 as u8
                        }
                        WasmVal::I64(x) => {
                            result.of.i64 = *x;
                            result.kind = wasm_valkind_enum_WASM_I64 as u8
                        }
                        WasmVal::F32(x) => {
                            result.of.f32 = *x;
                            result.kind = wasm_valkind_enum_WASM_F32 as u8
                        }
                        WasmVal::F64(x) => {
                            result.of.f64 = *x;
                            result.kind = wasm_valkind_enum_WASM_F64 as u8
                        }
                    };
                    result
                })
                .collect();
            // TODO: how many elements?
            let mut results: [wasm_val_t; 1] = Default::default();
            let trap = wasm_func_call(self.0, wasm_args.as_ptr(), results.as_mut_ptr());
            assert!(trap.is_null(), "call succeeded. no trap");
            WasmVal::new(results[0])
        }
    }
}

pub struct MemoryInternal(*mut wasm_memory_t);

impl Drop for MemoryInternal {
    fn drop(&mut self) {
        unsafe { wasm_memory_delete(self.0) }
    }
}

// Memory Uses Rc because Memory can be converted to Extern and has to be kept alive:
// let mem_ext = Memory::new(&store, MemoryType:new(2,3)).as_extern();
pub struct Memory(std::rc::Rc<MemoryInternal>);

impl Memory {
    pub fn new(store: &Store, min: u32, max: u32) -> Self {
        unsafe {
            let mut limits = wasm_limits_t::default();
            limits.min = min;
            limits.max = max;
            let memory_type = wasm_memorytype_new(&limits);
            let memory = Memory(std::rc::Rc::new(MemoryInternal(wasm_memory_new(
                store.0,
                memory_type,
            ))));
            wasm_memorytype_delete(memory_type);
            memory
        }
    }

    pub fn data(&self) -> &[u8] {
        unsafe {
            let data = wasm_memory_data((*self.0).0);
            let size = wasm_memory_data_size((*self.0).0);
            std::slice::from_raw_parts(data as *const u8, size)
        }
    }

    pub fn data_mut(&self) -> &mut [u8] {
        unimplemented!()
    }

    pub fn data_size(&self) -> usize {
        unsafe { wasm_memory_data_size((*self.0).0) }
    }

    pub fn size(&self) -> usize {
        unsafe { wasm_memory_size((*self.0).0) as usize }
    }
    pub fn grow(&self, delta: u32) -> bool {
        unsafe { wasm_memory_grow((*self.0).0, delta) }
    }
    pub fn as_extern(&self) -> Extern {
        unsafe {
            let e = wasm_memory_as_extern((*self.0).0);
            Extern(e, Some(Box::new(self.0.clone())))
        }
    }
    pub fn min(&self) -> u32 {
        unsafe { (*wasm_memorytype_limits(wasm_memory_type((*self.0).0))).min }
    }
    pub fn max(&self) -> u32 {
        unsafe { (*wasm_memorytype_limits(wasm_memory_type((*self.0).0))).max }
    }
}
