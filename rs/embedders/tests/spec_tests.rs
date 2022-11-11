use std::{ffi::OsString, fmt::Write, fs, path::PathBuf};

use ic_embedders::wasm_utils::wasm_transform;
use wasmtime::{
    Config, Engine, Global, GlobalType, Instance, Linker, Memory, MemoryType, Mutability, Store,
    Table, TableType, Val, ValType,
};
use wast::{
    parser::ParseBuffer,
    token::{Id, Span},
    QuoteWat, Wast, WastArg, WastDirective, Wat,
};

/// Tests shouldn't be run on these files.
///
/// `names.wast`: `wast` itself seems to hit an error reading this file.
/// `linking.wast`: The wast module Id's aren't yet properly handled.
/// `exports.wast`: The wast module Id's aren't yet properly handled.
/// `simd_i64x2_cmp.wast`: There is a bug in wasm-encoder that incorrectly
/// encodes the LeS instruction and causes this test to fail.
const FILES_TO_SKIP: &[&str] = &[
    "names.wast",
    "linking.wast",
    "exports.wast",
    "simd_i64x2_cmp.wast",
];

/// Conversions between wast and wasmtime types.
mod convert {
    use wast::{
        core::{HeapType, NanPattern, V128Pattern, WastArgCore},
        token::{Float32, Float64},
        WastArg, WastRet,
    };

    fn heap_type(heap_type: HeapType) -> wasmtime::Val {
        match heap_type {
            HeapType::Func => wasmtime::Val::FuncRef(None),
            HeapType::Extern => wasmtime::Val::ExternRef(None),
            HeapType::Any
            | HeapType::Eq
            | HeapType::Data
            | HeapType::Array
            | HeapType::I31
            | HeapType::Index(_) => panic!(
                "Unable to handle heap type {:?}. The GC proposal isn't supported",
                heap_type
            ),
        }
    }

    pub(super) fn arg(arg: WastArg) -> Option<wasmtime::Val> {
        match arg {
            WastArg::Core(WastArgCore::I32(i)) => Some(wasmtime::Val::I32(i)),
            WastArg::Core(WastArgCore::I64(i)) => Some(wasmtime::Val::I64(i)),
            WastArg::Core(WastArgCore::F32(f)) => Some(wasmtime::Val::F32(f.bits)),
            WastArg::Core(WastArgCore::F64(f)) => Some(wasmtime::Val::F64(f.bits)),
            WastArg::Core(WastArgCore::V128(v)) => {
                Some(wasmtime::Val::V128(u128::from_le_bytes(v.to_le_bytes())))
            }
            WastArg::Core(WastArgCore::RefNull(ty)) => Some(heap_type(ty)),
            WastArg::Core(WastArgCore::RefExtern(n)) => Some(wasmtime::ExternRef::new(n).into()),
            WastArg::Component(_) => {
                println!(
                    "Component feature not enabled. Can't handle WastArg {:?}",
                    arg
                );
                None
            }
        }
    }

    /// Comparison of a Wasmtime f32 result with the expected Wast value. Copied
    /// from
    /// https://github.com/bytecodealliance/wasmtime/blob/main/crates/wast/src/core.rs#L106.
    fn f32_equal(actual: u32, expected: &NanPattern<Float32>) -> bool {
        match expected {
            // Check if an f32 (as u32 bits to avoid possible quieting when moving values in registers, e.g.
            // https://developer.arm.com/documentation/ddi0344/i/neon-and-vfp-programmers-model/modes-of-operation/default-nan-mode?lang=en)
            // is a canonical NaN:
            //  - the sign bit is unspecified,
            //  - the 8-bit exponent is set to all 1s
            //  - the MSB of the payload is set to 1 (a quieted NaN) and all others to 0.
            // See https://webassembly.github.io/spec/core/syntax/values.html#floating-point.
            NanPattern::CanonicalNan => {
                let canon_nan = 0x7fc0_0000;
                (actual & 0x7fff_ffff) == canon_nan
            }

            // Check if an f32 (as u32, see comments above) is an arithmetic NaN.
            // This is the same as a canonical NaN including that the payload MSB is
            // set to 1, but one or more of the remaining payload bits MAY BE set to
            // 1 (a canonical NaN specifies all 0s). See
            // https://webassembly.github.io/spec/core/syntax/values.html#floating-point.
            NanPattern::ArithmeticNan => {
                const AF32_NAN: u32 = 0x7f80_0000;
                let is_nan = actual & AF32_NAN == AF32_NAN;
                const AF32_PAYLOAD_MSB: u32 = 0x0040_0000;
                let is_msb_set = actual & AF32_PAYLOAD_MSB == AF32_PAYLOAD_MSB;
                is_nan && is_msb_set
            }
            NanPattern::Value(expected_value) => actual == expected_value.bits,
        }
    }

    /// Comparison of a Wasmtime f64 result with the expected Wast value. Copied
    /// from
    /// https://github.com/bytecodealliance/wasmtime/blob/main/crates/wast/src/core.rs#L171.
    pub fn f64_equal(actual: u64, expected: &NanPattern<Float64>) -> bool {
        match expected {
            // Check if an f64 (as u64 bits to avoid possible quieting when moving values in registers, e.g.
            // https://developer.arm.com/documentation/ddi0344/i/neon-and-vfp-programmers-model/modes-of-operation/default-nan-mode?lang=en)
            // is a canonical NaN:
            //  - the sign bit is unspecified,
            //  - the 11-bit exponent is set to all 1s
            //  - the MSB of the payload is set to 1 (a quieted NaN) and all others to 0.
            // See https://webassembly.github.io/spec/core/syntax/values.html#floating-point.
            NanPattern::CanonicalNan => {
                let canon_nan = 0x7ff8_0000_0000_0000;
                (actual & 0x7fff_ffff_ffff_ffff) == canon_nan
            }

            // Check if an f64 (as u64, see comments above) is an arithmetic NaN. This is the same as a
            // canonical NaN including that the payload MSB is set to 1, but one or more of the remaining
            // payload bits MAY BE set to 1 (a canonical NaN specifies all 0s). See
            // https://webassembly.github.io/spec/core/syntax/values.html#floating-point.
            NanPattern::ArithmeticNan => {
                const AF64_NAN: u64 = 0x7ff0_0000_0000_0000;
                let is_nan = actual & AF64_NAN == AF64_NAN;
                const AF64_PAYLOAD_MSB: u64 = 0x0008_0000_0000_0000;
                let is_msb_set = actual & AF64_PAYLOAD_MSB == AF64_PAYLOAD_MSB;
                is_nan && is_msb_set
            }
            NanPattern::Value(expected_value) => actual == expected_value.bits,
        }
    }

    fn v128_equal(left: u128, right: &V128Pattern) -> bool {
        match right {
            V128Pattern::I8x16(parts) => {
                left == u128::from_le_bytes(
                    parts
                        .iter()
                        .flat_map(|i| i.to_le_bytes())
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap(),
                )
            }
            V128Pattern::I16x8(parts) => {
                left == u128::from_le_bytes(
                    parts
                        .iter()
                        .flat_map(|i| i.to_le_bytes())
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap(),
                )
            }
            V128Pattern::I32x4(parts) => {
                left == u128::from_le_bytes(
                    parts
                        .iter()
                        .flat_map(|i| i.to_le_bytes())
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap(),
                )
            }
            V128Pattern::I64x2(parts) => {
                left == u128::from_le_bytes(
                    parts
                        .iter()
                        .flat_map(|i| i.to_le_bytes())
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap(),
                )
            }
            V128Pattern::F32x4([r1, r2, r3, r4]) => {
                let bytes = left.to_le_bytes();
                let l1 = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
                let l2 = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
                let l3 = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
                let l4 = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
                f32_equal(l1, r1) && f32_equal(l2, r2) && f32_equal(l3, r3) && f32_equal(l4, r4)
            }
            V128Pattern::F64x2([r1, r2]) => {
                let bytes = left.to_le_bytes();
                let l1 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
                let l2 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
                f64_equal(l1, r1) && f64_equal(l2, r2)
            }
        }
    }

    fn val_equal(left: &wasmtime::Val, right: &WastRet) -> bool {
        use wasmtime::Val as V;
        use wast::core::WastRetCore as R;
        use WastRet::Core as C;

        match (left, right) {
            (V::I32(l), C(R::I32(r))) => l == r,
            (V::I64(l), C(R::I64(r))) => l == r,
            (V::F32(l), C(R::F32(r))) => f32_equal(*l, r),
            (V::F64(l), C(R::F64(r))) => f64_equal(*l, r),
            (V::V128(l), C(R::V128(r))) => v128_equal(*l, r),
            (V::ExternRef(None), C(R::RefExtern(_))) => false,
            // `WastArgCore::RefExtern` always stores a `u32`.
            (V::ExternRef(Some(l)), C(R::RefExtern(r))) => {
                let l = l.data().downcast_ref::<u32>().unwrap();
                l == r
            }
            (V::ExternRef(l), C(R::RefNull(_))) => l.is_none(),
            (V::FuncRef(l), C(R::RefNull(_))) => l.is_none(),
            (V::FuncRef(l), C(R::RefFunc(r))) => match (l, r) {
                (None, None) => true,
                // Should these be compared using the raw value?
                (Some(_), Some(_)) => false,
                _ => false,
            },
            _ => false,
        }
    }

    pub(super) fn vals_equal(left: &[wasmtime::Val], right: &[WastRet]) -> bool {
        if left.len() == right.len() {
            left.iter().zip(right.iter()).all(|(l, r)| val_equal(l, r))
        } else {
            false
        }
    }
}

fn wat_id<'a>(wat: &QuoteWat<'a>) -> Option<Id<'a>> {
    match wat {
        QuoteWat::Wat(Wat::Module(module)) => module.id,
        QuoteWat::Wat(Wat::Component(component)) => component.id,
        QuoteWat::QuoteModule(_, _) => None,
        QuoteWat::QuoteComponent(_, _) => None,
    }
}

/// The tests seem to assume there is an existing `spectest` which provides
/// these exports.
fn define_spectest_exports(linker: &mut Linker<()>, mut store: &mut Store<()>) {
    linker.func_wrap("spectest", "print", || {}).unwrap();
    linker
        .func_wrap("spectest", "print_f32", |_: f32| {})
        .unwrap();
    linker
        .func_wrap("spectest", "print_f64", |_: f64| {})
        .unwrap();
    linker
        .func_wrap("spectest", "print_f64_f64", |_: f64, _: f64| {})
        .unwrap();
    linker
        .func_wrap("spectest", "print_i32", |_: i32| {})
        .unwrap();
    linker
        .func_wrap("spectest", "print_i32_f32", |_: i32, _: f32| {})
        .unwrap();
    linker
        .func_wrap("spectest", "print_i64", |_: i64| {})
        .unwrap();

    let global_i32 = Global::new(
        &mut store,
        GlobalType::new(ValType::I32, Mutability::Const),
        Val::I32(666),
    )
    .unwrap();
    linker.define("spectest", "global_i32", global_i32).unwrap();
    let global_i64 = Global::new(
        &mut store,
        GlobalType::new(ValType::I64, Mutability::Const),
        Val::I64(666),
    )
    .unwrap();
    linker.define("spectest", "global_i64", global_i64).unwrap();
    let global_f32 = Global::new(
        &mut store,
        GlobalType::new(ValType::F32, Mutability::Const),
        Val::F32(0),
    )
    .unwrap();
    linker.define("spectest", "global_f32", global_f32).unwrap();
    let global_f64 = Global::new(
        &mut store,
        GlobalType::new(ValType::F64, Mutability::Const),
        Val::F64(0),
    )
    .unwrap();
    linker.define("spectest", "global_f64", global_f64).unwrap();

    let table = Table::new(
        &mut store,
        TableType::new(ValType::FuncRef, 10, Some(20)),
        Val::FuncRef(None),
    )
    .unwrap();
    linker.define("spectest", "table", table).unwrap();

    let memory = Memory::new(&mut store, MemoryType::new(1, Some(2))).unwrap();
    linker.define("spectest", "memory", memory).unwrap();
}

/// The last module that was loaded from the wast file.
enum CurrentModule<'a> {
    Unregistered(Result<(Instance, Option<Id<'a>>), anyhow::Error>),
    /// If the module has been registered, this is it's index in the registerd
    /// modules vector.
    Registered(usize),
    None,
}

struct TestState<'a> {
    /// The latest module.
    current: CurrentModule<'a>,
    /// Collection of modules which have been registered.
    registered: Vec<(String, Option<Id<'a>>, Instance)>,
    store: Store<()>,
    linker: Linker<()>,
    engine: Engine,
}

impl<'a> TestState<'a> {
    fn new() -> Self {
        // Note that the tests should pass with or without
        // `cranelift_nan_canonicalization`. But we only use `wasmtime` with
        // this feature enabled, so it's better to test the case we actually
        // use.
        let engine = Engine::new(Config::new().cranelift_nan_canonicalization(true)).unwrap();
        let mut store = Store::new(&engine, ());
        let mut linker = Linker::new(&engine);
        define_spectest_exports(&mut linker, &mut store);
        Self {
            current: CurrentModule::None,
            registered: vec![],
            store,
            linker,
            engine,
        }
    }

    fn try_create_instance(&mut self, wasm: &[u8]) -> Result<Instance, anyhow::Error> {
        let module = wasmtime::Module::new(&self.engine, wasm).unwrap();
        self.linker.instantiate(&mut self.store, &module)
    }

    fn update_module(&mut self, wasm: &[u8], id: Option<Id<'a>>) {
        let instance = self.try_create_instance(wasm).map(|i| (i, id));
        self.current = CurrentModule::Unregistered(instance);
    }

    fn register(&mut self, name: String, id: Option<Id<'a>>) {
        let index = self.registered.len();
        match std::mem::replace(&mut self.current, CurrentModule::Registered(index)) {
            CurrentModule::Registered(_) => panic!("Can't register the same module twice"),
            CurrentModule::Unregistered(Ok((instance, _))) => {
                self.linker
                    .instance(&mut self.store, &name, instance)
                    .unwrap();
                self.registered.push((name, id, instance));
            }
            CurrentModule::Unregistered(Err(e)) => {
                panic!("Last module could not be instantiated: {}", e)
            }
            CurrentModule::None => panic!("There is no current module to register"),
        }
    }

    fn run_with_wasmtime(
        &mut self,
        name: &str,
        params: &[wasmtime::Val],
        id: Option<Id<'a>>,
    ) -> Result<Vec<wasmtime::Val>, String> {
        let instance = match id {
            None => match &mut self.current {
                CurrentModule::Unregistered(Ok((i, _))) => i,
                CurrentModule::Registered(inx) => {
                    let (_, _, i) = self.registered.get_mut(*inx).unwrap();
                    i
                }
                CurrentModule::Unregistered(Err(e)) => {
                    return Err(format!(
                        "Current module had error {} before running {:?}:{} with params {:?}",
                        e, id, name, params
                    ))
                }
                CurrentModule::None => {
                    return Err(format!(
                        "No current module when trying to run {:?}:{} with params {:?}",
                        id, name, params
                    ))
                }
            },
            Some(id) => {
                if let Some((_, _, instance)) = self
                    .registered
                    .iter_mut()
                    .find(|(_, registered_id, _)| *registered_id == Some(id))
                {
                    instance
                } else if let CurrentModule::Unregistered(Ok((i, current_id))) = &mut self.current {
                    if *current_id == Some(id) {
                        i
                    } else {
                        panic!("Couldn't find module with id {:?}", id);
                    }
                } else {
                    panic!("Couldn't find module with id {:?}", id)
                }
            }
        };
        let function = instance.get_func(&mut self.store, name).unwrap();
        let result_count = function.ty(&mut self.store).results().count();
        let mut results = vec![wasmtime::Val::FuncRef(None); result_count];
        function
            .call(&mut self.store, params, &mut results)
            .map_err(|e| e.to_string())?;
        Ok(results)
    }

    fn run(
        &mut self,
        name: &str,
        params: Vec<WastArg>,
        id: Option<Id<'a>>,
    ) -> Result<Vec<wasmtime::Val>, String> {
        let params: Vec<_> = params.into_iter().map(|a| convert::arg(a)).collect();
        if params.iter().any(|p| p.is_none()) {
            return Ok(vec![]);
        }
        let params: Vec<_> = params.into_iter().map(Option::unwrap).collect();
        self.run_with_wasmtime(name, &params, id)
    }
}

fn is_component(wat: &QuoteWat) -> bool {
    match wat {
        QuoteWat::Wat(Wat::Component(_)) | QuoteWat::QuoteComponent(_, _) => true,
        QuoteWat::Wat(Wat::Module(_)) | QuoteWat::QuoteModule(_, _) => false,
    }
}

fn span_location(span: Span, text: &str, path: &PathBuf) -> String {
    let (line, col) = span.linecol_in(text);
    let line_text = &text[(span.offset() - col)..]
        .split_terminator('\n')
        .next()
        .unwrap();
    format!(
        "Test failed in wast {:?} at line {}: {}",
        path, line, line_text
    )
}

fn location(wat: &QuoteWat, text: &str, path: &PathBuf) -> String {
    let span = match wat {
        QuoteWat::Wat(Wat::Module(module)) => module.span,
        QuoteWat::Wat(Wat::Component(comp)) => comp.span,
        QuoteWat::QuoteModule(span, _) | QuoteWat::QuoteComponent(span, _) => *span,
    };
    span_location(span, text, path)
}

fn parse_and_encode(wat: &mut QuoteWat, text: &str, path: &PathBuf) -> Result<Vec<u8>, String> {
    let wasm = wat.encode().map_err(|e| {
        format!(
            "Error encoding wat from wast: {} in {}",
            e,
            location(wat, text, path)
        )
    })?;
    let module = wasm_transform::Module::parse(&wasm)
        .map_err(|e| format!("Parsing error: {:?} in {}", e, location(wat, text, path)))?;
    module
        .encode()
        .map_err(|e| format!("Parsing error: {:?} in {}", e, location(wat, text, path)))
}

fn validate_with_wasmtime(
    wasm: &[u8],
    wat: &QuoteWat,
    text: &str,
    path: &PathBuf,
) -> Result<(), String> {
    let engine = wasmtime::Engine::new(&wasmtime::Config::default()).unwrap();
    wasmtime::Module::validate(&engine, wasm).map_err(|e| {
        format!(
            "Failed to validate module with wasmtime: {} in {}",
            e,
            location(wat, text, path)
        )
    })
}

fn run_directive<'a>(
    directive: WastDirective<'a>,
    text: &str,
    path: &PathBuf,
    test_state: &mut TestState<'a>,
) -> Result<(), String> {
    match directive {
        // Here we check that an example module can be parsed and encoded with
        // wasm-transform and is still validated by wasmtime after the round
        // trip.
        WastDirective::Wat(mut wat) => {
            if is_component(&wat) {
                return Ok(());
            }
            let wasm = parse_and_encode(&mut wat, text, path)?;
            validate_with_wasmtime(&wasm, &wat, text, path)?;
            test_state.update_module(&wasm, wat_id(&wat));
            Ok(())
        }
        // wasm-transform itself should throw an error when trying to parse these modules.
        // TODO(RUN-448): Change this to assert `parse_and_encode` returned an error.
        WastDirective::AssertMalformed {
            span: _,
            module: mut wat,
            message,
        } => {
            if let Ok(wasm) = parse_and_encode(&mut wat, text, path) {
                if validate_with_wasmtime(&wasm, &wat, text, path).is_ok() {
                    return Err(format!(
                        "Should not have been able to validate malformed module ({}) {}",
                        message,
                        location(&wat, text, path)
                    ));
                }
            }
            Ok(())
        }
        // These directives include many wasm modules that wasm-transform won't
        // be able to recognize as invalid (e.g. function bodies that don't type
        // check). So we want to assert that after parsing and endcoding,
        // wasmtime still throws an error on validation. That is, wasm-transform
        // didn't somehow make an invalid module valid.
        WastDirective::AssertInvalid {
            span: _,
            module: mut wat,
            message,
        } => {
            if let Ok(wasm) = parse_and_encode(&mut wat, text, path) {
                if validate_with_wasmtime(&wasm, &wat, text, path).is_ok() {
                    return Err(format!(
                        "Should not have been able to validate invalid module ({}) {}",
                        message,
                        location(&wat, text, path)
                    ));
                }
            }
            Ok(())
        }
        WastDirective::AssertReturn {
            span,
            exec,
            results,
        } => {
            match exec {
                wast::WastExecute::Invoke(invoke) => {
                    let run_results = test_state.run(invoke.name, invoke.args, invoke.module)?;
                    if !convert::vals_equal(&run_results, &results) {
                        return Err(format!(
                            "Incorrect result running wasm at {}: Expected {:?} but got {:?}",
                            span_location(span, text, path),
                            results,
                            run_results,
                        ));
                    }
                }
                wast::WastExecute::Wat(_) | wast::WastExecute::Get { .. } => {}
            }
            Ok(())
        }
        WastDirective::Register {
            span: _,
            name,
            module,
        } => {
            let name = name.to_string();
            test_state.register(name, module);
            Ok(())
        }
        WastDirective::Invoke(invoke) => {
            let _ = test_state.run(invoke.name, invoke.args, invoke.module)?;
            Ok(())
        }
        WastDirective::AssertTrap {
            span,
            exec,
            message,
        } => match exec {
            wast::WastExecute::Invoke(invoke) => {
                let result = test_state.run(invoke.name, invoke.args, invoke.module);
                match result {
                    Ok(_) => Err(format!(
                        "Should not have been able to execute assert_trap of type {} at {}",
                        message,
                        span_location(span, text, path)
                    )),
                    Err(e) => {
                        // There seemes to be one case in `bulk.wast` where the
                        // error message contains extra information.
                        let message = if message.starts_with("uninitialized element") {
                            "uninitialized element"
                        } else {
                            message
                        };
                        if e.contains(message) {
                            Ok(())
                        } else {
                            Err(format!(
                                "Error for assert_trap at {}: {} did not contain trap message {}",
                                span_location(span, text, path),
                                e,
                                message
                            ))
                        }
                    }
                }
            }
            wast::WastExecute::Wat(_) | wast::WastExecute::Get { .. } => Ok(()),
        },
        WastDirective::AssertExhaustion {
            span,
            call: invoke,
            message,
        } => {
            let result = test_state.run(invoke.name, invoke.args, invoke.module);
            match result {
                Ok(_) => Err(format!(
                    "Should not have been able to execute assert_exhaustion of type {} at {}",
                    message,
                    span_location(span, text, path)
                )),
                Err(e) => {
                    if e.contains(message) {
                        Ok(())
                    } else {
                        Err(format!(
                            "Error for assert_exhaustion at {}: {} did not contain message {}",
                            span_location(span, text, path),
                            e,
                            message
                        ))
                    }
                }
            }
        }
        WastDirective::AssertException { span, exec } => match exec {
            wast::WastExecute::Invoke(invoke) => {
                let result = test_state.run(invoke.name, invoke.args, invoke.module);
                match result {
                    Ok(_) => Err(format!(
                        "Should not have been able to execute assert_exception at {}",
                        span_location(span, text, path)
                    )),
                    Err(_) => Ok(()),
                }
            }
            wast::WastExecute::Wat(_) | wast::WastExecute::Get { .. } => Ok(()),
        },
        WastDirective::AssertUnlinkable {
            span,
            module,
            message,
        } => {
            let mut wat = QuoteWat::Wat(module);
            let wasm = parse_and_encode(&mut wat, text, path)?;
            validate_with_wasmtime(&wasm, &wat, text, path)?;
            match test_state.try_create_instance(&wasm) {
                Ok(_) => Err(format!(
                    "Should not have been able to link assert_unlinkable at {} of type {}",
                    span_location(span, text, path),
                    message
                )),
                Err(e) => {
                    if e.to_string().contains(message) {
                        Ok(())
                    } else {
                        Err(format!(
                            "Error for assert_unlinkable at {}: {} did not contain message {}",
                            span_location(span, text, path),
                            e,
                            message
                        ))
                    }
                }
            }
        }
    }
}

fn test_spec_file(path: &PathBuf) -> Result<(), String> {
    let contents = fs::read_to_string(&path).unwrap();
    let buf = ParseBuffer::new(&contents).unwrap();

    let wast = wast::parser::parse::<Wast>(&buf).unwrap();
    let mut error_string = String::new();
    let mut test_state = TestState::new();
    for directive in wast.directives {
        if let Err(e) = run_directive(directive, &contents, path, &mut test_state) {
            writeln!(error_string, "{}", e).unwrap();
        }
    }
    if !error_string.is_empty() {
        Err(error_string)
    } else {
        Ok(())
    }
}

/// This test runs on data from the WebAssembly spec testsuite. The suite is not
/// incuded in our repo, but is imported by Bazel using the `new_git_repository`
/// rule in `WORKSPACE.bazel`.
///
/// If you need to look at the test `wast` files directly they can be found in
/// `bazel-ic/external/wasm_spec_testsuite/` after building this test.
#[test]
fn spec_testsuite() {
    let dir_path = "./external/wasm_spec_testsuite".to_string();
    let directory = std::fs::read_dir(dir_path).unwrap();
    let mut test_files = vec![];
    for entry in directory {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension() == Some(&OsString::from("wast"))
            && !FILES_TO_SKIP.contains(&path.file_name().unwrap().to_str().unwrap())
        {
            test_files.push(path);
        }
    }

    println!("Running spec tests on {} files", test_files.len());
    let mut errors = vec![];
    for path in test_files {
        println!("Running tests on file {:?}", path);
        if let Err(e) = test_spec_file(&path) {
            errors.push(e);
        }
    }

    if !errors.is_empty() {
        panic!("Errors from spec tests: {}", errors.join("\n"));
    }
}
