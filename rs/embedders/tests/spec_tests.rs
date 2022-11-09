use std::{ffi::OsString, fmt::Write, fs, path::PathBuf};

use ic_embedders::wasm_utils::wasm_transform;
use wasmtime::{
    Engine, Global, GlobalType, Instance, Linker, Memory, MemoryType, Mutability, Store, Table,
    TableType, Val, ValType,
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
/// All `simd` files are also skipped. There seems to be at least one encoding
/// bug in `wasm-encoder` that causes them to fail.
const FILES_TO_SKIP: &[&str] = &["names.wast", "linking.wast", "exports.wast"];

/// Conversions between wast and wasmtime types.
mod convert {
    use wasmtime::Val;
    use wast::{
        core::{HeapType, NanPattern, V128Pattern, WastArgCore, WastRetCore},
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

    // Canonicalize all nan values to these fixed nans.
    const F32_NAN: u32 = 4290772992;
    const F64_NAN: u64 = 18444492273895866368;

    pub(super) fn canonicalize_nans(r: Val) -> Val {
        match r {
            Val::F32(f) if f32::from_bits(f).is_nan() => Val::F32(F32_NAN),
            Val::F64(f) if f64::from_bits(f).is_nan() => Val::F64(F64_NAN),
            _ => r,
        }
    }

    fn nan32(f: NanPattern<Float32>) -> u32 {
        match f {
            NanPattern::CanonicalNan => F32_NAN,
            NanPattern::ArithmeticNan => F32_NAN,
            NanPattern::Value(f) => {
                let bits = f.bits;
                if f32::from_bits(bits).is_nan() {
                    F32_NAN
                } else {
                    bits
                }
            }
        }
    }

    fn nan64(f: NanPattern<Float64>) -> u64 {
        match f {
            NanPattern::CanonicalNan => F64_NAN as u64,
            NanPattern::ArithmeticNan => F64_NAN as u64,
            NanPattern::Value(f) => {
                let bits = f.bits;
                if f64::from_bits(bits).is_nan() {
                    F64_NAN
                } else {
                    bits
                }
            }
        }
    }

    fn v128_pattern(v: V128Pattern) -> i128 {
        match v {
            V128Pattern::I8x16(i8s) => i128::from_le_bytes(
                i8s.into_iter()
                    .map(|i| i as u8)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            ),
            V128Pattern::I16x8(is) => i128::from_le_bytes(
                is.into_iter()
                    .flat_map(|i| i.to_le_bytes())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            ),
            V128Pattern::I32x4(is) => i128::from_le_bytes(
                is.into_iter()
                    .flat_map(|i| i.to_le_bytes())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            ),
            V128Pattern::I64x2(is) => i128::from_le_bytes(
                is.into_iter()
                    .flat_map(|i| i.to_le_bytes())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            ),
            V128Pattern::F32x4(fs) => i128::from_le_bytes(
                fs.into_iter()
                    .flat_map(|f| nan32(f).to_le_bytes())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            ),
            V128Pattern::F64x2(fs) => i128::from_le_bytes(
                fs.into_iter()
                    .flat_map(|f| nan64(f).to_le_bytes())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            ),
        }
    }

    pub(super) fn ret(ret: WastRet) -> Option<wasmtime::Val> {
        match ret {
            WastRet::Core(WastRetCore::I32(i)) => Some(wasmtime::Val::I32(i)),
            WastRet::Core(WastRetCore::I64(i)) => Some(wasmtime::Val::I64(i)),
            WastRet::Core(WastRetCore::F32(f)) => Some(wasmtime::Val::F32(nan32(f))),
            WastRet::Core(WastRetCore::F64(f)) => Some(wasmtime::Val::F64(nan64(f))),
            WastRet::Core(WastRetCore::V128(v)) => {
                Some(wasmtime::Val::V128(v128_pattern(v) as u128))
            }
            WastRet::Core(WastRetCore::RefNull(ty)) => match ty {
                Some(ty) => Some(heap_type(ty)),
                None => Some(wasmtime::Val::null()),
            },
            WastRet::Core(WastRetCore::RefExtern(n)) => Some(wasmtime::ExternRef::new(n).into()),
            WastRet::Core(WastRetCore::RefFunc(_)) => {
                println!("RefFunc ret types not yet supported");
                None
            }
            WastRet::Core(WastRetCore::Either(_)) => {
                println!("Either ret types not yet supported");
                None
            }
            WastRet::Component(_) => {
                println!(
                    "Component feature not enabled. Can't handle WastRet {:?}",
                    ret
                );
                None
            }
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

fn val_equal(left: &wasmtime::Val, right: &wasmtime::Val) -> bool {
    use wasmtime::Val as V;

    match (left, right) {
        (V::I32(l), V::I32(r)) => l == r,
        (V::I64(l), V::I64(r)) => l == r,
        (V::F32(l), V::F32(r)) => l == r,
        (V::F64(l), V::F64(r)) => l == r,
        (V::V128(l), V::V128(r)) => l == r,
        // `WastArgCore::RefExtern` always stores a `u32`.
        (V::ExternRef(l), V::ExternRef(r)) => match (l, r) {
            (None, None) => true,
            (Some(l), Some(r)) => {
                let l = l.data().downcast_ref::<u32>().unwrap();
                let r = r.data().downcast_ref::<u32>().unwrap();
                l == r
            }
            _ => false,
        },
        (V::FuncRef(l), V::FuncRef(r)) => match (l, r) {
            (None, None) => true,
            // Should these be compared using the raw value?
            (Some(_), Some(_)) => false,
            _ => false,
        },
        _ => false,
    }
}

fn vals_equal(left: &[wasmtime::Val], right: &[wasmtime::Val]) -> bool {
    if left.len() == right.len() {
        left.iter().zip(right.iter()).all(|(l, r)| val_equal(l, r))
    } else {
        false
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
        let engine = Engine::default();
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
        self.run_with_wasmtime(name, &params, id).map(|results| {
            results
                .into_iter()
                .map(|r| convert::canonicalize_nans(r))
                .collect()
        })
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
                    let expected_results: Vec<_> =
                        results.into_iter().map(|r| convert::ret(r)).collect();
                    if expected_results.iter().any(|r| r.is_none()) {
                        return Ok(());
                    }
                    let expected_results: Vec<_> =
                        expected_results.into_iter().map(|r| r.unwrap()).collect();
                    if !vals_equal(&run_results, &expected_results) {
                        return Err(format!(
                            "Incorrect result running wasm at {}: Expected {:?} but got {:?}",
                            span_location(span, text, path),
                            expected_results,
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
            && !path.file_name().unwrap().to_str().unwrap().contains("simd")
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
