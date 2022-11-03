use std::{ffi::OsString, fmt::Write, fs, path::PathBuf};

use ic_embedders::wasm_utils::wasm_transform;
use wast::{parser::ParseBuffer, QuoteWat, Wast, WastDirective, Wat};

/// Tests shouldn't be run on these files.
///
/// `names.wast`: `wast` itself seems to hit an error reading this file.
const FILES_TO_SKIP: &[&str] = &["names.wast"];

fn is_component(wat: &QuoteWat) -> bool {
    match wat {
        QuoteWat::Wat(Wat::Component(_)) | QuoteWat::QuoteComponent(_, _) => true,
        QuoteWat::Wat(Wat::Module(_)) | QuoteWat::QuoteModule(_, _) => false,
    }
}

fn location(wat: &QuoteWat, text: &str, path: &PathBuf) -> String {
    let span = match wat {
        QuoteWat::Wat(Wat::Module(module)) => module.span,
        QuoteWat::Wat(Wat::Component(comp)) => comp.span,
        QuoteWat::QuoteModule(span, _) | QuoteWat::QuoteComponent(span, _) => *span,
    };
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

fn parse_and_encode(wat: &mut QuoteWat, text: &str, path: &PathBuf) -> Result<Vec<u8>, String> {
    let wasm = wat.encode().unwrap();
    let module = match wasm_transform::Module::parse(&wasm) {
        Ok(module) => module,
        Err(e) => {
            return Err(format!(
                "Parsing error: {:?} in {}",
                e,
                location(wat, text, path)
            ))
        }
    };
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

fn run_directive(directive: WastDirective, text: &str, path: &PathBuf) -> Result<(), String> {
    match directive {
        WastDirective::Wat(mut wat) => {
            if is_component(&wat) {
                return Ok(());
            }
            let wasm = parse_and_encode(&mut wat, text, path)?;
            validate_with_wasmtime(&wasm, &wat, text, path)
        }
        // Maybe if it's binary encoded we can assert that we aren't able to parse/encode?
        WastDirective::AssertMalformed {
            span: _,
            module: _,
            message: _,
        } => Ok(()),
        WastDirective::AssertInvalid {
            span: _,
            module: _,
            message: _,
        } => Ok(()),
        // Not sure what this is for?
        WastDirective::Register {
            span: _,
            name: _,
            module: _,
        } => Ok(()),
        // We aren't concerned with executing.
        WastDirective::Invoke(_)
        | WastDirective::AssertTrap {
            span: _,
            exec: _,
            message: _,
        }
        | WastDirective::AssertReturn {
            span: _,
            exec: _,
            results: _,
        }
        | WastDirective::AssertExhaustion {
            span: _,
            call: _,
            message: _,
        }
        | WastDirective::AssertUnlinkable {
            span: _,
            module: _,
            message: _,
        }
        | WastDirective::AssertException { span: _, exec: _ } => Ok(()),
    }
}

fn test_spec_file(path: &PathBuf) -> Result<(), String> {
    let contents = fs::read_to_string(&path).unwrap();
    let buf = ParseBuffer::new(&contents).unwrap();

    let wast = wast::parser::parse::<Wast>(&buf).unwrap();
    let mut error_string = String::new();
    for directive in wast.directives {
        if let Err(e) = run_directive(directive, &contents, path) {
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
        if let Err(e) = test_spec_file(&path) {
            errors.push(e);
        }
    }

    if !errors.is_empty() {
        panic!("Errors from spec tests: {}", errors.join("\n"));
    }
}
