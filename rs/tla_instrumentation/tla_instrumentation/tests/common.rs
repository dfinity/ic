use std::path::PathBuf;
use tla_instrumentation::UpdateTrace;
use tla_instrumentation::checker::{PredicateDescription, check_tla_code_link};

// Add JAVABASE/bin to PATH to make the Bazel-provided JRE available to scripts
fn set_java_path() {
    let current_path = std::env::var("PATH").unwrap();
    let bazel_java = std::env::var("JAVABASE").unwrap();
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("PATH", format!("{current_path}:{bazel_java}/bin")) };
}

/// Returns the path to the TLA module (e.g. `Foo.tla` -> `/home/me/tla/Foo.tla`).
/// TLA modules are read from $TLA_MODULES (space-separated list)
/// NOTE: this assumes unique basenames amongst the modules
pub fn get_tla_module_path(module: &str) -> PathBuf {
    let modules = std::env::var("TLA_MODULES").expect(
        "environment variable 'TLA_MODULES' should be a space-separated list of TLA modules",
    );

    modules
        .split(" ")
        .map(|f| f.into()) /* str -> PathBuf */
        .find(|f: &PathBuf| f.file_name().is_some_and(|file_name| file_name == module))
        .unwrap_or_else(|| {
            panic!("Could not find TLA module {module}, check 'TLA_MODULES' is set correctly")
        })
}

pub fn get_apalache_path() -> PathBuf {
    let apalache = std::env::var("TLA_APALACHE_BIN")
        .expect("environment variable 'TLA_APALACHE_BIN' should point to the apalache binary");
    let apalache = PathBuf::from(apalache);

    if !apalache.as_path().is_file() {
        panic!("bad apalache bin from 'TLA_APALACHE_BIN': '{apalache:?}'");
    }

    apalache
}

pub fn check_tla_trace(trace: &UpdateTrace) {
    set_java_path();
    let model_name = trace.model_name.clone();
    for pair in &trace.state_pairs {
        let constants = trace.constants.clone();
        println!("Constants: {constants:?}");
        // NOTE: the 'process_id" is actually the tla module name
        let tla_module = format!("{model_name}_Apalache.tla");
        let tla_module = get_tla_module_path(&tla_module);
        check_tla_code_link(
            &get_apalache_path(),
            PredicateDescription {
                tla_module,
                transition_predicate: "Next".to_string(),
                predicate_parameters: Vec::new(),
            },
            pair.clone(),
            constants,
        )
        .expect("TLA link check failed");
    }
}
