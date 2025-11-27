use serde_json::{Value, json};
use slog::{Logger, info};
use std::fs;
use std::path::Path;

const CANISTER_COUNTER_MO: &str = include_str!("../canisters/counter.mo");

pub fn add_counter_canister(log: &Logger, project_dir: &Path) {
    add_motoko_canister(log, project_dir, "counter", CANISTER_COUNTER_MO);
}

pub fn add_motoko_canister(
    log: &Logger,
    project_dir: &Path,
    canister_name: &str,
    main_source: &str,
) {
    info!(
        log,
        "Adding motoko canister '{canister_name}' to project in {}",
        project_dir.display()
    );

    let filename = format!("{canister_name}.mo");
    let main_path = project_dir.join(&filename);

    info!(log, "Writing {}", main_path.display());
    fs::write(main_path, main_source).unwrap();

    let canister = json!({
        "type": "motoko",
        "main": filename,
    });

    add_canister(log, project_dir, canister_name, canister);
}

pub fn add_canister(log: &Logger, project_dir: &Path, canister_name: &str, canister: Value) {
    let project_path = project_dir.join("dfx.json");
    info!(
        log,
        "Add canister '{canister_name}' to {}",
        project_path.display()
    );

    let project_json = fs::read_to_string(&project_path).unwrap();
    let mut project: Value = serde_json::from_str(&project_json).unwrap();

    let canisters = project
        .as_object_mut()
        .expect("Root should be an object")
        .get_mut("canisters")
        .expect("No 'canisters' field found");

    canisters[canister_name] = canister;

    let updated_project = serde_json::to_string_pretty(&project).unwrap();
    fs::write(project_path, updated_project).unwrap();
}
