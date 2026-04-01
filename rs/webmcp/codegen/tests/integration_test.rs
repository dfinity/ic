use ic_webmcp_codegen::did_parser::parse_did_file;
use ic_webmcp_codegen::schema_mapper::candid_to_json_schema;
use ic_webmcp_codegen::{Config, generate_manifest};
use std::path::PathBuf;

fn ledger_did_path() -> PathBuf {
    // CARGO_MANIFEST_DIR = .../rs/webmcp/codegen
    // repo root = .../  (3 levels up)
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .unwrap() // rs/webmcp
        .parent()
        .unwrap() // rs
        .parent()
        .unwrap() // repo root
        .join("rs/ledger_suite/icp/ledger.did")
}

#[test]
fn test_parse_icp_ledger_did() {
    let path = ledger_did_path();
    assert!(path.exists(), "ledger.did not found at {}", path.display());

    let parsed = parse_did_file(&path).expect("Failed to parse ledger.did");
    assert!(!parsed.methods.is_empty(), "Expected methods in ledger.did");

    // Check that some known methods exist
    let method_names: Vec<&str> = parsed.methods.iter().map(|m| m.name.as_str()).collect();
    assert!(
        method_names.contains(&"transfer"),
        "Expected 'transfer' method, found: {:?}",
        method_names
    );
    assert!(
        method_names.contains(&"account_balance"),
        "Expected 'account_balance' method, found: {:?}",
        method_names
    );

    // Check query vs update classification
    let account_balance = parsed
        .methods
        .iter()
        .find(|m| m.name == "account_balance")
        .unwrap();
    assert!(
        account_balance.is_query,
        "account_balance should be a query method"
    );

    let transfer = parsed
        .methods
        .iter()
        .find(|m| m.name == "transfer")
        .unwrap();
    assert!(!transfer.is_query, "transfer should be an update method");
}

#[test]
fn test_schema_generation_for_ledger_args() {
    let path = ledger_did_path();
    let parsed = parse_did_file(&path).expect("Failed to parse ledger.did");

    // Generate schemas for all method args and rets — should not panic
    for method in &parsed.methods {
        for arg in &method.args {
            let schema = candid_to_json_schema(arg, &parsed.env);
            assert!(
                schema.is_object(),
                "Schema for {}.arg should be a JSON object",
                method.name
            );
        }
        for ret in &method.rets {
            let schema = candid_to_json_schema(ret, &parsed.env);
            assert!(
                schema.is_object(),
                "Schema for {}.ret should be a JSON object",
                method.name
            );
        }
    }
}

#[test]
fn test_generate_manifest_from_ledger() {
    let config = Config {
        did_file: ledger_did_path(),
        canister_id: Some("ryjl3-tyaaa-aaaaa-aaaba-cai".to_string()),
        name: Some("ICP Ledger".to_string()),
        description: Some("ICP token ledger".to_string()),
        expose_methods: Some(vec!["transfer".to_string(), "account_balance".to_string()]),
        require_auth: vec!["transfer".to_string()],
        certified_queries: vec!["account_balance".to_string()],
        method_descriptions: [
            ("transfer".to_string(), "Transfer ICP tokens".to_string()),
            (
                "account_balance".to_string(),
                "Get account balance".to_string(),
            ),
        ]
        .into(),
        param_descriptions: Default::default(),
    };

    let manifest = generate_manifest(&config).expect("Failed to generate manifest");

    assert_eq!(manifest.schema_version, "1.0");
    assert_eq!(manifest.canister.name, "ICP Ledger");
    assert_eq!(
        manifest.canister.id.as_deref(),
        Some("ryjl3-tyaaa-aaaaa-aaaba-cai")
    );
    assert_eq!(manifest.tools.len(), 2);

    let transfer_tool = manifest
        .tools
        .iter()
        .find(|t| t.name == "transfer")
        .unwrap();
    assert_eq!(transfer_tool.method_type, "update");
    assert!(transfer_tool.requires_auth);
    assert_eq!(transfer_tool.description, "Transfer ICP tokens");

    let balance_tool = manifest
        .tools
        .iter()
        .find(|t| t.name == "account_balance")
        .unwrap();
    assert_eq!(balance_tool.method_type, "query");
    assert!(balance_tool.certified);
    assert_eq!(balance_tool.description, "Get account balance");

    // Auth section should be present since transfer requires auth
    let auth = manifest
        .authentication
        .as_ref()
        .expect("Expected auth section");
    assert_eq!(auth.auth_type, "internet-identity");
    assert!(
        auth.delegation_targets
            .contains(&"ryjl3-tyaaa-aaaaa-aaaba-cai".to_string())
    );

    // Verify the manifest serializes to valid JSON
    let json = serde_json::to_string_pretty(&manifest).expect("Failed to serialize manifest");
    assert!(json.contains("transfer"));
    assert!(json.contains("account_balance"));

    // Print it for manual inspection
    println!("Generated manifest:\n{}", json);
}

#[test]
fn test_js_emitter() {
    let config = Config {
        did_file: ledger_did_path(),
        canister_id: Some("ryjl3-tyaaa-aaaaa-aaaba-cai".to_string()),
        name: Some("ICP Ledger".to_string()),
        description: Some("ICP token ledger".to_string()),
        expose_methods: Some(vec!["account_balance".to_string()]),
        require_auth: vec![],
        certified_queries: vec![],
        method_descriptions: Default::default(),
        param_descriptions: Default::default(),
    };

    let manifest = generate_manifest(&config).expect("Failed to generate manifest");
    let js = ic_webmcp_codegen::js_emitter::emit_js(&manifest);

    assert!(js.contains("ICP Ledger"), "JS should contain canister name");
    assert!(
        js.contains("ryjl3-tyaaa-aaaaa-aaaba-cai"),
        "JS should contain canister ID"
    );
    assert!(
        js.contains("@dfinity/webmcp"),
        "JS should import from @dfinity/webmcp"
    );
    assert!(
        js.contains("initWebMCP"),
        "JS should define initWebMCP function"
    );
}
