//! Generate WebMCP manifest (webmcp.json) from parsed Candid interfaces.

use crate::config::Config;
use crate::did_parser::{CanisterMethod, parse_did_file};
use crate::schema_mapper::candid_to_json_schema;
use anyhow::Result;
use candid::TypeEnv;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// Top-level WebMCP manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebMCPManifest {
    pub schema_version: String,
    pub canister: CanisterInfo,
    pub tools: Vec<WebMCPTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<AuthenticationInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanisterInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebMCPTool {
    pub name: String,
    pub description: String,
    pub canister_method: String,
    pub method_type: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub certified: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub requires_auth: bool,
    #[serde(rename = "inputSchema")]
    pub input_schema: JsonValue,
    #[serde(rename = "outputSchema", skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<JsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationInfo {
    #[serde(rename = "type")]
    pub auth_type: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub delegation_targets: Vec<String>,
}

/// Generate a WebMCP manifest from configuration.
pub fn generate_manifest(config: &Config) -> Result<WebMCPManifest> {
    let parsed = parse_did_file(&config.did_file)?;

    let tools: Vec<WebMCPTool> = parsed
        .methods
        .iter()
        .filter(|m| {
            config
                .expose_methods
                .as_ref()
                .is_none_or(|exposed| exposed.contains(&m.name))
        })
        .map(|m| method_to_tool(m, config, &parsed.env))
        .collect();

    let has_auth_tools = tools.iter().any(|t| t.requires_auth);

    let authentication = if has_auth_tools {
        Some(AuthenticationInfo {
            auth_type: "internet-identity".to_string(),
            delegation_targets: config.canister_id.iter().cloned().collect(),
        })
    } else {
        None
    };

    Ok(WebMCPManifest {
        schema_version: "1.0".to_string(),
        canister: CanisterInfo {
            id: config.canister_id.clone(),
            name: config
                .name
                .clone()
                .unwrap_or_else(|| "IC Canister".to_string()),
            description: config
                .description
                .clone()
                .unwrap_or_else(|| "Internet Computer canister".to_string()),
        },
        tools,
        authentication,
    })
}

fn method_to_tool(method: &CanisterMethod, config: &Config, env: &TypeEnv) -> WebMCPTool {
    let description = config
        .method_descriptions
        .get(&method.name)
        .cloned()
        .unwrap_or_else(|| format!("Call {}", method.name));

    let input_schema = build_input_schema(method, config, env);
    let output_schema = build_output_schema(method, env);

    WebMCPTool {
        name: method.name.clone(),
        description,
        canister_method: method.name.clone(),
        method_type: if method.is_query {
            "query".to_string()
        } else {
            "update".to_string()
        },
        certified: config.certified_queries.contains(&method.name),
        requires_auth: config.require_auth.contains(&method.name),
        input_schema,
        output_schema,
    }
}

fn build_input_schema(method: &CanisterMethod, config: &Config, env: &TypeEnv) -> JsonValue {
    if method.args.is_empty() {
        return serde_json::json!({ "type": "object", "properties": {} });
    }

    // If single argument, use its schema directly (flattening records)
    if method.args.len() == 1 {
        let schema = candid_to_json_schema(&method.args[0], env);
        if schema.get("type") == Some(&serde_json::json!("object")) {
            return enrich_param_descriptions(schema, &method.name, config);
        }
    }

    // Multiple args → wrap in object with positional names
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for (i, ty) in method.args.iter().enumerate() {
        let arg_name = format!("arg{}", i);
        let mut schema = candid_to_json_schema(ty, env);
        // Add param description if available
        let key = format!("{}.{}", method.name, arg_name);
        if let Some(desc) = config.param_descriptions.get(&key) {
            schema["description"] = serde_json::json!(desc);
        }
        // All positional args are required (optional args use opt T in Candid)
        if !matches!(ty.as_ref(), candid::types::TypeInner::Opt(_)) {
            required.push(serde_json::json!(arg_name));
        }
        properties.insert(arg_name, schema);
    }

    let mut schema = serde_json::json!({
        "type": "object",
        "properties": serde_json::Value::Object(properties),
        "additionalProperties": false
    });
    if !required.is_empty() {
        schema["required"] = serde_json::Value::Array(required);
    }
    schema
}

/// Enrich a flattened record schema with param_descriptions from config.
fn enrich_param_descriptions(
    mut schema: JsonValue,
    method_name: &str,
    config: &Config,
) -> JsonValue {
    if let Some(props) = schema.get_mut("properties").and_then(|p| p.as_object_mut()) {
        for (field_name, field_schema) in props.iter_mut() {
            let key = format!("{}.{}", method_name, field_name);
            if let Some(desc) = config.param_descriptions.get(&key) {
                field_schema["description"] = serde_json::json!(desc);
            }
        }
    }
    schema
}

fn build_output_schema(method: &CanisterMethod, env: &TypeEnv) -> Option<JsonValue> {
    if method.rets.is_empty() {
        return None;
    }
    if method.rets.len() == 1 {
        return Some(candid_to_json_schema(&method.rets[0], env));
    }
    // Multiple return values → tuple as array
    let items: Vec<JsonValue> = method
        .rets
        .iter()
        .map(|t| candid_to_json_schema(t, env))
        .collect();
    Some(serde_json::json!({
        "type": "array",
        "prefixItems": items,
        "items": false
    }))
}
