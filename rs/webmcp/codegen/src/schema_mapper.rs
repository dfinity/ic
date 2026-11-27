//! Maps Candid types to JSON Schema for WebMCP tool definitions.

use candid::TypeEnv;
use candid::types::{Type, TypeInner};
use serde_json::{Value as JsonValue, json};
use std::collections::HashSet;

/// Convert a Candid type to a JSON Schema value.
///
/// The `env` is used to resolve `Var` references (type aliases defined in the .did file).
pub fn candid_to_json_schema(ty: &Type, env: &TypeEnv) -> JsonValue {
    let mut visited = HashSet::new();
    candid_to_json_schema_inner(ty, env, &mut visited)
}

fn candid_to_json_schema_inner(
    ty: &Type,
    env: &TypeEnv,
    visited: &mut HashSet<String>,
) -> JsonValue {
    match ty.as_ref() {
        TypeInner::Bool => json!({ "type": "boolean" }),
        TypeInner::Nat => {
            json!({ "type": "string", "pattern": "^[0-9]+$", "description": "Natural number" })
        }
        TypeInner::Int => {
            json!({ "type": "string", "pattern": "^-?[0-9]+$", "description": "Integer" })
        }
        TypeInner::Nat8 => json!({ "type": "integer", "minimum": 0, "maximum": 255 }),
        TypeInner::Nat16 => json!({ "type": "integer", "minimum": 0, "maximum": 65535 }),
        TypeInner::Nat32 => {
            json!({ "type": "integer", "minimum": 0, "maximum": 4_294_967_295_u64 })
        }
        TypeInner::Nat64 => {
            json!({ "type": "string", "pattern": "^[0-9]+$", "description": "64-bit natural number" })
        }
        TypeInner::Int8 => json!({ "type": "integer", "minimum": -128, "maximum": 127 }),
        TypeInner::Int16 => {
            json!({ "type": "integer", "minimum": -32768, "maximum": 32767 })
        }
        TypeInner::Int32 => {
            json!({ "type": "integer", "minimum": -2_147_483_648_i64, "maximum": 2_147_483_647 })
        }
        TypeInner::Int64 => {
            json!({ "type": "string", "pattern": "^-?[0-9]+$", "description": "64-bit integer" })
        }
        TypeInner::Float32 | TypeInner::Float64 => json!({ "type": "number" }),
        TypeInner::Text => json!({ "type": "string" }),
        TypeInner::Null => json!({ "type": "null" }),
        TypeInner::Principal => json!({
            "type": "string",
            "description": "IC Principal ID",
            "pattern": "^[a-z0-9-]+(\\.[a-z0-9-]+)*$"
        }),
        TypeInner::Vec(inner) => {
            if matches!(inner.as_ref(), TypeInner::Nat8) {
                // blob = vec nat8 → base64 string
                json!({
                    "type": "string",
                    "contentEncoding": "base64",
                    "description": "Binary data (base64-encoded)"
                })
            } else {
                json!({
                    "type": "array",
                    "items": candid_to_json_schema_inner(inner, env, visited)
                })
            }
        }
        TypeInner::Opt(inner) => {
            let inner_schema = candid_to_json_schema_inner(inner, env, visited);
            json!({
                "oneOf": [inner_schema, { "type": "null" }]
            })
        }
        TypeInner::Record(fields) => {
            let mut properties = serde_json::Map::new();
            let mut required = Vec::new();

            for field in fields {
                let field_name = field.id.to_string();
                let field_schema = candid_to_json_schema_inner(&field.ty, env, visited);
                if !matches!(field.ty.as_ref(), TypeInner::Opt(_)) {
                    required.push(JsonValue::String(field_name.clone()));
                }
                properties.insert(field_name, field_schema);
            }

            let mut schema = json!({
                "type": "object",
                "properties": JsonValue::Object(properties)
            });
            if !required.is_empty() {
                schema["required"] = JsonValue::Array(required);
            }
            schema
        }
        TypeInner::Variant(variants) => {
            let one_of: Vec<JsonValue> = variants
                .iter()
                .map(|v| {
                    let name = v.id.to_string();
                    if matches!(v.ty.as_ref(), TypeInner::Null) {
                        json!({ "const": name })
                    } else {
                        let payload = candid_to_json_schema_inner(&v.ty, env, visited);
                        json!({
                            "type": "object",
                            "properties": { name.clone(): payload },
                            "required": [name],
                            "additionalProperties": false
                        })
                    }
                })
                .collect();
            json!({ "oneOf": one_of })
        }
        TypeInner::Var(name) => {
            // Cycle detection: if we're already resolving this type, emit a ref
            if !visited.insert(name.clone()) {
                return json!({
                    "description": format!("Recursive type: {}", name)
                });
            }
            let result = if let Ok(resolved) = env.rec_find_type(name) {
                candid_to_json_schema_inner(resolved, env, visited)
            } else {
                json!({ "description": format!("Unresolved type: {}", name) })
            };
            visited.remove(name);
            result
        }
        // Reserved, Empty, Unknown, Knot, Func, Service, Class, Future
        _ => json!({}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_env() -> TypeEnv {
        TypeEnv::new()
    }

    #[test]
    fn test_nat_schema() {
        let ty: Type = TypeInner::Nat.into();
        let schema = candid_to_json_schema(&ty, &empty_env());
        assert_eq!(schema["type"], "string");
        assert!(schema["pattern"].as_str().unwrap().contains("[0-9]"));
    }

    #[test]
    fn test_text_schema() {
        let ty: Type = TypeInner::Text.into();
        let schema = candid_to_json_schema(&ty, &empty_env());
        assert_eq!(schema["type"], "string");
    }

    #[test]
    fn test_bool_schema() {
        let ty: Type = TypeInner::Bool.into();
        let schema = candid_to_json_schema(&ty, &empty_env());
        assert_eq!(schema["type"], "boolean");
    }

    #[test]
    fn test_principal_schema() {
        let ty: Type = TypeInner::Principal.into();
        let schema = candid_to_json_schema(&ty, &empty_env());
        assert_eq!(schema["type"], "string");
        assert!(
            schema["description"]
                .as_str()
                .unwrap()
                .contains("Principal")
        );
    }

    #[test]
    fn test_blob_schema() {
        let ty: Type = TypeInner::Vec(TypeInner::Nat8.into()).into();
        let schema = candid_to_json_schema(&ty, &empty_env());
        assert_eq!(schema["type"], "string");
        assert_eq!(schema["contentEncoding"], "base64");
    }

    #[test]
    fn test_vec_schema() {
        let ty: Type = TypeInner::Vec(TypeInner::Text.into()).into();
        let schema = candid_to_json_schema(&ty, &empty_env());
        assert_eq!(schema["type"], "array");
        assert_eq!(schema["items"]["type"], "string");
    }

    #[test]
    fn test_opt_schema() {
        let ty: Type = TypeInner::Opt(TypeInner::Text.into()).into();
        let schema = candid_to_json_schema(&ty, &empty_env());
        assert!(schema["oneOf"].is_array());
        assert_eq!(schema["oneOf"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_record_schema() {
        use candid::types::Field;
        use candid::types::internal::Label;
        use std::rc::Rc;

        let ty: Type = TypeInner::Record(vec![
            Field {
                id: Rc::new(Label::Named("owner".to_string())),
                ty: TypeInner::Principal.into(),
            },
            Field {
                id: Rc::new(Label::Named("subaccount".to_string())),
                ty: TypeInner::Opt(TypeInner::Vec(TypeInner::Nat8.into()).into()).into(),
            },
        ])
        .into();

        let schema = candid_to_json_schema(&ty, &empty_env());
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["owner"].is_object());
        assert!(schema["properties"]["subaccount"].is_object());
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&serde_json::json!("owner")));
        assert!(!required.contains(&serde_json::json!("subaccount")));
    }

    #[test]
    fn test_variant_schema() {
        use candid::types::Field;
        use candid::types::internal::Label;
        use std::rc::Rc;

        let ty: Type = TypeInner::Variant(vec![
            Field {
                id: Rc::new(Label::Named("Ok".to_string())),
                ty: TypeInner::Nat.into(),
            },
            Field {
                id: Rc::new(Label::Named("Err".to_string())),
                ty: TypeInner::Null.into(),
            },
        ])
        .into();

        let schema = candid_to_json_schema(&ty, &empty_env());
        let one_of = schema["oneOf"].as_array().unwrap();
        assert_eq!(one_of.len(), 2);
    }

    #[test]
    fn test_recursive_type_does_not_stack_overflow() {
        // Simulate: type Value = variant { Text: text; Array: vec Value }
        // This requires a TypeEnv with the recursive definition
        let did = r#"
            type Value = variant { Text : text; Array : vec Value; Leaf : null };
            service : { get : (text) -> (Value) query }
        "#;
        let ast = did.parse::<candid_parser::IDLProg>().unwrap();
        let mut env = TypeEnv::new();
        let actor = candid_parser::check_prog(&mut env, &ast).unwrap().unwrap();

        // Get the return type of `get` method
        let func = env.get_method(&actor, "get").unwrap();
        let ret_type = &func.rets[0];

        // This should NOT stack overflow
        let schema = candid_to_json_schema(ret_type, &env);
        // The recursive occurrence should be replaced with a description
        let json_str = serde_json::to_string(&schema).unwrap();
        assert!(
            json_str.contains("Recursive type"),
            "Expected recursive type marker in: {}",
            json_str
        );
    }
}
