//! Maps Candid types to JSON Schema for WebMCP tool definitions.

use candid::TypeEnv;
use candid::types::{Type, TypeInner};
use serde_json::{Value as JsonValue, json};

/// Convert a Candid type to a JSON Schema value.
///
/// The `env` is used to resolve `Var` references (type aliases defined in the .did file).
pub fn candid_to_json_schema(ty: &Type, env: &TypeEnv) -> JsonValue {
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
        TypeInner::Int16 => json!({ "type": "integer", "minimum": -32768, "maximum": 32767 }),
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
                    "items": candid_to_json_schema(inner, env)
                })
            }
        }
        TypeInner::Opt(inner) => {
            let inner_schema = candid_to_json_schema(inner, env);
            json!({
                "oneOf": [inner_schema, { "type": "null" }]
            })
        }
        TypeInner::Record(fields) => {
            let mut properties = serde_json::Map::new();
            let mut required = Vec::new();

            for field in fields {
                let field_name = field.id.to_string();
                let field_schema = candid_to_json_schema(&field.ty, env);
                // All record fields are required unless they're opt
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
                        // Unit variant
                        json!({ "const": name })
                    } else {
                        // Variant with payload
                        let payload = candid_to_json_schema(&v.ty, env);
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
            // Resolve type alias from the environment
            if let Ok(resolved) = env.rec_find_type(name) {
                candid_to_json_schema(resolved, env)
            } else {
                // Unresolvable — emit opaque schema
                json!({ "description": format!("Unresolved type: {}", name) })
            }
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
        // owner is required, subaccount (opt) is not
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
}
