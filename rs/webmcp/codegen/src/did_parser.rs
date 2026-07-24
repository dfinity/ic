//! Parse Candid .did files into structured method definitions.

use anyhow::{Context, Result};
use candid::TypeEnv;
#[cfg(test)]
use candid::types::TypeInner;
use candid::types::{Function, Type};
use std::path::Path;

/// A parsed canister method from a .did file.
#[derive(Debug, Clone)]
pub struct CanisterMethod {
    pub name: String,
    /// Argument types (positional — Candid functions don't name arguments).
    pub args: Vec<Type>,
    pub rets: Vec<Type>,
    pub is_query: bool,
}

/// Result of parsing a .did file: the type environment and list of methods.
pub struct ParsedInterface {
    pub env: TypeEnv,
    pub methods: Vec<CanisterMethod>,
}

/// Parse a .did file and return its type environment and service methods.
pub fn parse_did_file(path: &Path) -> Result<ParsedInterface> {
    let (env, actor) = candid_parser::check_file(path)
        .map_err(|e| anyhow::anyhow!("Failed to parse .did file {}: {}", path.display(), e))?;

    let actor = actor.context("No service definition found in .did file")?;

    extract_methods(&env, &actor)
}

/// Parse a Candid interface definition string.
pub fn parse_did_string(did: &str) -> Result<ParsedInterface> {
    let ast = did
        .parse::<candid_parser::IDLProg>()
        .map_err(|e| anyhow::anyhow!("Failed to parse Candid: {}", e))?;

    let mut env = TypeEnv::new();
    let actor = candid_parser::check_prog(&mut env, &ast)
        .map_err(|e| anyhow::anyhow!("Candid type check failed: {}", e))?
        .context("No service definition found")?;

    extract_methods(&env, &actor)
}

fn extract_methods(env: &TypeEnv, actor: &Type) -> Result<ParsedInterface> {
    let service_methods = env
        .as_service(actor)
        .map_err(|e| anyhow::anyhow!("Not a service type: {}", e))?;

    let mut methods = Vec::new();

    for (name, method_type) in service_methods {
        let func = env
            .as_func(method_type)
            .map_err(|e| anyhow::anyhow!("Method {} is not a function: {}", name, e))?;

        methods.push(func_to_method(name, func));
    }

    Ok(ParsedInterface {
        env: env.clone(),
        methods,
    })
}

fn func_to_method(name: &str, func: &Function) -> CanisterMethod {
    CanisterMethod {
        name: name.to_string(),
        args: func.args.clone(),
        rets: func.rets.clone(),
        is_query: func.is_query(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_service() {
        let did = r#"
            service : {
                greet : (text) -> (text) query;
                set_greeting : (text) -> ();
            }
        "#;

        let parsed = parse_did_string(did).unwrap();
        assert_eq!(parsed.methods.len(), 2);

        let greet = parsed.methods.iter().find(|m| m.name == "greet").unwrap();
        assert!(greet.is_query);
        assert_eq!(greet.args.len(), 1);
        assert!(matches!(greet.args[0].as_ref(), TypeInner::Text));
        assert_eq!(greet.rets.len(), 1);

        let set = parsed
            .methods
            .iter()
            .find(|m| m.name == "set_greeting")
            .unwrap();
        assert!(!set.is_query);
    }

    #[test]
    fn test_parse_service_with_types() {
        let did = r#"
            type Account = record { owner : principal; subaccount : opt blob };
            service : {
                balance_of : (Account) -> (nat) query;
            }
        "#;

        let parsed = parse_did_string(did).unwrap();
        assert_eq!(parsed.methods.len(), 1);

        let balance = &parsed.methods[0];
        assert_eq!(balance.name, "balance_of");
        assert!(balance.is_query);
        assert_eq!(balance.args.len(), 1);
    }
}
