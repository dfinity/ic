//! Validation of config values that come from outside the GuestOS.
//!
//! The GuestOS config is written by the HostOS, so on nodes where the GuestOS
//! runs in a trusted execution environment its contents are untrusted. Values
//! that end up in `ic.json5` are checked here before rendering, in addition to
//! being JSON-encoded by the template.

use anyhow::{Result, ensure};
use regex::Regex;
use std::sync::LazyLock;

static NODE_REWARD_TYPE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^type[0-9]+(\.[0-9])?$").unwrap());

/// Checks that `node_reward_type` has the form `typeN` or `typeN.M`.
pub fn validate_node_reward_type(node_reward_type: &str) -> Result<()> {
    ensure!(
        NODE_REWARD_TYPE_PATTERN.is_match(node_reward_type),
        "Invalid node_reward_type {node_reward_type:?}. It must match the pattern {}",
        NODE_REWARD_TYPE_PATTERN.as_str()
    );
    Ok(())
}

/// Checks that `domain_name` is a domain name in canonical ASCII form.
///
/// This is the same check the registry canister applies when a node registers
/// with a domain, so any domain that a node can register with passes it.
pub fn validate_domain_name(domain_name: &str) -> Result<()> {
    ensure!(
        idna::domain_to_ascii_strict(domain_name).is_ok_and(|ascii| ascii == domain_name),
        "Invalid domain name {domain_name:?}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_node_reward_types() {
        for node_reward_type in ["type0", "type1", "type1.1", "type3.1", "type42"] {
            validate_node_reward_type(node_reward_type)
                .unwrap_or_else(|e| panic!("{node_reward_type:?} was rejected: {e}"));
        }
    }

    #[test]
    fn rejects_invalid_node_reward_types() {
        for node_reward_type in [
            "",
            "type",
            "Type1",
            "type1.",
            "type1.10",
            "type1 ",
            "type1\"",
            "*/ registry_client: { local_store: \"/run/config/bootstrap/evil\" }, z: \"",
        ] {
            assert!(
                validate_node_reward_type(node_reward_type).is_err(),
                "{node_reward_type:?} was accepted"
            );
        }
    }

    #[test]
    fn accepts_valid_domain_names() {
        for domain_name in [
            "example.com",
            "a.example.com",
            "api-bn-1.example.org",
            "xn--bcher-kva.example",
        ] {
            validate_domain_name(domain_name)
                .unwrap_or_else(|e| panic!("{domain_name:?} was rejected: {e}"));
        }
    }

    #[test]
    fn rejects_invalid_domain_names() {
        for domain_name in [
            "",
            "Example.com",
            "bücher.example",
            "under_score.example.com",
            "example..com",
            "x\", /*",
            "example.com\n",
            "example.com/*",
        ] {
            assert!(
                validate_domain_name(domain_name).is_err(),
                "{domain_name:?} was accepted"
            );
        }
    }
}
