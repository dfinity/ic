use candid::Principal;
use serde::{Deserialize, Serialize};

const DOUBLE_INDENT: &str = "      ";

#[derive(Serialize, Deserialize, Debug)]
pub enum RequestType {
    Call,
    Query,
    ReadState,
}

// Defines the rate-limit rule to be stored in the canister
#[derive(Serialize, Deserialize, Debug)]
pub struct RateLimitRule {
    pub canister_id: Option<Principal>,
    pub subnet_id: Option<Principal>,
    pub methods_regex: Option<String>,
    pub request_type: Option<RequestType>,
    pub limit: String,
}

impl std::fmt::Display for RateLimitRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{DOUBLE_INDENT}Canister ID: {}",
            format_principal_option(&self.canister_id)
        )?;
        writeln!(
            f,
            "{DOUBLE_INDENT}Subnet ID: {}",
            format_principal_option(&self.subnet_id)
        )?;
        writeln!(
            f,
            "{DOUBLE_INDENT}Methods: {}",
            &self.methods_regex.clone().unwrap_or("None".to_string())
        )?;
        write!(f, "{DOUBLE_INDENT}Limit: {}", &self.limit)?;
        Ok(())
    }
}

fn format_principal_option(principal: &Option<Principal>) -> String {
    match principal {
        Some(p) => p.to_string(),
        None => "None".to_string(),
    }
}

impl RateLimitRule {
    pub fn to_bytes_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_bytes_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}
