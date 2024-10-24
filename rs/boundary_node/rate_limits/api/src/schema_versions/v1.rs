use candid::Principal;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const DOUBLE_INDENT: &str = "      ";

// Defines the rate-limit rule to be stored in the canister
#[derive(Serialize, Deserialize, Debug)]
pub struct RateLimitRule {
    pub canister_id: Option<Principal>,
    pub subnet_id: Option<Principal>,
    #[serde(with = "regex_serde")]
    pub methods: Regex,
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
        writeln!(f, "{DOUBLE_INDENT}Methods: {}", &self.methods)?;
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

mod regex_serde {
    use super::*;

    pub fn serialize<S>(regex: &Regex, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        regex.as_str().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Regex, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Regex::new(&s).map_err(serde::de::Error::custom)
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
