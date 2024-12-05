use std::{fmt, time::Duration};

use candid::Principal;
use humantime::parse_duration;
use ic_bn_lib::types::RequestType;
use regex::Regex;
use serde::{
    de::{self, Deserializer},
    ser::Serializer,
    Deserialize, Serialize,
};

const DOUBLE_INDENT: &str = "      ";

/// Implement serde parser for Action
struct ActionVisitor;
impl<'de> de::Visitor<'de> for ActionVisitor {
    type Value = Action;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "a rate limit spec in <count>/<duration> format e.g. '100/30s' or 'block'"
        )
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if s == "block" {
            return Ok(Action::Block);
        }

        let (count, interval) = s
            .split_once('/')
            .ok_or(de::Error::custom("invalid limit format"))?;

        let count = count.parse::<u32>().map_err(de::Error::custom)?;
        let interval = parse_duration(interval).map_err(de::Error::custom)?;

        if count == 0 || interval == Duration::ZERO {
            return Err(de::Error::custom("count and interval should be > 0"));
        }

        Ok(Action::Limit(count, interval))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Action {
    Block,
    Limit(u32, Duration),
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(deserializer: D) -> Result<Action, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ActionVisitor)
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block => write!(f, "block"),
            Self::Limit(l, d) => write!(f, "{l}/{}s", d.as_secs()),
        }
    }
}

impl Serialize for Action {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

// Defines the rate-limit rule to be stored in the canister
#[derive(Serialize, Deserialize, Debug)]
pub struct RateLimitRule {
    pub canister_id: Option<Principal>,
    pub subnet_id: Option<Principal>,
    #[serde(default, with = "serde_regex")]
    pub methods_regex: Option<Regex>,
    pub request_types: Option<Vec<RequestType>>,
    pub limit: Action,
}

/// Regex does not implement Eq, so do it manually
impl PartialEq for RateLimitRule {
    fn eq(&self, other: &Self) -> bool {
        self.methods_regex.as_ref().map(|x| x.as_str())
            == other.methods_regex.as_ref().map(|x| x.as_str())
            && self.request_types == other.request_types
            && self.canister_id == other.canister_id
            && self.subnet_id == other.subnet_id
            && self.limit == other.limit
    }
}
impl Eq for RateLimitRule {}

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
            &self
                .methods_regex
                .as_ref()
                .map(|x| x.to_string())
                .unwrap_or("None".to_string())
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

    pub fn to_bytes_yaml(&self) -> Result<Vec<u8>, serde_yaml::Error> {
        serde_yaml::to_string(self).map(|x| x.into())
    }

    pub fn from_bytes_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    pub fn from_bytes_yaml(bytes: &[u8]) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_slice(bytes)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use indoc::indoc;

    #[test]
    fn test_rules() {
        let rule_raw = indoc! {"
        canister_id: aaaaa-aa
        methods_regex: ^.*$
        limit: 100/1s
        "};

        let rule = RateLimitRule::from_bytes_yaml(rule_raw.as_bytes()).unwrap();
        assert_eq!(
            rule,
            RateLimitRule {
                canister_id: Some(Principal::from_text("aaaaa-aa").unwrap()),
                subnet_id: None,
                methods_regex: Some(Regex::new("^.*$").unwrap()),
                request_types: None,
                limit: Action::Limit(100, Duration::from_secs(1)),
            }
        );

        let rules = indoc! {"
        - canister_id: aaaaa-aa
          methods_regex: ^.*$
          limit: 100/1s

        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          methods_regex: ^(foo|bar)$
          limit: 60/1m

        - subnet_id: 3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe
          canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          limit: 90/1m

        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          methods_regex: ^(foo|bar)$
          limit: block

        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          request_types:
            - query
          methods_regex: ^(foo|bar)$
          limit: block

        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          request_types:
            - call
            - sync_call
          limit: block
        "};

        let rules: Vec<RateLimitRule> = serde_yaml::from_str(rules).unwrap();

        assert_eq!(
            rules,
            vec![
                RateLimitRule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("aaaaa-aa").unwrap()),
                    request_types: None,
                    methods_regex: Some(Regex::new("^.*$").unwrap()),
                    limit: Action::Limit(100, Duration::from_secs(1)),
                },
                RateLimitRule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap()),
                    request_types: None,
                    methods_regex: Some(Regex::new("^(foo|bar)$").unwrap()),
                    limit: Action::Limit(60, Duration::from_secs(60)),
                },
                RateLimitRule {
                    subnet_id: Some(
                        Principal::from_text(
                            "3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe"
                        )
                        .unwrap()
                    ),
                    canister_id: Some(Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap()),
                    request_types: None,
                    methods_regex: None,
                    limit: Action::Limit(90, Duration::from_secs(60)),
                },
                RateLimitRule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap()),
                    request_types: None,
                    methods_regex: Some(Regex::new("^(foo|bar)$").unwrap()),
                    limit: Action::Block,
                },
                RateLimitRule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap()),
                    request_types: Some(vec![RequestType::Query]),
                    methods_regex: Some(Regex::new("^(foo|bar)$").unwrap()),
                    limit: Action::Block,
                },
                RateLimitRule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap()),
                    request_types: Some(vec![RequestType::Call, RequestType::SyncCall]),
                    methods_regex: None,
                    limit: Action::Block,
                },
            ],
        );

        // Bad canister
        let rules = indoc! {"
        - canister_id: aaaaa-zzz
          limit: 100/1s
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.is_err());

        // Bad regex
        let rules = indoc! {"
        - canister_id: aaaaa-aa
          methods_regex: foo(bar
          limit: 100/1s
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.is_err());

        // Bad limits
        let rules = indoc! {"
        - canister_id: aaaaa-aa
          limit: 100/
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.is_err());

        let rules = indoc! {"
        - canister_id: aaaaa-aa
          limit: /100s
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.is_err());

        let rules = indoc! {"
        - canister_id: aaaaa-aa
          limit: /
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.is_err());

        let rules = indoc! {"
        - canister_id: aaaaa-aa
          limit: 0/1s
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.is_err());

        let rules = indoc! {"
        - canister_id: aaaaa-aa
          limit: 1/0s
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.is_err());

        let rules = indoc! {"
        - canister_id: aaaaa-aa
          limit: 1/1
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.is_err());

        // Bad request type
        let rules = indoc! {"
        - canister_id: aaaaa-aa
          request_types: [blah]
          limit: 10/1s
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.is_err());
    }
}
