use std::{
    fmt::{self, Display},
    time::Duration,
};

use candid::Principal;
use humantime::{format_duration, parse_duration};
use ipnet::IpNet;
use regex::Regex;
use serde::{
    Deserialize, Serialize,
    de::{self, Deserializer, Error},
    ser::Serializer,
};

pub const SCHEMA_VERSION: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestType {
    Unknown,
    QueryV2,
    QueryV3,
    #[serde(alias = "call")]
    CallV2,
    #[serde(alias = "sync_call")]
    CallV3,
    CallV4,
    ReadStateV2,
    ReadStateV3,
    ReadStateSubnetV2,
    ReadStateSubnetV3,
}

/// Implement serde parser for Action
struct ActionVisitor;
impl de::Visitor<'_> for ActionVisitor {
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
        } else if s == "pass" {
            return Ok(Action::Pass);
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

#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub enum Action {
    #[default]
    Pass,
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

impl Serialize for Action {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Block => write!(f, "block"),
            Self::Limit(l, d) => write!(f, "{l}/{}", format_duration(*d)),
        }
    }
}

// Checks that u8 is <= 32
fn de_le_32<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let v = u8::deserialize(deserializer)?;
    if v > 32 {
        return Err(D::Error::custom("v4 prefix must be <=32"));
    }

    Ok(v)
}

// Checks that u8 is <= 128
fn de_le_128<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let v = u8::deserialize(deserializer)?;
    if v > 128 {
        return Err(D::Error::custom("v6 prefix must be <=128"));
    }

    Ok(v)
}

/// IP prefix lengths for v4 and v6
/// v4 must be <= 32, v6 <= 128
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct IpPrefixes {
    #[serde(deserialize_with = "de_le_32")]
    pub v4: u8,
    #[serde(deserialize_with = "de_le_128")]
    pub v6: u8,
}

impl std::fmt::Display for IpPrefixes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v4: {}, v6: {}", self.v4, self.v6)
    }
}

/// Defines the rate-limit rule to be stored in the canister
#[derive(Clone, Deserialize, Serialize, Debug, Default)]
#[serde(remote = "Self")]
pub struct RateLimitRule {
    pub canister_id: Option<Principal>,
    pub subnet_id: Option<Principal>,
    #[serde(default, with = "serde_regex")]
    pub methods_regex: Option<Regex>,
    pub ip: Option<IpNet>,
    pub request_types: Option<Vec<RequestType>>,
    pub ip_prefix_group: Option<IpPrefixes>,
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
            && self.ip == other.ip
            && self.ip_prefix_group == other.ip_prefix_group
            && self.limit == other.limit
    }
}
impl Eq for RateLimitRule {}

impl<'de> Deserialize<'de> for RateLimitRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let this = Self::deserialize(deserializer)?;

        if this.ip_prefix_group.is_some() && !matches!(this.limit, Action::Limit(_, _)) {
            return Err(D::Error::custom(
                "ip_prefix_group only makes sense with 'limit' set to an actual ratelimit",
            ));
        }

        if this.canister_id.is_none()
            && this.subnet_id.is_none()
            && this.methods_regex.is_none()
            && this.request_types.is_none()
            && this.ip.is_none()
        {
            return Err(D::Error::custom(
                "at least one filtering condition must be specified",
            ));
        }

        Ok(this)
    }
}

impl Serialize for RateLimitRule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Self::serialize(self, serializer)
    }
}

impl std::fmt::Display for RateLimitRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CanisterID: {}, SubnetID: {}, Request Types: {:?}, Methods: {}, IP: {}, IP Prefix: {}, Limit: {}",
            format_option(&self.canister_id),
            format_option(&self.subnet_id),
            self.request_types,
            format_option(&self.methods_regex),
            format_option(&self.ip),
            format_option(&self.ip_prefix_group),
            self.limit,
        )
    }
}

fn format_option<T: Display>(v: &Option<T>) -> String {
    match v {
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
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    use super::*;
    use indoc::indoc;

    #[test]
    fn test_action() {
        assert_eq!((Action::Block).to_string(), "block");
        assert_eq!(
            (Action::Limit(30, Duration::from_secs(3601))).to_string(),
            "30/1h 1s"
        );

        assert_eq!(
            serde_yaml::from_slice::<Action>(b"block").unwrap(),
            Action::Block,
        );
        assert_eq!(
            serde_yaml::from_slice::<Action>(b"30/1h 1s").unwrap(),
            Action::Limit(30, Duration::from_secs(3601))
        );
    }

    #[test]
    fn test_rules() {
        let rule_raw = indoc! {"
        canister_id: aaaaa-aa
        methods_regex: ^.*$
        ip: 10.1.1.0/24
        ip_prefix_group:
          v4: 24
          v6: 64
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
                ip: Some(IpNet::new_assert(
                    IpAddr::V4(Ipv4Addr::new(10, 1, 1, 0)),
                    24
                )),
                ip_prefix_group: Some(IpPrefixes { v4: 24, v6: 64 }),
                limit: Action::Limit(100, Duration::from_secs(1)),
            }
        );

        // Bad prefix lengths
        let rule_raw = indoc! {"
        canister_id: aaaaa-aa
        methods_regex: ^.*$
        ip: 10.1.1.0/24
        ip_prefix_group:
          v4: 33
          v6: 64
        limit: 100/1s
        "};

        assert!(
            RateLimitRule::from_bytes_yaml(rule_raw.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("v4 prefix must be")
        );

        let rule_raw = indoc! {"
        canister_id: aaaaa-aa
        methods_regex: ^.*$
        ip: 10.1.1.0/24
        ip_prefix_group:
          v4: 24
          v6: 129
        limit: 100/1s
        "};

        assert!(
            RateLimitRule::from_bytes_yaml(rule_raw.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("v6 prefix must be")
        );

        // limit: block with ip prefixes
        let rule_raw = indoc! {"
        canister_id: aaaaa-aa
        methods_regex: ^.*$
        ip: 10.1.1.0/24
        ip_prefix_group:
          v4: 24
          v6: 64
        limit: block
        "};

        assert!(
            RateLimitRule::from_bytes_yaml(rule_raw.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("ip_prefix_group only makes sense with")
        );

        // No conditions
        let rule_raw = indoc! {"
        ip_prefix_group:
            v4: 24
            v6: 64
        limit: 100/1s
        "};

        assert!(
            RateLimitRule::from_bytes_yaml(rule_raw.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("at least one filtering condition must be")
        );

        let rules = indoc! {"
        - canister_id: aaaaa-aa
          methods_regex: ^.*$
          ip: 2001:db8::/32
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
            - query_v2
          methods_regex: ^(foo|bar)$
          limit: block

        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          request_types:
            - query_v2
            - call_v3
          limit: block

        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          request_types:
            - call_v2
            - call_v3
          limit: pass
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
                    ip: Some(IpNet::new_assert(
                        IpAddr::V6(Ipv6Addr::from_str("2001:db8::").unwrap()),
                        32
                    )),
                    ip_prefix_group: None,
                    limit: Action::Limit(100, Duration::from_secs(1)),
                },
                RateLimitRule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap()),
                    request_types: None,
                    methods_regex: Some(Regex::new("^(foo|bar)$").unwrap()),
                    ip: None,
                    ip_prefix_group: None,
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
                    ip: None,
                    ip_prefix_group: None,
                    limit: Action::Limit(90, Duration::from_secs(60)),
                },
                RateLimitRule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap()),
                    request_types: None,
                    methods_regex: Some(Regex::new("^(foo|bar)$").unwrap()),
                    ip: None,
                    ip_prefix_group: None,
                    limit: Action::Block,
                },
                RateLimitRule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap()),
                    request_types: Some(vec![RequestType::QueryV2]),
                    methods_regex: Some(Regex::new("^(foo|bar)$").unwrap()),
                    ip: None,
                    ip_prefix_group: None,
                    limit: Action::Block,
                },
                RateLimitRule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap()),
                    request_types: Some(vec![RequestType::QueryV2, RequestType::CallV3]),
                    methods_regex: None,
                    ip: None,
                    ip_prefix_group: None,
                    limit: Action::Block,
                },
                RateLimitRule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap()),
                    request_types: Some(vec![RequestType::CallV2, RequestType::CallV3]),
                    methods_regex: None,
                    ip: None,
                    ip_prefix_group: None,
                    limit: Action::Pass,
                },
            ],
        );

        // Bad canister
        let rules = indoc! {"
        - canister_id: aaaaa-zzz
          limit: 100/1s
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.unwrap_err().to_string().contains("canister_id"));

        // Bad regex
        let rules = indoc! {"
        - canister_id: aaaaa-aa
          methods_regex: foo(bar
          limit: 100/1s
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.unwrap_err().to_string().contains("regex"));

        // Bad limits
        let rules = indoc! {"
        - canister_id: aaaaa-aa
          limit: 100/
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.unwrap_err().to_string().contains("limit"));

        let rules = indoc! {"
        - canister_id: aaaaa-aa
          limit: /100s
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.unwrap_err().to_string().contains("limit"));

        let rules = indoc! {"
        - canister_id: aaaaa-aa
          limit: /
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.unwrap_err().to_string().contains("limit"));

        let rules = indoc! {"
        - canister_id: aaaaa-aa
          limit: 0/1s
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.unwrap_err().to_string().contains("limit"));

        let rules = indoc! {"
        - canister_id: aaaaa-aa
          limit: 1/0s
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.unwrap_err().to_string().contains("limit"));

        let rules = indoc! {"
        - canister_id: aaaaa-aa
          limit: 1/1
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.unwrap_err().to_string().contains("limit"));

        // Bad request type
        let rules = indoc! {"
        - canister_id: aaaaa-aa
          request_types: [blah]
          limit: 10/1s
        "};
        let rules = serde_yaml::from_str::<Vec<RateLimitRule>>(rules);
        assert!(rules.unwrap_err().to_string().contains("request_type"));

        // Backwards compatibility for call_v2 (call) and call_v3 (sync_call)
        let rules = indoc! {"
        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          request_types:
            - call
          limit: block

        - canister_id: 5s2ji-faaaa-aaaaa-qaaaq-cai
          request_types:
            - sync_call
          limit: pass

        - canister_id: aaaaa-aa
          request_types:
            - call
            - sync_call
          limit: pass
          "};

        let rules: Vec<RateLimitRule> = serde_yaml::from_str(rules).unwrap();

        assert_eq!(
            rules,
            vec![
                RateLimitRule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap()),
                    request_types: Some(vec![RequestType::CallV2]),
                    methods_regex: None,
                    ip: None,
                    ip_prefix_group: None,
                    limit: Action::Block,
                },
                RateLimitRule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("5s2ji-faaaa-aaaaa-qaaaq-cai").unwrap()),
                    request_types: Some(vec![RequestType::CallV3]),
                    methods_regex: None,
                    ip: None,
                    ip_prefix_group: None,
                    limit: Action::Pass,
                },
                RateLimitRule {
                    subnet_id: None,
                    canister_id: Some(Principal::from_text("aaaaa-aa").unwrap()),
                    request_types: Some(vec![RequestType::CallV2, RequestType::CallV3]),
                    methods_regex: None,
                    ip: None,
                    ip_prefix_group: None,
                    limit: Action::Pass,
                },
            ],
        );
    }
}
