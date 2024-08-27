use ipnet::IpNet;
use serde_json;

use std::fmt;
use std::fmt::Display;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub enum FirewallRuleDestination {
    #[serde(alias = "hostos")]
    HostOS,
    #[serde(alias = "guestos")]
    GuestOS,
    #[serde(alias = "both")]
    Both,
}

impl Default for FirewallRuleDestination {
    fn default() -> Self {
        Self::Both
    }
}

fn firewall_rule_destination_is_default(d: &FirewallRuleDestination) -> bool {
    *d == FirewallRuleDestination::default()
}

fn firewall_rule_protocol_is_default(d: &FirewallRuleProtocol) -> bool {
    *d == FirewallRuleProtocol::default()
}

fn firewall_rule_action_is_default(d: &FirewallRuleAction) -> bool {
    *d == FirewallRuleAction::default()
}

fn firewall_rule_comment_is_empty(d: &str) -> bool {
    d.is_empty()
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct FirewallRulePortRange {
    from: u16,
    to: u16,
}

impl FirewallRulePortRange {
    pub fn as_nft_interval(&self) -> String {
        match self.from == self.to {
            true => format!("{}", self.from),
            false => format!("{}-{}", self.from, self.to),
        }
    }
}

impl<'de> serde::Deserialize<'de> for FirewallRulePortRange {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(d)?;
        match value {
            serde_json::Value::String(s) => {
                return FirewallRulePortRange::from_str(s.as_str())
                    .map_err(serde::de::Error::custom)
            }
            serde_json::Value::Number(n) => {
                let x: Option<u64> = n.as_u64();
                let xx = match x {
                    None => return Err(serde::de::Error::custom("Port is not a positive integer")),
                    Some(y) => match u16::try_from(y) {
                        Ok(z) => z,
                        Err(_) => {
                            return Err(serde::de::Error::custom(
                                "Port is not a positive integer lower than 65536",
                            ));
                        }
                    },
                };
                Ok(FirewallRulePortRange { from: xx, to: xx })
            }
            _ => Err(serde::de::Error::custom("Invalid data type for port range")),
        }
    }
}

impl serde::Serialize for FirewallRulePortRange {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.from == self.to {
            serializer.serialize_u16(self.from)
        } else {
            serializer.serialize_str(format!("{}-{}", self.from, self.to).as_str())
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ParsePortRangeError {
    message: String,
}

impl ParsePortRangeError {
    fn new(msg: &str) -> Self {
        Self {
            message: msg.to_string(),
        }
    }
}

impl Display for ParsePortRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "parse port(s) error: {}", self.message)
    }
}

impl FromStr for FirewallRulePortRange {
    type Err = ParsePortRangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains("-") {
            let (x, y) = s
                .trim_start_matches('(')
                .trim_end_matches(')')
                .split_once('-')
                .ok_or(ParsePortRangeError::new(
                    format!(
                        "port range {} is not a valid integer port range delimited by a dash",
                        s
                    )
                    .as_str(),
                ))?;
            let x_fromstr = x.parse::<u16>().map_err(|_| {
                ParsePortRangeError::new("lower port bound is not a positive integer below 65536")
            })?;
            let y_fromstr = y.parse::<u16>().map_err(|_| {
                ParsePortRangeError::new("upper port bound is not a positive integer below 65536")
            })?;
            if x_fromstr > y_fromstr {
                return Err(ParsePortRangeError::new(
                    "lower port bound is greater than upper port bound",
                ));
            }
            Ok(FirewallRulePortRange {
                from: x_fromstr,
                to: y_fromstr,
            })
        } else {
            let x_fromstr = s.parse::<u16>().map_err(|_| {
                ParsePortRangeError::new("port is not a positive integer below 65536")
            })?;
            Ok(FirewallRulePortRange {
                from: x_fromstr,
                to: x_fromstr,
            })
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum FirewallRuleProtocol {
    TCP,
    UDP,
    All,
}

impl FirewallRuleProtocol {
    pub fn name(&self) -> &str {
        match self {
            Self::TCP => "tcp",
            Self::UDP => "udp",
            Self::All => "all",
        }
    }
}

impl Default for FirewallRuleProtocol {
    fn default() -> Self {
        Self::All
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum FirewallRuleAction {
    Accept,
    Drop,
}

impl Default for FirewallRuleAction {
    fn default() -> Self {
        Self::Accept
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct FirewallRule {
    pub from: IpNet,
    #[serde(default, skip_serializing_if = "firewall_rule_destination_is_default")]
    pub to: FirewallRuleDestination,
    #[serde(default, skip_serializing_if = "firewall_rule_protocol_is_default")]
    pub protocol: FirewallRuleProtocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_ports: Option<FirewallRulePortRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_ports: Option<FirewallRulePortRange>,
    #[serde(default, skip_serializing_if = "firewall_rule_action_is_default")]
    pub action: FirewallRuleAction,
    #[serde(default, skip_serializing_if = "firewall_rule_comment_is_empty")]
    pub comment: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct FirewallSettings {
    pub rules: Vec<FirewallRule>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_serialize_and_deserialize_firewall() {
        let (inp, exp) = (
            "[
  {
    \"from\": \"2001:db8:abcd:0012::0/64\",
    \"to\": \"GuestOS\"
  },
  {
    \"from\": \"2001:db8:abcd:0013::0/64\",
    \"to\": \"HostOS\",
    \"protocol\": \"tcp\",
    \"to_ports\": \"15-60\",
    \"action\": \"drop\"
  },
  {
    \"from\": \"12.13.14.15/24\",
    \"to\": \"HostOS\",
    \"action\": \"accept\"
  }
]",
            "[
  {
    \"from\": \"2001:db8:abcd:12::/64\",
    \"to\": \"GuestOS\"
  },
  {
    \"from\": \"2001:db8:abcd:13::/64\",
    \"to\": \"HostOS\",
    \"protocol\": \"tcp\",
    \"to_ports\": \"15-60\",
    \"action\": \"drop\"
  },
  {
    \"from\": \"12.13.14.15/24\",
    \"to\": \"HostOS\"
  }
]",
        );
        let firewall_settings: Vec<FirewallRule> = serde_json::from_str(inp).unwrap();
        let outp = serde_json::to_string_pretty(&firewall_settings).unwrap();
        assert_eq!(exp, outp);
    }
}
