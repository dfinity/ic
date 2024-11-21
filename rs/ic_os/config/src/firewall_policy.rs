use crate::types::firewall::{FirewallRuleAction, FirewallSettings};
use ipnet::IpNet;
use std::error::Error;
use std::fmt::Display;

static MAX_IPV4_PREFIX_LEN: u8 = 16;
static MAX_IPV6_PREFIX_LEN: u8 = 64;

#[derive(Debug)]
pub struct FirewallRulePolicyError {
    rule_num: usize,
    text: String,
}

impl Display for FirewallRulePolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rule #{}: {}", self.rule_num + 1, self.text)
    }
}

impl Error for FirewallRulePolicyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[derive(Debug)]
pub struct FirewallPolicyError {
    errors: Vec<FirewallRulePolicyError>,
}

impl Display for FirewallPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "The following firewall rules do not comply with firewall policy:"
        )?;
        for e in self.errors.iter() {
            write!(f, "\n* {}", e)?
        }
        Ok(())
    }
}

impl Error for FirewallPolicyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[derive(Default)]
pub struct FirewallPolicyChecker {}

impl FirewallPolicyChecker {
    pub fn check(&self, settings: FirewallSettings) -> Result<(), FirewallPolicyError> {
        let errors: Vec<FirewallRulePolicyError> = settings
            .rules
            .iter()
            .enumerate()
            .map(|(rule_num, rule)| match rule.action {
                FirewallRuleAction::Accept => match rule.from {
                    IpNet::V4(range) => {
                        if range.prefix_len() < MAX_IPV4_PREFIX_LEN {
                            Err(FirewallRulePolicyError {
                                rule_num,
                                text: format!(
                                    "IPv4 subnet prefix too large ({}, above maximum {})",
                                    range.prefix_len(),
                                    MAX_IPV4_PREFIX_LEN
                                ),
                            })
                        } else {
                            Ok(())
                        }
                    }
                    IpNet::V6(range) => {
                        if range.prefix_len() < MAX_IPV6_PREFIX_LEN {
                            Err(FirewallRulePolicyError {
                                rule_num,
                                text: format!(
                                    "IPv4 subnet prefix too large ({}, above maximum {})",
                                    range.prefix_len(),
                                    MAX_IPV6_PREFIX_LEN
                                ),
                            })
                        } else {
                            Ok(())
                        }
                    }
                },
                _ => Ok(()),
            })
            .filter_map(|r| match r {
                Err(e) => Some(e),
                Ok(_) => None,
            })
            .collect();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(FirewallPolicyError { errors })
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{firewall_policy::FirewallPolicyChecker, types::firewall::*};
    use anyhow::Result;
    use serde_json;

    #[test]
    fn test_invalid_policy_ipv6_too_loose() -> Result<()> {
        let ruleset: Vec<FirewallRule> = serde_json::from_str(
            "[
  {
    \"from\": \"2001:db8:abcd:0012::0/63\",
    \"to\": \"GuestOS\"
  }
]",
        )?;
        let checker = FirewallPolicyChecker::default();
        checker
            .check(FirewallSettings { rules: ruleset })
            .expect_err("Should have been an error");
        Ok(())
    }

    #[test]
    fn test_invalid_policy_ipv4_too_loose() -> Result<()> {
        let ruleset: Vec<FirewallRule> = serde_json::from_str(
            "[
  {
    \"from\": \"10.240.0.0/15\",
    \"to\": \"GuestOS\"
  }
]",
        )?;
        let checker = FirewallPolicyChecker::default();
        checker
            .check(FirewallSettings { rules: ruleset })
            .expect_err("Should have been an error");
        Ok(())
    }

    #[test]
    fn test_invalid_policy_within_bounds() -> Result<()> {
        let ruleset: Vec<FirewallRule> = serde_json::from_str(
            "[
  {
    \"from\": \"2001:db8:abcd:0012::0/64\",
    \"to\": \"GuestOS\"
  },
  {
    \"from\": \"10.240.0.0/16\",
    \"to\": \"GuestOS\"
  }
]",
        )?;
        let checker = FirewallPolicyChecker::default();
        checker
            .check(FirewallSettings { rules: ruleset })
            .expect("Should be OK");
        Ok(())
    }
}
