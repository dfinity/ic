use crate::types::firewall::FirewallRule;
use crate::types::firewall::FirewallSettings;
use anyhow::Result;
use std::error::Error;
use std::fmt::Display;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug)]
pub enum FirewallRulesError {
    IOError((PathBuf, std::io::Error)),
    ParseError((PathBuf, serde_json::Error)),
}

impl Display for FirewallRulesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallRulesError::IOError((path, _)) => {
                write!(f, "Cannot read file {}", path.display())
            }
            FirewallRulesError::ParseError((path, _)) => {
                write!(
                    f,
                    "Cannot parse file {} as a list of firewall rules",
                    path.display()
                )
            }
        }
    }
}

impl Error for FirewallRulesError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            FirewallRulesError::IOError((_, e)) => Some(e),
            FirewallRulesError::ParseError((_, e)) => Some(e),
        }
    }
}

/// Parse a user-supplied firewall configuration file.
/// Returns a list of firewall rules.
///
/// The firewall configuration file format is described in document Network-Configuration.adoc.
fn get_firewall_rules_json(firewall_file: &Path) -> Result<Vec<FirewallRule>, FirewallRulesError> {
    let file = match File::open(firewall_file) {
        Ok(file) => file,
        Err(e) => {
            return Err(FirewallRulesError::IOError((
                firewall_file.to_path_buf(),
                e,
            )))
        }
    };
    match serde_json::from_reader(&file) {
        Ok(val) => Ok(val),
        Err(e) => Err(FirewallRulesError::ParseError((
            firewall_file.to_path_buf(),
            e,
        ))),
    }
}

/// Parse an optionally explicitly specified firewall configuration file
/// falling back to a default configuration file.
///
/// If the firewall configuration file is *not* specified, the default
/// is read.  In this specific case, if the default configuration file does
/// not exist, the result value is Ok(None).
///
/// If the firewall configuration file *is* specified, and it does not exist,
/// an Err<FirewallRulesError> is returned.
///
/// Also read the documentation of get_firewall_rules_json.
pub fn get_firewall_rules_json_or_default(
    firewall_file: Option<&Path>,
    default_firewall_file: &Path,
) -> Result<Option<FirewallSettings>, FirewallRulesError> {
    match firewall_file {
        Some(firewall_file) => {
            get_firewall_rules_json(firewall_file).map(|r| Some(FirewallSettings { rules: r }))
        }
        None => match get_firewall_rules_json(Path::new(default_firewall_file)) {
            Ok(config) => Ok(Some(FirewallSettings { rules: config })),
            Err(FirewallRulesError::IOError((_, e)))
                if e.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::firewall::{FirewallRuleAction, FirewallRuleDestination};
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn temp_fixture(text: &str) -> Result<NamedTempFile> {
        let mut temp_file = NamedTempFile::new()?;
        write!(temp_file, "{}", text)?;
        Ok(temp_file)
    }

    macro_rules! bad_rules_must_be_bad {
        ($text:literal) => {
            let temp_file = temp_fixture($text)?;
            let outp = get_firewall_rules_json(temp_file.path());
            assert!(outp.is_err());
            Ok(())
        };
    }

    #[test]
    fn test_get_firewall_rules_json() -> Result<()> {
        // Test valid firewall.json.
        let temp_file = temp_fixture(
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
    \"to\": \"Both\",
    \"action\": \"accept\"
  }
]",
        )?;
        let outp = get_firewall_rules_json(temp_file.path())?;

        assert_eq!(outp[0].to, FirewallRuleDestination::GuestOS);
        assert_eq!(outp[1].to, FirewallRuleDestination::HostOS);
        assert_eq!(outp[2].to, FirewallRuleDestination::Both);
        assert_eq!(outp[0].action, FirewallRuleAction::Accept);
        assert_eq!(outp[1].action, FirewallRuleAction::Drop);
        assert_eq!(outp[2].action, FirewallRuleAction::Accept);

        Ok(())
    }

    #[test]
    fn test_get_firewall_rules_json_port_out_of_range() -> Result<()> {
        bad_rules_must_be_bad! {"[
  {
    \"from\": \"2001:db8:abcd:0012::0/64\",
    \"to\": \"GuestOS\"
    \"to_ports\": 65537,
  }
]"}
    }

    #[test]
    fn test_get_firewall_rules_json_port_empty() -> Result<()> {
        bad_rules_must_be_bad! {"[
  {
    \"from\": \"2001:db8:abcd:0012::0/64\",
    \"to_ports\": \"\",
  }
]"}
    }

    #[test]
    fn test_get_firewall_rules_json_port_incomplete() -> Result<()> {
        bad_rules_must_be_bad! {"[
  {
    \"from\": \"2001:db8:abcd:0012::0/64\",
    \"to_ports\": \"-24\",
  }
]"}
    }

    #[test]
    fn test_get_firewall_rules_json_empty_ip() -> Result<()> {
        bad_rules_must_be_bad! {"[
  {
    \"from\": \"\",
  }
]"}
    }

    #[test]
    fn test_get_firewall_rules_json_empty_file() -> Result<()> {
        bad_rules_must_be_bad! {""}
    }
}
