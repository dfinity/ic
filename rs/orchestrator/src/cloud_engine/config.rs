//! The `ic-gateway` configuration an engine's operator canister hands out.

use super::operator::{AcmeCredentials, HttpGatewayConfig};
use crate::error::{OrchestratorError, OrchestratorResult};
use idna::domain_to_ascii_strict;
use serde::Serialize;
use std::{fmt, path::Path};
use url::Url;

/// A complete, validated engine configuration.
///
/// `ic-gateway` terminates TLS for the engine, so it cannot run without all of
/// these. An incomplete config is therefore not an error but simply nothing to
/// apply, which [`TryFrom`] reports as [`Incomplete`](ConfigError::Incomplete).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct GatewayConfig {
    pub base_domains: Vec<String>,
    pub dns_api_url: Url,
    pub dns_api_key: String,
    pub acme_account: AcmeAccount,
}

/// An `instant_acme::AccountCredentials`. `key_pkcs8` is the account private key
/// as PKCS#8 DER, base64url without padding.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AcmeAccount {
    pub id: String,
    pub key_pkcs8: String,
    pub directory: String,
}

#[derive(Debug)]
pub(crate) enum ConfigError {
    /// At least one field is not configured yet. Nothing to apply, not a failure.
    Incomplete(&'static str),
    /// A configured field is unusable, e.g. a domain `ic-gateway` would reject.
    Invalid(String),
}

impl TryFrom<(HttpGatewayConfig, AcmeCredentials)> for GatewayConfig {
    type Error = ConfigError;

    fn try_from(
        (gateway, acme): (HttpGatewayConfig, AcmeCredentials),
    ) -> Result<Self, Self::Error> {
        let base_domains = gateway
            .base_domains
            .filter(|domains| !domains.is_empty())
            .ok_or(ConfigError::Incomplete("base_domains"))?;
        // `ic-gateway` parses DOMAIN as a comma-separated list of FQDNs, so a
        // value it would reject must not reach it: it would exit at startup.
        let base_domains = base_domains
            .iter()
            .map(|domain| match domain_to_ascii_strict(domain) {
                Ok(ascii) if !ascii.is_empty() => Ok(ascii),
                _ => Err(ConfigError::Invalid(format!(
                    "{domain} is not a valid domain name"
                ))),
            })
            .collect::<Result<Vec<_>, _>>()?;

        let dns_api_url = gateway
            .dns_api_url
            .ok_or(ConfigError::Incomplete("dns_api_url"))?;
        let dns_api_url = Url::parse(&dns_api_url)
            .map_err(|err| ConfigError::Invalid(format!("dns_api_url is not a URL: {err}")))?;
        // The IC-DNS-LB client appends a path to this URL and rejects anything
        // it cannot use as a base.
        if dns_api_url.cannot_be_a_base() {
            return Err(ConfigError::Invalid(
                "dns_api_url cannot be used as a base URL".to_string(),
            ));
        }

        let dns_api_key = gateway
            .dns_api_key
            .filter(|key| !key.is_empty())
            .ok_or(ConfigError::Incomplete("dns_api_key"))?;

        // All three ACME fields are needed together: `instant_acme` requires the
        // directory URL to restore an account, and refuses one without a key.
        let acme_account = AcmeAccount {
            id: acme.id.ok_or(ConfigError::Incomplete("acme id"))?,
            key_pkcs8: acme
                .key_pkcs8
                .ok_or(ConfigError::Incomplete("acme key_pkcs8"))?,
            directory: acme
                .directory
                .ok_or(ConfigError::Incomplete("acme directory"))?,
        };

        Ok(Self {
            base_domains,
            dns_api_url,
            dns_api_key,
            acme_account,
        })
    }
}

impl GatewayConfig {
    /// The environment that overrides the shipped `ic-gateway.env`, which only
    /// carries policy (which challenge, which DNS backend, which ports).
    ///
    /// The two credentials go into the environment rather than the argument
    /// list: arguments are logged by the process runner and are world-readable
    /// through `/proc/<pid>/cmdline`, the environment is neither.
    pub(crate) fn env_overlay(
        &self,
        acme_cache_dir: &Path,
    ) -> OrchestratorResult<Vec<(String, String)>> {
        let account_credentials = serde_json::to_string(&self.acme_account).map_err(|err| {
            OrchestratorError::cloud_engine_error(format!(
                "could not encode the ACME account: {err}"
            ))
        })?;

        Ok(vec![
            (
                "ACME_CACHE_PATH".to_string(),
                acme_cache_dir.display().to_string(),
            ),
            ("DOMAIN".to_string(), self.base_domains.join(",")),
            (
                "ACME_DNS_IC_DNS_LB_URLS".to_string(),
                self.dns_api_url.to_string(),
            ),
            (
                "ACME_DNS_IC_DNS_LB_TOKEN".to_string(),
                self.dns_api_key.clone(),
            ),
            ("ACME_ACCOUNT_CREDS".to_string(), account_credentials),
        ])
    }
}

#[cfg(test)]
impl GatewayConfig {
    /// A complete config serving `base_domain`, for tests that only care about
    /// whether a config is present or has changed.
    pub(crate) fn for_test(base_domain: &str) -> Self {
        Self {
            base_domains: vec![base_domain.to_string()],
            dns_api_url: Url::parse("https://dns.example.com/").unwrap(),
            dns_api_key: "dns-key".to_string(),
            acme_account: AcmeAccount {
                id: "account-id".to_string(),
                key_pkcs8: "a2V5".to_string(),
                directory: "https://acme.example.com/dir".to_string(),
            },
        }
    }
}

/// Redacts the credentials, so that a `GatewayConfig` is safe to log.
impl fmt::Debug for GatewayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayConfig")
            .field("base_domains", &self.base_domains)
            .field("dns_api_url", &self.dns_api_url.as_str())
            .field("dns_api_key", &"<redacted>")
            .field("acme_account", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete(field) => write!(f, "{field} is not configured yet"),
            Self::Invalid(msg) => write!(f, "{msg}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

    fn gateway() -> HttpGatewayConfig {
        HttpGatewayConfig {
            base_domains: Some(vec!["engine.example.com".to_string()]),
            dns_api_url: Some("https://dns.example.com/".to_string()),
            dns_api_key: Some("dns-key".to_string()),
        }
    }

    fn acme() -> AcmeCredentials {
        AcmeCredentials {
            id: Some("account-id".to_string()),
            key_pkcs8: Some("a2V5".to_string()),
            directory: Some("https://acme.example.com/dir".to_string()),
        }
    }

    fn parse(
        gateway: HttpGatewayConfig,
        acme: AcmeCredentials,
    ) -> Result<GatewayConfig, ConfigError> {
        GatewayConfig::try_from((gateway, acme))
    }

    #[test]
    fn complete_config_is_accepted() {
        let config = parse(gateway(), acme()).expect("the config should be complete");

        assert_eq!(config.base_domains, vec!["engine.example.com".to_string()]);
        assert_eq!(config.dns_api_url.as_str(), "https://dns.example.com/");
        assert_eq!(config.dns_api_key, "dns-key");
        assert_eq!(config.acme_account.id, "account-id");
    }

    #[test]
    fn empty_config_is_incomplete() {
        assert_matches!(
            parse(HttpGatewayConfig::default(), AcmeCredentials::default()),
            Err(ConfigError::Incomplete("base_domains"))
        );
    }

    #[test]
    fn every_missing_field_is_incomplete() {
        let cases: Vec<(&str, HttpGatewayConfig, AcmeCredentials)> = vec![
            (
                "base_domains",
                HttpGatewayConfig {
                    base_domains: None,
                    ..gateway()
                },
                acme(),
            ),
            (
                "dns_api_url",
                HttpGatewayConfig {
                    dns_api_url: None,
                    ..gateway()
                },
                acme(),
            ),
            (
                "dns_api_key",
                HttpGatewayConfig {
                    dns_api_key: None,
                    ..gateway()
                },
                acme(),
            ),
            ("acme id", gateway(), AcmeCredentials { id: None, ..acme() }),
            (
                "acme key_pkcs8",
                gateway(),
                AcmeCredentials {
                    key_pkcs8: None,
                    ..acme()
                },
            ),
            (
                "acme directory",
                gateway(),
                AcmeCredentials {
                    directory: None,
                    ..acme()
                },
            ),
        ];

        for (field, gateway, acme) in cases {
            assert_matches!(
                parse(gateway, acme),
                Err(ConfigError::Incomplete(missing)) if missing == field,
                "expected {field} to be reported as missing"
            );
        }
    }

    #[test]
    fn empty_base_domain_list_is_incomplete() {
        assert_matches!(
            parse(
                HttpGatewayConfig {
                    base_domains: Some(vec![]),
                    ..gateway()
                },
                acme()
            ),
            Err(ConfigError::Incomplete("base_domains"))
        );
    }

    #[test]
    fn domains_are_normalized() {
        // Mixed case and IDNs are serviceable after normalization to the
        // lowercase ASCII form `ic-gateway` expects.
        let config = parse(
            HttpGatewayConfig {
                base_domains: Some(vec![
                    "Engine.Example.com".to_string(),
                    "bücher.example".to_string(),
                ]),
                ..gateway()
            },
            acme(),
        )
        .expect("normalizable domains should be accepted");

        assert_eq!(
            config.base_domains,
            vec![
                "engine.example.com".to_string(),
                "xn--bcher-kva.example".to_string()
            ]
        );
    }

    #[test]
    fn unusable_values_are_invalid() {
        // A comma would silently split into two domains, an empty label and a
        // scheme-less URL are rejected by ic-gateway.
        for domain in ["a.example.com,b.example.com", "not a domain", ""] {
            assert_matches!(
                parse(
                    HttpGatewayConfig {
                        base_domains: Some(vec![domain.to_string()]),
                        ..gateway()
                    },
                    acme()
                ),
                Err(ConfigError::Invalid(_)),
                "expected {domain} to be rejected"
            );
        }

        for url in ["not-a-url", "mailto:someone@example.com"] {
            assert_matches!(
                parse(
                    HttpGatewayConfig {
                        dns_api_url: Some(url.to_string()),
                        ..gateway()
                    },
                    acme()
                ),
                Err(ConfigError::Invalid(_)),
                "expected {url} to be rejected"
            );
        }
    }

    #[test]
    fn debug_hides_the_credentials() {
        let config = parse(gateway(), acme()).unwrap();
        let debug = format!("{config:?}");

        assert!(debug.contains("engine.example.com"), "{debug}");
        assert!(!debug.contains("dns-key"), "{debug}");
        assert!(!debug.contains("a2V5"), "{debug}");
    }
}
