//! The `ic-gateway` configuration an engine's operator canister hands out.

use super::{
    error::{CloudEngineError, CloudEngineResult},
    operator::{AcmeCredentials, HttpGatewayConfig},
};
use crate::error::{OrchestratorError, OrchestratorResult};
use idna::domain_to_ascii_strict;
use serde::Serialize;
use std::{collections::HashMap, ffi::OsString, fmt, path::Path};
use url::Url;

/// A complete, validated engine configuration.
///
/// `ic-gateway` terminates TLS for the engine, so it cannot run without all of
/// these. An incomplete config is therefore not an error but simply nothing to
/// apply, which [`validate_engine_config`] reports as
/// [`Incomplete`](CloudEngineError::Incomplete).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EngineConfig {
    pub base_domains: Vec<String>,
    pub dns_api_urls: Vec<Url>,
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

/// Turns what the operator canister handed out into an [`EngineConfig`],
/// rejecting values `ic-gateway` could not run with.
pub(super) fn validate_engine_config(
    gateway: HttpGatewayConfig,
    acme: AcmeCredentials,
) -> CloudEngineResult<EngineConfig> {
    let base_domains = gateway
        .base_domains
        .filter(|domains| !domains.is_empty())
        .ok_or(CloudEngineError::Incomplete("base_domains"))?
        // `ic-gateway` parses DOMAIN as a comma-separated list of FQDNs, so a
        // value it would reject must not reach it: it would exit at startup.
        .iter()
        .map(|domain| match domain_to_ascii_strict(domain) {
            Ok(ascii) if !ascii.is_empty() => Ok(ascii),
            _ => Err(CloudEngineError::failed(format!(
                "{domain} is not a valid domain name"
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;

    let dns_api_urls = gateway
        .dns_api_urls
        .filter(|urls| !urls.is_empty())
        .ok_or(CloudEngineError::Incomplete("dns_api_urls"))?
        // The IC-DNS-LB client appends a path to each of these, so it rejects
        // anything it cannot use as a base.
        .iter()
        .map(|url| match Url::parse(url) {
            Ok(parsed) if parsed.cannot_be_a_base() => Err(CloudEngineError::failed(format!(
                "{url} cannot be used as a base URL"
            ))),
            Ok(parsed) => Ok(parsed),
            Err(err) => Err(CloudEngineError::failed(format!(
                "{url} is not a URL: {err}"
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;

    let dns_api_key = gateway
        .dns_api_key
        .filter(|key| !key.is_empty())
        .ok_or(CloudEngineError::Incomplete("dns_api_key"))?;

    // All three ACME fields are needed together: `instant_acme` requires the
    // directory URL to restore an account, and refuses one without a key.
    let acme_account = AcmeAccount {
        id: acme.id.ok_or(CloudEngineError::Incomplete("acme id"))?,
        key_pkcs8: acme
            .key_pkcs8
            .ok_or(CloudEngineError::Incomplete("acme key_pkcs8"))?,
        directory: acme
            .directory
            .ok_or(CloudEngineError::Incomplete("acme directory"))?,
    };

    Ok(EngineConfig {
        base_domains,
        dns_api_urls,
        dns_api_key,
        acme_account,
    })
}

impl EngineConfig {
    /// The environment that overrides the shipped `ic-gateway.env`, which only
    /// carries policy (which challenge, which DNS backend, which ports).
    ///
    /// The two credentials go into the environment rather than the argument
    /// list: arguments are logged by the process runner and are world-readable
    /// through `/proc/<pid>/cmdline`, the environment is neither.
    pub(crate) fn env_overlay(
        &self,
        acme_cache_dir: &Path,
    ) -> OrchestratorResult<HashMap<OsString, OsString>> {
        let account_credentials = serde_json::to_string(&self.acme_account).map_err(|err| {
            OrchestratorError::invalid_configuration_error(format!(
                "the ACME account could not be encoded: {err}"
            ))
        })?;

        Ok([
            ("ACME_CACHE_PATH", acme_cache_dir.display().to_string()),
            ("DOMAIN", self.base_domains.join(",")),
            (
                "ACME_DNS_IC_DNS_LB_URLS",
                self.dns_api_urls
                    .iter()
                    .map(Url::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ("ACME_DNS_IC_DNS_LB_TOKEN", self.dns_api_key.clone()),
            ("ACME_ACCOUNT_CREDS", account_credentials),
        ]
        .into_iter()
        .map(|(key, value)| (OsString::from(key), OsString::from(value)))
        .collect())
    }
}

#[cfg(test)]
impl EngineConfig {
    /// A complete config serving `base_domain`, for tests that only care about
    /// whether a config is present or has changed.
    pub(crate) fn for_test(base_domain: &str) -> Self {
        Self {
            base_domains: vec![base_domain.to_string()],
            dns_api_urls: vec![Url::parse("https://dns.example.com/").unwrap()],
            dns_api_key: "dns-key".to_string(),
            acme_account: AcmeAccount {
                id: "account-id".to_string(),
                key_pkcs8: "a2V5".to_string(),
                directory: "https://acme.example.com/dir".to_string(),
            },
        }
    }
}

/// Redacts the credentials, so that an [`EngineConfig`] is safe to log.
impl fmt::Debug for EngineConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dns_api_urls: Vec<&str> = self.dns_api_urls.iter().map(Url::as_str).collect();

        f.debug_struct("EngineConfig")
            .field("base_domains", &self.base_domains)
            .field("dns_api_urls", &dns_api_urls)
            .field("dns_api_key", &"<redacted>")
            .field("acme_account", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

    fn gateway() -> HttpGatewayConfig {
        HttpGatewayConfig {
            base_domains: Some(vec!["engine.example.com".to_string()]),
            dns_api_urls: Some(vec!["https://dns.example.com/".to_string()]),
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

    fn parse(gateway: HttpGatewayConfig, acme: AcmeCredentials) -> CloudEngineResult<EngineConfig> {
        validate_engine_config(gateway, acme)
    }

    #[test]
    fn complete_config_is_accepted() {
        let config = parse(gateway(), acme()).expect("the config should be complete");

        assert_eq!(config.base_domains, vec!["engine.example.com".to_string()]);
        assert_eq!(
            config
                .dns_api_urls
                .iter()
                .map(Url::as_str)
                .collect::<Vec<_>>(),
            vec!["https://dns.example.com/"]
        );
        assert_eq!(config.dns_api_key, "dns-key");
        assert_eq!(config.acme_account.id, "account-id");
    }

    #[test]
    fn empty_config_is_incomplete() {
        assert_matches!(
            parse(HttpGatewayConfig::default(), AcmeCredentials::default()),
            Err(CloudEngineError::Incomplete("base_domains"))
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
                "dns_api_urls",
                HttpGatewayConfig {
                    dns_api_urls: None,
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
                Err(CloudEngineError::Incomplete(missing)) if missing == field,
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
            Err(CloudEngineError::Incomplete("base_domains"))
        );
    }

    #[test]
    fn empty_dns_api_url_list_is_incomplete() {
        assert_matches!(
            parse(
                HttpGatewayConfig {
                    dns_api_urls: Some(vec![]),
                    ..gateway()
                },
                acme()
            ),
            Err(CloudEngineError::Incomplete("dns_api_urls"))
        );
    }

    #[test]
    fn every_dns_api_url_is_handed_to_the_gateway() {
        // `ic-gateway` parses ACME_DNS_IC_DNS_LB_URLS as a comma-separated list,
        // so all of the operator's URLs have to survive into that one value.
        let config = parse(
            HttpGatewayConfig {
                dns_api_urls: Some(vec![
                    "https://dns1.example.com/".to_string(),
                    "https://dns2.example.com/".to_string(),
                ]),
                ..gateway()
            },
            acme(),
        )
        .expect("multiple DNS API URLs should be accepted");

        assert_eq!(
            config
                .dns_api_urls
                .iter()
                .map(Url::as_str)
                .collect::<Vec<_>>(),
            vec!["https://dns1.example.com/", "https://dns2.example.com/"]
        );

        let env = config
            .env_overlay(Path::new("/var/lib/ic/data/acme"))
            .expect("the overlay should be encodable");

        assert_eq!(
            env.get(&OsString::from("ACME_DNS_IC_DNS_LB_URLS")),
            Some(&OsString::from(
                "https://dns1.example.com/,https://dns2.example.com/"
            ))
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
                Err(CloudEngineError::Failed(_)),
                "expected {domain} to be rejected"
            );
        }

        for url in ["not-a-url", "mailto:someone@example.com"] {
            assert_matches!(
                parse(
                    HttpGatewayConfig {
                        dns_api_urls: Some(vec![url.to_string()]),
                        ..gateway()
                    },
                    acme()
                ),
                Err(CloudEngineError::Failed(_)),
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
