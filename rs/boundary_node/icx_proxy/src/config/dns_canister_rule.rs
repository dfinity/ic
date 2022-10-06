use anyhow::anyhow;
use candid::Principal;

const DNS_ALIAS_FORMAT_HELP: &str = "Format is dns.alias:principal-id";

#[derive(Clone, Debug)]
enum PrincipalDeterminationStrategy {
    // A domain name which matches the suffix is an alias for this specific Principal.
    Alias(Principal),

    // The subdomain to the immediate left of the suffix is the Principal,
    // if it parses as a valid Principal.
    PrecedingDomainName,
}

/// A mapping from a domain name to a Principal.  The domain name must
/// match the last portion, as split by '.', of the host specified in the request.
#[derive(Clone, Debug)]
pub struct DnsCanisterRule {
    /// The hostname parts that must match the right-hand side of the domain name.  Lower case.
    dns_suffix: Vec<String>,

    strategy: PrincipalDeterminationStrategy,
}

impl DnsCanisterRule {
    /// Create a rule for a domain name alias with form dns.alias:canister-id
    pub fn new_alias(dns_alias: &str) -> anyhow::Result<DnsCanisterRule> {
        let (domain_name, principal) = split_dns_alias(dns_alias)?;
        let dns_suffix = split_hostname_lowercase(&domain_name);
        Ok(DnsCanisterRule {
            dns_suffix,
            strategy: PrincipalDeterminationStrategy::Alias(principal),
        })
    }

    /// Create a rule which for domain names that match the specified suffix,
    /// if the preceding subdomain parses as a principal, return that principal.
    pub fn new_suffix(suffix: &str) -> DnsCanisterRule {
        let dns_suffix: Vec<String> = split_hostname_lowercase(suffix);
        DnsCanisterRule {
            dns_suffix,
            strategy: PrincipalDeterminationStrategy::PrecedingDomainName,
        }
    }

    /// Return the associated principal if this rule applies to the domain name.
    pub fn lookup<I, T>(&self, split_hostname: I) -> Option<Principal>
    where
        T: AsRef<str>,
        I: IntoIterator<Item = T>,
        I::IntoIter: DoubleEndedIterator,
    {
        fn extend_with_none<T>(i: impl Iterator<Item = T>) -> impl Iterator<Item = Option<T>> {
            i.map(Some).chain(std::iter::once(None))
        }
        fn eq(a: impl AsRef<str>, b: &str) -> bool {
            a.as_ref().eq_ignore_ascii_case(b)
        }

        use PrincipalDeterminationStrategy::{Alias, PrecedingDomainName};

        let split_hostname = split_hostname.into_iter().rev();
        let dns_suffix = self.dns_suffix().iter().rev();
        match (&self.strategy, split_hostname.size_hint()) {
            (Alias(_), (_, Some(len))) if len < self.dns_suffix().len() => None,
            (Alias(principal), _) => {
                // Extend `split_hostname` with `None`
                if extend_with_none(split_hostname)
                    .zip(dns_suffix)
                    // Loop through `split_hostname` and `dns_suffix`.
                    //
                    // If we reach the end of `split_hostname` (aka the `None` we extended) before
                    // we reach the end of `dns_suffix`, then short circuit with `false`.
                    .all(|(host, dns)| host.map(|host| eq(host, dns)).unwrap_or(false))
                {
                    Some(*principal)
                } else {
                    None
                }
            }
            (PrecedingDomainName, (_, Some(len))) if len <= self.dns_suffix().len() => None,
            (PrecedingDomainName, _) => split_hostname
                // Extend `dns_suffix` with `None`
                .zip(extend_with_none(dns_suffix))
                // Loop through `split_hostname` and `dns_suffix`.
                //
                // Once we reach the end of `dns_suffix` (aka the `None` we extended) we know
                // we're at the subdomain of `split_hostname`, so extract that.
                .map_while(|(host, dns)| match dns {
                    Some(dns) if eq(&host, dns) => Some(None),
                    Some(_) => None,
                    None => Principal::from_text(host.as_ref()).ok().map(Some),
                })
                .find_map(|x| x),
        }
    }

    pub fn dns_suffix(&self) -> &Vec<String> {
        &self.dns_suffix
    }
}

fn split_hostname_lowercase(hostname: &str) -> Vec<String> {
    hostname
        .split('.')
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

fn split_dns_alias(alias: &str) -> Result<(String, Principal), anyhow::Error> {
    match alias.find(':') {
        Some(0) => Err(anyhow!(
            r#"No domain specifed in DNS alias "{}".  {}"#,
            alias.to_string(),
            DNS_ALIAS_FORMAT_HELP
        )),
        Some(index) if index == alias.len() - 1 => Err(anyhow!(
            r#"No canister ID specifed in DNS alias "{}".  {}"#,
            alias.to_string(),
            DNS_ALIAS_FORMAT_HELP
        )),
        Some(index) => {
            let (domain_name, principal) = alias.split_at(index);
            let principal = &principal[1..];
            let principal = Principal::from_text(principal)?;
            Ok((domain_name.to_string(), principal))
        }
        None => Err(anyhow!(
            r#"Unrecognized DNS alias "{}".  {}"#,
            alias.to_string(),
            DNS_ALIAS_FORMAT_HELP,
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::config::dns_canister_rule::DnsCanisterRule;

    #[test]
    fn parse_error_no_colon() {
        let e = parse_dns_alias("happy.little.domain.name!r7inp-6aaaa-aaaaa-aaabq-cai")
            .expect_err("expected failure due to missing colon");
        assert_eq!(
            e.to_string(),
            r#"Unrecognized DNS alias "happy.little.domain.name!r7inp-6aaaa-aaaaa-aaabq-cai".  Format is dns.alias:principal-id"#
        )
    }

    #[test]
    fn parse_error_nothing_after_colon() {
        let e = parse_dns_alias("happy.little.domain.name:")
            .expect_err("expected failure due to nothing after colon");
        assert_eq!(
            e.to_string(),
            r#"No canister ID specifed in DNS alias "happy.little.domain.name:".  Format is dns.alias:principal-id"#
        )
    }

    #[test]
    fn parse_error_nothing_before_colon() {
        let e = parse_dns_alias(":r7inp-6aaaa-aaaaa-aaabq-cai")
            .expect_err("expected failure due to nothing after colon");
        assert_eq!(
            e.to_string(),
            r#"No domain specifed in DNS alias ":r7inp-6aaaa-aaaaa-aaabq-cai".  Format is dns.alias:principal-id"#
        )
    }

    fn parse_dns_alias(alias: &str) -> anyhow::Result<DnsCanisterRule> {
        DnsCanisterRule::new_alias(alias)
    }
}
