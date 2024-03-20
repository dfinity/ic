use std::collections::HashSet;

use anyhow::Error;
use candid::Principal;
use regex::Regex;

// System subnets routing table
pub const SYSTEM_SUBNETS: [(Principal, Principal); 5] = [
    (
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01]),
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x01, 0x01]),
    ),
    (
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x01]),
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x01]),
    ),
    (
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x01]),
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xff, 0xff, 0x01, 0x01]),
    ),
    (
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x01, 0xa0, 0x00, 0x00, 0x01, 0x01]),
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x01, 0xaf, 0xff, 0xff, 0x01, 0x01]),
    ),
    (
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x02, 0x10, 0x00, 0x00, 0x01, 0x01]),
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x02, 0x1f, 0xff, 0xff, 0x01, 0x01]),
    ),
];

pub fn is_system_subnet(canister_id: Principal) -> bool {
    SYSTEM_SUBNETS
        .iter()
        .map(|x| canister_id >= x.0 && canister_id <= x.1)
        .any(|x| x)
}

// Things needed to verify domain-canister match
pub struct DomainCanisterMatcher {
    pub pre_isolation_canisters: HashSet<Principal>,
    pub domains_app: Vec<Regex>,
    pub domains_system: Vec<Regex>,
}

impl DomainCanisterMatcher {
    pub fn new(
        pre_isolation_canisters: HashSet<Principal>,
        domains_app: Vec<String>,
        domains_system: Vec<String>,
    ) -> Result<Self, Error> {
        // Compile the matching regexes
        let domains_app = domains_app
            .into_iter()
            .map(|x| Regex::new(&x))
            .collect::<Result<Vec<_>, _>>()?;
        let domains_system = domains_system
            .into_iter()
            .map(|x| Regex::new(&x))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            pre_isolation_canisters,
            domains_app,
            domains_system,
        })
    }
}

impl DomainCanisterMatcher {
    pub fn check(&self, canister_id: Principal, host: &str) -> bool {
        if self.pre_isolation_canisters.contains(&canister_id) {
            return true;
        }

        let domains = if is_system_subnet(canister_id) {
            &self.domains_system
        } else {
            &self.domains_app
        };

        domains.iter().map(|x| x.is_match(host)).any(|x| x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_system_subnet() {
        assert!(is_system_subnet(
            Principal::from_text("qoctq-giaaa-aaaaa-aaaea-cai").unwrap(),
        )); // nns
        assert!(is_system_subnet(
            Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap()
        )); // identity
        assert!(!is_system_subnet(
            Principal::from_text("oydqf-haaaa-aaaao-afpsa-cai").unwrap()
        )); // something else
    }

    #[test]
    fn test_domain_canister_match() {
        let mut pic = HashSet::new();
        pic.insert(Principal::from_text("2dcn6-oqaaa-aaaai-abvoq-cai").unwrap());

        let dcm = DomainCanisterMatcher::new(
            pic,
            vec![r"^([^.]+\.)?(raw\.)?icp0\.io$".into()],
            vec![r"^([^.]+\.)?(raw\.)?ic0\.app$".into()],
        )
        .unwrap();

        assert!(dcm.check(
            Principal::from_text("qoctq-giaaa-aaaaa-aaaea-cai").unwrap(), // nns on system domain
            "ic0.app",
        ));

        assert!(!dcm.check(
            Principal::from_text("s6hwe-laaaa-aaaab-qaeba-cai").unwrap(), // something else on system domain
            "ic0.app",
        ));

        assert!(dcm.check(
            Principal::from_text("s6hwe-laaaa-aaaab-qaeba-cai").unwrap(), // something else on app domain
            "icp0.io",
        ));

        assert!(dcm.check(
            Principal::from_text("2dcn6-oqaaa-aaaai-abvoq-cai").unwrap(), // pre-isolation canister on system domain
            "ic0.app",
        ));
    }
}
