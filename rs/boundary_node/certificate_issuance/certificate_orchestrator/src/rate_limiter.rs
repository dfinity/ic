use anyhow::{Error, anyhow};
use candid::Principal;
use certificate_orchestrator_interface::{Id, Name};
use publicsuffix::{List, Psl};
use std::collections::BTreeMap;

use crate::{
    LocalRef,
    registration::{Create, CreateError},
};

// The rate limiter only subtracts available tokens and needs to be paired with a timer that adds available tokens.
pub struct WithRateLimit<T> {
    limited: T,
    rate: u32, // Number of new registrations allowed for some apex domain to be created per given period. Has to be >= 1.
    available_tokens: LocalRef<BTreeMap<String, u32>>, // Map: apex domain -> available tokens
    suffix_list: List, // suffix list used for rate limiting
}

impl<T: Create> WithRateLimit<T> {
    pub fn new(
        limited: T,
        rate: u32,
        available_tokens: LocalRef<BTreeMap<String, u32>>,
        suffix_list: List,
    ) -> Self {
        Self {
            limited,
            rate,
            available_tokens,
            suffix_list,
        }
    }
}

impl<T: Create> Create for WithRateLimit<T> {
    fn create(&self, name: &str, canister: &Principal) -> Result<Id, CreateError> {
        let apex_domain = extract_apex_domain(name, &self.suffix_list)?; // the apex domain being rate-limited
        self.available_tokens.with(|at| {
            let mut at = at.borrow_mut();
            let tokens = *at.get(&apex_domain).unwrap_or(&self.rate);
            if tokens < 1 {
                return Err(CreateError::RateLimited(apex_domain));
            };
            let create_result = self.limited.create(name, canister)?;
            at.insert(apex_domain, tokens - 1);
            Ok(create_result)
        })
    }
}

fn extract_apex_domain(name: &str, domain_list: &List) -> Result<String, Error> {
    // check if the name is okay
    let _: Name = name.try_into()?;
    // get apex domain
    if let Some(domain) = domain_list.domain(name.as_bytes()) {
        let s = String::from_utf8(domain.as_bytes().into())?;
        Ok(s)
    } else {
        Err(anyhow!("error parsing the domain"))
    }
}

#[cfg(test)]
mod tests {
    use crate::rate_limiter::{List, extract_apex_domain};
    use anyhow::Error;

    #[test]
    fn parse_apex() -> Result<(), Error> {
        let list: List = include_str!("../public_suffix_list.dat").parse().unwrap();

        let domain = "bob.alice.com";
        assert_ne!(extract_apex_domain(domain, &list)?, String::from("bob.com"));

        let test_cases_eq = vec![
            ("bob.com", "bob.com"),
            ("alice.bob.com", "bob.com"),
            ("charlie.alice.bob.com", "bob.com"),
            ("bob.co.uk", "bob.co.uk"),
            ("charlie.alice.bob.co.uk", "bob.co.uk"),
        ];
        for (s1, s2) in test_cases_eq {
            assert_eq!(extract_apex_domain(s1, &list)?, String::from(s2));
        }

        let test_cases_err = vec![(""), ("bob"), ("%bob.com")];
        for s in test_cases_err {
            assert!(extract_apex_domain(s, &list).is_err());
        }

        Ok(())
    }
}
