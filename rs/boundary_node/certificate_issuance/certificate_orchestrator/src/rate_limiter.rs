use anyhow::{Context, Error};
use candid::Principal;
use certificate_orchestrator_interface::{Id, Name};
use std::collections::BTreeMap;

use crate::{
    registration::{Create, CreateError},
    LocalRef,
};

// The rate limiter only subtracts available tokens and needs to be paired with a timer that adds available tokens.
pub struct WithRateLimit<T> {
    limited: T,
    rate: u32, // Number of new registrations allowed for some apex domain to be created per given period. Has to be >= 1.
    available_tokens: LocalRef<BTreeMap<String, u32>>, // Map: apex domain -> available tokens
}

impl<T: Create> WithRateLimit<T> {
    pub fn new(limited: T, rate: u32, available_tokens: LocalRef<BTreeMap<String, u32>>) -> Self {
        Self {
            limited,
            rate,
            available_tokens,
        }
    }
}

impl<T: Create> Create for WithRateLimit<T> {
    fn create(&self, name: &str, canister: &Principal) -> Result<Id, CreateError> {
        let apex_domain = extract_apex_domain(name)?; // the apex domain being rate-limited
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

fn extract_apex_domain(name: &str) -> Result<String, Error> {
    // check if the name is okay
    let _: Name = name.try_into()?;
    // get apex domain
    let v: Vec<&str> = name.split('.').collect();
    let mut rev = v.iter().rev();
    let (d2, d1) = (
        rev.next().context("Invalid domain argument")?,
        rev.next().context("Invalid domain argument")?,
    );
    Ok(format!("{}.{}", *d1, *d2))
}

#[cfg(test)]
mod tests {
    use crate::rate_limiter::extract_apex_domain;
    use anyhow::Error;

    #[test]
    fn parse_apex() -> Result<(), Error> {
        let domain = "bob.alice.com";
        assert_ne!(extract_apex_domain(domain)?, String::from("bob.com"));

        let test_cases_eq = vec![
            ("bob.com", "bob.com"),
            ("alice.bob.com", "bob.com"),
            ("charlie.alice.bob.com", "bob.com"),
        ];
        for (s1, s2) in test_cases_eq {
            assert_eq!(extract_apex_domain(s1)?, String::from(s2));
        }

        let test_cases_err = vec![(""), ("bob"), ("%bob.com")];
        for s in test_cases_err {
            assert!(extract_apex_domain(s).is_err());
        }

        Ok(())
    }
}
