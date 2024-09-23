use anyhow::{bail, Error};
use candid::Principal;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CanisterAlias {
    pub id: String,
    pub principal: Principal,
}

pub fn parse_canister_alias(value: &str) -> Result<CanisterAlias, Error> {
    match value.find(':') {
        None => {
            bail!("invalid canister alias '{value}'")
        }

        Some(0) => {
            bail!("canister alias missing id '{value}'")
        }

        Some(index) if index == value.len() - 1 => {
            bail!("canister alias missing principal '{value}'")
        }

        Some(index) => {
            let (id, principal) = value.split_at(index);

            let id = id.to_string();
            let principal = Principal::from_text(&principal[1..])?;

            Ok(CanisterAlias { id, principal })
        }
    }
}

#[cfg(test)]
mod tests {
    use candid::Principal;

    use crate::canister_alias::{parse_canister_alias, CanisterAlias};

    #[test]
    fn parse_canister_alias_fail() {
        let test_cases = &[
            "",    // invalid alias
            ":",   // missing id and principal
            "a:",  // missing principal
            ":b",  // missing id
            "a:b", // invalid principal
        ];

        for tc in test_cases {
            let output = parse_canister_alias(tc);
            assert!(output.is_err());
        }
    }

    #[test]
    fn parse_canister_alias_ok() {
        struct TestCase {
            input: String,
            output: CanisterAlias,
        }

        let test_cases = &[TestCase {
            input: String::from("a:g3wsl-eqaaa-aaaan-aaaaa-cai"),
            output: CanisterAlias {
                id: String::from("a"),
                principal: Principal::from_text("g3wsl-eqaaa-aaaan-aaaaa-cai").unwrap(),
            },
        }];

        for tc in test_cases {
            let output = parse_canister_alias(&tc.input);
            assert_eq!(output.unwrap(), tc.output);
        }
    }
}
