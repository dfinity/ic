use crate::pb::v1::Subaccount as SubaccountProto;
#[cfg(any(test, feature = "canbench-rs", feature = "test"))]
use ic_nervous_system_temporary::Temporary;
use std::{cell::Cell, convert::TryInto};

mod cached_upgrade_steps;
pub mod canister_control;
pub mod extensions;
pub(crate) mod follower_index;
pub mod following;
pub mod governance;
pub mod init;
pub mod logs;
pub mod neuron;
pub mod pb;
pub mod proposal;
pub mod reward;
pub mod sns_upgrade;
pub mod topics;
mod treasury;
pub mod types;
pub mod upgrade_journal;

pub mod icrc_ledger_helper;
pub mod storage;

// Feature flag for SNS Extensions
thread_local! {
    static SNS_EXTENSIONS_ENABLED: Cell<bool> = const { Cell::new(true) };
}

pub fn is_sns_extensions_enabled() -> bool {
    SNS_EXTENSIONS_ENABLED.get()
}

/// Only integration tests should use this.
#[cfg(any(test, feature = "canbench-rs", feature = "test"))]
pub fn temporarily_enable_sns_extensions() -> Temporary {
    Temporary::new(&SNS_EXTENSIONS_ENABLED, true)
}

/// Only integration tests should use this.
#[cfg(any(test, feature = "canbench-rs", feature = "test"))]
pub fn temporarily_disable_sns_extensions() -> Temporary {
    Temporary::new(&SNS_EXTENSIONS_ENABLED, false)
}

trait Len {
    fn len(&self) -> usize;
}

/// Maximum size, in bytes, of a scalar field (e.g., of type `String` or numeric types) that.
/// Scalar values greater than this will be truncated during error reporting.
pub const MAX_SCALAR_FIELD_LEN_BYTES: usize = 50_000;

/// Warning: the len method on str and String is in bytes, not characters. If
/// you want to constrain the number of characters, look at
/// validate_chars_count.
fn validate_len<V>(field_name: &str, field_value: &V, min: usize, max: usize) -> Result<(), String>
where
    V: Len + ToString,
{
    let len = field_value.len();

    if len < min {
        let defect = &format!("too short (min = {min} vs. observed = {len})");

        let bounded_field_value = field_value.to_string();

        return field_err(field_name, bounded_field_value, defect);
    }

    if len > max {
        let defect = &format!("too long (max = {max} vs. observed = {len})");

        let bounded_field_value = field_value
            .to_string()
            .chars()
            .take(max)
            .collect::<String>();

        return field_err(field_name, bounded_field_value, defect);
    }

    Ok(())
}

impl Len for str {
    fn len(&self) -> usize {
        self.len()
    }
}

impl Len for String {
    fn len(&self) -> usize {
        self.len()
    }
}

impl<T> Len for Vec<T> {
    fn len(&self) -> usize {
        self.len()
    }
}

impl Len for &str {
    fn len(&self) -> usize {
        (*self).len()
    }
}

impl Len for &String {
    fn len(&self) -> usize {
        (*self).len()
    }
}

impl<T> Len for &Vec<T> {
    fn len(&self) -> usize {
        (*self).len()
    }
}

/// Validate field value within some (message) struct.
fn validate_chars_count(
    field_name: &str,
    field_value: &str,
    min: usize,
    max: usize,
) -> Result<(), String> {
    let len = field_value.chars().count();

    if len < min {
        let defect = &format!("too short (min = {min} vs. observed = {len})");

        return field_err(field_name, field_value.to_string(), defect);
    }

    if len > max {
        let defect = &format!("too long (max = {max} vs. observed = {len})");
        let bounded_field_value = field_value.chars().take(max).collect::<String>();

        return field_err(field_name, bounded_field_value, defect);
    }

    Ok(())
}

fn validate_required_field<'a, Inner>(
    field_name: &str,
    field_value: &'a Option<Inner>,
) -> Result<&'a Inner, String> {
    field_value
        .as_ref()
        .ok_or_else(|| format!("The {field_name} field must be populated."))
}

/// Return an Err whose inner value describes (in detail) what is wrong with `field_value`,
/// and where within some (Protocol Buffers message) struct.
///
/// Only up to the first `MAX_SCALAR_FIELD_LEN_BYTES` bytes will be taken from `field_value`.
fn field_err(field_name: &str, field_value: String, defect: &str) -> Result<(), String> {
    let mut bounded_field_value = String::new();
    // Concatenate characters one-by-one, until we either run out of characters or exceed
    // the limit (in which case we pop the last character to still comply with the limits).
    // Note that a `char` is always 4 bytes, but pushing it to a string does not always increase
    // a string's byte size by 4 bytes. For example:
    // ```
    // println!("bytes = {}", std::mem::size_of_val(&'\u{200D}')); // bytes = 4
    // println!("bytes = {}", std::mem::size_of_val("\u{200D}"));  // bytes = 3
    // ```
    for c in field_value.chars() {
        bounded_field_value.push(c);
        if bounded_field_value.len() > MAX_SCALAR_FIELD_LEN_BYTES {
            bounded_field_value.pop();
            break;
        }
    }
    Err(format!(
        "The first {} characters of the value in field `{}` are {}: `{}`",
        bounded_field_value.chars().count(),
        field_name,
        defect,
        bounded_field_value
    ))
}

impl TryFrom<pb::v1::Account> for icrc_ledger_types::icrc1::account::Account {
    type Error = String;

    fn try_from(account: pb::v1::Account) -> Result<Self, String> {
        let owner = *validate_required_field("owner", &account.owner)?;
        let subaccount: Option<icrc_ledger_types::icrc1::account::Subaccount> =
            match account.subaccount {
                Some(s) => match s.subaccount.as_slice().try_into() {
                    Ok(s) => Ok(Some(s)),
                    Err(_) => Err(format!(
                        "Invalid Subaccount length. Expected 32, found {}",
                        s.subaccount.len()
                    )),
                },
                None => Ok(None),
            }?;
        Ok(Self {
            owner: owner.0,
            subaccount,
        })
    }
}

impl From<icrc_ledger_types::icrc1::account::Account> for pb::v1::Account {
    fn from(account: icrc_ledger_types::icrc1::account::Account) -> Self {
        let maybe_subaccount_pb = account.subaccount.map(|subaccount| SubaccountProto {
            subaccount: subaccount.into(),
        });
        pb::v1::Account {
            owner: Some(account.owner.into()),
            subaccount: maybe_subaccount_pb,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Debug;

    pub fn assert_is_err<Ok, Err>(result: Result<Ok, Err>)
    where
        Ok: Debug,
        Err: Debug,
    {
        assert!(result.is_err(), "result: {result:?}");
    }

    pub fn assert_is_ok<Ok, Err>(result: Result<Ok, Err>)
    where
        Ok: Debug,
        Err: Debug,
    {
        assert!(result.is_ok(), "result: {result:?}");
    }

    #[test]
    fn test_validate_len() {
        let min = 1;
        let max = 5;
        let validate = |field_value| validate_len("field_name", field_value, min, max);

        assert_is_err(validate(&""));
        assert_is_err(validate(&"123456"));

        assert_is_ok(validate(&"a"));
        assert_is_ok(validate(&"ab"));
        assert_is_ok(validate(&"abc"));
        assert_is_ok(validate(&"abcde"));

        assert_is_err(validate(&"abcd\u{1F389}"));
        assert_eq!(
            validate(&"abcdefg"),
            Err(
                "The first 5 characters of the value in field `field_name` are too long \
                 (max = 5 vs. observed = 7): `abcde`"
                    .to_string()
            ),
        );
    }

    #[test]
    fn test_validate_chars_count() {
        let min = 1;
        let max = 5;
        let validate = |field_value| validate_chars_count("field_name", field_value, min, max);

        assert_is_err(validate(""));
        assert_is_err(validate("123456"));

        assert_is_ok(validate("a"));
        assert_is_ok(validate("ab"));
        assert_is_ok(validate("abc"));
        assert_is_ok(validate("abcd\u{1F389}"));
    }

    struct Widget {
        foo: Option<i32>,
    }

    #[test]
    fn test_validate_required_field_fail() {
        let widget = Widget { foo: None };
        let result: Result<&i32, String> = validate_required_field("foo", &widget.foo);
        match result {
            Ok(_) => panic!(
                "validate_required_field is supposed to return Err, \
                 but returned {result:?} instead."
            ),

            Err(err) => {
                assert!(err.contains("foo"), "err: {err:?}");
                assert!(err.contains("populated"), "err: {err:?}");
            }
        }
    }

    #[test]
    fn test_validate_required_field_success() {
        let widget = Widget { foo: Some(42) };
        let result: Result<&i32, String> = validate_required_field("foo", &widget.foo);
        match result {
            Err(_) => panic!(
                "validate_required_field is supposed to return Ok, \
                 but returned {result:?} instead."
            ),

            Ok(foo) => {
                let expected: &i32 = widget.foo.as_ref().unwrap();
                assert_eq!(foo, expected, "result: {result:?}");
                assert_eq!(*foo, 42, "result: {result:?}");
            }
        }
    }

    #[test]
    fn test_field_err() {
        let result = field_err("my_field", 41.to_string(), "not the meaning of life");
        match result {
            Ok(()) => panic!("field_err is supposed to always return an Err."),
            Err(err) => {
                assert!(err.contains("my_field"), "err: {err}");
                assert!(err.contains("41"), "err: {err}");
                assert!(err.contains("not the meaning of life"), "err: {err}");
            }
        }
    }

    #[test]
    fn test_giant_field_err() {
        let barely_not_too_large_len = 12_500;

        let run_test_for_value_of_size = |value_size| {
            let input_value: String = (0..value_size).map(|_| '🤝').collect();
            // Sanity check: We construct a string in which each character is encoded as 4 bytes.
            assert_eq!(input_value.len(), 4 * input_value.chars().count());
            let observer_err = field_err("field_name", input_value.clone(), "defect").unwrap_err();
            (input_value, observer_err)
        };

        // Value is (barely) not too large to be fully included in the defect description.
        {
            let (input_value, observer_err) = run_test_for_value_of_size(barely_not_too_large_len);
            assert!(observer_err.contains(&input_value));
        }

        // Value is too large to be fully included in the defect description.
        {
            let (input_value, observer_err) =
                run_test_for_value_of_size(barely_not_too_large_len + 1);
            assert!(
                !observer_err.contains(&input_value),
                "Expected ```{observer_err}``` not to contain ```{input_value}```."
            );
            // Only the last character was dropped.
            assert!(observer_err.contains(&input_value[..(input_value.chars().count() - 1)]));
        }
    }
}
