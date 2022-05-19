pub mod canister_control;
pub mod governance;
pub mod init;
pub mod neuron;
pub mod pb;
pub mod proposal;
mod reward;
pub mod types;

use std::fmt::Debug;

trait Len {
    fn len(&self) -> usize;
}

/// Warning: the len method on str and String is in bytes, not characters. If
/// you want to constrain the number of characters, look at
/// validate_chars_count.
fn validate_len<V>(field_name: &str, field_value: &V, min: usize, max: usize) -> Result<(), String>
where
    V: Len + Debug,
{
    let len = field_value.len();

    if len < min {
        return field_err(
            field_name,
            field_value,
            &format!("too short (min = {} vs. observed = {})", min, len),
        );
    }

    if len > max {
        return field_err(
            field_name,
            field_value,
            &format!("too long (min = {} vs. observed = {})", min, len),
        );
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
        return field_err(
            field_name,
            field_value,
            &format!("too short (min = {} vs. observed = {})", min, len),
        );
    }

    if len > max {
        return field_err(
            field_name,
            field_value,
            &format!("too long (max = {} vs. observed = {})", max, len),
        );
    }

    Ok(())
}

fn validate_required_field<'a, Inner>(
    field_name: &str,
    field_value: &'a Option<Inner>,
) -> Result<&'a Inner, String> {
    field_value
        .as_ref()
        .ok_or_else(|| format!("The {} field must be populated.", field_name))
}

/// Return an Err whose inner value describes (in detail) what is wrong with a
/// field value, and where within some (Protocol Buffers message) struct.
fn field_err(field_name: &str, field_value: impl Debug, defect: &str) -> Result<(), String> {
    Err(format!(
        "The value in field {} is {}: {:?}",
        field_name, defect, field_value
    ))
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
        assert!(result.is_err(), "result: {:?}", result);
    }

    pub fn assert_is_ok<Ok, Err>(result: Result<Ok, Err>)
    where
        Ok: Debug,
        Err: Debug,
    {
        assert!(result.is_ok(), "result: {:?}", result);
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
                 but returned {:?} instead.",
                result
            ),

            Err(err) => {
                assert!(err.contains("foo"), "err: {:?}", err);
                assert!(err.contains("populated"), "err: {:?}", err);
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
                 but returned {:?} instead.",
                result
            ),

            Ok(foo) => {
                let expected: &i32 = widget.foo.as_ref().unwrap();
                assert_eq!(foo, expected, "result: {:?}", result);
                assert_eq!(*foo, 42, "result: {:?}", result);
            }
        }
    }

    #[test]
    fn test_field_err() {
        let result = field_err("my_field", 41, "not the meaning of life");
        match result {
            Ok(()) => panic!("field_err is supposed to always return an Err."),
            Err(err) => {
                assert!(err.contains("my_field"), "err: {}", err);
                assert!(err.contains("41"), "err: {}", err);
                assert!(err.contains("not the meaning of life"), "err: {}", err);
            }
        }
    }
}
