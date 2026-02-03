#![allow(clippy::arc_with_non_send_sync)]
#[cfg(test)]
use assert_matches::assert_matches;
#[cfg(test)]
use candid::{Int, Nat, Principal};
use num_bigint::BigInt;
#[cfg(test)]
use std::collections::BTreeMap;
use std::{borrow::Cow, sync::Arc};

use super::generic_value::Value;

#[derive(Debug, Clone, PartialEq)]
pub enum ValuePredicateFailures {
    Failures(Vec<String>),
    And(Vec<ValuePredicateFailures>),
    Or(Vec<ValuePredicateFailures>),
    Item {
        key: String,
        failure: Box<ValuePredicateFailures>,
    },
}

impl ValuePredicateFailures {
    const INDENT: usize = 2;

    pub fn new(failure: impl Into<String>) -> Self {
        Self::Failures(vec![failure.into()])
    }

    pub fn item(key: impl Into<String>, failure: Self) -> Self {
        Self::Item {
            key: key.into(),
            failure: Box::new(failure),
        }
    }

    pub fn pretty_print(&self, f: &mut std::fmt::Formatter<'_>, indent: usize) -> std::fmt::Result {
        use ValuePredicateFailures::*;

        let sub_indent = indent + Self::INDENT;

        match self {
            Failures(failures) => {
                let mut first = true;
                for failure in failures {
                    writeln!(
                        f,
                        "{:width$}{} {}",
                        "",
                        if first { "*" } else { " " },
                        failure,
                        width = indent
                    )?;
                    if first {
                        first = false
                    }
                }
            }
            And(failures) => {
                writeln!(
                    f,
                    "{:width$}Expected all of the following validators to be successfull:",
                    "",
                    width = indent
                )?;
                for failure in failures {
                    failure.pretty_print(f, sub_indent)?;
                }
            }
            Or(failures) => {
                writeln!(
                    f,
                    "{:width$}Expected at least one of the following validators to be successfull:",
                    "",
                    width = indent
                )?;
                for failure in failures {
                    failure.pretty_print(f, sub_indent)?;
                }
            }
            Item { key, failure } => {
                writeln!(f, "{:width$}{}", "", key, width = indent)?;
                failure.pretty_print(f, sub_indent)?;
            }
        }
        Ok(())
    }
}

impl std::fmt::Display for ValuePredicateFailures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.pretty_print(f, 0)
    }
}

pub type ValuePredicate = Arc<dyn Fn(Cow<Value>) -> Result<(), ValuePredicateFailures>>;

pub fn is_blob() -> ValuePredicate {
    use ValuePredicateFailures as Fail;

    Arc::new(|v: Cow<Value>| match v.as_ref() {
        Value::Blob(_) => Ok(()),
        _ => Err(Fail::new("expected blob")),
    })
}

#[test]
fn test_is_blob() {
    for value in [
        Value::text("foobar"),
        Value::Int(Int::from(0)),
        Value::Nat(Nat::from(0_u8)),
        Value::Nat64(0),
        Value::Array(vec![]),
        Value::Map(BTreeMap::new()),
    ] {
        assert_matches!(is_blob()(Cow::Owned(value)), Err(_));
    }

    assert_eq!(is_blob()(Cow::Owned(Value::blob(vec![]))), Ok(()));
}

pub fn is_text() -> ValuePredicate {
    use ValuePredicateFailures as Fail;

    Arc::new(|v: Cow<Value>| match v.as_ref() {
        Value::Text(_) => Ok(()),
        _ => Err(Fail::new("expected text")),
    })
}

#[test]
fn test_is_text() {
    for value in [
        Value::blob(vec![]),
        Value::Int(Int::from(0)),
        Value::Nat(Nat::from(0_u8)),
        Value::Nat64(0),
        Value::Array(vec![]),
        Value::Map(BTreeMap::new()),
    ] {
        let res = is_text()(Cow::Owned(value.clone()));
        assert_matches!(res, Err(_), "{}", value);
    }
    assert_eq!(is_text()(Cow::Owned(Value::text("foobar"))), Ok(()));
}

pub fn is_nat() -> ValuePredicate {
    use ValuePredicateFailures as Fail;

    Arc::new(|v: Cow<Value>| match v.as_ref() {
        Value::Nat(_) => Ok(()),
        _ => Err(Fail::new("expected nat")),
    })
}

#[test]
fn test_is_nat() {
    for value in [
        Value::blob(vec![]),
        Value::Int(Int::from(0)),
        Value::text("foobar"),
        Value::Nat64(0),
        Value::Array(vec![]),
        Value::Map(BTreeMap::new()),
    ] {
        let res = is_nat()(Cow::Owned(value.clone()));
        assert_matches!(res, Err(_), "{}", value);
    }
    assert_eq!(is_nat()(Cow::Owned(Value::Nat(Nat::from(0_u8)))), Ok(()));
}

pub fn is_nat64() -> ValuePredicate {
    use ValuePredicateFailures as Fail;

    Arc::new(|v: Cow<Value>| match v.as_ref() {
        Value::Nat64(_) => Ok(()),
        _ => Err(Fail::new("expected nat64")),
    })
}

#[test]
fn test_is_nat64() {
    for value in [
        Value::blob(vec![]),
        Value::Int(Int::from(0)),
        Value::text("foobar"),
        Value::Nat(Nat::from(0_u8)),
        Value::Array(vec![]),
        Value::Map(BTreeMap::new()),
    ] {
        let res = is_nat64()(Cow::Owned(value.clone()));
        assert_matches!(res, Err(_), "{}", value);
    }
    assert_eq!(is_nat64()(Cow::Owned(Value::Nat64(0))), Ok(()));
}

pub fn is_int() -> ValuePredicate {
    use ValuePredicateFailures as Fail;

    Arc::new(|v: Cow<Value>| match v.as_ref() {
        Value::Int(_) => Ok(()),
        _ => Err(Fail::new("expected int")),
    })
}

#[test]
fn test_is_int() {
    for value in [
        Value::blob(vec![]),
        Value::Nat64(0),
        Value::text("foobar"),
        Value::Nat(Nat::from(0_u8)),
        Value::Array(vec![]),
        Value::Map(BTreeMap::new()),
    ] {
        let res = is_int()(Cow::Owned(value.clone()));
        assert_matches!(res, Err(_), "{}", value);
    }
    assert_eq!(is_int()(Cow::Owned(Value::Int(Int::from(0)))), Ok(()));
}

pub fn is_array() -> ValuePredicate {
    use ValuePredicateFailures as Fail;

    Arc::new(|v: Cow<Value>| match v.as_ref() {
        Value::Array(_) => Ok(()),
        _ => Err(Fail::new("expected array")),
    })
}

#[test]
fn test_is_array() {
    for value in [
        Value::blob(vec![]),
        Value::Nat64(0),
        Value::text("foobar"),
        Value::Nat(Nat::from(0_u8)),
        Value::Int(Int::from(0)),
        Value::Map(BTreeMap::new()),
    ] {
        let res = is_array()(Cow::Owned(value.clone()));
        assert_matches!(res, Err(_), "{}", value);
    }
    assert_eq!(is_array()(Cow::Owned(Value::Array(vec![]))), Ok(()));
}

pub fn is_map() -> ValuePredicate {
    use ValuePredicateFailures as Fail;

    Arc::new(|v: Cow<Value>| match v.as_ref() {
        Value::Map(_) => Ok(()),
        _ => Err(Fail::new("expected map")),
    })
}

#[test]
fn test_is_map() {
    for value in [
        Value::blob(vec![]),
        Value::Nat64(0),
        Value::text("foobar"),
        Value::Nat(Nat::from(0_u8)),
        Value::Int(Int::from(0)),
        Value::Array(vec![]),
    ] {
        let res = is_map()(Cow::Owned(value.clone()));
        assert_matches!(res, Err(_), "{}", value);
    }
    assert_eq!(is_map()(Cow::Owned(Value::Map(BTreeMap::new()))), Ok(()));
}

pub fn is(expected: Value) -> ValuePredicate {
    use ValuePredicateFailures as Fail;

    Arc::new(move |v: Cow<Value>| {
        if v.as_ref() == &expected {
            Ok(())
        } else {
            Err(Fail::new(format!("expected {expected}")))
        }
    })
}

pub fn is_not(value: Value) -> ValuePredicate {
    use ValuePredicateFailures as Fail;

    Arc::new(move |v: Cow<Value>| {
        if v.as_ref() == &value {
            Err(Fail::new(format!("should not be {value}")))
        } else {
            Ok(())
        }
    })
}

fn value_to_num(v: Value) -> Option<BigInt> {
    match v {
        Value::Blob(_) | Value::Text(_) | Value::Array(_) | Value::Map(_) => None,
        Value::Nat(n) => Some(n.0.into()),
        Value::Nat64(n) => Some(n.into()),
        Value::Int(i) => Some(i.0),
    }
}

pub fn is_equal_to(n: impl Into<BigInt>) -> ValuePredicate {
    use ValuePredicateFailures as Fail;

    let n: BigInt = n.into();
    Arc::new(move |v: Cow<Value>| match value_to_num(v.into_owned()) {
        None => Err(Fail::new(format!("expected a number to check for = {n}"))),
        Some(num) if num != n => Err(Fail::new(format!("the number {num} is not = {n}"))),
        Some(_) => Ok(()),
    })
}

pub fn is_more_than(n: impl Into<BigInt>) -> ValuePredicate {
    use ValuePredicateFailures as Fail;

    let n: BigInt = n.into();
    Arc::new(move |v: Cow<Value>| match value_to_num(v.into_owned()) {
        None => Err(Fail::new(format!("expected a number to check for > {n}"))),
        Some(num) if num <= n => Err(Fail::new(format!("the number {num} is not > {n}"))),
        Some(_) => Ok(()),
    })
}

pub fn is_less_than(n: impl Into<BigInt>) -> ValuePredicate {
    use ValuePredicateFailures as Fail;

    let n: BigInt = n.into();
    Arc::new(move |v: Cow<Value>| match value_to_num(v.into_owned()) {
        None => Err(Fail::new(format!("expected a number to check for < {n}"))),
        Some(num) if num >= n => Err(Fail::new(format!("the number {num} is not < {n}"))),
        Some(_) => Ok(()),
    })
}

pub fn is_more_or_equal_to(n: impl Into<BigInt> + Clone) -> ValuePredicate {
    or(vec![is_equal_to(n.clone()), is_more_than(n)])
}

pub fn is_less_or_equal_to(n: impl Into<BigInt> + Clone) -> ValuePredicate {
    or(vec![is_equal_to(n.clone()), is_less_than(n)])
}

pub fn len(p: ValuePredicate) -> ValuePredicate {
    use ValuePredicateFailures as Fail;

    Arc::new(move |v: Cow<Value>| {
        let len = match v.as_ref() {
            Value::Nat(_) | Value::Nat64(_) | Value::Int(_) => {
                return Err(Fail::new(
                    "expected a collection (blob, text, array or map)",
                ));
            }
            Value::Blob(bs) => Value::Nat64(bs.len() as u64),
            Value::Text(s) => Value::Nat64(s.len() as u64),
            Value::Array(array) => Value::Nat64(array.len() as u64),
            Value::Map(map) => Value::Nat64(map.len() as u64),
        };
        p(Cow::Owned(len))
    })
}

pub fn element(idx: usize, p: ValuePredicate) -> ValuePredicate {
    use ValuePredicateFailures as Fail;

    Arc::new(move |v: Cow<Value>| match v.as_ref() {
        Value::Nat(_) | Value::Nat64(_) | Value::Int(_) | Value::Map(_) => Err(Fail::new(
            "expected an indexed collection (blob, text or array)",
        )),
        Value::Blob(bs) => match bs.get(idx) {
            Some(b) => {
                p(Cow::Owned(Value::Nat64(*b as u64))).map_err(|f| Fail::item(idx.to_string(), f))
            }
            None => Err(Fail::new(format!(
                "index {idx} is out of bounds for the given blob"
            ))),
        },
        Value::Text(s) => match s.chars().nth(idx) {
            Some(subs) => {
                p(Cow::Owned(Value::text(subs))).map_err(|f| Fail::item(idx.to_string(), f))
            }
            None => Err(Fail::new(format!(
                "index {idx} is out of bounds for the given string"
            ))),
        },
        Value::Array(array) => match array.get(idx) {
            Some(e) => p(Cow::Borrowed(e)).map_err(|f| Fail::item(idx.to_string(), f)),
            None => Err(Fail::new(format!(
                "index {idx} is out of bounds for the given array"
            ))),
        },
    })
}

pub fn is_principal() -> ValuePredicate {
    and(vec![is_blob(), len(is_less_or_equal_to(29))])
}

#[test]
fn test_is_principal() {
    for value in [
        Value::text("foobar"),
        Value::Int(Int::from(0)),
        Value::Nat(Nat::from(0_u8)),
        Value::Nat64(0),
        Value::Array(vec![]),
        Value::Map(BTreeMap::new()),
    ] {
        assert_matches!(is_principal()(Cow::Owned(value)), Err(_));
    }

    for len in 0..Principal::MAX_LENGTH_IN_BYTES + 1 {
        assert_eq!(
            is_principal()(Cow::Owned(Value::blob(vec![0u8; len]))),
            Ok(())
        );
    }
    assert_matches!(
        is_principal()(Cow::Owned(Value::blob(vec![
            0u8;
            Principal::MAX_LENGTH_IN_BYTES
                + 1
        ]))),
        Err(_)
    );
}

pub fn is_subaccount() -> ValuePredicate {
    and(vec![is_blob(), len(is_equal_to(32))])
}

#[test]
fn test_is_subaccount() {
    for value in [
        Value::text("foobar"),
        Value::Int(Int::from(0)),
        Value::Nat(Nat::from(0_u8)),
        Value::Nat64(0),
        Value::Array(vec![]),
        Value::Map(BTreeMap::new()),
    ] {
        assert_matches!(is_principal()(Cow::Owned(value)), Err(_));
    }

    for len in 31..34 {
        if len == 32 {
            assert_eq!(
                is_subaccount()(Cow::Owned(Value::blob(vec![0u8; len]))),
                Ok(())
            );
        } else {
            assert_matches!(
                is_subaccount()(Cow::Owned(Value::blob(vec![0u8; len]))),
                Err(_)
            );
        }
    }
}

pub fn is_account() -> ValuePredicate {
    and(vec![
        is_array(),
        element(0, is_principal()),
        or(vec![
            len(is_equal_to(1)),
            and(vec![len(is_equal_to(2)), element(1, is_subaccount())]),
        ]),
    ])
}

#[test]
fn test_is_account() {
    for value in [
        Value::text("foobar"),
        Value::Int(Int::from(0)),
        Value::Nat(Nat::from(0_u8)),
        Value::Nat64(0),
        Value::blob(vec![]),
        Value::Map(BTreeMap::new()),
    ] {
        assert_matches!(is_account()(Cow::Owned(value)), Err(_));
    }
    // empty array
    assert_matches!(is_account()(Cow::Owned(Value::Array(vec![]))), Err(_));
    // wrong types
    assert_matches!(
        is_account()(Cow::Owned(Value::Array(vec![
            Value::text("foobar"),
            Value::Int(Int::from(0))
        ]))),
        Err(_)
    );
    let principal = Value::blob([1u8; 20]);
    let subaccount = Value::blob([1u8; 32]);
    // wrong order
    assert_matches!(
        is_account()(Cow::Owned(Value::Array(vec![
            subaccount.clone(),
            principal.clone()
        ]))),
        Err(_)
    );
    // only subaccount
    assert_matches!(
        is_account()(Cow::Owned(Value::Array(vec![subaccount.clone()]))),
        Err(_)
    );
    // 2 subaccounts
    assert_matches!(
        is_account()(Cow::Owned(Value::Array(vec![
            principal.clone(),
            subaccount.clone(),
            subaccount.clone()
        ]))),
        Err(_)
    );
    // only principal
    assert_matches!(
        is_account()(Cow::Owned(Value::Array(vec![principal.clone()]))),
        Ok(())
    );
    // principal and subaccount
    assert_matches!(
        is_account()(Cow::Owned(Value::Array(vec![principal, subaccount]))),
        Ok(())
    );
}

#[derive(Clone, Debug, PartialEq)]
pub enum ItemRequirement {
    Required,
    Optional,
}

pub fn item(key: &'static str, requirement: ItemRequirement, p: ValuePredicate) -> ValuePredicate {
    use ItemRequirement::*;
    use ValuePredicateFailures as Fail;

    Arc::new(move |v: Cow<Value>| match v.as_ref() {
        Value::Map(map) => match map.get(key) {
            Some(value) => p(Cow::Borrowed(value)).map_err(|f| Fail::item(key, f)),
            None if requirement == Required => {
                Err(Fail::item(key, Fail::new("key not found in map")))
            }
            _ => Ok(()),
        },
        _ => Err(Fail::new("expected a map")),
    })
}

#[test]
fn test_item() {
    use ItemRequirement::*;

    let value = Value::map([("foo", Value::Nat64(0))]);

    // key doesn't exist
    let validator = item("foo", Required, is(Value::Nat64(1)));
    assert_matches!(validator(Cow::Borrowed(&value)), Err(_));

    // wrong predicate
    let validator = item("foo", Required, is(Value::Nat64(1)));
    assert_matches!(validator(Cow::Borrowed(&value)), Err(_));

    // valid predicate
    let validator = item("foo", Required, is(Value::Nat64(0)));
    assert_matches!(validator(Cow::Borrowed(&value)), Ok(_));
}

pub fn and(vps: Vec<ValuePredicate>) -> ValuePredicate {
    use ValuePredicateFailures as Fail;

    Arc::new(move |v: Cow<Value>| {
        let mut failures = vec![];
        for vp in &vps {
            match vp(v.clone()) {
                Err(Fail::And(curr_failures)) => failures.extend(curr_failures),
                Err(curr_failure) => failures.push(curr_failure),
                _ => {}
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(Fail::And(failures))
        }
    })
}

pub fn or(vps: Vec<ValuePredicate>) -> ValuePredicate {
    use ValuePredicateFailures as Fail;

    if vps.is_empty() {
        return Arc::new(move |_: Cow<Value>| {
            Err(Fail::new("Empty or is always false, this is likely a bug"))
        });
    }

    Arc::new(move |v: Cow<Value>| {
        let mut failures = vec![];
        for vp in &vps {
            match vp(v.clone()) {
                Err(Fail::Or(curr_failures)) => failures.extend(curr_failures),
                Err(curr_failure) => failures.push(curr_failure),
                _ => return Ok(()),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(Fail::Or(failures))
        }
    })
}
