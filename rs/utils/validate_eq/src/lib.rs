use std::collections::BTreeMap;
use std::fmt::Debug;

/// ValidateEq trait is indended to verify equality of vetted subset of fields
/// and reporting a path to divergence for logging if any.
///
/// Gigantic fields such as PageMaps that are unfeasible to compare in production are meant to
/// be exempted from comparison.

pub trait ValidateEq {
    fn validate_eq(&self, rhs: &Self) -> Result<(), String>;
}

impl<K, V> ValidateEq for BTreeMap<K, V>
where
    K: PartialEq + Debug,
    V: ValidateEq,
{
    fn validate_eq(&self, rhs: &Self) -> Result<(), String> {
        if self.len() != rhs.len() {
            return Err(format!(
                "Length divergence:\nlhs keys = {:#?}\nrhs keys = {:#?}",
                self.keys().collect::<Vec<_>>(),
                rhs.keys().collect::<Vec<_>>()
            ));
        }
        for (l, r) in self.iter().zip(rhs.iter()) {
            if l.0 != r.0 {
                return Err(format!(
                    "Key divergence:\nlhs = {:#?}\nrhs = {:#?}",
                    l.0, r.0
                ));
            }
            if let Err(err) = l.1.validate_eq(r.1) {
                return Err(format!("key={:#?}.{}", l.0, err));
            }
        }
        Ok(())
    }
}

impl<T> ValidateEq for Option<T>
where
    T: ValidateEq,
{
    fn validate_eq(&self, rhs: &Self) -> Result<(), String> {
        match (self.as_ref(), rhs.as_ref()) {
            (Some(..), None) => {
                Err("Comparing Option<_> failed; left is Some, right is None".to_string())
            }
            (None, Some(..)) => {
                Err("Comparing Option<_> failed; left is None, right is Some".to_string())
            }
            (Some(lhs), Some(rhs)) => lhs.validate_eq(rhs),
            (None, None) => Ok(()),
        }
    }
}

impl<T> ValidateEq for std::collections::VecDeque<T>
where
    T: ValidateEq,
{
    fn validate_eq(&self, rhs: &Self) -> Result<(), String> {
        if self.len() != rhs.len() {
            return Err(format!(
                "Length divergence; lhs={}, rhs={}",
                self.len(),
                rhs.len()
            ));
        }
        for (l, r) in self.iter().zip(rhs.iter()) {
            l.validate_eq(r)?;
        }
        Ok(())
    }
}

impl<T> ValidateEq for std::sync::Arc<T>
where
    T: ValidateEq,
{
    fn validate_eq(&self, rhs: &Self) -> Result<(), String> {
        use std::ops::Deref;
        self.deref().validate_eq(rhs.deref())
    }
}

impl<A, B> ValidateEq for (A, B)
where
    A: ValidateEq,
    B: ValidateEq,
{
    fn validate_eq(&self, rhs: &Self) -> Result<(), String> {
        self.0.validate_eq(&rhs.0)?;
        self.1.validate_eq(&rhs.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_validate_eq_derive::ValidateEq;

    #[derive(ValidateEq)]
    struct A {
        a: u64,
        #[allow(dead_code)]
        #[validate_eq(Ignore)]
        b: u64,
    }
    #[derive(ValidateEq)]
    struct C {
        #[validate_eq(CompareWithValidateEq)]
        a: A,
        c: u64,
    }

    #[test]
    fn test_derive() {
        assert!(A { a: 2, b: 2 }.validate_eq(&A { a: 2, b: 1 }).is_ok());
        assert!(A { a: 2, b: 2 }.validate_eq(&A { a: 1, b: 2 }).is_err());

        assert!(C {
            a: A { a: 2, b: 2 },
            c: 2
        }
        .validate_eq(&C {
            a: A { a: 2, b: 1 },
            c: 2
        })
        .is_ok());

        assert!(C {
            a: A { a: 2, b: 2 },
            c: 2
        }
        .validate_eq(&C {
            a: A { a: 1, b: 1 },
            c: 2
        })
        .is_err());
    }

    #[test]
    fn test_btreemap() {
        let mut map_0 = BTreeMap::from([
            (1u64, A { a: 1, b: 2 }),
            (2u64, A { a: 2, b: 2 }),
            (3u64, A { a: 3, b: 3 }),
        ]);
        let mut map_1 = BTreeMap::from([
            (1u64, A { a: 1, b: 2 }),
            (2u64, A { a: 2, b: 2 }),
            (3u64, A { a: 3, b: 10 }),
        ]);

        // b is ignored.
        assert!(map_0.validate_eq(&map_1).is_ok());

        // a is not ignored.
        map_0.get_mut(&3).unwrap().a = 4;
        assert!(map_0.validate_eq(&map_1).is_err());

        // Different lengths are an error.
        map_0.remove(&3);
        assert!(map_0.validate_eq(&map_1).is_err());

        map_1.remove(&3);
        assert!(map_0.validate_eq(&map_1).is_ok());

        // Different key value is an error.
        map_0.insert(3u64, A { a: 3, b: 2 });
        map_1.insert(4u64, A { a: 3, b: 2 });
        assert!(map_0.validate_eq(&map_1).is_err());
    }

    #[test]
    fn test_derive_generic() {
        // Should compile.
        #[derive(ValidateEq)]
        #[allow(dead_code)]
        struct A<T> {
            #[validate_eq(Ignore)]
            a: std::collections::VecDeque<T>,
            b: u64,
        }
    }
}
