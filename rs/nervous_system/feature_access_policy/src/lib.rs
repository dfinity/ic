use std::fmt::Debug;
use std::{collections::HashSet, hash::Hash};

const ERROR_EMPTY_COLLECTION_ALLOW_ONLY: &str =
    "An empty collection of items sent to `allow_only`. Use `deny_all`.";
const ERROR_EMPTY_COLLECTION_DENY_ONLY: &str =
    "An empty collection of items sent to `deny_only`. Use `allow_all`.";

#[derive(Debug)]
pub struct FeatureAccessPolicy<T> {
    inner: FeatureAccessPolicyInner<T>,
}

#[derive(Debug)]
enum FeatureAccessPolicyInner<T> {
    AllowAll,
    AllowOnly(HashSet<T>),
    DenyAll,
    DenyOnly(HashSet<T>),
}

impl<T> FeatureAccessPolicy<T>
where
    T: Debug + Eq + Hash,
{
    pub fn allow_all() -> Self {
        Self {
            inner: FeatureAccessPolicyInner::AllowAll,
        }
    }

    pub fn deny_all() -> Self {
        Self {
            inner: FeatureAccessPolicyInner::DenyAll,
        }
    }

    /// Use only when sure that some items will be passed in the collection
    /// as the function will panic if it receives an empty collection.
    ///
    /// If you want the library to make a best effort guess, use `FeatureAccessPolicy::allow()`
    #[track_caller]
    pub fn allow_only<I: IntoIterator<Item = T>>(items: I) -> Self {
        let items: HashSet<T> = items.into_iter().collect();

        if items.is_empty() {
            panic!("{ERROR_EMPTY_COLLECTION_ALLOW_ONLY}");
        }

        Self {
            inner: FeatureAccessPolicyInner::AllowOnly(items),
        }
    }

    /// Use when unsure about the number of items in the collection.
    ///
    /// The library will try to make a best effort guess about what the
    /// code calling it expects it to do.
    ///
    /// If the collection doesn't contain any elements it will deem it
    /// as `DenyAll`.
    /// If the collection has some elements it will deem it as `AllowOnly`
    pub fn allow<I: IntoIterator<Item = T>>(items: I) -> Self {
        let items: HashSet<T> = items.into_iter().collect();

        if items.is_empty() {
            return Self {
                inner: FeatureAccessPolicyInner::DenyAll,
            };
        }

        Self {
            inner: FeatureAccessPolicyInner::AllowOnly(items),
        }
    }

    /// Use only when sure that some items will be passed in the collection
    /// as the function will panic if it receives an empty collection.
    ///
    /// If you want the library to make a best effort guess, use `FeatureAccessPolicy::deny()`
    #[track_caller]
    pub fn deny_only<I: IntoIterator<Item = T>>(items: I) -> Self {
        let items: HashSet<T> = items.into_iter().collect();

        if items.is_empty() {
            panic!("{ERROR_EMPTY_COLLECTION_DENY_ONLY}");
        }

        Self {
            inner: FeatureAccessPolicyInner::DenyOnly(items),
        }
    }

    /// Use when unsure about the number of items in the collection.
    ///
    /// The library will try to make a best effort guess about what the
    /// code calling it expects it to do.
    ///
    /// If the collection doesn't contain any elements it will deem it
    /// as `AllowAll`.
    /// If the collection has some elements it will deem it as `DenyOnly`
    pub fn deny<I: IntoIterator<Item = T>>(items: I) -> Self {
        let items: HashSet<T> = items.into_iter().collect();

        if items.is_empty() {
            return Self {
                inner: FeatureAccessPolicyInner::AllowAll,
            };
        }

        Self {
            inner: FeatureAccessPolicyInner::DenyOnly(items),
        }
    }

    pub fn is_allowed(&self, item: &T) -> bool {
        match &self.inner {
            FeatureAccessPolicyInner::AllowAll => true,
            FeatureAccessPolicyInner::AllowOnly(items) => items.contains(item),
            FeatureAccessPolicyInner::DenyAll => false,
            FeatureAccessPolicyInner::DenyOnly(items) => !items.contains(item),
        }
    }

    pub fn is_all_allowed(&self) -> bool {
        matches!(self.inner, FeatureAccessPolicyInner::AllowAll)
    }

    pub fn is_all_denied(&self) -> bool {
        matches!(self.inner, FeatureAccessPolicyInner::DenyAll)
    }
}

#[cfg(test)]
mod tests {
    use std::panic::UnwindSafe;

    use super::*;

    #[test]
    fn allow_all_works() {
        let policy: FeatureAccessPolicy<i32> = FeatureAccessPolicy::allow_all();

        assert!(policy.is_allowed(&1));
        assert!(policy.is_allowed(&42));
    }

    #[test]
    fn deny_all_works() {
        let policy: FeatureAccessPolicy<i32> = FeatureAccessPolicy::deny_all();

        assert!(!policy.is_allowed(&1));
        assert!(!policy.is_allowed(&42));
    }

    fn unwind_policy_creation_expecting_error(
        policy_creator: impl FnOnce() -> FeatureAccessPolicy<i32> + UnwindSafe,
        expect: &str,
    ) {
        let result = std::panic::catch_unwind(policy_creator);

        let err: Box<String> = result.unwrap_err().downcast().unwrap();

        assert_eq!(*err, expect);
    }

    #[test]
    fn allow_only_panics_with_proper_message() {
        unwind_policy_creation_expecting_error(
            || FeatureAccessPolicy::allow_only([]),
            ERROR_EMPTY_COLLECTION_ALLOW_ONLY,
        );
    }

    #[test]
    fn deny_only_panics_with_proper_message() {
        unwind_policy_creation_expecting_error(
            || FeatureAccessPolicy::deny_only([]),
            ERROR_EMPTY_COLLECTION_DENY_ONLY,
        );
    }

    #[test]
    fn allow_only_works() {
        let policy = FeatureAccessPolicy::allow_only([1, 42]);

        assert!(policy.is_allowed(&42));
        assert!(!policy.is_allowed(&999));
    }

    #[test]
    fn deny_only_works() {
        let policy = FeatureAccessPolicy::deny_only([1, 42]);

        assert!(!policy.is_allowed(&42));
        assert!(policy.is_allowed(&999));
    }

    #[test]
    fn allow_works() {
        // Allowing no one should be `DenyAll`
        let policy: FeatureAccessPolicy<i32> = FeatureAccessPolicy::allow([]);

        assert!(!policy.is_allowed(&1));
        assert!(!policy.is_allowed(&42));

        // Allowing some should be `AllowOnly`
        let policy = FeatureAccessPolicy::allow([1, 42]);

        assert!(policy.is_allowed(&42));
        assert!(!policy.is_allowed(&999));
    }

    #[test]
    fn deny_works() {
        // Denying no one should be `AllowAll`
        let policy: FeatureAccessPolicy<i32> = FeatureAccessPolicy::deny([]);

        assert!(policy.is_allowed(&1));
        assert!(policy.is_allowed(&42));

        // Denying some should be `DenyOnly`
        let policy = FeatureAccessPolicy::deny([1, 42]);

        assert!(!policy.is_allowed(&42));
        assert!(policy.is_allowed(&999));
    }

    #[test]
    fn is_all_allowed_works() {
        let policy: FeatureAccessPolicy<i32> = FeatureAccessPolicy::allow_all();

        assert!(policy.is_all_allowed());
        assert!(!policy.is_all_denied());

        let policy = FeatureAccessPolicy::allow_only([1, 42]);
        assert!(!policy.is_all_allowed());
        assert!(!policy.is_all_denied());
    }

    #[test]
    fn is_all_denied_works() {
        let policy: FeatureAccessPolicy<i32> = FeatureAccessPolicy::deny_all();
        assert!(policy.is_all_denied());
        assert!(!policy.is_all_allowed());

        let policy = FeatureAccessPolicy::deny_only([1, 42]);
        assert!(!policy.is_all_allowed());
        assert!(!policy.is_all_denied());
    }
}
