//! # Feature Access Policy
//!
//! A flexible library for managing feature access control through allowlists and denylists.
//!
//! ## Overview
//!
//! `FeatureAccessPolicy<T>` provides a type-safe way to control access to features or resources
//! using four distinct policy modes:
//!
//! - **Allow All**: Permits access to everything (open by default)
//! - **Allow Only**: Permits access only to explicitly listed items (allowlist/whitelist)
//! - **Deny All**: Denies access to everything (closed by default)
//! - **Deny Only**: Denies access only to explicitly listed items (denylist/blacklist)
//!
//! ## Creating Policies
//!
//! ### Explicit Policies
//!
//! Use these when you want to explicitly set a policy without any items:
//!
//! ```rust
//! use ic_nervous_system_access_list::FeatureAccessPolicy;
//!
//! // Allow everything
//! let policy = FeatureAccessPolicy::<&str>::allow_all();
//! assert!(policy.is_allowed(&"any_feature"));
//!
//! // Deny everything
//! let policy = FeatureAccessPolicy::<&str>::deny_all();
//! assert!(!policy.is_allowed(&"any_feature"));
//! ```
//!
//! ### Lenient Policies (Best-Effort)
//!
//! Use `allow()` and `deny()` when the collection size is uncertain or might be empty.
//! These methods make a best-effort guess about intent:
//!
//! - `allow()` with empty collection → `DenyAll` (conservative: nothing allowed)
//! - `deny()` with empty collection → `AllowAll` (permissive: nothing denied)
//!
//! ```rust
//! use ic_nervous_system_access_list::FeatureAccessPolicy;
//!
//! // If features is empty, deny everything (safe default)
//! let features = vec!["read", "write"];
//! let policy = FeatureAccessPolicy::allow(features);
//!
//! // Empty collection becomes deny-all
//! let empty: Vec<&str> = vec![];
//! let policy = FeatureAccessPolicy::allow(empty);
//! assert!(policy.is_all_denied());
//!
//! // If blocked is empty, allow everything
//! let blocked: Vec<&str> = vec![];
//! let policy = FeatureAccessPolicy::deny(blocked);
//! assert!(policy.is_all_allowed());
//! ```
//!
//! ## Checking Access
//!
//! ```rust
//! use ic_nervous_system_access_list::FeatureAccessPolicy;
//!
//! let policy = FeatureAccessPolicy::allow(vec!["read", "write"]);
//!
//! // Check individual items
//! if policy.is_allowed(&"read") {
//!     // Grant access
//! }
//!
//! // Check policy type
//! assert!(!policy.is_all_allowed());
//! assert!(!policy.is_all_denied());
//! ```
//!
//! ## Common Use Cases
//!
//! ### Feature Flags
//!
//! ```rust
//! use ic_nervous_system_access_list::FeatureAccessPolicy;
//! use std::cell::RefCell;
//!
//! thread_local! {
//!     static CALLER_POLICY: RefCell<FeatureAccessPolicy<&'static str>> = RefCell::new(
//!         FeatureAccessPolicy::allow(
//!             [
//!                 "maiwj-n4dkq-rojw2-sujtw-otasa-qystf-dycvm-ckccf-3w75k-ar24y-czw",
//!                 "tvpnz-xwmg5-42fpu-gbq54-hpxom-al3sk-fmp54-kzxlk-5a62i-i3y6r-dig",
//!                 "2cv6d-25re4-tbbjg-burlp-lxrvj-3ros7-6d5tn-r2h7b-ihv5c-ptm7w-7gi",
//!                 "2stme-neaks-e73td-xcn3m-yyj2g-chvim-i4get-6irx5-fhfxe-joaa6-2iw",
//!             ]
//!         )
//!     );
//! }
//!
//! pub(crate) fn is_caller_allowed(caller: &str) -> bool {
//!    CALLER_POLICY.with_borrow(|policy| policy.is_allowed(&caller))
//! }
//! ```
//!
//! ## Design Decisions
//!
//! ### Why does empty allowlist become deny-all?
//!
//! An empty allowlist means "nothing is explicitly allowed", which semantically means
//! "deny everything". This is the conservative, secure default.
//!
//! ### Why does empty denylist become allow-all?
//!
//! An empty denylist means "nothing is explicitly denied", which semantically means
//! "allow everything". This is the permissive default when no restrictions are specified.
//!
//! ## Performance
//!
//! - Item lookups are O(1) using `HashSet`
//! - Memory usage is O(n) where n is the number of explicitly listed items
//! - `AllowAll` and `DenyAll` policies use O(1) memory

use std::fmt::Debug;
use std::{collections::HashSet, hash::Hash};

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
