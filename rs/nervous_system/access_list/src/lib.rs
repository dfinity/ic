//! # Access List
//!
//! A flexible library for managing authorization through allowlists and denylists.
//!
//! ## Overview
//!
//! `AccessList<T>` provides a type-safe way to control access to features or resources
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
//! use ic_nervous_system_access_list::AccessList;
//!
//! // Allow everything
//! let policy = AccessList::<&str>::allow_all();
//! assert!(policy.is_allowed(&"any_feature"));
//!
//! // Deny everything
//! let policy = AccessList::<&str>::deny_all();
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
//! use ic_nervous_system_access_list::AccessList;
//!
//! // If features is empty, deny everything (safe default)
//! let features = vec!["read", "write"];
//! let policy = AccessList::allow(features);
//!
//! // Empty collection becomes deny-all
//! let empty: Vec<&str> = vec![];
//! let policy = AccessList::allow(empty);
//! assert!(policy.is_all_denied());
//!
//! // If blocked is empty, allow everything
//! let blocked: Vec<&str> = vec![];
//! let policy = AccessList::deny(blocked);
//! assert!(policy.is_all_allowed());
//! ```
//!
//! ## Checking Access
//!
//! ```rust
//! use ic_nervous_system_access_list::AccessList;
//!
//! let policy = AccessList::allow(vec!["read", "write"]);
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
//! use ic_nervous_system_access_list::AccessList;
//! use std::cell::RefCell;
//!
//! thread_local! {
//!     static CALLER_POLICY: RefCell<AccessList<&'static str>> = RefCell::new(
//!         AccessList::allow(
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
//! ## Performance
//!
//! - Item lookups are O(1) using `HashSet`
//! - Memory usage is O(n) where n is the number of explicitly listed items
//! - `AllowAll` and `DenyAll` policies use O(1) memory

use std::fmt::Debug;
use std::{collections::HashSet, hash::Hash};

#[derive(Debug)]
pub struct AccessList<T> {
    inner: AccessListInner<T>,
}

#[derive(Debug)]
enum AccessListInner<T> {
    AllowOnly(HashSet<T>),
    DenyOnly(HashSet<T>),
}

impl<T> AccessList<T>
where
    T: Debug + Eq + Hash,
{
    pub fn allow_all() -> Self {
        Self {
            inner: AccessListInner::DenyOnly(HashSet::new()),
        }
    }

    pub fn deny_all() -> Self {
        Self {
            inner: AccessListInner::AllowOnly(HashSet::new()),
        }
    }

    pub fn allow<I>(items: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        let items: HashSet<T> = items.into_iter().collect();

        Self {
            inner: AccessListInner::AllowOnly(items),
        }
    }

    pub fn deny<I>(items: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        let items: HashSet<T> = items.into_iter().collect();

        Self {
            inner: AccessListInner::DenyOnly(items),
        }
    }

    pub fn is_allowed(&self, item: &T) -> bool {
        match &self.inner {
            AccessListInner::AllowOnly(items) => items.contains(item),
            AccessListInner::DenyOnly(items) => !items.contains(item),
        }
    }

    pub fn is_all_allowed(&self) -> bool {
        if let AccessListInner::DenyOnly(items) = &self.inner
            && items.is_empty()
        {
            return true;
        }
        false
    }

    pub fn is_all_denied(&self) -> bool {
        if let AccessListInner::AllowOnly(items) = &self.inner
            && items.is_empty()
        {
            return true;
        }
        false
    }
}
