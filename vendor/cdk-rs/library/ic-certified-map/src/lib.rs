//! This package provides a map backed by a Merkle tree that can be used
//! by Internet Computer canisters to implement certified queries.
//!
//! You can certify your data by using the [`RbTree`] type as a map of
//! known names to the values you want certified. After you record its
//! [`root_hash`](RbTree::root_hash) into your canister's [certified data],
//! query calls can access a [data certificate] proving that the IC certified
//! the hash, under the [path] `/canister/<canister id>/certified_data`.
//! By providing this certificate, as well as a [`witness`](RbTree::witness)
//! that the value exists in the hash, you can then prove to the caller that
//! the IC certified the data.
//!
//! [certified data]: https://docs.rs/ic-cdk/latest/ic_cdk/api/fn.set_certified_data.html
//! [data certificate]: https://docs.rs/ic-cdk/latest/ic_cdk/api/fn.data_certificate.html
//! [path]: https://internetcomputer.org/docs/current/references/ic-interface-spec#state-tree
//!
//! # Example
//!
//! ```
//! # use std::cell::*;
//! # use ic_cdk::*;
//! # use ic_certified_map::*;
//! # use candid::CandidType;
//! # use serde::Serialize;
//!
//! thread_local! {
//!     static COUNTER: Cell<i32> = Cell::new(0);
//!     static TREE: RefCell<RbTree<&'static str, Hash>> = RefCell::new(RbTree::new());
//! }
//!
//! #[update]
//! fn inc() {
//!     let count = COUNTER.with(|counter| {
//!         let count = counter.get() + 1;
//!         counter.set(count);
//!         count
//!     });
//!     TREE.with(|tree| {
//!         let mut tree = tree.borrow_mut();
//!         tree.insert("counter", leaf_hash(&count.to_be_bytes()));
//!         ic_cdk::api::set_certified_data(&tree.root_hash());
//!     })
//! }
//!
//! #[derive(CandidType)]
//! struct CertifiedCounter {
//!     count: i32,
//!     certificate: Vec<u8>,
//!     witness: Vec<u8>,
//! }
//!
//! #[query]
//! fn get() -> CertifiedCounter {
//!     let certificate = ic_cdk::api::data_certificate().expect("No data certificate available");
//!     let witness = TREE.with(|tree| {
//!         let tree = tree.borrow();
//!         let mut witness = vec![];
//!         let mut witness_serializer = serde_cbor::Serializer::new(&mut witness);
//!         witness_serializer.self_describe();
//!         tree.witness(b"counter").serialize(&mut witness_serializer).unwrap();
//!         witness
//!     });
//!     let count = COUNTER.with(|counter| counter.get());
//!     CertifiedCounter {
//!         count,
//!         certificate,
//!         witness,
//!     }
//! }
//! ```

#![warn(
    elided_lifetimes_in_paths,
    missing_debug_implementations,
    missing_docs,
    unsafe_op_in_unsafe_fn,
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc
)]

mod hashtree;
mod rbtree;

pub use crate::hashtree::*;
pub use crate::rbtree::*;
