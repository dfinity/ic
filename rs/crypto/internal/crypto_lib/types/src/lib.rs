#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

//! Types that are used internally in the crypto component.
//!
//! The structure of internal types is as follows:
//!
//! The type for the external API (e.g. `EncryptionPublicKey`) is defined in the
//! types crate:
//! * It wraps a type (e.g. `CspEncryptionPublicKey`) that is defined in the
//!   internal-types crate. The type is wrapped as a private field called
//!   `internal`.
//! * This ensures that callers using the external API do not have access to the
//!   internal type (unless they imported crypto/internal-types in Cargo.toml,
//!   which is frowned upon).
//!
//! The type for the internal API (e.g. `CspEncryptionPublicKey`) is defined in
//! the internal-types crate:
//! * It wraps a type (e.g. `InternalCspEncryptionPublicKey`) that is defined in
//!   the same crate. The type is wrapped as a private field called `internal`.
//! * This makes it a bit harder to access the internal CSP type from the
//!   outside, as it would explicitly have to be imported (which is frowned
//!   upon).
//! * Note that the same pattern as for external types could be used for CSP
//!   types at a later point, so that accessing the internal CSP type would
//!   require an import in Cargo.toml.
pub mod curves;
pub mod encrypt;
pub mod scope;
pub mod serde_macro;
pub mod sign;

/// The index of a node.
pub type NodeIndex = u32;
