/// Newtypes that protect sensitive data (e.g. secret keys)
///
/// This crate provides the following features for these sensitive data:
/// - The underlying data are zeroed when the secret goes out of scope.
///   - This is best-effort, and any copies that exist, say during creation of
///     the secret or during serialization/deserialization, may need to be
///     cleared manually.
///   - Composite types holding a member of one of these secret types *may*
///     choose to implement the `Zeroize` trait, but this is not necessary (the
///     types in this crate will zeroize themselves when they go out of scope
///     regardless).
/// - The sensitive data can only be accessed via the `expose_secret` method,
///   which aids in auditing all accesses of the data.
/// - The sensitive data are redacted in any Debug logs.
///
/// Note that, because these types must clear their sensitive memory
/// via a `drop` method, these types *cannot* be `Copy`'d.
/// Instead, explicit `move`s must be used.
pub mod secret_array;
pub use secret_array::*;

#[cfg(test)]
mod tests;
