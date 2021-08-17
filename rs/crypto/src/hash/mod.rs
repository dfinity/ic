use ic_crypto_internal_types::context::{Context, DomainSeparationContext};
use ic_crypto_sha256::Sha256;
use ic_interfaces::crypto::CryptoHashable;
use ic_types::crypto::{CryptoHash, CryptoHashOf};

#[cfg(test)]
mod tests;

// tag::hash-interface[]
/// Creates a (typed) domain-separated cryptographic hash.
///
/// The bytes that are hashed are a combination of
/// * the byte representation of the hash domain obtained via `CryptoHashable`s
///   supertrait `CryptoHashDomain`
/// * the bytes fed to the hasher state via `CryptoHashable`s supertrait `Hash`
///
/// Note that the trait `CryptoHashDomain` is sealed for security reasons. To
/// implement this trait for a new struct that shall be cryptographically
/// hashed, contact the crypto team.
///
/// The (secure) hashing algorithm that is used internally is intentionally
/// unspecified because it may be subject to change across registry/protocol
/// versions. Use `Sha256` instead if the algorithm used for producing
/// the hash must not change across registry/protocol versions.
pub fn crypto_hash<T: CryptoHashable>(data: &T) -> CryptoHashOf<T> {
    let mut hash = Sha256::new();
    hash.write(DomainSeparationContext::new(data.domain()).as_bytes());
    data.hash(&mut hash);
    CryptoHashOf::new(CryptoHash(hash.finish().to_vec()))
}
// end::hash-interface[]
