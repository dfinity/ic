//! Hashing to group elements (fields, curves)
use crate::utils::{curve_order, RAND_ChaCha20};
use ic_crypto_internal_bls12381_common::{hash_to_miracl_g1, MiraclG1};
use ic_crypto_internal_bls12381_serde_miracl::{
    miracl_fr_to_bytes, miracl_g1_to_bytes, miracl_g2_to_bytes,
};
use ic_crypto_sha::{Context, DomainSeparationContext, Sha256};
use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::ecp::ECP;
use miracl_core::bls12381::ecp2::ECP2;
use std::collections::BTreeMap;

#[cfg(test)]
mod tests;

const DOMAIN_RO_INT: &str = "ic-random-oracle-integer";
const DOMAIN_RO_STRING: &str = "ic-random-oracle-string";
const DOMAIN_RO_SCALAR_ELEMENT: &str = "ic-random-oracle-bls12381-scalar";
const DOMAIN_RO_ECP_POINT: &str = "ic-random-oracle-bls12381-g1";
const DOMAIN_RO_ECP2_POINT: &str = "ic-random-oracle-bls12381-g2";
const DOMAIN_RO_BYTE_ARRAY: &str = "ic-random-oracle-byte-array";
const DOMAIN_RO_MAP: &str = "ic-random-oracle-map";
const DOMAIN_RO_VECTOR: &str = "ic-random-oracle-vector";

/// Initializes an hasher with a DomainSeparationContext string.
fn new_hasher_with_domain(domain: &str) -> Sha256 {
    Sha256::new_with_context(&DomainSeparationContext::new(domain))
}

/// Hashes the unique encoding of some structured data. Each data type uses a
/// distinct domain separator.
pub trait UniqueHash {
    fn unique_hash(&self) -> [u8; 32];
}

/// Computes the unique digest of a string.
///
/// The digest is the hash of the domain separator appended with the UTF-8
/// encoding of a string.
impl UniqueHash for String {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_STRING);
        hasher.write(&self.as_bytes());
        hasher.finish()
    }
}

/// Computes the unique digest of an integer.
///
/// The digest is the hash of the domain separator appended with the big-endian
/// encoding of the byte representation of the integer.
impl UniqueHash for usize {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_INT);
        hasher.write(&self.to_be_bytes());
        hasher.finish()
    }
}

/// Computes the unique digest of a byte vector.
///
/// The digest is the hash of the domain separator appended with the bytes in
/// the vector.
impl UniqueHash for Vec<u8> {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_BYTE_ARRAY);
        hasher.write(&self);
        hasher.finish()
    }
}

/// Computes the unique digest of an element in the scalar field of the
/// curve BLS12_381.
///
/// The scalar is reduced modulo the order of the group and serialized in 32
/// bytes using big-endian order. The digest is the hash of the domain separator
/// appended with the serialization of the scalar.
impl UniqueHash for BIG {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_SCALAR_ELEMENT);
        hasher.write(&miracl_fr_to_bytes(self).0);
        hasher.finish()
    }
}

/// Computes the unique digest of a group element in G1 of the BLS12_381 curve.
///
/// The group element is serialized according to the IETF draft of BLS signatures: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/?include_text=1
/// The digest is the hash of the domain separator appended with the
/// serialization of the group element.
impl UniqueHash for ECP {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_ECP_POINT);
        hasher.write(&miracl_g1_to_bytes(self).0);
        hasher.finish()
    }
}

/// Computes the unique digest of a group element in G2 of the BLS12_381 curve.
///
/// The group element is serialized according to the IETF draft of BLS signatures: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/?include_text=1
/// The digest is the hash of the domain separator appended with the
/// serialization of the group element.
impl UniqueHash for ECP2 {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_ECP2_POINT);
        hasher.write(&miracl_g2_to_bytes(self).0);
        hasher.finish()
    }
}

/// Computes the unique digest of a vector.
///
/// The digest is the hash of the domain separator concatenated with the unique
/// digests of the entries in the vector.
impl<T: UniqueHash> UniqueHash for Vec<T> {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_VECTOR);
        for item in self.iter() {
            hasher.write(&item.unique_hash())
        }
        hasher.finish()
    }
}

impl UniqueHash for Box<dyn UniqueHash> {
    fn unique_hash(&self) -> [u8; 32] {
        (**self).unique_hash()
    }
}

/// Computes the unique digest of a vector with entries of different types.
impl UniqueHash for Vec<&dyn UniqueHash> {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_VECTOR);
        for item in self.iter() {
            hasher.write(&item.unique_hash())
        }
        hasher.finish()
    }
}

/// Ordered map with elements that can be uniquely hashed.
pub type HashableMap = BTreeMap<String, Box<dyn UniqueHash>>;

/// Computes the unique digest of a map.
///
/// For each entry, it computes the concatenation of the unique digest of the
/// key with the unique digest of the value. The concatenated key-value hashes
/// are then sorted and concatenated. The digest is the hash of the domain
/// separator concatenated with the sorted concatenations.
impl UniqueHash for HashableMap {
    fn unique_hash(&self) -> [u8; 32] {
        let hashed_map = HashedMap::from(self);
        hashed_map.unique_hash()
    }
}

/// Ordered map storing the unique digests of values using unique digests as the
/// keys.
///
/// It is used to store the digests of key-value pairs of an HashableMap.
pub struct HashedMap(pub BTreeMap<[u8; 32], [u8; 32]>);

impl Default for HashedMap {
    fn default() -> Self {
        Self::new()
    }
}

impl HashedMap {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Inserts the digest of `value` using the digest of `key` as the key.
    ///
    /// If the digest of the key is not in the map, it returns None.
    /// Otherwise, it updates the hashed value and returns the old digest.
    pub fn insert_hashed<S: ToString, T: UniqueHash>(
        &mut self,
        key: S,
        value: &T,
    ) -> Option<[u8; 32]> {
        self.0
            .insert(key.to_string().unique_hash(), value.unique_hash())
    }
}

impl From<&HashableMap> for HashedMap {
    /// Computes the hash of the key-value pairs in an HashableMap and stores
    /// them in an HashedMap.
    fn from(hashable_map: &HashableMap) -> HashedMap {
        let mut map = HashedMap::new();
        for (key, value) in hashable_map {
            map.insert_hashed(key.clone(), value);
        }
        map
    }
}

/// Computes the domain separated hash of an HashedMap.
///
/// The digest is the hash of the domain separator concatenated with the sorted
/// key-value pairs. Note: keys and values in an HashedMap are digests.
impl UniqueHash for HashedMap {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_MAP);
        // This iterates over the entries of a map sorted by key.
        for (hashed_key, hashed_value) in self.0.iter() {
            hasher.write(hashed_key);
            hasher.write(hashed_value)
        }
        hasher.finish()
    }
}

/// Computes the hash of a struct using an hash function that can be modelled as
/// a random oracle.
///
/// The digest is the hash of `domain` appended with the unique digest of
/// `data`. A distinct `domain` should be used for each purpose of the random
/// oracle.
pub fn random_oracle(domain: &str, data: &dyn UniqueHash) -> [u8; 32] {
    let mut hasher = new_hasher_with_domain(domain);
    hasher.write(&data.unique_hash());
    hasher.finish()
}

/// Computes the hash of a struct using an hash function that can be modelled as
/// a random oracle. Returns an element in the scalar field of curve BLS12_381.
///
/// A distinct `domain` should be used for each purpose of the random oracle.
pub fn random_oracle_to_scalar(domain: &str, data: &dyn UniqueHash) -> BIG {
    let hash = random_oracle(domain, data);
    let rng = &mut RAND_ChaCha20::new(hash);
    BIG::randomnum(&curve_order(), rng)
}

/// Computes the hash of a struct using an hash function that can be modelled as
/// a random oracle. Returns a group element of G1 in BLS12_381.
///
/// A distinct `domain` should be used for each purpose of the random oracle.
pub fn random_oracle_to_miracl_g1(domain: &str, data: &dyn UniqueHash) -> MiraclG1 {
    hash_to_miracl_g1(
        &DomainSeparationContext::new(domain).as_bytes(),
        &data.unique_hash(),
    )
}
