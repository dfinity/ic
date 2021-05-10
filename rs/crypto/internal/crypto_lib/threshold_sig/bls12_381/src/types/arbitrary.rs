//! Generate data for proptests

#![allow(clippy::unwrap_used)]

use super::*;
use crate::crypto;
use ff::PrimeField;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_types::NumberOfNodes;
use pairing::bls12_381::FrRepr;
use proptest::prelude::*;

//mod tests;

//////////////////////
// Proptest strategies
// These are for generating data types
#[cfg(test)]
pub fn secret_key() -> impl Strategy<Value = SecretKey> {
    any::<[u64; 4]>()
        .prop_map(|seed| Fr::from_repr(FrRepr(seed)))
        .prop_filter("Key must be valid".to_owned(), |secret_key| {
            secret_key.is_ok()
        })
        .prop_map(|secret_key| secret_key.unwrap())
}
#[cfg(test)]
pub fn public_key() -> impl Strategy<Value = PublicKey> {
    secret_key().prop_map(|secret_key| crypto::public_key_from_secret_key(&secret_key))
}
#[cfg(test)]
pub fn individual_signature() -> impl Strategy<Value = IndividualSignature> {
    any::<([u64; 4], [u8; 9])>()
        .prop_map(|(seed, message)| (Fr::from_repr(FrRepr(seed)), message))
        .prop_filter("Key must be valid".to_owned(), |(key, _message)| {
            key.is_ok()
        })
        .prop_map(|(secret_key, message)| crypto::sign_message(&message, &secret_key.unwrap()))
}
#[cfg(test)]
pub fn combined_signature() -> impl Strategy<Value = CombinedSignature> {
    individual_signature().prop_map(|signature| {
        crypto::combine_signatures(&[Some(signature)], NumberOfNodes::from(1)).unwrap()
    })
}

#[cfg(test)]
pub fn threshold_sig_public_key_bytes() -> impl Strategy<Value = PublicKeyBytes> {
    public_key().prop_map(PublicKeyBytes::from)
}

#[cfg(test)]
pub fn individual_signature_bytes() -> impl Strategy<Value = IndividualSignatureBytes> {
    individual_signature().prop_map(|signature| signature.into())
}
#[cfg(test)]
pub fn combined_signature_bytes() -> impl Strategy<Value = CombinedSignatureBytes> {
    combined_signature().prop_map(|signature| signature.into())
}

#[cfg(test)]
impl proptest::prelude::Arbitrary for IndividualSignatureBytes {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        individual_signature_bytes().boxed()
    }
}

#[cfg(test)]
impl proptest::prelude::Arbitrary for CombinedSignatureBytes {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        combined_signature_bytes().boxed()
    }
}
