//! Generate data for proptests
use super::*;
use crate::crypto::*;
use ic_crypto_internal_seed::Seed;
use proptest::prelude::*;
mod tests;

fn keypair_from_seed_bytes(seed_bytes: [u8; 32]) -> (SecretKey, PublicKey) {
    let seed = Seed::from_bytes(&seed_bytes);
    keypair_from_rng(&mut seed.into_rng())
}

//////////////////////
// Proptest strategies
// These are for generating data types
pub fn key_pair() -> impl Strategy<Value = (SecretKey, PublicKey)> {
    any::<[u8; 32]>().prop_map(keypair_from_seed_bytes)
}
pub fn secret_key() -> impl Strategy<Value = SecretKey> {
    key_pair().prop_map(|keypair| keypair.0)
}
pub fn public_key() -> impl Strategy<Value = PublicKey> {
    key_pair().prop_map(|keypair| keypair.1)
}
pub fn individual_signature() -> impl Strategy<Value = IndividualSignature> {
    any::<([u8; 32], [u8; 8])>()
        .prop_map(|(seed, message)| (keypair_from_seed_bytes(seed), message))
        .prop_map(|(keypair, message)| {
            let (secret_key, _public_key) = keypair;
            sign_message(&message, &secret_key)
        })
}
pub fn pop() -> impl Strategy<Value = Pop> {
    any::<[u8; 32]>()
        .prop_map(keypair_from_seed_bytes)
        .prop_map(|keypair| {
            let (secret_key, public_key) = keypair;
            create_pop(&public_key, &secret_key)
        })
}
pub fn combined_signature() -> impl Strategy<Value = CombinedSignature> {
    individual_signature().prop_map(|signature| combine_signatures(&[signature]))
}

pub fn secret_key_bytes() -> impl Strategy<Value = SecretKeyBytes> {
    key_pair().prop_map(|(secret_key, _public_key)| SecretKeyBytes::from(&secret_key))
}
pub fn public_key_bytes() -> impl Strategy<Value = PublicKeyBytes> {
    public_key().prop_map(|public_key| PublicKeyBytes::from(&public_key))
}
pub fn key_pair_bytes() -> impl Strategy<Value = (SecretKeyBytes, PublicKeyBytes)> {
    key_pair().prop_map(|(secret_key, public_key)| {
        (
            SecretKeyBytes::from(&secret_key),
            PublicKeyBytes::from(&public_key),
        )
    })
}
pub fn individual_signature_bytes() -> impl Strategy<Value = IndividualSignatureBytes> {
    individual_signature().prop_map(|signature| IndividualSignatureBytes::from(&signature))
}
pub fn pop_bytes() -> impl Strategy<Value = PopBytes> {
    pop().prop_map(|pop| PopBytes::from(&pop))
}
pub fn combined_signature_bytes() -> impl Strategy<Value = CombinedSignatureBytes> {
    combined_signature().prop_map(|signature| CombinedSignatureBytes::from(&signature))
}

//////////////////
// Arbitrary trait
// Note: This is needed because Rust doesn't support const generics yet.
impl proptest::prelude::Arbitrary for PublicKeyBytes {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        public_key_bytes().boxed()
    }
}

impl proptest::prelude::Arbitrary for SecretKeyBytes {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        secret_key_bytes().boxed()
    }
}

impl proptest::prelude::Arbitrary for IndividualSignatureBytes {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        individual_signature_bytes().boxed()
    }
}
impl proptest::prelude::Arbitrary for PopBytes {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        pop_bytes().boxed()
    }
}

impl proptest::prelude::Arbitrary for CombinedSignatureBytes {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        combined_signature_bytes().boxed()
    }
}
