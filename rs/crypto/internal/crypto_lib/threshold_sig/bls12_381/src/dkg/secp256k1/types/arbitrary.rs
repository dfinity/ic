use super::*;
use crate::dkg::secp256k1::ephemeral_key::create_ephemeral;
use ic_types_test_utils::arbitrary as arbitrary_types;
use proptest::prelude::*;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

mod tests;

/////////////
// PUBLIC KEY
pub fn secp256k1_public_key() -> impl Strategy<Value = EphemeralPublicKey> {
    any::<[u8; 32]>().prop_map(|seed| EphemeralPublicKey::random(&mut ChaChaRng::from_seed(seed)))
}
impl proptest::prelude::Arbitrary for EphemeralPublicKey {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        secp256k1_public_key().boxed()
    }
}

//////
// POP
pub fn secp256k1_pop() -> impl Strategy<Value = EphemeralPop> {
    any::<[u8; 32]>().prop_map(|seed| {
        let mut rng = ChaChaRng::from_seed(seed);
        let spec_ext = EphemeralPublicKey::from(&EphemeralSecretKey::random(&mut rng));
        let spec_c = EphemeralSecretKey::random(&mut rng);
        let spec_s = EphemeralSecretKey::random(&mut rng);
        EphemeralPop {
            spec_ext,
            spec_c,
            spec_s,
        }
    })
}
impl proptest::prelude::Arbitrary for EphemeralPop {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        secp256k1_pop().boxed()
    }
}
impl proptest::prelude::Arbitrary for EphemeralPopBytes {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        secp256k1_pop().prop_map(EphemeralPopBytes::from).boxed()
    }
}

////////////
// Complaint
pub fn complaint() -> impl Strategy<Value = CLibComplaint> {
    any::<[u8; 32]>().prop_map(|seed| {
        let mut rng = ChaChaRng::from_seed(seed);
        let diffie_hellman = EphemeralPublicKey::from(&EphemeralSecretKey::random(&mut rng));
        let pok_challenge = EphemeralSecretKey::random(&mut rng);
        let pok_response = EphemeralSecretKey::random(&mut rng);
        CLibComplaint {
            diffie_hellman,
            pok_challenge,
            pok_response,
        }
    })
}
impl proptest::prelude::Arbitrary for CLibComplaint {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        complaint().boxed()
    }
}

/////////////
// SECRET KEY
pub fn secp256k1_secret_key() -> impl Strategy<Value = EphemeralSecretKey> {
    any::<[u8; 32]>().prop_map(|seed| EphemeralSecretKey::random(&mut ChaChaRng::from_seed(seed)))
}
pub fn secp256k1_secret_key_bytes() -> impl Strategy<Value = EphemeralSecretKeyBytes> {
    secp256k1_secret_key().prop_map(EphemeralSecretKeyBytes::from)
}
impl proptest::prelude::Arbitrary for EphemeralSecretKey {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        secp256k1_secret_key().boxed()
    }
}
impl proptest::prelude::Arbitrary for EphemeralSecretKeyBytes {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        secp256k1_secret_key_bytes().boxed()
    }
}

/////////////
// KEY SET
pub fn secp256k1_key_set() -> impl Strategy<Value = EphemeralKeySetBytes> {
    (any::<[u8; 32]>(), arbitrary_types::dkg_id()).prop_map(|(seed, dkg_id)| {
        let rng = &mut ChaChaRng::from_seed(seed);
        let sender = b"Some sender";
        let (secret_key_bytes, public_key_bytes, pop_bytes) = create_ephemeral(rng, dkg_id, sender);
        EphemeralKeySetBytes {
            secret_key_bytes,
            public_key_bytes,
            pop_bytes,
        }
    })
}
impl proptest::prelude::Arbitrary for EphemeralKeySetBytes {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        secp256k1_key_set().boxed()
    }
}
