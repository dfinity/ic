//! Prop-test utilities for Groth20 NiDKG types.
use super::*;
use ic_crypto_internal_types::curves::bls12_381::Fr as FrBytes;
use proptest::prelude::{any, BoxedStrategy, Strategy};

fn arbitrary_key_set() -> impl Strategy<Value = FsEncryptionKeySet> {
    any::<u8>().prop_map(|byte| FsEncryptionKeySet {
        public_key: FsEncryptionPublicKey(G1Bytes([byte; G1Bytes::SIZE])),
        pok: FsEncryptionPok {
            blinder: G1Bytes([byte; G1Bytes::SIZE]),
            response: FrBytes([byte; FrBytes::SIZE]),
        },
        secret_key: FsEncryptionSecretKey {
            bte_nodes: Vec::new(),
        },
    })
}
impl proptest::prelude::Arbitrary for FsEncryptionKeySet {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        arbitrary_key_set().boxed()
    }
}

fn arbitrary_key_set_with_pop() -> impl Strategy<Value = FsEncryptionKeySetWithPop> {
    any::<u8>().prop_map(|byte| FsEncryptionKeySetWithPop {
        public_key: FsEncryptionPublicKey(G1Bytes([byte; G1Bytes::SIZE])),
        pop: FsEncryptionPop {
            pop_key: G1Bytes([byte; G1Bytes::SIZE]),
            challenge: FrBytes([byte; FrBytes::SIZE]),
            response: FrBytes([byte; FrBytes::SIZE]),
        },
        secret_key: FsEncryptionSecretKey {
            bte_nodes: Vec::new(),
        },
    })
}
impl proptest::prelude::Arbitrary for FsEncryptionKeySetWithPop {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        arbitrary_key_set_with_pop().boxed()
    }
}
