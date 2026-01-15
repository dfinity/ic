//! Prop-test utilities for Groth20 NiDKG types.
use super::*;
use ic_crypto_internal_types::curves::bls12_381::FrBytes;
use proptest::prelude::{BoxedStrategy, Strategy, any};

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
