use crate::CspPublicKey;
use crate::KeyId;
use crate::types::CspPop;
use ic_crypto_internal_multi_sig_bls12381::types::{PopBytes, PublicKeyBytes};
use ic_crypto_internal_test_vectors::unhex::hex_to_32_bytes;
use ic_crypto_internal_test_vectors::unhex::hex_to_48_bytes;
use ic_crypto_internal_test_vectors::unhex::hex_to_96_bytes;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::{EccCurveType, MEGaPublicKey};

pub struct MultiBlsTestVector {
    pub seed: u64,
    pub key_id: KeyId,
    pub public_key: CspPublicKey,
    pub proof_of_possession: CspPop,
}

pub fn multi_bls_test_vector() -> MultiBlsTestVector {
    MultiBlsTestVector {
        seed: 42,
        key_id: KeyId::from(hex_to_32_bytes(
            "3d62cc7907437135fcfb396bddbd26406af4ebeb28f84005054ffdbf17bc2437",
        )),
        public_key: CspPublicKey::MultiBls12_381(PublicKeyBytes(hex_to_96_bytes(
            "8b3c2d8d76cd5bc5a8b0ddfaff949f350d696c456805f9fd64f2ce827b002eecd3d95d47afcb9137f355b8c87713149205531d7457d9a9f9addaf9b625c7435dd24cce498cf997fd9dfc77a79dbbe8dc68c63d1612cceac61ee091ec14ed699c",
        ))),
        proof_of_possession: CspPop::MultiBls12_381(PopBytes(hex_to_48_bytes(
            "884d40b5b2781d4489d340705627e3f1a9097f67103654be4858a02771ee98f26e2a09830d7bb434aa9b381f9ef99e3e",
        ))),
    }
}

pub struct MEGaTestVector {
    pub seed: u64,
    pub public_key: MEGaPublicKey,
}

pub fn mega_test_vector() -> MEGaTestVector {
    MEGaTestVector {
        seed: 42,
        public_key: MEGaPublicKey::deserialize(
            EccCurveType::K256,
            &hex::decode("036a503d726f507e472c28b35df36d53313736c4fcddefe1b69f30fcb97f0b603d")
                .expect("invalid hex string"),
        )
        .expect("invalid MEGa public key"),
    }
}
