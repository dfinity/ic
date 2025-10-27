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
            "6ddef5dfbbd4b641a7cc838ea5d2018c892dd6ef21d641a93f9d3b73b95c6258",
        )),
        public_key: CspPublicKey::MultiBls12_381(PublicKeyBytes(hex_to_96_bytes(
            "b5077d187db1ff824d246bc7c311f909047e20375dc836087da1d7e5c3add0e8fc838af6aaa7373b41824c9bd080f47c0a50e3cdf06bf1cb4061a6cc6ab1802acce096906cece92e7487a29e89a187b618e6af1292515202640795f3359161c2",
        ))),
        proof_of_possession: CspPop::MultiBls12_381(PopBytes(hex_to_48_bytes(
            "8c3a46485252433f478d733275ae3d259f6ced963cf496974ea1dc95e6ca3aee588c4a2e12de34f46e7ef0adffe664d7",
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
