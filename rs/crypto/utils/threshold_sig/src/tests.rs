#![allow(clippy::unwrap_used)]
use super::*;
use ic_crypto_internal_csp::types::{CspSignature, ThresBls12_381_Signature};
use ic_crypto_internal_threshold_sig_bls12381::types::CombinedSignatureBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_interfaces::crypto::SignableMock;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use std::convert::TryFrom;

/// Test vectors for verifying individual or combined threshold signatures
struct TestVector {
    public_key: &'static str,
    message: &'static [u8],
    signature: &'static str,
    valid: bool,
}

/// Test vectors created with the crypto CLI.
///
/// Each message is prefixed by the domain separator for SignableMock:
///
/// `printf "\x14signable_mock_domain$message"`
const TEST_VECTORS: [TestVector; 6] = [
    TestVector {
        public_key: "rhikA2Yo5M6YyK4JjdN0LB3/1koSp2GjQh/ZX6rKv5aFIC7npCY2PicCsFd7wQVzE6ZqudtpER8u/tE//hZcDPz+dtxEBA2wz3IOU7lNQLHfsTcDNehb/dFYCbgYXN+d",
        message: b"DeedleDee",
        signature: "i2lvnjJXA9PdH8Ed+S6jIYyX6YR1ZOymEaEbifqQZ6XUT/PsuD93UIDwL3CTZxSU",
        valid: true,
    },
    TestVector {
        public_key: "gFAsZ5fEg+OK3fM2hMhWu+PDRw+QRrvPGps2G21P7K5opBv4KDZxl4cxTBNhJC6FFAycQoVOuc1K966qf9XwSZhjuXmKbp7iL+hp0gSJlhRkqDhkNh+JamKAY/XSaEA2",
        message: b"HumDrum",
        signature: "lsH/4J7ytN2N54BaxRIh6wub7vXmgC/RmRnmOU6vy//cPD4LJBeLN5vr/nzd7M0N",
        valid: true,
    },
    TestVector {
        public_key: "tnw7dxZmkGIq5+fsHQhViFTM44jzTAVZ7xxKc1FisIpb8MlW/wwkL/Z2xSRQkBU1FoaQIWa4jeEOwKKyfOJpdtqi/ZgwbDqbY7lJtpK2jPreKjsUb+qBsXAL34ohJWto",
        message: b"CookieDough",
        signature: "joYvOS960Kr349X+E/DIfyJR6A1lD/feJ7BwglwjlALtN+F3X7BwDL5EQAbYAlPf",
        valid: true,
    },
    // Modified public key in vector 0
    TestVector {
        public_key: "RhikA2Yo5M6YyK4JjdN0LB3/1koSp2GjQh/ZX6rKv5aFIC7npCY2PicCsFd7wQVzE6ZqudtpER8u/tE//hZcDPz+dtxEBA2wz3IOU7lNQLHfsTcDNehb/dFYCbgYXN+d",
        message: b"DeedleDee",
        signature: "i2lvnjJXA9PdH8Ed+S6jIYyX6YR1ZOymEaEbifqQZ6XUT/PsuD93UIDwL3CTZxSU",
        valid: false,
    },
    // Modified message in vector 1
    TestVector {
        public_key: "GFAsZ5fEg+OK3fM2hMhWu+PDRw+QRrvPGps2G21P7K5opBv4KDZxl4cxTBNhJC6FFAycQoVOuc1K966qf9XwSZhjuXmKbp7iL+hp0gSJlhRkqDhkNh+JamKAY/XSaEA2",
        message: b"ShockHorror",
        signature: "lsH/4J7ytN2N54BaxRIh6wub7vXmgC/RmRnmOU6vy//cPD4LJBeLN5vr/nzd7M0N",
        valid: false,
    },
    // Modified signature in vector 2
    TestVector {
        public_key: "tnw7dxZmkGIq5+fsHQhViFTM44jzTAVZ7xxKc1FisIpb8MlW/wwkL/Z2xSRQkBU1FoaQIWa4jeEOwKKyfOJpdtqi/ZgwbDqbY7lJtpK2jPreKjsUb+qBsXAL34ohJWto",
        message: b"CookieDough",
        signature: "JoYvOS960Kr349X+E/DIfyJR6A1lD/feJ7BwglwjlALtN+F3X7BwDL5EQAbYAlPf",
        valid: false,
    },
];

#[test]
fn signature_verification_should_pass_test_vectors() {
    for (index, vector) in TEST_VECTORS.iter().enumerate() {
        let public_key = {
            let public_key = base64::decode(&vector.public_key).expect("Invalid base64 in test");
            assert_eq!(
                public_key.len(),
                PublicKeyBytes::SIZE,
                "Test vector public key has wrong length"
            );
            let mut buffer = [0u8; PublicKeyBytes::SIZE];
            buffer.copy_from_slice(&public_key);
            ThresholdSigPublicKey::from(CspThresholdSigPublicKey::ThresBls12_381(PublicKeyBytes(
                buffer,
            )))
        };
        let signature: CombinedThresholdSigOf<SignableMock> = {
            let signature = base64::decode(&vector.signature).expect("Invalid base64 in test");
            assert_eq!(
                signature.len(),
                CombinedSignatureBytes::SIZE,
                "Test vector signature has wrong length"
            );
            let mut buffer = [42; CombinedSignatureBytes::SIZE];
            buffer.copy_from_slice(&signature);
            let signature = CspSignature::ThresBls12_381(ThresBls12_381_Signature::Combined(
                CombinedSignatureBytes(buffer),
            ));
            CombinedThresholdSigOf::try_from(signature).unwrap()
        };

        let message = SignableMock::new(vector.message.to_vec());

        let result = verify_combined(&message, &signature, &public_key);
        assert_eq!(
            result.is_ok(),
            vector.valid,
            "Unexpected result for test vector {}",
            index
        );
    }
}
