// From: crypto/src/sign/threshold_sig/dkg/dealing.rs
mod dkg_dealing {
    use crate::types::CspDealing;
    use ic_types::crypto::dkg::Dealing;

    // TODO (CRP-248): implement the conversion correctly once an agreement is
    // reached
    impl From<&CspDealing> for Dealing {
        fn from(csp_dealing: &CspDealing) -> Self {
            // To keep this simple, we temporarily use a cbor serialization.
            Dealing(serde_cbor::to_vec(csp_dealing).expect("Cannot serialize csp dealing"))
        }
    }

    // TODO (CRP-346): implement the conversion correctly once agreement is reached
    impl From<&Dealing> for CspDealing {
        fn from(dealing: &Dealing) -> Self {
            // To keep this simple, we temporarily use a cbor serialization.
            serde_cbor::from_slice(&dealing.0).expect("Cannot deserialize Dealing into CspDealing")
        }
    }
}

// From: crypto/src/sign/threshold_sig/dkg/response.rs
mod dkg_response_verify {
    use crate::types::{CspPop, CspResponse};
    use ic_types::crypto::dkg::EncryptionPublicKeyPop;
    use ic_types::crypto::dkg::Response;

    // TODO (CRP-327): implement the conversion correctly once an agreement is
    // reached
    impl From<&EncryptionPublicKeyPop> for CspPop {
        fn from(enc_pk_pop: &EncryptionPublicKeyPop) -> Self {
            // To keep this simple, we temporarily use a cbor serialization.
            serde_cbor::from_slice(&enc_pk_pop.0)
                .expect("Cannot deserialize encryption public key pop")
        }
    }

    // TODO (CRP-327): implement the conversion correctly once agreement is reached
    impl From<&CspResponse> for Response {
        fn from(csp_response: &CspResponse) -> Self {
            // To keep this simple, we temporarily use a cbor serialization.
            Response(serde_cbor::to_vec(csp_response).expect("Cannot serialize CSP response"))
        }
    }

    // TODO (CRP-361): implement conversion with wrapping + move to internal-types
    impl From<&Response> for CspResponse {
        fn from(response: &Response) -> Self {
            // To keep this simple, we temporarily use a cbor serialization.
            serde_cbor::from_slice(&response.0)
                .expect("Cannot deserialize Response into CspResponse")
        }
    }
}
