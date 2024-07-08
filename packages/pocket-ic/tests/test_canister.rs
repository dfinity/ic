use candid::Principal;
use ic_cdk::api::management_canister::ecdsa::{
    ecdsa_public_key as ic_cdk_ecdsa_public_key, sign_with_ecdsa as ic_cdk_sign_with_ecdsa,
    EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument, EcdsaPublicKeyResponse, SignWithEcdsaArgument,
};
use ic_cdk::update;

#[update]
async fn ecdsa_public_key(
    canister_id: Option<Principal>,
    derivation_path: Vec<Vec<u8>>,
    name: String,
) -> Result<EcdsaPublicKeyResponse, String> {
    let arg = EcdsaPublicKeyArgument {
        canister_id,
        derivation_path,
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name,
        },
    };
    Ok(ic_cdk_ecdsa_public_key(arg)
        .await
        .map_err(|(code, msg)| format!("Reject code: {:?}; Reject message: {}", code, msg))?
        .0)
}

#[update]
async fn sign_with_ecdsa(
    message_hash: Vec<u8>,
    derivation_path: Vec<Vec<u8>>,
    name: String,
) -> Result<Vec<u8>, String> {
    let arg = SignWithEcdsaArgument {
        message_hash,
        derivation_path,
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name,
        },
    };
    Ok(ic_cdk_sign_with_ecdsa(arg)
        .await
        .map_err(|(code, msg)| format!("Reject code: {:?}; Reject message: {}", code, msg))?
        .0
        .signature)
}

fn main() {}

#[cfg(test)]
mod tests {
    use super::*;
    use candid_parser::utils::{service_equal, CandidSource};
    use lazy_static::lazy_static;
    use std::{env::var_os, path::PathBuf};

    lazy_static! {
        static ref DECLARED_INTERFACE: String = {
            let cargo_manifest_dir =
                var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR env var undefined");

            let path = PathBuf::from(cargo_manifest_dir).join("tests/test_canister.did");

            let contents = std::fs::read(path).unwrap();
            String::from_utf8(contents).unwrap()
        };
        static ref IMPLEMENTED_INTERFACE: String = {
            candid::export_service!();
            __export_service()
        };
    }

    #[test]
    fn test_candid_interface() {
        let result = service_equal(
            CandidSource::Text(&IMPLEMENTED_INTERFACE),
            CandidSource::Text(&DECLARED_INTERFACE),
        );

        if let Err(err) = result {
            panic!(
                "Implemented interface:\n\
                 {}\n\
                 \n\
                 Declared interface:\n\
                 {}\n\
                 \n\
                 Error:\n\
                 {}n\
                 \n\
                 The Candid service implementation is not equal to the declared interface.",
                *IMPLEMENTED_INTERFACE, *DECLARED_INTERFACE, err,
            );
        }
    }
}
