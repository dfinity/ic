use crate::{crypto::SignedBytesWithoutDomainSeparator, messages::Blob, CountBytes};
use base64::URL_SAFE_NO_PAD;
use ic_crypto_sha256::Sha256;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct ClientData {
    r#type: String,
    challenge: String,
    origin: String,
}

/// Verification of a signature that was generated with web authentication
/// requires as auxiliary information the AuthenticatorData and the
/// ClientDataJSON objects returned by the call to the authenticator. A
/// WebAuthnSignature contains both the actual cryptographic signature
/// and this auxiliary information.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WebAuthnSignature {
    authenticator_data: Blob,
    client_data_json: Blob,
    signature: Blob,
}

impl WebAuthnSignature {
    pub fn new(authenticator_data: Blob, client_data_json: Blob, signature: Blob) -> Self {
        Self {
            authenticator_data,
            client_data_json,
            signature,
        }
    }

    pub fn authenticator_data(&self) -> Blob {
        self.authenticator_data.clone()
    }

    pub fn client_data_json(&self) -> Blob {
        self.client_data_json.clone()
    }

    pub fn signature(&self) -> Blob {
        self.signature.clone()
    }
}

impl CountBytes for WebAuthnSignature {
    fn count_bytes(&self) -> usize {
        self.authenticator_data.0.len() + self.client_data_json.0.len() + self.signature.0.len()
    }
}

impl TryFrom<&[u8]> for WebAuthnSignature {
    type Error = String;

    fn try_from(blob: &[u8]) -> Result<Self, Self::Error> {
        let signature: WebAuthnSignature = serde_cbor::from_slice(blob)
            .map_err(|err| format!("Signature CBOR parsing failed with: {}", err))?;
        Ok(signature)
    }
}

/// The challenge signed with web authentication is contained in ClientDataJSON.
/// WebAuthnEnvelope parses a WebAuthenticationSignature, provides access to the
/// challenge contained in it, and also produces the byte string that is
/// required in the signature verification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct WebAuthnEnvelope {
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    client_data: ClientData,
    signed_bytes: Vec<u8>,
    // The decoded challenge, this will be either a message id or hash(delegation)
    challenge: Vec<u8>,
}

impl WebAuthnEnvelope {
    pub fn challenge(&self) -> Vec<u8> {
        self.challenge.clone()
    }
}

impl TryFrom<&WebAuthnSignature> for WebAuthnEnvelope {
    type Error = String;

    fn try_from(signature: &WebAuthnSignature) -> Result<Self, Self::Error> {
        let client_data: ClientData =
            match serde_json::from_slice(&signature.client_data_json.0[..]) {
                Ok(client_data) => client_data,
                Err(err) => return Err(format!("ClientDataJSON parsing failed with: {}", err)),
            };

        let challenge = match base64::decode_config(&client_data.challenge, URL_SAFE_NO_PAD) {
            Ok(challenge) => challenge,
            Err(err) => return Err(format!("Challenge base64url parsing failed with: {}", err)),
        };

        let mut signed_bytes = signature.authenticator_data.0.clone();
        signed_bytes.append(&mut Sha256::hash(&signature.client_data_json.0.clone()[..]).to_vec());

        Ok(WebAuthnEnvelope {
            client_data_json: signature.client_data_json.0.clone(),
            authenticator_data: signature.authenticator_data.0.clone(),
            client_data,
            signed_bytes,
            challenge,
        })
    }
}

impl SignedBytesWithoutDomainSeparator for WebAuthnEnvelope {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        self.signed_bytes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn try_from_cbor_ok() {
        let cbor_bytes = hex!("D9D9F7A37261757468656E74696361746F725F6461746158252F1B671A93F444B8EC77E0211F9624C9C2612182B864F0D4AC9D335F5B4FE502010000005370636C69656E745F646174615F6A736F6E78987B2274797065223A22776562617574686E2E676574222C226368616C6C656E6765223A225044786863476B74636D56786457567A644331705A43776758334A6C6358566C6333516761575266506A34222C226F726967696E223A2268747470733A2F2F63636763652D62616261612D61616161612D61616161612D63616161612D61616161612D61616161612D712E6963302E617070227D697369676E617475726558473045022100C69C75C6D6C449EA936094476E8BFCAD90D831A6437A87117615ADD6D6A5168802201E2E4535976794286FA264EB81D7B14B3F168AB7F62AD5C0B9D6EBFC64EB0C8C");
        let signature = WebAuthnSignature::try_from(&cbor_bytes[..]);
        assert!(signature.is_ok());
        let signature = signature.ok().unwrap();
        let result = WebAuthnEnvelope::try_from(&signature);
        assert!(result.is_ok());
        let result = result.ok().unwrap();
        assert_eq!(
            result.challenge,
            [
                60, 60, 97, 112, 105, 45, 114, 101, 113, 117, 101, 115, 116, 45, 105, 100, 44, 32,
                95, 114, 101, 113, 117, 101, 115, 116, 32, 105, 100, 95, 62, 62
            ]
        );
        assert_eq!(
            result.authenticator_data,
            hex!("2f1b671a93f444b8ec77e0211f9624c9c2612182b864f0d4ac9d335f5b4fe5020100000053")
                .to_vec()
        );
        assert_eq!(result.as_signed_bytes_without_domain_separator().to_vec(), hex!("2f1b671a93f444b8ec77e0211f9624c9c2612182b864f0d4ac9d335f5b4fe50201000000537f91225ffff1e2912a0f8ca7a0ef61df01ae3d8898fca283036239259bab4f82").to_vec());
    }
}
