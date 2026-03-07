use ic_base_types::NumBytes;
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::{
    proxy::{ProxyDecodeError, try_from_option_field},
    types::v1::{
        VetKdAgreement as VetKdAgreementProto, VetKdErrorCode as VetKdErrorCodeProto,
        vet_kd_agreement::Agreement as VetKdInternalAgreementProto,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, convert::TryFrom};
use strum_macros::EnumCount;

use crate::{CountBytes, messages::CallbackId};

use super::{iterator_to_bytes, slice_to_messages};

/// Errors that may occur when handling a chain key request.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize, EnumCount)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum ChainKeyErrorCode {
    TimedOut = 1,
    InvalidKey = 2,
}

/// Consensus may either agree on a successful response, or reject the request.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize, EnumCount)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum ChainKeyAgreement {
    Success(Vec<u8>),
    Reject(ChainKeyErrorCode),
}

impl CountBytes for ChainKeyAgreement {
    fn count_bytes(&self) -> usize {
        match self {
            ChainKeyAgreement::Success(data) => data.len(),
            ChainKeyAgreement::Reject(_) => size_of::<ChainKeyErrorCode>(),
        }
    }
}

/// Payload that contains completed chain key agreements.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct ChainKeyPayload {
    pub agreements: BTreeMap<CallbackId, ChainKeyAgreement>,
}

impl ChainKeyPayload {
    pub fn is_empty(&self) -> bool {
        self.agreements.is_empty()
    }
}

impl From<ChainKeyAgreement> for VetKdInternalAgreementProto {
    fn from(agreement: ChainKeyAgreement) -> Self {
        match agreement {
            ChainKeyAgreement::Success(data) => VetKdInternalAgreementProto::Data(data),
            ChainKeyAgreement::Reject(error_code) => {
                VetKdInternalAgreementProto::Reject(VetKdErrorCodeProto::from(error_code).into())
            }
        }
    }
}

impl TryFrom<VetKdInternalAgreementProto> for ChainKeyAgreement {
    type Error = ProxyDecodeError;
    fn try_from(proto: VetKdInternalAgreementProto) -> Result<Self, Self::Error> {
        let res = match proto {
            VetKdInternalAgreementProto::Data(data) => ChainKeyAgreement::Success(data),
            VetKdInternalAgreementProto::Reject(error_code) => ChainKeyAgreement::Reject(
                ChainKeyErrorCode::try_from(VetKdErrorCodeProto::try_from(error_code).map_err(
                    |_| ProxyDecodeError::ValueOutOfRange {
                        typ: "ChainKeyErrorCode",
                        err: format!("Unexpected value for chain key error code {error_code}"),
                    },
                )?)?,
            ),
        };
        Ok(res)
    }
}

impl From<ChainKeyErrorCode> for VetKdErrorCodeProto {
    fn from(value: ChainKeyErrorCode) -> Self {
        match value {
            ChainKeyErrorCode::TimedOut => VetKdErrorCodeProto::TimedOut,
            ChainKeyErrorCode::InvalidKey => VetKdErrorCodeProto::InvalidKey,
        }
    }
}

impl TryFrom<VetKdErrorCodeProto> for ChainKeyErrorCode {
    type Error = ProxyDecodeError;

    fn try_from(value: VetKdErrorCodeProto) -> Result<Self, Self::Error> {
        match value {
            VetKdErrorCodeProto::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "ChainKeyErrorCode",
                err: format!("Unexpected value for chain key error code {value:?}"),
            }),
            VetKdErrorCodeProto::TimedOut => Ok(ChainKeyErrorCode::TimedOut),
            VetKdErrorCodeProto::InvalidKey => Ok(ChainKeyErrorCode::InvalidKey),
        }
    }
}

pub fn chain_key_payload_to_bytes(payload: ChainKeyPayload, max_size: NumBytes) -> Vec<u8> {
    let message_iterator = payload
        .agreements
        .into_iter()
        .map(|(callback_id, agreement)| VetKdAgreementProto {
            callback_id: callback_id.get(),
            agreement: Some(agreement.into()),
        });

    iterator_to_bytes(message_iterator, max_size)
}

pub fn bytes_to_chain_key_payload(data: &[u8]) -> Result<ChainKeyPayload, ProxyDecodeError> {
    let messages: Vec<VetKdAgreementProto> =
        slice_to_messages(data).map_err(ProxyDecodeError::DecodeError)?;
    let mut payload = ChainKeyPayload::default();

    for message in messages {
        let callback_id = CallbackId::from(message.callback_id);
        let response = try_from_option_field(message.agreement, "VetKdAgreement::agreement")?;
        payload.agreements.insert(callback_id, response);
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use rand::RngCore;

    use crate::exhaustive::ExhaustiveSet;

    use super::*;

    #[test]
    fn test_chain_key_payload_conversion() {
        let set = ChainKeyPayload::exhaustive_set(&mut reproducible_rng());
        println!("Number of ChainKeyPayload variants: {}", set.len());
        let max_size = NumBytes::new(2 * 1024 * 1024);
        for element in set {
            // serialize -> deserialize round-trip
            let bytes = chain_key_payload_to_bytes(element.clone(), max_size);
            let new_element = bytes_to_chain_key_payload(&bytes).unwrap();

            assert_eq!(
                element, new_element,
                "deserialized ChainKeyPayload is different from original"
            );
        }
    }

    #[test]
    fn test_large_chain_key_payload_conversion() {
        let mut rng = reproducible_rng();
        // Max size is 10_000 bytes
        let max_size = NumBytes::new(10 * 1000);

        // Each agreement has 1000 bytes (in deserialized form)
        let mut make_agreement = || {
            let mut data = [0; 1000];
            rng.fill_bytes(&mut data);
            ChainKeyAgreement::Success(data.to_vec())
        };

        // 8 Agreements should still fit in the payload
        let payload_fits = ChainKeyPayload {
            agreements: (0..9)
                .map(|i| (CallbackId::new(i), make_agreement()))
                .collect(),
        };

        let bytes = chain_key_payload_to_bytes(payload_fits.clone(), max_size);
        assert!(bytes.len() as u64 <= max_size.get());
        let new_payload = bytes_to_chain_key_payload(&bytes).unwrap();

        assert_eq!(
            new_payload, payload_fits,
            "deserialized ChainKeyPayload is different from original"
        );

        // The 9th agreement should be truncated
        let mut payload_too_large = payload_fits.clone();
        payload_too_large
            .agreements
            .insert(CallbackId::new(9), make_agreement());

        let bytes = chain_key_payload_to_bytes(payload_too_large, max_size);
        assert!(bytes.len() as u64 <= max_size.get());
        let new_payload = bytes_to_chain_key_payload(&bytes).unwrap();

        assert_eq!(
            new_payload, payload_fits,
            "deserialized ChainKeyPayload is different from original"
        );

        // But there should still be space for a reject
        let mut payload_reject = payload_fits.clone();
        payload_reject.agreements.insert(
            CallbackId::new(9),
            ChainKeyAgreement::Reject(ChainKeyErrorCode::TimedOut),
        );

        let bytes = chain_key_payload_to_bytes(payload_reject.clone(), max_size);
        assert!(bytes.len() as u64 <= max_size.get());
        let new_payload = bytes_to_chain_key_payload(&bytes).unwrap();

        assert_eq!(
            new_payload, payload_reject,
            "deserialized ChainKeyPayload is different from original"
        );
    }
}
