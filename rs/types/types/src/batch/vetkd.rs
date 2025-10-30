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

/// Errors that may occur when handling a VetKd request.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize, EnumCount)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum VetKdErrorCode {
    TimedOut = 1,
    InvalidKey = 2,
}

/// Consensus may either agree on a successful response, or reject the request.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize, EnumCount)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum VetKdAgreement {
    Success(Vec<u8>),
    Reject(VetKdErrorCode),
}

impl CountBytes for VetKdAgreement {
    fn count_bytes(&self) -> usize {
        match self {
            VetKdAgreement::Success(data) => data.len(),
            VetKdAgreement::Reject(_) => size_of::<VetKdErrorCode>(),
        }
    }
}

/// Payload that contains completed VetKey agreements.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct VetKdPayload {
    pub vetkd_agreements: BTreeMap<CallbackId, VetKdAgreement>,
}

impl VetKdPayload {
    pub fn is_empty(&self) -> bool {
        self.vetkd_agreements.is_empty()
    }
}

impl From<VetKdAgreement> for VetKdInternalAgreementProto {
    fn from(agreement: VetKdAgreement) -> Self {
        match agreement {
            VetKdAgreement::Success(data) => VetKdInternalAgreementProto::Data(data),
            VetKdAgreement::Reject(error_code) => {
                VetKdInternalAgreementProto::Reject(VetKdErrorCodeProto::from(error_code).into())
            }
        }
    }
}

impl TryFrom<VetKdInternalAgreementProto> for VetKdAgreement {
    type Error = ProxyDecodeError;
    fn try_from(proto: VetKdInternalAgreementProto) -> Result<Self, Self::Error> {
        let res = match proto {
            VetKdInternalAgreementProto::Data(data) => VetKdAgreement::Success(data),
            VetKdInternalAgreementProto::Reject(error_code) => VetKdAgreement::Reject(
                VetKdErrorCode::try_from(VetKdErrorCodeProto::try_from(error_code).map_err(
                    |_| ProxyDecodeError::ValueOutOfRange {
                        typ: "VetKdErrorCode",
                        err: format!("Unexpected value for VetKd error code {error_code}"),
                    },
                )?)?,
            ),
        };
        Ok(res)
    }
}

impl From<VetKdErrorCode> for VetKdErrorCodeProto {
    fn from(value: VetKdErrorCode) -> Self {
        match value {
            VetKdErrorCode::TimedOut => VetKdErrorCodeProto::TimedOut,
            VetKdErrorCode::InvalidKey => VetKdErrorCodeProto::InvalidKey,
        }
    }
}

impl TryFrom<VetKdErrorCodeProto> for VetKdErrorCode {
    type Error = ProxyDecodeError;

    fn try_from(value: VetKdErrorCodeProto) -> Result<Self, Self::Error> {
        match value {
            VetKdErrorCodeProto::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "VetKdErrorCode",
                err: format!("Unexpected value for VetKd error code {value:?}"),
            }),
            VetKdErrorCodeProto::TimedOut => Ok(VetKdErrorCode::TimedOut),
            VetKdErrorCodeProto::InvalidKey => Ok(VetKdErrorCode::InvalidKey),
        }
    }
}

pub fn vetkd_payload_to_bytes(payload: VetKdPayload, max_size: NumBytes) -> Vec<u8> {
    let message_iterator = payload
        .vetkd_agreements
        .into_iter()
        .map(|(callback_id, agreement)| VetKdAgreementProto {
            callback_id: callback_id.get(),
            agreement: Some(agreement.into()),
        });

    iterator_to_bytes(message_iterator, max_size)
}

pub fn bytes_to_vetkd_payload(data: &[u8]) -> Result<VetKdPayload, ProxyDecodeError> {
    let messages: Vec<VetKdAgreementProto> =
        slice_to_messages(data).map_err(ProxyDecodeError::DecodeError)?;
    let mut payload = VetKdPayload::default();

    for message in messages {
        let callback_id = CallbackId::from(message.callback_id);
        let response = try_from_option_field(message.agreement, "VetKdAgreement::agreement")?;
        payload.vetkd_agreements.insert(callback_id, response);
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
    fn test_vetkd_payload_conversion() {
        let set = VetKdPayload::exhaustive_set(&mut reproducible_rng());
        println!("Number of VetKdPayload variants: {}", set.len());
        let max_size = NumBytes::new(2 * 1024 * 1024);
        for element in set {
            // serialize -> deserialize round-trip
            let bytes = vetkd_payload_to_bytes(element.clone(), max_size);
            let new_element = bytes_to_vetkd_payload(&bytes).unwrap();

            assert_eq!(
                element, new_element,
                "deserialized VetKdPayload is different from original"
            );
        }
    }

    #[test]
    fn test_large_vetkd_payload_conversion() {
        let mut rng = reproducible_rng();
        // Max size is 10_000 bytes
        let max_size = NumBytes::new(10 * 1000);

        // Each agreement has 1000 bytes (in deserialized form)
        let mut make_agreement = || {
            let mut data = [0; 1000];
            rng.fill_bytes(&mut data);
            VetKdAgreement::Success(data.to_vec())
        };

        // 8 Agreements should still fit in the payload
        let payload_fits = VetKdPayload {
            vetkd_agreements: (0..9)
                .map(|i| (CallbackId::new(i), make_agreement()))
                .collect(),
        };

        let bytes = vetkd_payload_to_bytes(payload_fits.clone(), max_size);
        assert!(bytes.len() as u64 <= max_size.get());
        let new_payload = bytes_to_vetkd_payload(&bytes).unwrap();

        assert_eq!(
            new_payload, payload_fits,
            "deserialized VetKdPayload is different from original"
        );

        // The 9th agreement should be truncated
        let mut payload_too_large = payload_fits.clone();
        payload_too_large
            .vetkd_agreements
            .insert(CallbackId::new(9), make_agreement());

        let bytes = vetkd_payload_to_bytes(payload_too_large, max_size);
        assert!(bytes.len() as u64 <= max_size.get());
        let new_payload = bytes_to_vetkd_payload(&bytes).unwrap();

        assert_eq!(
            new_payload, payload_fits,
            "deserialized VetKdPayload is different from original"
        );

        // But there should still be space for a reject
        let mut payload_reject = payload_fits.clone();
        payload_reject.vetkd_agreements.insert(
            CallbackId::new(9),
            VetKdAgreement::Reject(VetKdErrorCode::TimedOut),
        );

        let bytes = vetkd_payload_to_bytes(payload_reject.clone(), max_size);
        assert!(bytes.len() as u64 <= max_size.get());
        let new_payload = bytes_to_vetkd_payload(&bytes).unwrap();

        assert_eq!(
            new_payload, payload_reject,
            "deserialized VetKdPayload is different from original"
        );
    }
}
