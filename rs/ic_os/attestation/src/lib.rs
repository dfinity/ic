use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

pub mod attestation_package;
pub mod custom_data;
pub mod registry;
pub mod verification;

#[cfg(test)]
mod e2e_tests;

pub use verification_error::Detail as VerificationErrorDetail;

tonic::include_proto!("attestation");

impl VerificationError {
    pub fn internal(err: impl Display) -> Self {
        VerificationErrorDetail::Internal(VerificationErrorDescription {
            message: err.to_string(),
        })
        .into()
    }

    pub fn invalid_attestation_report(err: impl Display) -> Self {
        VerificationErrorDetail::InvalidAttestationReport(VerificationErrorDescription {
            message: err.to_string(),
        })
        .into()
    }

    pub fn invalid_certificate_chain(err: impl Display) -> Self {
        VerificationErrorDetail::InvalidCertificateChain(VerificationErrorDescription {
            message: err.to_string(),
        })
        .into()
    }

    pub fn invalid_chip_id(err: impl Display) -> Self {
        VerificationErrorDetail::InvalidChipId(VerificationErrorDescription {
            message: err.to_string(),
        })
        .into()
    }

    pub fn invalid_custom_data(err: impl Display) -> Self {
        VerificationErrorDetail::InvalidCustomData(VerificationErrorDescription {
            message: err.to_string(),
        })
        .into()
    }

    pub fn invalid_measurement(err: impl Display) -> Self {
        VerificationErrorDetail::InvalidMeasurement(VerificationErrorDescription {
            message: err.to_string(),
        })
        .into()
    }

    pub fn invalid_signature(err: impl Display) -> Self {
        VerificationErrorDetail::InvalidSignature(VerificationErrorDescription {
            message: err.to_string(),
        })
        .into()
    }
}

impl Display for VerificationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for VerificationError {}

impl From<VerificationErrorDetail> for VerificationError {
    fn from(value: VerificationErrorDetail) -> Self {
        VerificationError {
            message: value.to_string(),
            detail: Some(value),
        }
    }
}

impl Display for VerificationErrorDetail {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_candid_deserialization() {
        let candid_encoded = [
            68, 73, 68, 76, 4, 108, 2, 145, 197, 253, 128, 7, 1, 199, 235, 196, 208, 9, 113, 110,
            2, 107, 7, 221, 198, 160, 17, 3, 254, 197, 253, 80, 3, 225, 202, 224, 152, 2, 3, 205,
            187, 143, 197, 4, 3, 161, 218, 255, 183, 6, 3, 229, 220, 132, 191, 7, 3, 178, 160, 223,
            129, 11, 3, 108, 1, 199, 235, 196, 208, 9, 113, 1, 0, 1, 2, 3, 97, 98, 99, 72, 73, 110,
            118, 97, 108, 105, 100, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 67, 104,
            97, 105, 110, 40, 73, 110, 118, 97, 108, 105, 100, 67, 101, 114, 116, 105, 102, 105,
            99, 97, 116, 101, 67, 104, 97, 105, 110, 69, 114, 114, 111, 114, 32, 123, 32, 109, 101,
            115, 115, 97, 103, 101, 58, 32, 34, 97, 98, 99, 34, 32, 125, 41,
        ];
        let deserialized: VerificationError =
            candid::decode_one(&candid_encoded).expect("Failed to decode VerificationError");

        match deserialized.detail.unwrap() {
            VerificationErrorDetail::InvalidCertificateChain(desc) => {
                assert_eq!(desc.message, "abc");
            }
            _ => panic!("Unexpected variant"),
        }
    }
}
