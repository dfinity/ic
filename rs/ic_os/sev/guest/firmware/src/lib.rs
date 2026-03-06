use sev::Generation;
use sev::error::UserApiError;
#[cfg(target_os = "linux")]
use sev::firmware::guest::Firmware;
use sev::firmware::guest::{AttestationReport, DerivedKey};
use sev::firmware::host::TcbVersion;
use sev::parser::{ByteParser, Encoder};

/// Trait representing the SEV guest firmware interface.
#[mockall::automock]
pub trait SevGuestFirmware: Sync + Send {
    fn get_report(
        &mut self,
        message_version: Option<u32>,
        data: Option<[u8; 64]>,
        vmpl: Option<u32>,
    ) -> Result<Vec<u8>, UserApiError>;

    fn get_derived_key(
        &mut self,
        message_version: Option<u32>,
        derived_key_request: DerivedKey,
    ) -> Result<[u8; 32], UserApiError>;

    /// Returns whether the generated attestation report has a fake root certificate.
    /// This can be true only in mock firmwares.
    fn generates_report_with_fake_root_cert(&self) -> bool {
        false
    }

    /// Returns whether the generated attestation report may have a wrong custom data.
    /// This can be true only in mock firmwares.
    fn generates_report_with_wrong_custom_data(&self) -> bool {
        false
    }
    /// Returns whether the generated attestation report may have a wrong signature.
    /// This can be true only in mock firmwares.
    fn generates_report_with_wrong_signature(&self) -> bool {
        false
    }
}

/// Implementation for the actual AMD firmware.
#[cfg(target_os = "linux")]
impl SevGuestFirmware for Firmware {
    fn get_report(
        &mut self,
        message_version: Option<u32>,
        data: Option<[u8; 64]>,
        vmpl: Option<u32>,
    ) -> Result<Vec<u8>, UserApiError> {
        self.get_report(message_version, data, vmpl)
    }

    fn get_derived_key(
        &mut self,
        message_version: Option<u32>,
        derived_key_request: DerivedKey,
    ) -> Result<[u8; 32], UserApiError> {
        self.get_derived_key(message_version, derived_key_request)
    }
}

/// Converts a `TcbVersion` to its raw `u64` representation (little-endian layout
/// matching the AMD SEV-SNP ABI).
pub fn tcb_version_to_u64(tcb: &TcbVersion) -> u64 {
    let mut buf = Vec::new();
    tcb.encode(&mut buf, Generation::Milan)
        .expect("Failed to encode TcbVersion");
    let bytes: [u8; 8] = buf.try_into().expect("TcbVersion should encode to 8 bytes");
    u64::from_le_bytes(bytes)
}

/// Returns the reported TCB version from a parsed attestation report.
pub fn reported_tcb(report: &AttestationReport) -> TcbVersion {
    report.reported_tcb
}

/// Returns the SEV launch measurement (48 bytes) from a parsed attestation report.
pub fn measurement(report: &AttestationReport) -> &[u8; 48] {
    &report.measurement
}

/// Parses raw report bytes into an `AttestationReport`.
pub fn parse_attestation_report(report_bytes: &[u8]) -> Result<AttestationReport, UserApiError> {
    AttestationReport::from_bytes(report_bytes).map_err(|_| UserApiError::Unknown)
}
