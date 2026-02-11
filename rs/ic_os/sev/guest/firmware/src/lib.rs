use sev::error::UserApiError;
use sev::firmware::guest::DerivedKey;
#[cfg(target_os = "linux")]
use sev::firmware::guest::Firmware;

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
