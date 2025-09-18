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
}

#[cfg(target_os = "linux")]
/// Implementation for the actual AMD firmware.
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
