use sev::error::UserApiError;
use sev::firmware::guest::DerivedKey;
#[cfg(target_os = "linux")]
use sev::firmware::guest::Firmware;

#[mockall::automock]
pub trait SevGuestFirmware: Sync + Send {
    fn get_derived_key(
        &mut self,
        message_version: Option<u32>,
        derived_key_request: DerivedKey,
    ) -> Result<[u8; 32], UserApiError>;
}

#[cfg(target_os = "linux")]
impl SevGuestFirmware for Firmware {
    fn get_derived_key(
        &mut self,
        message_version: Option<u32>,
        derived_key_request: DerivedKey,
    ) -> Result<[u8; 32], UserApiError> {
        self.get_derived_key(message_version, derived_key_request)
    }
}
