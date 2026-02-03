use sev::error::UserApiError;
#[cfg(target_os = "linux")]
use sev::firmware::host::Firmware;
use sev::firmware::host::{Identifier, SnpPlatformStatus};

#[mockall::automock]
pub trait SevHostFirmware: Sync + Send {
    fn snp_platform_status(&mut self) -> Result<SnpPlatformStatus, UserApiError>;
    fn get_identifier(&mut self) -> Result<Identifier, UserApiError>;
}

#[cfg(target_os = "linux")]
impl SevHostFirmware for Firmware {
    fn snp_platform_status(&mut self) -> Result<SnpPlatformStatus, UserApiError> {
        self.snp_platform_status()
    }

    fn get_identifier(&mut self) -> Result<Identifier, UserApiError> {
        self.get_identifier()
    }
}
