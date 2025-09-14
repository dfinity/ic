use crate::host::HostSevCertificateProvider;
use crate::host::firmware::MockSevHostFirmware;
use anyhow::Result;
use sev::firmware::host::{Identifier, SnpPlatformStatus, TcbVersion};
use tempfile::TempDir;

/// Filename corresponding to mock_firmware()
pub const MOCK_CACHE_FILENAME: &str = "vcek_eabe711026ad4d9e45ab0a53cf339471c9f3e42d5ca9d947fafdd517695e6aa1b2376f0d953c4c62c96e4f9c10d36207733bd2b43f46304629979b52e7227a03_bl03_tee00_snp23_ucode213.der";
/// AMD KDS URL corresponding to mock_firmware()
pub const MOCK_AMD_KEY_SERVER_URL: &str = "https://kdsintf.amd.com/vcek/v1/Milan/eabe711026ad4d9e45ab0a53cf339471c9f3e42d5ca9d947fafdd517695e6aa1b2376f0d953c4c62c96e4f9c10d36207733bd2b43f46304629979b52e7227a03?blSPL=03&teeSPL=00&snpSPL=23&ucodeSPL=213";

/// Fetched from [MOCK_AMD_KEY_SERVER_URL]
pub const MOCK_AMD_KEY_SERVER_RESPONSE: &[u8] =
    include_bytes!("../../fixtures/mock_amd_key_server_response.crt");

pub fn mock_cert_cache_dir() -> Result<TempDir> {
    let tmpdir = TempDir::new()?;
    std::fs::write(
        tmpdir.path().join(MOCK_CACHE_FILENAME),
        MOCK_AMD_KEY_SERVER_RESPONSE,
    )?;
    Ok(tmpdir)
}

pub fn mock_host_sev_certificate_provider() -> Result<(HostSevCertificateProvider, TempDir)> {
    let dir = mock_cert_cache_dir()?;
    Ok((
        HostSevCertificateProvider::new_for_test(
            dir.path().to_path_buf(),
            Box::new(mock_sev_host_firmware()),
        ),
        dir,
    ))
}

pub fn mock_snp_platform_status() -> SnpPlatformStatus {
    SnpPlatformStatus {
        reported_tcb_version: TcbVersion {
            fmc: None,
            bootloader: 3,
            tee: 0,
            snp: 23,
            microcode: 213,
        },
        ..Default::default()
    }
}

pub fn mock_chip_id() -> Identifier {
    Identifier(vec![
        234, 190, 113, 16, 38, 173, 77, 158, 69, 171, 10, 83, 207, 51, 148, 113, 201, 243, 228, 45,
        92, 169, 217, 71, 250, 253, 213, 23, 105, 94, 106, 161, 178, 55, 111, 13, 149, 60, 76, 98,
        201, 110, 79, 156, 16, 211, 98, 7, 115, 59, 210, 180, 63, 70, 48, 70, 41, 151, 155, 82,
        231, 34, 122, 3,
    ])
}

pub fn mock_sev_host_firmware() -> MockSevHostFirmware {
    let mut mock_firmware = MockSevHostFirmware::new();
    mock_firmware
        .expect_snp_platform_status()
        .return_once(|| Ok(mock_snp_platform_status()));
    mock_firmware
        .expect_get_identifier()
        .return_once(|| Ok(mock_chip_id()));
    mock_firmware
}
