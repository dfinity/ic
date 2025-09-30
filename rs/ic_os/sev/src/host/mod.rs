use anyhow::{Context, Result, anyhow};
use der::pem::LineEnding;
use der::{Decode, Document};
use firmware::SevHostFirmware;
use reqwest::{Proxy, Response};
use sev::firmware::host::{Identifier, SnpPlatformStatus};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

mod firmware;
pub mod testing;

const SOCKS_PROXY: &str = "socks5://socks5.ic0.app:1080";

pub struct HostSevCertificateProvider {
    implementation: Option<HostSevCertificateProviderImpl>,
}

impl HostSevCertificateProvider {
    /// Creates a HostSevCertificateProvider using `certificate_cache_dir` as a cache.
    /// If `enable_trusted_execution_environment` is false, the provider won't return certificates.
    pub fn new(
        certificate_cache_dir: PathBuf,
        enable_trusted_execution_environment: bool,
    ) -> Result<Self> {
        if !enable_trusted_execution_environment {
            return Ok(Self::new_disabled());
        }

        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("SEV is only supported on Linux");

        #[cfg(target_os = "linux")]
        Ok(Self {
            implementation: Some(HostSevCertificateProviderImpl {
                certificate_cache_dir,
                sev_host_firmware: Box::new(
                    sev::firmware::host::Firmware::open().context("Could not open SEV firmware")?,
                ),
            }),
        })
    }

    /// Creates a HostSevCertificateProvider that doesn't return certificates.
    pub fn new_disabled() -> Self {
        Self {
            implementation: None,
        }
    }

    /// Creates a HostSevCertificateProvider that uses the given `sev_host_firmware` for
    /// querying the platform status.
    pub fn new_for_test(
        certificate_cache_dir: PathBuf,
        sev_host_firmware: Box<dyn SevHostFirmware>,
    ) -> Self {
        Self {
            implementation: Some(HostSevCertificateProviderImpl {
                certificate_cache_dir,
                sev_host_firmware,
            }),
        }
    }

    /// Returns the Host's SEV certificate chain as a PEM-formatted string if SEV firmware is
    /// enabled or None if SEV is disabled.
    pub async fn load_certificate_chain_pem(&mut self) -> Result<Option<String>> {
        if let Some(implementation) = &mut self.implementation {
            Ok(Some(implementation.load_certificate_chain_pem().await?))
        } else {
            Ok(None)
        }
    }
}

struct HostSevCertificateProviderImpl {
    certificate_cache_dir: PathBuf,
    sev_host_firmware: Box<dyn SevHostFirmware>,
}

impl HostSevCertificateProviderImpl {
    pub async fn load_certificate_chain_pem(&mut self) -> Result<String> {
        let chain_pem = format!(
            "{}{}{}",
            self.load_vcek_pem().await?,
            std::str::from_utf8(sev::certs::snp::builtin::milan::ASK)
                .expect("ASK PEM is invalid UTF-8"),
            std::str::from_utf8(sev::certs::snp::builtin::milan::ARK)
                .expect("ARK PEM is invalid UTF-8"),
        );

        Ok(chain_pem)
    }

    async fn load_vcek_pem(&mut self) -> Result<String> {
        let vcek_der = self.load_vcek_der().await?;

        let vcek_pem = der::Document::from_der(&vcek_der)
            .context("Failed to parse VCEK")?
            .to_pem("CERTIFICATE", LineEnding::LF)
            .context("Failed to convert VCEK to PEM")?;

        Ok(vcek_pem)
    }

    async fn load_vcek_der(&mut self) -> Result<Vec<u8>> {
        let status = self
            .sev_host_firmware
            .snp_platform_status()
            .context("Failed to get SNP platform status")?;
        let chip_id = self
            .sev_host_firmware
            .get_identifier()
            .context("Failed to get chip identifier")?;

        let cache_filename = Self::get_cache_filename(&chip_id, &status);
        let cache_path = self.certificate_cache_dir.join(&cache_filename);

        // Return VCEK from file cache if available.
        if cache_path.exists() {
            match fs::read(&cache_path) {
                Ok(vcek_der) => {
                    return Ok(vcek_der);
                }
                Err(err) => {
                    eprintln!("Failed to read cached VCEK: {err}");
                }
            }
        }

        let vcek_der = self
            .load_vcek_from_amd_key_server(&chip_id, &status)
            .await?;
        // Verify VCEK DER before saving to cache.
        Document::from_der(&vcek_der).context("Failed to parse downloaded VCEK")?;

        if let Err(err) = self.save_to_cache(&cache_path, &vcek_der) {
            eprintln!("Failed to save VCEK to cache: {err}");
        }

        Ok(vcek_der)
    }

    fn save_to_cache(&self, cache_path: &Path, vcek_der: &[u8]) -> Result<()> {
        // Ensure cache directory exists
        fs::create_dir_all(&self.certificate_cache_dir)
            .context("Failed to create certificate cache directory")?;

        // Save to temp file and rename to prevent race conditions
        let temp_file = NamedTempFile::with_prefix_in("vcek", &self.certificate_cache_dir)
            .context("Failed to create temporary file")?;
        fs::write(&temp_file, vcek_der).context("Failed to write VCEK")?;
        temp_file
            .persist(cache_path)
            .context("Failed to rename temporary file")?;
        Ok(())
    }

    fn get_hw_id_string(chip_id: &Identifier) -> String {
        chip_id.0.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn get_cache_filename(chip_id: &Identifier, status: &SnpPlatformStatus) -> String {
        let hw_id = Self::get_hw_id_string(chip_id);
        let reported_tcb = status.reported_tcb_version;
        format!(
            "vcek_{}_bl{:02}_tee{:02}_snp{:02}_ucode{:02}.der",
            hw_id,
            reported_tcb.bootloader,
            reported_tcb.tee,
            reported_tcb.snp,
            reported_tcb.microcode
        )
    }

    async fn load_vcek_from_amd_key_server(
        &self,
        chip_id: &Identifier,
        status: &SnpPlatformStatus,
    ) -> Result<Vec<u8>> {
        let url = Self::get_kds_url(chip_id, status);

        let response = match Self::load_url(&url, false).await {
            Ok(response) => Ok(response),
            Err(err_no_proxy) => Self::load_url(&url, true).await.map_err(|err_proxy| {
                anyhow!(
                    "Could not connect \
                     Error without proxy: {err_no_proxy:?} \
                     Error with proxy: {err_proxy:?}"
                )
            }),
        };

        let vcek = response
            .with_context(|| format!("Could not fetch VCEK from {url}"))?
            .bytes()
            .await
            .context("Could not extract VCEK from response")?;

        Ok(vcek.to_vec())
    }

    async fn load_url(url: &str, with_proxy: bool) -> reqwest::Result<Response> {
        let mut builder = reqwest::Client::builder();
        if with_proxy {
            builder = builder.proxy(Proxy::all(SOCKS_PROXY)?);
        }
        builder
            .build()
            .expect("reqwest Builder failed")
            .get(url)
            .send()
            .await
    }

    fn get_kds_url(chip_id: &Identifier, status: &SnpPlatformStatus) -> String {
        const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
        const KDS_VCEK: &str = "/vcek/v1";
        const SEV_PROD_NAME: &str = "Milan";

        let hw_id = Self::get_hw_id_string(chip_id);
        let reported_tcb = status.reported_tcb_version;
        format!(
            "{KDS_CERT_SITE}{KDS_VCEK}/{SEV_PROD_NAME}/{hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            reported_tcb.bootloader, reported_tcb.tee, reported_tcb.snp, reported_tcb.microcode,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::firmware::MockSevHostFirmware;
    use crate::host::testing::{MOCK_AMD_KEY_SERVER_URL, MOCK_CACHE_FILENAME};
    use std::fs;
    use tempfile::TempDir;
    use testing::{mock_chip_id, mock_sev_host_firmware, mock_snp_platform_status};
    use tokio::test;

    #[test]
    async fn test_helper_functions() {
        let chip_id = mock_chip_id();
        let status = mock_snp_platform_status();

        assert_eq!(
            HostSevCertificateProviderImpl::get_cache_filename(&chip_id, &status),
            MOCK_CACHE_FILENAME
        );

        assert_eq!(
            HostSevCertificateProviderImpl::get_kds_url(&chip_id, &status),
            MOCK_AMD_KEY_SERVER_URL
        );
    }

    #[test]
    async fn test_certificate_chain_with_cache() {
        // Filenames on ext4 must be <= 255 bytes
        assert!(MOCK_CACHE_FILENAME.len() <= 255);

        let temp_dir = TempDir::new().unwrap();
        let cache_dir = temp_dir.path().to_path_buf();

        // If we actually tried to query the key server, it would fail because of the non-existing
        // chip id. However, we prepopulate the file cache to test that the file cache is used
        // when available.
        let non_existing_chip_id = Identifier(vec![0; 32]);

        let cache_filename = HostSevCertificateProviderImpl::get_cache_filename(
            &non_existing_chip_id,
            &mock_snp_platform_status(),
        );
        let cache_path = cache_dir.join(cache_filename);
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(
            cache_path,
            rcgen::generate_simple_self_signed([]).unwrap().cert.der(),
        )
        .unwrap();

        let mut firmware = MockSevHostFirmware::new();
        firmware
            .expect_snp_platform_status()
            .return_once(|| Ok(mock_snp_platform_status()));
        firmware
            .expect_get_identifier()
            .return_once(move || Ok(non_existing_chip_id));

        let mut provider = HostSevCertificateProvider::new_for_test(cache_dir, Box::new(firmware));

        let chain_pem = provider
            .load_certificate_chain_pem()
            .await
            .expect("Failed to load certificate chain")
            .expect("No certificate chain");

        let cert_count = chain_pem.matches("-----BEGIN CERTIFICATE-----\n").count();
        assert_eq!(
            cert_count, 3,
            "Chain should contain exactly 3 certificates (VCEK, ASK, ARK)"
        );
    }
    #[test]
    async fn test_firmware_error() {
        let temp_dir = TempDir::new().unwrap();
        let cache_dir = temp_dir.path().to_path_buf();

        let mut erroring_firmware = MockSevHostFirmware::new();
        erroring_firmware
            .expect_snp_platform_status()
            .return_once(|| Err(sev::error::UserApiError::Unknown));

        assert!(
            HostSevCertificateProvider::new_for_test(cache_dir, Box::new(erroring_firmware))
                .load_certificate_chain_pem()
                .await
                .expect_err("Expected error")
                .to_string()
                .contains("Failed to get SNP platform status")
        );
    }

    #[test]
    async fn test_invalid_cached_certificate() {
        let temp_dir = TempDir::new().unwrap();
        let cache_dir = temp_dir.path().to_path_buf();

        // Create invalid cache file
        let cache_filename = HostSevCertificateProviderImpl::get_cache_filename(
            &mock_chip_id(),
            &mock_snp_platform_status(),
        );
        let cache_path = cache_dir.join(cache_filename);
        fs::write(&cache_path, b"invalid der data").unwrap();

        assert!(
            HostSevCertificateProvider::new_for_test(cache_dir, Box::new(mock_sev_host_firmware()))
                .load_certificate_chain_pem()
                .await
                .expect_err("Expected error")
                .to_string()
                .contains("Failed to parse VCEK")
        );
    }

    #[test]
    async fn test_load_from_amd_key_server() {
        let temp_dir = TempDir::new().unwrap();
        let cache_dir = temp_dir.path().to_path_buf();

        let mut provider = HostSevCertificateProvider::new_for_test(
            cache_dir.clone(),
            Box::new(mock_sev_host_firmware()),
        );

        // First call should fetch from AMD server and cache
        let chain_pem = provider
            .load_certificate_chain_pem()
            .await
            .expect("Could not load certificate chain")
            .expect("No certificate chain");

        assert_eq!(
            pem::parse_many(chain_pem)
                .expect("Parsing PEMs failed")
                .len(),
            3
        );

        // Verify cached data exists and is not empty
        let cached_data =
            fs::read(cache_dir.join(MOCK_CACHE_FILENAME)).expect("Could not read cached data");
        assert!(!cached_data.is_empty(), "Cached VCEK should not be empty");
    }
}
