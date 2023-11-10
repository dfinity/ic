use anyhow::Result;
use core::fmt;
use openssl::x509::X509;
use sev::firmware::host::{CertTableEntry, CertType};
use std::fmt::{Display, Formatter};
use std::{fs, path::Path};

/// Location of certs
static ARK_PEM: &str = "/var/lib/ic/data/ark.pem";
static ASK_PEM: &str = "/var/lib/ic/data/ask.pem";
static VCEK_PEM: &str = "/var/lib/ic/data/vcek.pem";
static CERTS_DIR: &str = "/var/lib/ic/data";

#[derive(Default, Debug)]
pub struct Certs {
    pub ark: Option<X509>,
    pub ask: Option<X509>,
    pub vcek: Option<X509>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CertsError {
    ARKCertMissingError { description: String },
    ARKCertMismatchError,
    CertMissingError { description: String },
    CertExportError { description: String },
    SevFirmwareError,
    BadCertError,
    GetExtReportError { description: String },
    IOError { description: String },
}

impl Display for CertsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Load certs
/// If the certs are already available, return them
/// If ARK.pem is missing, return an error because it is hardcoded and considered the root of trust
/// If ASK.pem or VCEK.pem are missing, fetch them from PSP via SNP_GET_EXT_REPORT ioctl
pub fn load_certs() -> Result<Certs, CertsError> {
    if let Err(error) = is_available() {
        match error {
            CertsError::ARKCertMissingError { .. } => return Err(error),
            CertsError::CertMissingError { .. } => fetch_certs(Path::new(CERTS_DIR))?,
            _ => return Err(error),
        }
    }

    let certs = Certs {
        ark: read_pem(ARK_PEM),
        ask: read_pem(ASK_PEM),
        vcek: read_pem(VCEK_PEM),
    };

    Ok(certs)
}

/// Check if certs are available
fn is_available() -> Result<(), CertsError> {
    fs::metadata(ARK_PEM).map_err(|e| CertsError::ARKCertMissingError {
        description: format!("{}", e),
    })?;
    fs::metadata(ASK_PEM).map_err(|e| CertsError::CertMissingError {
        description: format!("{}", e),
    })?;
    fs::metadata(VCEK_PEM).map_err(|e| CertsError::CertMissingError {
        description: format!("{}", e),
    })?;
    Ok(())
}

fn read_pem(path: &str) -> Option<X509> {
    fs::read(path).ok().and_then(|f| X509::from_pem(&f).ok())
}

pub fn pem_to_der(pem: &Option<X509>) -> Vec<u8> {
    pem.as_ref()
        .and_then(|p| p.to_der().ok())
        .unwrap_or_default()
}

fn export_cert(c: &CertTableEntry, name: &str, certs_dir: &Path) -> Result<()> {
    let path = certs_dir.join(format!("{}.pem", name));
    fs::write(path, c.data.as_slice())
        .map_err(|e| anyhow::anyhow!(format!("Error writing cert {}, error: {:?}", name, e)))
}

/// Fetch certs from PSP firmware and write them to the cert location.
fn fetch_certs(certs_dir: &Path) -> Result<(), CertsError> {
    // Get extended attestation report to derive certs
    let mut guest_firmware =
        sev::firmware::guest::Firmware::open().map_err(|_| CertsError::SevFirmwareError)?;
    let (_report, certs) = guest_firmware
        .get_ext_report(None, None, Some(0))
        .map_err(|e| CertsError::GetExtReportError {
            description: format!("{}", e),
        })?;
    if certs.is_empty() {
        return Err(CertsError::CertMissingError {
            description: "get_ext_report failed to get certs".to_string(),
        });
    }

    for c in certs {
        match c.cert_type {
            CertType::ASK => {
                export_cert(&c, "ask", certs_dir).map_err(|e| CertsError::CertExportError {
                    description: format!("{}", e),
                })?
            }
            CertType::VCEK => {
                export_cert(&c, "vcek", certs_dir).map_err(|e| CertsError::CertExportError {
                    description: format!("{}", e),
                })?
            }
            CertType::ARK => {
                // Check if the new ARK.pem matches the hardcoded ARK.pem
                if fs::read(ARK_PEM).map_err(|e| CertsError::IOError {
                    description: format!("{}", e),
                })? != c.data()
                {
                    return Err(CertsError::ARKCertMismatchError);
                }
            }
            _ => {
                return Err(CertsError::BadCertError);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_load_certs() {
        assert!(load_certs().is_err());
    }

    #[test]
    fn test_export_certs() {
        // Starting of a pem cert
        const DATA: &[u8] = &[
            45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69,
            45, 45, 45, 45, 45,
        ];
        let c = CertTableEntry::new(CertType::ARK, Vec::from(DATA));
        let cert_dir = tempfile::tempdir().unwrap();
        let _ = export_cert(&c, "test", cert_dir.path());
        let expected_cert = cert_dir.path().join("test.pem");
        assert!(fs::metadata(expected_cert).is_ok());
    }
}
