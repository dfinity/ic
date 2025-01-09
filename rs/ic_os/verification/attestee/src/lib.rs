use crate::sev_firmware::SevFirmware;
use anyhow::Result;
use attestation::attestation::{FetchAttestationTokenCustomData, SevAttestationReport};
use der::Encode;
use sha2::{Digest, Sha512};

mod attestation_token_fetcher;
mod sev_firmware;

fn generate_attestation_report_for_attestation_token(
    firmware: &mut dyn SevFirmware,
    custom_data: &FetchAttestationTokenCustomData,
) -> Result<SevAttestationReport> {
    let mut encoded_custom_data = vec![];
    custom_data.encode(&mut encoded_custom_data)?;
    let mut hasher = Sha512::new();
    hasher.update(&encoded_custom_data);
    let report = firmware.get_report(hasher.finalize().into())?;
    Ok(report)
}
