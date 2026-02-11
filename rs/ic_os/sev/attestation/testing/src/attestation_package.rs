use crate::attestation_report::{AttestationReportBuilder, FakeAttestationReportSigner};
use attestation::SevCertificateChain;
use attestation::attestation_package::{
    ParsedSevAttestationPackage, SevRootCertificateVerification,
};
use attestation::custom_data::EncodeSevCustomData;
use std::fmt::Debug;

/// Helper for building SEV attestation packages for testing.
///
/// The returned attestation package's root certificate is obviously not a real AMD certificate,
/// but it passes verification under [SevRootCertificateVerification::TestOnlySkipVerification].
///
/// Example:
/// ```
/// let parsed_attestation_package = ParsedSevAttestationPackageBuilder::new()
///     .with_custom_data(&SomeCustomData { ... })
///     .with_measurement([21u8; 48])
///     .with_chip_id([33u8; 64])
///     .build();
/// // Or if an SevAttestationPackage is needed:
/// let sev_attestation_package: SevAttestationPackage = parsed_attestation_package.into();
/// ```
pub struct ParsedSevAttestationPackageBuilder {
    attestation_report_builder: AttestationReportBuilder,
    signer: FakeAttestationReportSigner,
    custom_data_debug_info: Option<String>,
}

impl Default for ParsedSevAttestationPackageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ParsedSevAttestationPackageBuilder {
    pub fn new() -> Self {
        Self {
            attestation_report_builder: AttestationReportBuilder::new(),
            signer: FakeAttestationReportSigner::default(),
            custom_data_debug_info: None,
        }
    }

    pub fn with_custom_data(mut self, custom_data: &(impl EncodeSevCustomData + Debug)) -> Self {
        self.attestation_report_builder = self
            .attestation_report_builder
            .with_custom_data(custom_data.encode_for_sev().unwrap().to_bytes());
        self.custom_data_debug_info = Some(format!("{custom_data:?}"));
        self
    }

    pub fn with_measurement(mut self, measurement: [u8; 48]) -> Self {
        self.attestation_report_builder = self
            .attestation_report_builder
            .with_measurement(measurement);
        self
    }

    pub fn with_chip_id(mut self, chip_id: [u8; 64]) -> Self {
        self.attestation_report_builder = self.attestation_report_builder.with_chip_id(chip_id);
        self
    }

    pub fn with_signer(mut self, signer: FakeAttestationReportSigner) -> Self {
        self.signer = signer;
        self
    }

    pub fn build(&self) -> ParsedSevAttestationPackage {
        let attestation_report = self.attestation_report_builder.build_signed(&self.signer);
        ParsedSevAttestationPackage::new(
            attestation_report,
            SevCertificateChain {
                vcek_pem: Some(self.signer.get_vcek_pem()),
                ask_pem: Some(self.signer.get_ask_pem()),
                ark_pem: Some(self.signer.get_ark_pem()),
            },
            SevRootCertificateVerification::TestOnlySkipVerification,
            self.custom_data_debug_info.clone(),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attestation::SevAttestationPackage;
    use attestation::attestation_package::AttestationPackageVerifier;
    use attestation::custom_data::{SevCustomData, SevCustomDataNamespace};
    use rand::SeedableRng;

    #[test]
    fn test_attestation_package_is_valid() {
        let custom_data = SevCustomData::random(
            SevCustomDataNamespace::Test,
            &mut rand::rngs::SmallRng::seed_from_u64(0),
        );
        let sev_attestation_package: SevAttestationPackage =
            ParsedSevAttestationPackageBuilder::new()
                .with_custom_data(&custom_data)
                .with_measurement([21u8; 48])
                .with_chip_id([33u8; 64])
                .build()
                .into();

        ParsedSevAttestationPackage::parse(
            sev_attestation_package,
            SevRootCertificateVerification::TestOnlySkipVerification,
        )
        .verify_measurement(&[[21u8; 48]])
        .verify_chip_id(&[[33u8; 64]])
        .verify_custom_data(&custom_data)
        .expect("Attestation package is invalid");
    }
}
