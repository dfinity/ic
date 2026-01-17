use sev::parser::Encoder;
use sev_guest::firmware::{MockSevGuestFirmware, SevGuestFirmware};

pub use attestation_testing::attestation_report::{
    AttestationReportBuilder, FakeAttestationReportSigner,
};

#[derive(Clone)]
pub struct MockSevGuestFirmwareBuilder {
    custom_data_override: Option<[u8; 64]>,
    derived_key: Option<[u8; 32]>,
    measurement: [u8; 48],
    chip_id: [u8; 64],
    signer: Option<FakeAttestationReportSigner>,
}

impl Default for MockSevGuestFirmwareBuilder {
    fn default() -> Self {
        Self {
            derived_key: None,
            custom_data_override: None,
            measurement: [0u8; 48],
            chip_id: [0u8; 64],
            signer: None,
        }
    }
}

impl MockSevGuestFirmwareBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_custom_data_override(mut self, custom_data: Option<[u8; 64]>) -> Self {
        self.custom_data_override = custom_data;
        self
    }

    pub fn with_derived_key(mut self, derived_key: Option<[u8; 32]>) -> Self {
        self.derived_key = derived_key;
        self
    }

    pub fn with_measurement(mut self, measurement: [u8; 48]) -> Self {
        self.measurement = measurement;
        self
    }

    pub fn with_chip_id(mut self, chip_id: [u8; 64]) -> Self {
        self.chip_id = chip_id;
        self
    }

    pub fn with_signer(mut self, signer: Option<FakeAttestationReportSigner>) -> Self {
        self.signer = signer;
        self
    }

    pub fn build(&self) -> MockSevGuestFirmware {
        let mut firmware = MockSevGuestFirmware::new();
        let this = self.clone();
        firmware
            .expect_get_report()
            .returning(move |_, custom_data, _| {
                let actual_custom_data =
                    this.custom_data_override.or(custom_data).unwrap_or([0; 64]);

                let builder = AttestationReportBuilder::new()
                    .with_measurement(this.measurement)
                    .with_custom_data(actual_custom_data)
                    .with_chip_id(this.chip_id);

                let attestation_report = if let Some(signer) = &this.signer {
                    builder.build_signed(signer)
                } else {
                    builder.build_unsigned()
                };

                let mut out = vec![];
                attestation_report.encode(&mut out, ()).unwrap();
                Ok(out)
            });

        firmware.expect_get_derived_key().returning(move |_, _| {
            Ok(this
                .derived_key
                .unwrap_or(this.measurement[4..36].try_into().unwrap()))
        });

        firmware.expect_is_mock().returning(|| true);

        firmware
    }
}

impl SevGuestFirmware for MockSevGuestFirmwareBuilder {
    fn get_report(
        &mut self,
        message_version: Option<u32>,
        data: Option<[u8; 64]>,
        vmpl: Option<u32>,
    ) -> Result<Vec<u8>, sev::error::UserApiError> {
        self.build().get_report(message_version, data, vmpl)
    }

    fn get_derived_key(
        &mut self,
        message_version: Option<u32>,
        derived_key_request: sev::firmware::guest::DerivedKey,
    ) -> Result<[u8; 32], sev::error::UserApiError> {
        self.build()
            .get_derived_key(message_version, derived_key_request)
    }

    fn is_mock(&self) -> bool {
        self.build().is_mock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sev::certs::snp::{Chain, Verifiable};

    #[test]
    fn test_fake_cert_chain_and_signature_are_accepted_by_sev_lib() {
        let signer = FakeAttestationReportSigner::default();
        let attestation_report = AttestationReportBuilder::new().build_signed(&signer);

        let cert_chain = Chain::from_pem(
            signer.get_ark_pem().as_bytes(),
            signer.get_ask_pem().as_bytes(),
            signer.get_vcek_pem().as_bytes(),
        )
        .expect("Failed to create certificate chain from PEM");

        (&cert_chain, &attestation_report)
            .verify()
            .expect("Failed to verify attestation report with fake signer");
    }
}
