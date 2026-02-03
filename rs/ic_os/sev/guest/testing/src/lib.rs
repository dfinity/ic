use sev::parser::Encoder;
use sev_guest_firmware::MockSevGuestFirmware;
use sev_guest_firmware::SevGuestFirmware;

pub use attestation_testing::attestation_report::{
    AttestationReportBuilder, FakeAttestationReportSigner,
};

#[derive(Clone)]
pub struct MockSevGuestFirmwareBuilder {
    custom_data_override: Option<[u8; 64]>,
    /// If not set, the derived key will be derived from the measurement bytes.
    derived_key: Option<[u8; 32]>,
    measurement: [u8; 48],
    chip_id: [u8; 64],
    signer: Option<FakeAttestationReportSigner>,
    generates_report_with_wrong_custom_data: Option<bool>,
    generates_report_with_wrong_signature: Option<bool>,
}

impl Default for MockSevGuestFirmwareBuilder {
    fn default() -> Self {
        Self {
            derived_key: None,
            custom_data_override: None,
            measurement: [0u8; 48],
            chip_id: [0u8; 64],
            signer: None,
            generates_report_with_wrong_custom_data: None,
            generates_report_with_wrong_signature: None,
        }
    }
}

impl MockSevGuestFirmwareBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make the firmware return a custom data that does not match the one passed to `get_report`.
    /// Can be used for testing invalid attestation packages.
    /// Automatically marks the firmware as generating invalid custom data, unless overriden by
    /// `with_generates_report_with_wrong_custom_data`.
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

    /// Make the firmware return attestation reports signed by this signer.
    /// Automatically marks the firmware as generating valid signatures, unless overriden by
    /// `with_generates_report_with_wrong_signature`.
    pub fn with_signer(mut self, signer: Option<FakeAttestationReportSigner>) -> Self {
        self.signer = signer;
        self
    }

    /// By default, the mock firmware reports that it generates wrong custom data when
    /// `with_custom_data_override` is used, which is useful for testing invalid attestation
    /// packages.
    /// This can be overridden by setting this flag to `false`.
    pub fn with_generates_report_with_wrong_custom_data(mut self, value: bool) -> Self {
        self.generates_report_with_wrong_custom_data = Some(value);
        self
    }

    /// By default, the mock firmware reports that it generates valid signatures when
    /// `with_signer` is used.
    /// This can be overridden by setting this flag to `false`.
    pub fn with_generates_report_with_wrong_signature(mut self, value: bool) -> Self {
        self.generates_report_with_wrong_signature = Some(value);
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
            // In reality, the chip would use a more complex process to derive the key from the
            // measurement. In testing, we use a simple approach.
            Ok(this
                .derived_key
                .unwrap_or(this.measurement[4..36].try_into().unwrap()))
        });

        firmware
            .expect_generates_report_with_fake_root_cert()
            .return_const(true);
        firmware
            .expect_generates_report_with_wrong_custom_data()
            .return_const(
                self.generates_report_with_wrong_custom_data
                    .unwrap_or(self.custom_data_override.is_some()),
            );
        firmware
            .expect_generates_report_with_wrong_signature()
            .return_const(
                self.generates_report_with_wrong_signature
                    .unwrap_or(self.signer.is_none()),
            );

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

    fn generates_report_with_fake_root_cert(&self) -> bool {
        self.build().generates_report_with_fake_root_cert()
    }

    fn generates_report_with_wrong_custom_data(&self) -> bool {
        self.build().generates_report_with_wrong_custom_data()
    }

    fn generates_report_with_wrong_signature(&self) -> bool {
        self.build().generates_report_with_wrong_signature()
    }
}
