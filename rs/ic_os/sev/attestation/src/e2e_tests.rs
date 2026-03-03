use crate::attestation_package::{
    AttestationPackageVerifier, ParsedSevAttestationPackage, SevRootCertificateVerification,
};
use crate::custom_data::{DerEncodedCustomData, EncodeSevCustomData, SevCustomDataNamespace};
use crate::{
    SevAttestationPackage, SevCertificateChain, VerificationErrorDescription,
    VerificationErrorDetail,
};
use attestation_testing::attestation_report::{
    AttestationReportBuilder, FakeAttestationReportSigner,
};
use sev::parser::ByteParser;

const CHIP_ID: [u8; 64] = [3; 64];
const MEASUREMENT: [u8; 48] = [42; 48];

#[derive(der::Sequence, Debug)]
struct FooCustomData {
    a: i32,
    b: i64,
}

#[derive(der::Sequence, Debug)]
struct NewFooCustomData {
    a: i32,
}

impl DerEncodedCustomData for FooCustomData {
    fn namespace(&self) -> SevCustomDataNamespace {
        SevCustomDataNamespace::Test
    }

    fn needs_legacy_encoding() -> bool {
        true
    }
}

impl DerEncodedCustomData for NewFooCustomData {
    fn namespace(&self) -> SevCustomDataNamespace {
        SevCustomDataNamespace::Test
    }
}

const CUSTOM_DATA: FooCustomData = FooCustomData {
    a: 42,
    b: 1234567890,
};

const NEW_CUSTOM_DATA: NewFooCustomData = NewFooCustomData { a: 42 };

fn generate_valid_attestation_package() -> SevAttestationPackage {
    let signer = FakeAttestationReportSigner::default();

    let custom_data_bytes = CUSTOM_DATA
        .encode_for_sev()
        .expect("Failed to encode custom data for SEV")
        .to_bytes();

    let attestation_report = AttestationReportBuilder::new()
        .with_custom_data(custom_data_bytes)
        .with_measurement(MEASUREMENT)
        .with_chip_id(CHIP_ID)
        .build_signed(&signer);

    let attestation_report_bytes = attestation_report
        .to_bytes()
        .expect("Failed to serialize attestation report");

    SevAttestationPackage {
        attestation_report: Some(attestation_report_bytes.to_vec()),
        certificate_chain: Some(SevCertificateChain {
            vcek_pem: Some(signer.get_vcek_pem()),
            ask_pem: Some(signer.get_ask_pem()),
            ark_pem: Some(signer.get_ark_pem()),
        }),
        custom_data_debug_info: Some(format!("{CUSTOM_DATA:?}")),
    }
}

#[test]
fn test_valid_attestation_package() {
    let attestation_report = *ParsedSevAttestationPackage::parse(
        generate_valid_attestation_package(),
        SevRootCertificateVerification::TestOnlySkipVerification,
    )
    .verify_measurement(&[MEASUREMENT])
    .verify_custom_data(&CUSTOM_DATA)
    .verify_chip_id(&[CHIP_ID])
    .expect("Failed to verify attestation package")
    .attestation_report();

    assert_eq!(attestation_report.chip_id.as_slice(), CHIP_ID);
    assert_eq!(attestation_report.measurement.as_slice(), MEASUREMENT);
    assert_eq!(
        attestation_report.report_data.as_slice(),
        CUSTOM_DATA
            .encode_for_sev()
            .expect("Failed to encode custom data for SEV")
            .to_bytes()
    );
}

#[test]
fn test_invalid_attestation_report() {
    let mut attestation_package = generate_valid_attestation_package();

    // Truncate the attestation report to make it unparsable.
    attestation_package
        .attestation_report
        .as_mut()
        .unwrap()
        .truncate(5);

    let error = ParsedSevAttestationPackage::parse(
        attestation_package,
        SevRootCertificateVerification::TestOnlySkipVerification,
    )
    .expect_err("Verification should fail due to invalid attestation report")
    .detail
    .unwrap();

    assert!(
        matches!(
            error,
            VerificationErrorDetail::InvalidAttestationReport { .. }
        ),
        "Expected InvalidAttestationReport error, got {error:?}",
    );
}

#[test]
fn test_invalid_signature() {
    let mut attestation_package = generate_valid_attestation_package();

    // Corrupt the attestation report to invalidate the signature.
    if let Some(report) = &mut attestation_package.attestation_report
        && !report.is_empty()
    {
        report[0] ^= 0xFF; // Flip some bits
    }

    let error = ParsedSevAttestationPackage::parse(
        attestation_package,
        SevRootCertificateVerification::TestOnlySkipVerification,
    )
    .expect_err("Verification should fail due to invalid signature")
    .detail
    .unwrap();

    assert!(
        matches!(error, VerificationErrorDetail::InvalidSignature { .. }),
        "Expected InvalidSignature error, got {error:?}",
    );
}

#[test]
fn test_invalid_custom_data() {
    let attestation_package = generate_valid_attestation_package();

    let invalid_custom_data = FooCustomData {
        a: 43, // Different from the original
        b: 1234567890,
    };

    let error = ParsedSevAttestationPackage::parse(
        attestation_package,
        SevRootCertificateVerification::TestOnlySkipVerification,
    )
    .unwrap()
    .verify_custom_data(&invalid_custom_data)
    .expect_err("Verification should fail due to invalid custom data")
    .detail
    .unwrap();

    assert!(
        matches!(error, VerificationErrorDetail::InvalidCustomData { .. }),
        "Expected InvalidCustomData error, got {error:?}",
    );
}

#[test]
fn test_invalid_measurement() {
    let attestation_package = generate_valid_attestation_package();

    let error = ParsedSevAttestationPackage::parse(
        attestation_package,
        SevRootCertificateVerification::TestOnlySkipVerification,
    )
    .unwrap()
    .verify_measurement(&[[0; 48]]) // Different from MEASUREMENT
    .expect_err("Verification should fail due to invalid measurement")
    .detail
    .unwrap();

    assert!(
        matches!(error, VerificationErrorDetail::InvalidMeasurement { .. }),
        "Expected InvalidMeasurement error, got {error:?}",
    );
}

#[test]
fn test_invalid_chip_id() {
    let attestation_package = generate_valid_attestation_package();

    let error = ParsedSevAttestationPackage::parse(
        attestation_package,
        SevRootCertificateVerification::TestOnlySkipVerification,
    )
    .unwrap()
    .verify_chip_id(&[[0; 64]]) // Different from CHIP_ID
    .expect_err("Verification should fail due to invalid chip ID")
    .detail
    .unwrap();

    assert!(
        matches!(error, VerificationErrorDetail::InvalidChipId { .. }),
        "Expected InvalidChipId error, got {error:?}",
    );
}

#[test]
fn test_invalid_certificate_chain() {
    let mut attestation_package = generate_valid_attestation_package();

    // Replace the ASK with one that does not sign the VCEK.
    attestation_package
        .certificate_chain
        .as_mut()
        .unwrap()
        .ask_pem
        .replace(FakeAttestationReportSigner::new([1; 32]).get_ask_pem());

    let error = ParsedSevAttestationPackage::parse(
        attestation_package,
        SevRootCertificateVerification::TestOnlySkipVerification,
    )
    .expect_err("Verification should fail due to invalid certificate chain")
    .detail
    .unwrap();

    assert!(
        matches!(
            error,
            VerificationErrorDetail::InvalidCertificateChain { .. }
        ),
        "Expected InvalidCertificateChain error, got {error:?}",
    );
}

#[test]
fn test_invalid_root_certificate() {
    // generate_valid_attestation_package generates a valid package but with our own fake root cert
    // which won't pass root cert verification.
    let attestation_package = generate_valid_attestation_package();

    let error = ParsedSevAttestationPackage::parse(
        attestation_package,
        SevRootCertificateVerification::Verify,
    )
    .expect_err("Verification should fail due to invalid root certificate")
    .detail
    .unwrap();

    assert!(
        matches!(
            &error,
            VerificationErrorDetail::InvalidCertificateChain(VerificationErrorDescription { message })
                if message.contains("does not match expected root certificate")
        ),
        "Expected error about unexpected root certificate, got {error:?}",
    );
}

#[test]
fn test_legacy_custom_data_accepted() {
    let signer = FakeAttestationReportSigner::default();

    let legacy_custom_data = CUSTOM_DATA
        .encode_for_sev_legacy()
        .expect("Failed to encode custom data in legacy format");

    let attestation_report_bytes = AttestationReportBuilder::new()
        .with_custom_data(legacy_custom_data)
        .with_measurement(MEASUREMENT)
        .with_chip_id(CHIP_ID)
        .build_signed(&signer)
        .to_bytes()
        .unwrap();

    let attestation_package = SevAttestationPackage {
        attestation_report: Some(attestation_report_bytes.to_vec()),
        certificate_chain: Some(SevCertificateChain {
            vcek_pem: Some(signer.get_vcek_pem()),
            ask_pem: Some(signer.get_ask_pem()),
            ark_pem: Some(signer.get_ark_pem()),
        }),
        custom_data_debug_info: None,
    };

    ParsedSevAttestationPackage::parse(
        attestation_package,
        SevRootCertificateVerification::TestOnlySkipVerification,
    )
    .verify_measurement(&[MEASUREMENT])
    .verify_custom_data(&CUSTOM_DATA)
    .verify_chip_id(&[CHIP_ID])
    .expect("Failed to verify attestation package with legacy custom data format");
}

#[test]
fn test_legacy_custom_data_not_accepted_for_new_types() {
    let signer = FakeAttestationReportSigner::default();

    let legacy_custom_data = NEW_CUSTOM_DATA
        .encode_for_sev_legacy()
        .expect("Failed to encode custom data in legacy format");

    let attestation_report_bytes = AttestationReportBuilder::new()
        .with_custom_data(legacy_custom_data)
        .with_measurement(MEASUREMENT)
        .with_chip_id(CHIP_ID)
        .build_signed(&signer)
        .to_bytes()
        .unwrap();

    let attestation_package = SevAttestationPackage {
        attestation_report: Some(attestation_report_bytes.to_vec()),
        certificate_chain: Some(SevCertificateChain {
            vcek_pem: Some(signer.get_vcek_pem()),
            ask_pem: Some(signer.get_ask_pem()),
            ark_pem: Some(signer.get_ark_pem()),
        }),
        custom_data_debug_info: None,
    };

    let error = ParsedSevAttestationPackage::parse(
        attestation_package,
        SevRootCertificateVerification::TestOnlySkipVerification,
    )
    .verify_custom_data(&NEW_CUSTOM_DATA)
    .expect_err(
        "Verification should fail because legacy custom data format is not accepted for new types",
    )
    .detail
    .unwrap();

    assert!(
        matches!(error, VerificationErrorDetail::InvalidCustomData { .. }),
        "Expected InvalidCustomData error, got {error:?}",
    );
}
