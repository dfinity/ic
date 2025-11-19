use crate::attestation_package::generate_attestation_package;
use crate::custom_data::{DerEncodedCustomData, EncodeSevCustomData};
use crate::verification::{SevRootCertificateVerification, verify_attestation_package};
use crate::{SevAttestationPackage, VerificationErrorDescription, VerificationErrorDetail};
use config_types::TrustedExecutionEnvironmentConfig;
use ic_sev::guest::firmware::MockSevGuestFirmware;
use ic_sev::guest::testing::{FakeAttestationReportSigner, MockSevGuestFirmwareBuilder};
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;

const CHIP_ID: [u8; 64] = [3; 64];
const MEASUREMENT: [u8; 48] = [42; 48];

#[derive(der::Sequence, Debug)]
struct FooCustomData {
    a: i32,
    b: i64,
}

const CUSTOM_DATA: FooCustomData = FooCustomData {
    a: 42,
    b: 1234567890,
};

fn valid_sev_firmware() -> MockSevGuestFirmware {
    let signer = FakeAttestationReportSigner::default();
    MockSevGuestFirmwareBuilder::new()
        .with_chip_id(CHIP_ID)
        .with_measurement(MEASUREMENT)
        .with_signer(Some(signer))
        .build()
}

fn generate_valid_attestation_package() -> SevAttestationPackage {
    generate_attestation_package(
        &mut valid_sev_firmware(),
        &TrustedExecutionEnvironmentConfig {
            sev_cert_chain_pem: FakeAttestationReportSigner::default().get_certificate_chain_pem(),
        },
        &DerEncodedCustomData(CUSTOM_DATA),
    )
    .expect("Failed to generate attestation package")
}

#[test]
fn test_valid_attestation_package() {
    let attestation_package = generate_valid_attestation_package();

    let attestation_report =
        AttestationReport::from_bytes(attestation_package.attestation_report.as_ref().unwrap())
            .expect("Failed to parse attestation report from attestation package");

    assert_eq!(attestation_report.chip_id.as_slice(), CHIP_ID);
    assert_eq!(attestation_report.measurement.as_slice(), MEASUREMENT);
    assert_eq!(
        attestation_report.report_data.as_slice(),
        &DerEncodedCustomData(CUSTOM_DATA)
            .encode_for_sev()
            .expect("Failed to encode custom data for SEV"),
    );

    verify_attestation_package(
        &attestation_package,
        SevRootCertificateVerification::TestOnlySkipVerification,
        &[MEASUREMENT],
        &DerEncodedCustomData(CUSTOM_DATA),
        Some(&CHIP_ID),
    )
    .expect("Failed to verify attestation package");

    verify_attestation_package(
        &attestation_package,
        SevRootCertificateVerification::TestOnlySkipVerification,
        &[MEASUREMENT],
        &DerEncodedCustomData(CUSTOM_DATA),
        None, // Skip chip ID check
    )
    .expect("Failed to verify attestation package");
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

    let error = verify_attestation_package(
        &attestation_package,
        SevRootCertificateVerification::TestOnlySkipVerification,
        &[MEASUREMENT],
        &DerEncodedCustomData(CUSTOM_DATA),
        Some(&CHIP_ID),
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

    let error = verify_attestation_package(
        &attestation_package,
        SevRootCertificateVerification::TestOnlySkipVerification,
        &[MEASUREMENT],
        &DerEncodedCustomData(CUSTOM_DATA),
        Some(&CHIP_ID),
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

    let error = verify_attestation_package(
        &attestation_package,
        SevRootCertificateVerification::TestOnlySkipVerification,
        &[MEASUREMENT],
        &DerEncodedCustomData(invalid_custom_data),
        Some(&CHIP_ID),
    )
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

    let error = verify_attestation_package(
        &attestation_package,
        SevRootCertificateVerification::TestOnlySkipVerification,
        &[[0; 48]], // Different from MEASUREMENT
        &DerEncodedCustomData(CUSTOM_DATA),
        Some(&CHIP_ID),
    )
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

    let error = verify_attestation_package(
        &attestation_package,
        SevRootCertificateVerification::TestOnlySkipVerification,
        &[MEASUREMENT],
        &DerEncodedCustomData(CUSTOM_DATA),
        Some(&[0; 64]), // Different from CHIP_ID
    )
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

    let error = verify_attestation_package(
        &attestation_package,
        SevRootCertificateVerification::TestOnlySkipVerification,
        &[MEASUREMENT],
        &DerEncodedCustomData(CUSTOM_DATA),
        Some(&CHIP_ID),
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

    let error = verify_attestation_package(
        &attestation_package,
        SevRootCertificateVerification::Verify,
        &[MEASUREMENT],
        &DerEncodedCustomData(CUSTOM_DATA),
        Some(&CHIP_ID),
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
