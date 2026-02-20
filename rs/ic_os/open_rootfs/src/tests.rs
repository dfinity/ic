use crate::partitions::{A_BOOT_UUID, A_ROOT_UUID, B_BOOT_UUID, B_ROOT_UUID};
use crate::recovery::{CONFIG_PARTITION_LABEL, RECOVERY_PROPOSAL_FILE_NAME};
use anyhow::{Context, Result};
use candid::Encode;
use command_runner::MockCommandRunner;
use config_tool::serialize_and_write_config;
use config_types::{GuestOSConfig, TrustedExecutionEnvironmentConfig};
use ic_certification_test_utils::{CertificateBuilder, CertificateData};
use ic_crypto_tree_hash::{Label, LabeledTree, flatmap};
use ic_device::mount::PartitionSelector;
use ic_device::mount::testing::MockPartitionProvider;
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_governance_api::proposal::Action;
use ic_nns_governance_api::{
    BlessAlternativeGuestOsVersion, GuestLaunchMeasurement, GuestLaunchMeasurements, Proposal,
    ProposalInfo, ProposalStatus,
};
use linux_kernel_command_line::KernelCommandLine;
use rand::SeedableRng;
use sev_guest_testing::{FakeAttestationReportSigner, MockSevGuestFirmwareBuilder};
use std::collections::HashMap;
use std::fs;
use std::os::unix::prelude::ExitStatusExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tempfile::TempDir;
use uuid::Uuid;

const BASE_ROOTFS_HASH: &str = "ba5e";
const RECOVERY_ROOTFS_HASH: &str =
    "1d0dad2a5a983ae4be9a401b0aac325d2a38f1ba217efe0c43bc68806d2ba54a";
const CHIP_ID: [u8; 64] = [42u8; 64];
const MEASUREMENT: [u8; 48] = [66u8; 48];

const A_ROOT_PATH: &str = "/dev/disk/by-partuuid/7c0a626e-e5ea-e543-b5c5-300eb8304db7";
const B_ROOT_PATH: &str = "/dev/disk/by-partuuid/a78bc3a8-376c-054a-96e7-3904b915d0c5";

struct TestFixture {
    root_device: PathBuf,
    kernel_cmdline: KernelCommandLine,
    sev_firmware: Option<MockSevGuestFirmwareBuilder>,
    command_runner: MockCommandRunner,
    partition_provider: MockPartitionProvider,
}

impl TestFixture {
    fn new() -> Self {
        let signer = FakeAttestationReportSigner::default();

        let cmdline =
            KernelCommandLine::from_str(&format!("root_hash={BASE_ROOTFS_HASH}")).unwrap();

        let config_media = Arc::new(TempDir::with_prefix("config").unwrap());
        let guestos_config = GuestOSConfig {
            trusted_execution_environment_config: Some(TrustedExecutionEnvironmentConfig {
                sev_cert_chain_pem: signer.get_certificate_chain_pem(),
            }),
            ..Default::default()
        };

        serialize_and_write_config(&config_media.path().join("config.json"), &guestos_config)
            .expect("Failed to write GuestOS config");

        let mut partitions = HashMap::new();
        partitions.insert(
            PartitionSelector::ByUuid(A_BOOT_UUID),
            Arc::new(TempDir::with_prefix("a_boot").unwrap()),
        );
        partitions.insert(
            PartitionSelector::ByUuid(B_BOOT_UUID),
            Arc::new(TempDir::with_prefix("b_boot").unwrap()),
        );
        partitions.insert(
            PartitionSelector::ByLabel(CONFIG_PARTITION_LABEL.to_string()),
            config_media,
        );

        let sev_firmware = MockSevGuestFirmwareBuilder::new()
            .with_chip_id(CHIP_ID)
            .with_measurement(MEASUREMENT)
            .with_signer(Some(signer));

        let mut command_runner = MockCommandRunner::new();
        command_runner
            .expect_output()
            .withf(|cmd| {
                cmd.get_program() == "blkid" && cmd.get_args().any(|arg| arg == "PARTUUID")
            })
            .returning(|cmd| {
                let output = if cmd.get_args().any(|arg| arg == A_ROOT_PATH) {
                    A_ROOT_UUID.to_string()
                } else if cmd.get_args().any(|arg| arg == B_ROOT_PATH) {
                    B_ROOT_UUID.to_string()
                } else {
                    Uuid::nil().to_string()
                };
                Ok(std::process::Output {
                    status: std::process::ExitStatus::default(),
                    stdout: output.into_bytes(),
                    stderr: vec![],
                })
            });

        Self {
            root_device: A_ROOT_PATH.into(),
            kernel_cmdline: cmdline,
            sev_firmware: Some(sev_firmware),
            command_runner,
            partition_provider: MockPartitionProvider::new(partitions),
        }
    }

    fn set_root_device(&mut self, device: &str) -> &mut Self {
        self.root_device = device.into();
        self
    }

    fn set_root_hash(&mut self, hash: &str) -> &mut Self {
        self.kernel_cmdline = KernelCommandLine::from_str(&format!("root_hash={}", hash)).unwrap();
        self
    }

    /// Set up the expectation for the veritysetup command for `device` and `hash`
    /// with the expectation that veritysetup will succeed or fail as specified
    fn expect_verity(&mut self, device_str: &str, hash: &str, success: bool) -> &mut Self {
        let verifysetup_verify = format!(
            r#""veritysetup" "verify" "{device_str}" "{device_str}" "{hash}" "--hash-offset" "10603200512""#
        );
        self.command_runner
            .expect_output()
            .withf(move |cmd| format!("{cmd:?}") == verifysetup_verify)
            .once()
            .returning(move |_| {
                if success {
                    Ok(std::process::Output {
                        status: std::process::ExitStatus::from_raw(0),
                        stdout: vec![],
                        stderr: vec![],
                    })
                } else {
                    Ok(std::process::Output {
                        status: std::process::ExitStatus::from_raw(1),
                        stdout: vec![],
                        stderr: b"Mock veritysetup was configured to fail".to_vec(),
                    })
                }
            });

        // If success, expect a following open command
        let verifysetup_open = format!(
            r#""veritysetup" "open" "{device_str}" "vroot" "{device_str}" "{hash}" "--hash-offset" "10603200512""#
        );
        if success {
            self.command_runner
                .expect_output()
                .withf(move |cmd| format!("{cmd:?}") == verifysetup_open)
                .once()
                .returning(move |_| {
                    Ok(std::process::Output {
                        status: std::process::ExitStatus::default(),
                        stdout: vec![],
                        stderr: vec![],
                    })
                });
        }

        self
    }

    /// Adds an alternative GuestOS proposal to the partition with the given UUID.
    fn add_recovery_proposal(
        &mut self,
        partition_uuid: Uuid,
        proposal: BlessAlternativeGuestOsVersion,
        status: ProposalStatus,
    ) -> &mut Self {
        let proposal_info = ProposalInfo {
            id: Some(ProposalId { id: 1 }),
            status: status as i32,
            proposal: Some(Proposal {
                action: Some(Action::BlessAlternativeGuestOsVersion(proposal)),
                ..Default::default()
            }),
            ..Default::default()
        };

        // Encode as Option<ProposalInfo> to match what get_proposal_info returns
        let reply_bytes = Encode!(&Some(proposal_info)).unwrap();

        let tree = LabeledTree::SubTree(flatmap![
            Label::from("request_status") => LabeledTree::SubTree(flatmap![
                Label::from(vec![1u8; 32]) => LabeledTree::SubTree(flatmap![
                    Label::from("status") => LabeledTree::Leaf(b"replied".to_vec()),
                    Label::from("reply") => LabeledTree::Leaf(reply_bytes),
                ])
            ]),
            Label::from("time") => LabeledTree::Leaf(vec![0u8; 8])
        ]);

        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        let (_cert, root_pk, cert_cbor) =
            CertificateBuilder::new_with_rng(CertificateData::CustomTree(tree), &mut rng).build();

        let nns_public_key =
            ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_to_pem(root_pk)
                .expect("Failed to encode NNS public key");

        // Write proposal to boot partition
        fs::write(
            self.partition_provider
                .get_partition(PartitionSelector::ByUuid(partition_uuid))
                .unwrap()
                .join(RECOVERY_PROPOSAL_FILE_NAME),
            &cert_cbor,
        )
        .expect("Failed to write recovery proposal");

        // Write NNS public key override to CONFIG media
        fs::write(
            self.partition_provider
                .get_partition(PartitionSelector::ByLabel(
                    CONFIG_PARTITION_LABEL.to_string(),
                ))
                .unwrap()
                .join("nns_public_key_override.pem"),
            &nns_public_key,
        )
        .expect("Failed to write NNS public key");

        self
    }

    fn run(self) -> Result<()> {
        crate::run(
            &self.root_device,
            &self.kernel_cmdline,
            || {
                Ok(Box::new(
                    self.sev_firmware
                        .as_ref()
                        .context("Missing SEV firmware")?
                        .build(),
                ))
            },
            &self.command_runner,
            &self.partition_provider,
        )
    }
}

#[test]
fn test_run_succeeds_with_base_root_hash() {
    let mut fixture = TestFixture::new();
    fixture.expect_verity(A_ROOT_PATH, "ba5e", true);
    fixture.run().expect("Expected success");
}

#[test]
fn test_run_succeeds_with_base_root_hash_without_sev_firmware() {
    let mut fixture = TestFixture::new();
    fixture.sev_firmware = None;
    fixture.expect_verity(A_ROOT_PATH, "ba5e", true);
    fixture.run().expect("Expected success");
}

#[test]
fn test_run_fails_when_base_hash_fails_and_no_recovery() {
    let mut fixture = TestFixture::new();
    fixture.expect_verity(A_ROOT_PATH, BASE_ROOTFS_HASH, false);
    let result = fixture.run();

    assert!(result.is_err(), "Expected failure");
}

#[test]
fn test_run_with_missing_root_hash_in_cmdline() {
    let mut fixture = TestFixture::new();
    fixture.kernel_cmdline = KernelCommandLine::from_str("").unwrap();
    let result = fixture.run();

    assert!(result.is_err(), "Expected failure when root_hash missing");
    assert!(result.unwrap_err().to_string().contains("root_hash"));
}

#[test]
fn test_run_with_different_root_devices() {
    let test_cases = vec![(A_ROOT_PATH, "base_hash_1"), (B_ROOT_PATH, "base_hash_2")];

    for (device, hash) in test_cases {
        let mut fixture = TestFixture::new();
        fixture.set_root_device(device);
        fixture.set_root_hash(hash);
        fixture.expect_verity(device, hash, true);
        let result = fixture.run();

        assert!(result.is_ok(), "Expected success for device {}", device);
    }
}

#[test]
fn test_run_attempts_recovery_when_base_hash_fails() {
    let mut fixture = TestFixture::new();
    fixture.expect_verity(A_ROOT_PATH, BASE_ROOTFS_HASH, false);
    let result = fixture
        .run()
        .expect_err("Expected failure when no alternative GuestOS proposal found");

    assert!(
        format!("{result:?}").contains("No alternative GuestOS proposal found"),
        "Error should mention missing alternative GuestOS proposal"
    );
}

#[test]
fn test_recovery_proposal_end_to_end() {
    let mut fixture = TestFixture::new();

    let proposal = BlessAlternativeGuestOsVersion {
        chip_ids: Some(vec![CHIP_ID.to_vec()]),
        rootfs_hash: Some(RECOVERY_ROOTFS_HASH.to_string()),
        base_guest_launch_measurements: Some(GuestLaunchMeasurements {
            guest_launch_measurements: Some(vec![GuestLaunchMeasurement {
                measurement: Some(MEASUREMENT.to_vec()),
                metadata: None,
            }]),
        }),
    };
    fixture
        .expect_verity(A_ROOT_PATH, BASE_ROOTFS_HASH, false)
        .expect_verity(A_ROOT_PATH, RECOVERY_ROOTFS_HASH, true)
        .add_recovery_proposal(A_BOOT_UUID, proposal, ProposalStatus::Executed);

    fixture
        .run()
        .expect("rootfs via alternative GuestOS proposal failed");
}

#[test]
fn test_recovery_proposal_chip_id_mismatch() {
    let mut fixture = TestFixture::new();

    let proposal = BlessAlternativeGuestOsVersion {
        chip_ids: Some(vec![vec![1u8; 64]]), // does not include CHIP_ID
        rootfs_hash: Some(RECOVERY_ROOTFS_HASH.to_string()),
        base_guest_launch_measurements: Some(GuestLaunchMeasurements {
            guest_launch_measurements: Some(vec![GuestLaunchMeasurement {
                measurement: Some(MEASUREMENT.to_vec()),
                metadata: None,
            }]),
        }),
    };
    fixture
        .set_root_device(B_ROOT_PATH)
        .expect_verity(B_ROOT_PATH, BASE_ROOTFS_HASH, false)
        .add_recovery_proposal(B_BOOT_UUID, proposal, ProposalStatus::Executed);

    let error = fixture
        .run()
        .expect_err("rootfs via alternative GuestOS proposal should fail due to chip ID mismatch");
    assert!(format!("{error:?}").contains("InvalidChipId"), "{error:?}");
}

#[test]
fn test_recovery_proposal_measurement_mismatch() {
    let mut fixture = TestFixture::new();

    let proposal = BlessAlternativeGuestOsVersion {
        chip_ids: Some(vec![CHIP_ID.to_vec()]),
        rootfs_hash: Some(RECOVERY_ROOTFS_HASH.to_string()),
        base_guest_launch_measurements: Some(GuestLaunchMeasurements {
            guest_launch_measurements: Some(vec![GuestLaunchMeasurement {
                measurement: Some(vec![1u8; 48]), // different from MEASUREMENT
                metadata: None,
            }]),
        }),
    };
    fixture
        .set_root_device(B_ROOT_PATH)
        .expect_verity(B_ROOT_PATH, BASE_ROOTFS_HASH, false)
        .add_recovery_proposal(B_BOOT_UUID, proposal, ProposalStatus::Executed);

    let error = fixture.run().expect_err(
        "rootfs via alternative GuestOS proposal should fail due to measurement mismatch",
    );
    assert!(
        format!("{error:?}").contains("InvalidMeasurement"),
        "{error:?}"
    );
}

#[test]
fn test_recovery_proposal_rootfs_mismatch() {
    let mut fixture = TestFixture::new();
    let proposal = BlessAlternativeGuestOsVersion {
        chip_ids: Some(vec![CHIP_ID.to_vec()]),
        rootfs_hash: Some(RECOVERY_ROOTFS_HASH.to_string()),
        base_guest_launch_measurements: Some(GuestLaunchMeasurements {
            guest_launch_measurements: Some(vec![GuestLaunchMeasurement {
                measurement: Some(MEASUREMENT.to_vec()),
                metadata: None,
            }]),
        }),
    };
    fixture
        .set_root_device(B_ROOT_PATH)
        .expect_verity(B_ROOT_PATH, BASE_ROOTFS_HASH, false)
        // Failure when trying recovery hash
        .expect_verity(B_ROOT_PATH, RECOVERY_ROOTFS_HASH, false)
        .add_recovery_proposal(B_BOOT_UUID, proposal, ProposalStatus::Executed);
    let error = fixture.run().expect_err(
        "rootfs via alternative GuestOS proposal should fail due to rootfs hash mismatch",
    );
    assert!(format!("{error:?}").contains("veritysetup"), "{error:?}");
}

#[test]
fn test_nns_root_key_mismatch() {
    let mut fixture = TestFixture::new();
    let proposal = BlessAlternativeGuestOsVersion {
        chip_ids: Some(vec![CHIP_ID.to_vec()]),
        rootfs_hash: Some(RECOVERY_ROOTFS_HASH.to_string()),
        base_guest_launch_measurements: Some(GuestLaunchMeasurements {
            guest_launch_measurements: Some(vec![GuestLaunchMeasurement {
                measurement: Some(MEASUREMENT.to_vec()),
                metadata: None,
            }]),
        }),
    };
    fixture
        .set_root_device(B_ROOT_PATH)
        .expect_verity(B_ROOT_PATH, BASE_ROOTFS_HASH, false)
        .add_recovery_proposal(B_BOOT_UUID, proposal, ProposalStatus::Executed);

    // Remove NNS public key override, so proposal will be verified against public NNS key
    // which will fail.
    fs::remove_file(
        fixture
            .partition_provider
            .get_partition(PartitionSelector::ByLabel(
                CONFIG_PARTITION_LABEL.to_string(),
            ))
            .unwrap()
            .join("nns_public_key_override.pem"),
    )
    .expect("Failed to remove NNS public key");

    let error = fixture
        .run()
        .expect_err("rootfs via alternative GuestOS proposal should fail due to NNS key mismatch");
    assert!(
        format!("{error:?}").contains("Signature verification failed"),
        "{error:?}"
    );
}

#[test]
fn test_attestation_report_signature_mismatch() {
    let mut fixture = TestFixture::new();
    // Replace sev firmware so the attestation report is no longer signed by the cert chain
    // in the TEE config
    fixture.sev_firmware = Some(
        fixture
            .sev_firmware
            .unwrap()
            .with_signer(Some(FakeAttestationReportSigner::new([1; 32]))),
    );

    let proposal = BlessAlternativeGuestOsVersion {
        chip_ids: Some(vec![CHIP_ID.to_vec()]),
        rootfs_hash: Some(RECOVERY_ROOTFS_HASH.to_string()),
        base_guest_launch_measurements: Some(GuestLaunchMeasurements {
            guest_launch_measurements: Some(vec![GuestLaunchMeasurement {
                measurement: Some(MEASUREMENT.to_vec()),
                metadata: None,
            }]),
        }),
    };
    fixture
        .expect_verity(A_ROOT_PATH, BASE_ROOTFS_HASH, false)
        .add_recovery_proposal(A_BOOT_UUID, proposal, ProposalStatus::Executed);

    let error = fixture.run().expect_err(
        "rootfs via alternative GuestOS proposal should fail due to signature mismatch",
    );
    assert!(
        format!("{error:?}").contains("InvalidSignature"),
        "{error:?}"
    );
}

#[test]
fn test_recovery_proposal_status_not_executed() {
    let mut fixture = TestFixture::new();
    let proposal = BlessAlternativeGuestOsVersion {
        chip_ids: Some(vec![CHIP_ID.to_vec()]),
        rootfs_hash: Some(RECOVERY_ROOTFS_HASH.to_string()),
        base_guest_launch_measurements: Some(GuestLaunchMeasurements {
            guest_launch_measurements: Some(vec![GuestLaunchMeasurement {
                measurement: Some(MEASUREMENT.to_vec()),
                metadata: None,
            }]),
        }),
    };
    fixture
        .expect_verity(A_ROOT_PATH, BASE_ROOTFS_HASH, false)
        .add_recovery_proposal(A_BOOT_UUID, proposal, ProposalStatus::Open);

    let error = fixture.run().expect_err(
        "rootfs via alternative GuestOS proposal should fail due to proposal status mismatch",
    );
    assert!(
        format!("{error:?}").contains("PROPOSAL_STATUS_OPEN"),
        "{error:?}"
    );
}
