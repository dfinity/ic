#![cfg(test)]

use anyhow::bail;
use attestation::verification::SevRootCertificateVerification;
use attestation_testing::registry::setup_mock_registry_client_with_blessed_versions;
use config_types::{
    DeploymentEnvironment, GuestOSConfig, GuestOSSettings, GuestOSUpgradeConfig, GuestVMType,
    ICOSSettings, Ipv6Config, NetworkSettings, TrustedExecutionEnvironmentConfig,
};
use futures::future::Either;
use futures::{FutureExt, TryFutureExt};
use guest_upgrade_client::DiskEncryptionKeyExchangeClientAgent;
use guest_upgrade_server::DiskEncryptionKeyExchangeServerAgent;
use guest_upgrade_shared::DEFAULT_SERVER_PORT;
use ic_protobuf::registry::replica_version::v1::{
    GuestLaunchMeasurement, GuestLaunchMeasurements, ReplicaVersionRecord,
};
use ic_sev::guest::key_deriver::{Key, derive_key_from_sev_measurement};
use ic_sev::guest::testing::{FakeAttestationReportSigner, MockSevGuestFirmwareBuilder};
use std::future::Future;
use std::net::Ipv6Addr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tempfile::NamedTempFile;
use vsock_lib::MockVSockClient;
use vsock_lib::protocol::{Command, Payload};

static FREE_PORT: AtomicU16 = AtomicU16::new(DEFAULT_SERVER_PORT);

const REPLICA_VERSION: &str = "replica_version_1";
/// We register the following two measurements in the mock registry.
const DEFAULT_CLIENT_MEASUREMENT: [u8; 48] = [42; 48];
const DEFAULT_SERVER_MEASUREMENT: [u8; 48] = [52; 48];
/// A measurement that is not registered in the mock registry.
const UNREGISTERED_MEASUREMENT: [u8; 48] = [99; 48];
/// Custom data that does not match the expected value.
const BOGUS_CUSTOM_DATA: [u8; 64] = [255; 64];
/// Expected chip ID of the machine.
const DEFAULT_CHIP_ID: [u8; 64] = [88; 64];
/// Chip ID that is different from the expected one.
const DIFFERENT_CHIP_ID: [u8; 64] = [123; 64];

#[derive(Debug, Clone)]
struct TestConfig {
    /// Client measurement for SEV attestation
    client_measurement: [u8; 48],
    /// Server measurement for SEV attestation
    server_measurement: [u8; 48],
    /// Server chip ID (should be same as client for success)
    server_chip_id: [u8; 64],
    /// Client chip ID
    client_chip_id: [u8; 64],
    /// Whether to sign attestation reports
    sign_attestation_reports: bool,
    /// Custom data to use in attestation (None for default)
    /// Allows testing invalid attestation data
    custom_data_override: Option<[u8; 64]>,
    can_open_disk: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            client_measurement: DEFAULT_CLIENT_MEASUREMENT,
            server_measurement: DEFAULT_SERVER_MEASUREMENT,
            sign_attestation_reports: true,
            custom_data_override: None,
            client_chip_id: DEFAULT_CHIP_ID,
            server_chip_id: DEFAULT_CHIP_ID,
            can_open_disk: false,
        }
    }
}

/// Test fixture containing all shared setup for disk encryption key exchange tests
struct DiskEncryptionKeyExchangeTestFixture {
    /// Mock registry client
    registry_client: Arc<dyn ic_interfaces_registry::RegistryClient>,
    /// Trusted execution environment configuration
    trusted_execution_environment_config: TrustedExecutionEnvironmentConfig,
    /// Guest OS configuration for the client
    client_guestos_config: GuestOSConfig,
    /// Temporary file for storing previous key
    previous_key: NamedTempFile,
    /// Server mock SEV firmware
    server_sev_firmware: MockSevGuestFirmwareBuilder,
    /// Client mock SEV firmware
    client_sev_firmware: MockSevGuestFirmwareBuilder,
    /// Port for the server to listen on
    server_port: u16,
    /// True to assume that the disk can already be opened without key exchange
    can_open_disk: bool,
}

impl DiskEncryptionKeyExchangeTestFixture {
    fn new(config: TestConfig) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let registry_client = Arc::new(setup_mock_registry_client_with_blessed_versions(
            1.into(),
            &[REPLICA_VERSION],
            &[(
                REPLICA_VERSION,
                ReplicaVersionRecord {
                    release_package_sha256_hex: "abc".to_string(),
                    guest_launch_measurements: Some(GuestLaunchMeasurements {
                        guest_launch_measurements: vec![
                            GuestLaunchMeasurement {
                                measurement: DEFAULT_CLIENT_MEASUREMENT.into(),
                                metadata: None,
                            },
                            GuestLaunchMeasurement {
                                measurement: DEFAULT_SERVER_MEASUREMENT.into(),
                                metadata: None,
                            },
                        ],
                    }),
                    release_package_urls: vec![],
                },
            )],
        ));

        let fake_attestation_report_signer = FakeAttestationReportSigner::default();

        let trusted_execution_environment_config = TrustedExecutionEnvironmentConfig {
            sev_cert_chain_pem: fake_attestation_report_signer.get_certificate_chain_pem(),
        };

        let client_guestos_config = GuestOSConfig {
            config_version: "1.0".to_string(),
            network_settings: NetworkSettings {
                ipv6_config: Ipv6Config::Unknown,
                ipv4_config: None,
                domain_name: None,
            },
            icos_settings: ICOSSettings {
                node_reward_type: None,
                mgmt_mac: Default::default(),
                deployment_environment: DeploymentEnvironment::Mainnet,
                nns_urls: vec![],
                use_node_operator_private_key: false,
                enable_trusted_execution_environment: true,
                use_ssh_authorized_keys: false,
                icos_dev_settings: Default::default(),
            },
            guestos_settings: GuestOSSettings::default(),
            guest_vm_type: GuestVMType::Upgrade,
            upgrade_config: GuestOSUpgradeConfig {
                peer_guest_vm_address: Some(Ipv6Addr::LOCALHOST),
            },
            trusted_execution_environment_config: Some(
                trusted_execution_environment_config.clone(),
            ),
            recovery_config: None,
        };

        let previous_key = NamedTempFile::new().unwrap();
        // Increment port for each test case so tests can run in parallel
        let server_port = FREE_PORT.fetch_add(1, Ordering::Relaxed);

        Self {
            server_sev_firmware: MockSevGuestFirmwareBuilder::new()
                .with_chip_id(config.server_chip_id)
                .with_custom_data_override(config.custom_data_override)
                .with_signer(
                    config
                        .sign_attestation_reports
                        .then_some(fake_attestation_report_signer.clone()),
                )
                .with_measurement(config.server_measurement),
            client_sev_firmware: MockSevGuestFirmwareBuilder::new()
                .with_chip_id(config.client_chip_id)
                .with_custom_data_override(config.custom_data_override)
                .with_signer(
                    config
                        .sign_attestation_reports
                        .then_some(fake_attestation_report_signer.clone()),
                )
                .with_measurement(config.client_measurement),
            registry_client,
            trusted_execution_environment_config,
            client_guestos_config,
            previous_key,
            server_port,
            can_open_disk: config.can_open_disk,
        }
    }

    /// Run the key exchange test and return (server status, client status).
    async fn run_key_exchange_test(&self) -> (anyhow::Result<()>, anyhow::Result<()>) {
        let mut vsock_client = MockVSockClient::default();
        let client_agent = self.create_client_agent();

        let (client_result_send, client_result_recv) = tokio::sync::oneshot::channel();

        vsock_client
            .expect_send_command()
            .once()
            .withf(|command| matches!(command, Command::StartUpgradeGuestVM))
            .return_once(move |_| {
                println!("Starting Upgrade Client");
                tokio::spawn(async move {
                    let client_result = client_agent.run().await;
                    client_result_send
                        .send(client_result)
                        .expect("Failed to send client result")
                });
                Ok(Payload::NoPayload)
            });

        let server_agent = self.create_server_agent(vsock_client);

        let server_future = server_agent
            .exchange_keys()
            .map_err(|e| e.into())
            .inspect_ok(|_| println!("Server finished successfully"))
            .inspect_err(|e| eprintln!("Server finished with error: {e:?}"));

        let client_future = client_result_recv
            .map(|result| result.expect("Failed to receive client result"))
            .inspect_ok(|_| println!("Client finished successfully"))
            .inspect_err(|e| eprintln!("Client finished with error: {e:?}"));

        join_with_timeout(server_future.boxed(), client_future.boxed()).await
    }

    fn create_server_agent(
        &self,
        vsock_client: MockVSockClient,
    ) -> DiskEncryptionKeyExchangeServerAgent {
        let server_sev_firmware = self.server_sev_firmware.clone();
        DiskEncryptionKeyExchangeServerAgent::new_for_testing(
            tokio::runtime::Handle::current(),
            Box::new(vsock_client),
            Arc::new(move || Ok(Box::new(server_sev_firmware.clone()))),
            SevRootCertificateVerification::TestOnlySkipVerification,
            self.trusted_execution_environment_config.clone(),
            self.registry_client.clone(),
            self.server_port,
            Duration::from_secs(2),
        )
    }

    fn create_client_agent(&self) -> DiskEncryptionKeyExchangeClientAgent {
        let can_open_disk = self.can_open_disk;
        DiskEncryptionKeyExchangeClientAgent::new(
            self.client_guestos_config.clone(),
            SevRootCertificateVerification::TestOnlySkipVerification,
            Box::new(self.client_sev_firmware.clone()),
            self.registry_client.clone(),
            Box::new(move |_, _, _| Ok(can_open_disk)),
            self.previous_key.path().to_path_buf(),
            self.server_port,
        )
    }

    /// Check if the previous key file was populated correctly
    fn verify_previous_key_populated(&self) {
        let key_content =
            std::fs::read_to_string(self.previous_key.path()).expect("Failed to read previous key");

        let expected_key = derive_key_from_sev_measurement(
            &mut self.server_sev_firmware.clone(),
            Key::DiskEncryptionKey {
                device_path: Path::new("/dev/vda10"),
            },
        )
        .unwrap();

        assert_eq!(
            key_content, expected_key,
            "Previous key file content does not match expected derived key"
        );
    }
}

/// Wait for either future to finish and then wait a little more for the other future to finish (if
/// one is stuck, we don't want to wait indefinitely).
async fn join_with_timeout<A, B>(
    future_a: impl Future<Output = anyhow::Result<A>> + Unpin,
    future_b: impl Future<Output = anyhow::Result<B>> + Unpin,
) -> (anyhow::Result<A>, anyhow::Result<B>) {
    const TIMEOUT: Duration = Duration::from_millis(500);

    match futures::future::select(future_a, future_b).await {
        Either::Left((future_a_result, future_b)) => {
            let future_b_result = tokio::time::timeout(TIMEOUT, future_b)
                .await
                .unwrap_or_else(|_| bail!("Timeout"));
            (future_a_result, future_b_result)
        }
        Either::Right((future_b_result, future_a)) => {
            let future_a_result = tokio::time::timeout(TIMEOUT, future_a)
                .await
                .unwrap_or_else(|_| bail!("Timeout"));
            (future_a_result, future_b_result)
        }
    }
}

fn assert_status_contains_error(result: &anyhow::Result<()>, error: &str) {
    let err = result.as_ref().expect_err("Expected error");
    assert!(format!("{err:?}").contains(error), "{err:?}");
}

fn assert_statuses_contain_errors(
    (server_result, client_result): (anyhow::Result<()>, anyhow::Result<()>),
    error: &str,
) {
    assert_status_contains_error(&server_result, error);
    assert_status_contains_error(&client_result, error);
}

#[tokio::test]
async fn test_exchange_keys_successfully() {
    let fixture = DiskEncryptionKeyExchangeTestFixture::new(TestConfig::default());
    let (server_result, client_result) = fixture.run_key_exchange_test().await;

    server_result.expect("Key exchange should succeed");
    client_result.expect("Key exchange should succeed");

    fixture.verify_previous_key_populated();
}

#[tokio::test]
async fn test_client_measurement_not_in_registry() {
    let config = TestConfig {
        client_measurement: UNREGISTERED_MEASUREMENT,
        ..Default::default()
    };

    assert_statuses_contain_errors(
        DiskEncryptionKeyExchangeTestFixture::new(config)
            .run_key_exchange_test()
            .await,
        "InvalidMeasurement",
    );
}

#[tokio::test]
async fn test_server_measurement_not_in_registry() {
    let config = TestConfig {
        server_measurement: UNREGISTERED_MEASUREMENT,
        ..Default::default()
    };

    let fixture = DiskEncryptionKeyExchangeTestFixture::new(config);
    assert_statuses_contain_errors(fixture.run_key_exchange_test().await, "InvalidMeasurement");

    assert!(
        std::fs::read(fixture.previous_key.path())
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn test_wrong_custom_data() {
    let config = TestConfig {
        custom_data_override: Some(BOGUS_CUSTOM_DATA),
        ..Default::default()
    };

    assert_statuses_contain_errors(
        DiskEncryptionKeyExchangeTestFixture::new(config)
            .run_key_exchange_test()
            .await,
        "InvalidCustomData",
    );
}

#[tokio::test]
async fn test_server_is_unreachable() {
    // We don't start the server, so the client should fail to connect
    let result = DiskEncryptionKeyExchangeTestFixture::new(TestConfig::default())
        .create_client_agent()
        .run()
        .await
        .expect_err("Key exchange should fail when server is unreachable");

    assert!(
        result.to_string().contains("Could not connect to server"),
        "{result}"
    );
}

#[tokio::test]
async fn test_server_timeout() {
    let mut vsock_client = MockVSockClient::default();

    vsock_client
        .expect_send_command()
        .once()
        .withf(|command| matches!(command, Command::StartUpgradeGuestVM))
        .return_once(move |_| {
            println!("Not starting upgrade client - simulating timeout");
            // Don't start the client - this will cause the server to timeout
            Ok(Payload::NoPayload)
        });

    DiskEncryptionKeyExchangeTestFixture::new(TestConfig::default())
        .create_server_agent(vsock_client)
        .exchange_keys()
        .await
        .expect_err("Key exchange should fail when server times out");
}

#[tokio::test]
async fn test_attestation_reports_not_signed() {
    let config = TestConfig {
        sign_attestation_reports: false,
        ..Default::default()
    };
    let (server_result, client_result) = DiskEncryptionKeyExchangeTestFixture::new(config)
        .run_key_exchange_test()
        .await;

    assert_status_contains_error(&server_result, "Debug info from Upgrade VM");
    assert_statuses_contain_errors((server_result, client_result), "InvalidSignature");
}

#[tokio::test]
async fn test_different_chip_id() {
    let config = TestConfig {
        client_chip_id: DIFFERENT_CHIP_ID,
        ..Default::default()
    };

    assert_statuses_contain_errors(
        DiskEncryptionKeyExchangeTestFixture::new(config)
            .run_key_exchange_test()
            .await,
        "InvalidChipId",
    );
}

#[tokio::test]
async fn test_can_open_disk() {
    let config = TestConfig {
        can_open_disk: true,
        // If the client can open the disk, the client should not care about the server's
        // measurement since it won't even call the server.
        server_measurement: UNREGISTERED_MEASUREMENT,
        ..Default::default()
    };

    let fixture = DiskEncryptionKeyExchangeTestFixture::new(config);
    let (server_result, client_result) = fixture.run_key_exchange_test().await;

    server_result.expect("Key exchange should succeed");
    client_result.expect("Key exchange should succeed");
}
