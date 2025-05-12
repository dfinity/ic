use crate::tls::TlsConnector;
use anyhow::{anyhow, Context, Result};
use attestation::attestation_report::SevAttestationPackageGenerator;
use attestation::certificates::CertificateProvider;
use attestation::verify::verify_attestation_report;
use clap::Parser;
use der::asn1::OctetStringRef;
use futures_util::FutureExt;
use hyper_util::client::legacy::connect::Connect;
use ic_config::crypto::CryptoConfig;
use ic_crypto::CryptoComponentImpl;
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key;
use ic_interfaces::crypto::BasicSigVerifier;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{no_op_logger, ReplicaLogger};
use ic_os_upgrade::api;
use ic_os_upgrade::api::disk_encryption_key_exchange_service_client::DiskEncryptionKeyExchangeServiceClient;
use ic_os_upgrade::api::{
    GetDiskEncryptionKeyRequest, GetNodeSigningKeyRequest, SignalStatusRequest,
};
use ic_os_upgrade::custom_data::GetDiskEncryptionKeyTokenCustomData;
use ic_os_upgrade::registry::get_blessed_guest_launch_measurements_from_registry;
use ic_os_upgrade::sev_status::{get_sev_status, SevStatus};
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client_helpers::blessed_replica_version::BlessedReplicaVersionRegistry;
use ic_registry_client_helpers::firewall::FirewallRegistry;
use ic_registry_client_helpers::node::NodeRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_nns_data_provider_wrappers::CertifiedNnsDataProvider;
use ic_types::crypto::{BasicSig, BasicSigOf, NodeIdProof};
use ic_types::{node_id_try_from_option, NodeId};
use itertools::Itertools;
use sev::certs::snp::builtin::milan;
use std::any::Any;
use std::error::Error;
use std::future::Future;
use std::net::IpAddr;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tonic::client::GrpcService;
use tonic::codegen::Service;
use tonic::transport::{Channel, Endpoint};
use url::Url;

mod tls;

/// Command-line arguments for the application
#[derive(Parser, Debug)]
#[command(long_about = None)]
struct Args {
    /// Comma-separated URLs of the NNS.
    #[arg(long)]
    pub nns_url: String,
    //
    // /// IP address of the server (running on the active VM).
    // #[arg(long)]
    // pub server_address: IpAddr,
    //
    // /// Path to the NNS public key in PEM format.
    // #[arg(long)]
    // pub nns_pub_key_pem: PathBuf,
    //
    // /// Path to the file where the key will be written.
    // #[arg(long)]
    // pub out: PathBuf,
    //
    #[arg(long)]
    pub replica_config_file: PathBuf,
}

#[tokio::main]
pub async fn main() -> Result<()> {
    let args = Args::parse();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let endpoint = format!(
        // This is a bit hacky. We have a custom TLS connector which tonic is not aware
        // of. If we specified https://, tonic would complain that we did not configure TLS.
        // Instead, we make tonic believe that we're connecting to http but then replace the scheme
        // with https in tls::TlsConnector just before starting the connection.
        "http://[{}]:{}",
        // "https://[2a00:fb01:400:44:6801:95ff:fed7:d475]:{}",
        args.server_address,
        api::PORT
    );

    let (mut upgrade_service_client, tls_shared_keying_material) =
        create_upgrade_service_client(&endpoint)
            .await
            .context(format!("Could not connect to server at {endpoint}"))?;

    let retrieve_status = retrieve_disk_encryption_key(
        &args,
        &mut upgrade_service_client,
        &tls_shared_keying_material,
    )
    .await;

    let _ignored = upgrade_service_client
        .signal_status(SignalStatusRequest {
            success: Some(retrieve_status.is_ok()),
        })
        .await;

    retrieve_status
}

async fn retrieve_disk_encryption_key(
    args: &Args,
    upgrade_service_client: &mut DiskEncryptionKeyExchangeServiceClient<Channel>,
    tls_shared_keying_material: &[u8; 32],
) -> Result<()> {
    let certificate_provider = CertificateProvider::new(PathBuf::from("/tmp"));
    let attestation_report_generator = SevAttestationPackageGenerator::new(certificate_provider);

    let registry_client = Arc::new(create_nns_registry_client(&args)?);

    let (crypto_config, _) = CryptoConfig::new_in_temp_dir();
    let crypto_component = CryptoComponentImpl::new(
        &crypto_config,
        None,
        registry_client.clone(),
        no_op_logger(),
        None,
    );

    let node_id = get_node_id(
        &crypto_component,
        upgrade_service_client,
        registry_client.deref(),
    )
    .await
    .context("Could not get node ID")?;

    let custom_data = GetDiskEncryptionKeyTokenCustomData {
        tls_shared_key_for_attestation: OctetStringRef::new(tls_shared_keying_material)
            .expect("Could not encode tls shared key"),
    };
    let my_attestation_package =
        attestation_report_generator.generate_attestation_package(&custom_data)?;

    let get_key_response = upgrade_service_client
        .get_disk_encryption_key(GetDiskEncryptionKeyRequest {
            sev_attestation_package: Some(my_attestation_package),
        })
        .await
        .context("Call to get_disk_encryption_key failed")?
        .into_inner();

    let server_attestation_report = get_key_response
        .sev_attestation_package
        .context("Server attestation report is missing")?;

    let blessed_measurements =
        get_blessed_guest_launch_measurements_from_registry(registry_client.deref())
            .map_err(|e| anyhow!("Failed to get blessed measurements from registry: {e}"))?;

    verify_attestation_report(
        &server_attestation_report,
        milan::ARK,
        &blessed_measurements,
        &custom_data,
    )
    .context("Server attestation report verification failed")?;

    let disk_encryption_key = get_key_response
        .key
        .context("GetKeyResponse does not contain a key")?;

    let disk_encryption_key =
        String::from_utf8(disk_encryption_key).context("Key is not valid UTF-8")?;

    std::fs::write(&args.out, disk_encryption_key)
        .with_context(|| format!("Failed to write key to {}", args.out.display()))?;
    Ok(())
}

async fn get_node_id(
    sig_verifier: &dyn BasicSigVerifier<NodeIdProof>,
    upgrade_service_client: &mut DiskEncryptionKeyExchangeServiceClient<Channel>,
    registry_client: &dyn RegistryClient,
) -> Result<NodeId> {
    use rand::RngCore;

    let mut challenge = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);

    let response = upgrade_service_client
        .get_node_signing_key(GetNodeSigningKeyRequest {
            challenge: Some(challenge.clone()),
        })
        .await
        .context("Call to get_node_signing_key failed")?
        .into_inner();

    let node_id = node_id_try_from_option(response.node_id)
        .context("Could not extract node ID from response")?;

    let proof = response.proof.context("Proof is missing in response")?;

    sig_verifier
        .verify_basic_sig(
            &BasicSigOf::new(BasicSig(proof)),
            &NodeIdProof(challenge),
            node_id,
            registry_client.get_latest_version(),
        )
        .context("Node ID verification failed")?;

    Ok(node_id)
}

fn create_nns_registry_client(args: &Args) -> Result<RegistryClientImpl> {
    let nns_public_key = parse_threshold_sig_key(args.nns_pub_key_pem.as_path())
        .context("Cannot read NNS public key")?;
    let nns_urls = args
        .nns_url
        .split(",")
        .map(|url| Url::parse(url).with_context(|| url.to_string()))
        .collect::<Result<Vec<_>, _>>()
        .context("Cannot parse NNS URLs")?;

    let client = RegistryClientImpl::new(
        Arc::new(CertifiedNnsDataProvider::new(
            tokio::runtime::Handle::current(),
            nns_urls,
            nns_public_key,
        )),
        /*metrics_registry=*/ None,
    );
    // TODO:
    // client.try_polling_latest_version(usize::MAX)?;

    Ok(client)
}

async fn create_upgrade_service_client(
    endpoint: &str,
) -> Result<(DiskEncryptionKeyExchangeServiceClient<Channel>, [u8; 32])> {
    let tls_shared_keying_material = Arc::new(Mutex::new([0; 32]));
    let channel = Endpoint::from_shared(endpoint.to_string())?
        .connect_with_connector(TlsConnector {
            tls_shared_key_for_attestation: tls_shared_keying_material.clone(),
        })
        .await?;

    let client = DiskEncryptionKeyExchangeServiceClient::new(channel);
    let tls_shared_keying_material = tls_shared_keying_material.lock().unwrap().to_owned();
    Ok((client, tls_shared_keying_material))
}
