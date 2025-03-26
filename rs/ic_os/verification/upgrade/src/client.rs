use crate::api::upgrade_service_client::UpgradeServiceClient;
use crate::api::{
    GetDiskEncryptionKeyRequest, InitializeGetDiskEncryptionKeyRequest,
    InitializeGetDiskEncryptionKeyResponse,
};
use anyhow::{bail, Context};
use attestation::verify::verify_attestation_report;
use clap::builder::TypedValueParser;
use clap::Parser;
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key;
use ic_interfaces_registry::RegistryClient;
use ic_protobuf::registry::replica_version::v1::BlessedReplicaVersions;
use ic_registry_canister_client::CanisterRegistryClient;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client_helpers::blessed_replica_version;
use ic_registry_client_helpers::blessed_replica_version::BlessedReplicaVersionRegistry;
use ic_registry_client_helpers::firewall::FirewallRegistry;
use ic_registry_client_helpers::node::NodeRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_nns_data_provider_wrappers::CertifiedNnsDataProvider;
use itertools::Itertools;
use std::error::Error;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;
use tonic::client::GrpcService;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tonic::Request;
use url::Url;

mod api;

/// Command-line arguments for the application
#[derive(Parser, Debug)]
#[command(long_about = None)]
struct Args {
    /// Comma-separated URLs of the NNS.
    #[arg(long)]
    pub nns_url: String,

    /// IPv6 Address of the server (running on the active VM).
    #[arg(long)]
    pub server_address: IpAddr,

    /// Path to the NNS public key in PEM format.
    #[arg(long)]
    pub nns_pub_key_pem: PathBuf,
}

const SERVER_DOMAIN_NAME: &str = "localhost";
const SERVER_ROOT_CERT: &[u8] = include_bytes!("../server_cert.pem");

const MILAN_ARK_ASK: &[u8] = include_bytes!("../milan.pem");

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();
    let args = Args::parse();

    let endpoint = format!(
        "https://[{}]:{}",
        // "https://[2a00:fb01:400:44:6801:95ff:fed7:d475]:{}",
        args.server_address,
        api::PORT
    );

    let mut upgrade_service_client = create_upgrade_service_client(endpoint.clone())
        .await
        .context(format!("Could not connect to server at {endpoint}"))?;

    let blessed_measurements = get_blessed_measurements(&args)?;

    let nonce_generated_by_me = attestation::generate_nonce();

    let initialize_response = upgrade_service_client
        .initialize_get_disk_encryption_key(InitializeGetDiskEncryptionKeyRequest {
            nonce: Some(nonce_generated_by_me.clone()),
        })
        .await
        .context("Call to initialize_get_disk_encryption_key failed")?;

    let get_key_response = upgrade_service_client
        .get_disk_encryption_key(GetDiskEncryptionKeyRequest {
            sev_attestation_report: None,
        })
        .await
        .context("Call to get_disk_encryption_key failed")?;

    // verify_attestation_report(get_key_response.get_ref().sev_attestation_report

    return Ok(());

    // // initialize(&client)
    //
    // let request = Request::new(SetDiskEncryptionKeyRequest {
    //     key: Some(vec![1, 2, 3]),
    //     nonce: None,
    //     sev_attestation_report: None,
    // });
    //
    // // Call the set_disk_encryption_key method
    // let _response = client
    //     .set_disk_encryption_key(request)
    //     .await
    //     .context("Setting disk encryption key failed on the other VM")?;

    Ok(())
}

fn get_blessed_measurements(args: &Args) -> anyhow::Result<Vec<String>> {
    let mut nns_registry_client = create_nns_registry_client(&args)?;
    nns_registry_client.try_polling_latest_version(usize::MAX)?;
    let blessed_replica_versions = nns_registry_client
        .get_blessed_replica_versions(nns_registry_client.get_latest_version())?
        .context("Blessed replica versions are not available")?;
    let measurements = blessed_replica_versions.blessed_guest_launch_measurement_sha256_hexes;
    if measurements.is_empty() {
        bail!("No blessed guest launch measurements found");
    }

    Ok(measurements)
}

async fn create_upgrade_service_client(
    endpoint: String,
) -> anyhow::Result<UpgradeServiceClient<Channel>> {
    let config = ClientTlsConfig::new()
        .domain_name(SERVER_DOMAIN_NAME)
        .ca_certificate(Certificate::from_pem(SERVER_ROOT_CERT));

    let channel = Channel::from_shared(endpoint.clone())?
        .tls_config(config)?
        .connect()
        .await?;

    Ok(UpgradeServiceClient::new(channel))
}

fn create_nns_registry_client(args: &Args) -> anyhow::Result<RegistryClientImpl> {
    let nns_public_key = parse_threshold_sig_key(args.nns_pub_key_pem.as_path())
        .context("Cannot read NNS public key")?;
    let nns_urls = args
        .nns_url
        .split(",")
        .map(|url| Url::parse(url).with_context(|| url.to_string()))
        .collect::<Result<Vec<_>, _>>()
        .context("Cannot parse NNS URLs")?;

    Ok(RegistryClientImpl::new(
        Arc::new(CertifiedNnsDataProvider::new(
            tokio::runtime::Handle::current(),
            nns_urls,
            nns_public_key,
        )),
        /*metrics_registry=*/ None,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, Der};
    use sev::certs::snp::ca::Chain;
    use sev::certs::snp::{Certificate, Verifiable};
    use sev::firmware::host::{CertTableEntry, CertType};
    use sev::Generation;
    use x509_parser::pem::{parse_x509_pem, Pem, PemIterator};
    use x509_parser::prelude::{FromDer, X509Certificate};

    #[test]
    fn test() {
        // let pem = parse_x509_pem(&MILAN_ARK_ASK).unwrap().1;
        // let (ark_pem, ask_pem) = Pem::iter_from_buffer(MILAN_ARK_ASK)
        //     .map(Result::unwrap)
        //     .collect_tuple()
        //     .unwrap();
        //
        // let ark = ark_pem.parse_x509().unwrap();
        // let ask = ask_pem.parse_x509().unwrap();
        // println!("{}", ark.subject.to_string());
        // // dbg!(&ask.issuer);

        sev::certs::snp::Chain {
            ca: Generation::Milan.into(),
            vek: Certificate::from(),
        };

        // let table = sev::certs::snp::Chain::from_cert_table_pem(
        //     vec![
        //         CertTableEntry {
        //             cert_type: CertType::ARK,
        //             data: sev::certs::sev::builtin::milan::ARK.to_vec(),
        //         }
        //     ]
        // ).unwrap();
        // dbg!(table);
        // sev::certs::sev::Chain {
        //     ca: Generation::Milan.into(),
        //     sev: Chain {
        //         pdh: (),
        //         pek: (),
        //         oca: (),
        //         cek: (),
        //     },
        // }
        // let x = X509Certificate::from_der(sev::certs::sev::builtin::milan::ARK).unwrap().1;
        // dbg!(&x.subject);
    }
}
