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
    use sev::firmware::guest::AttestationReport;
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

        let chain = sev::certs::snp::Chain::from_pem(
            sev::certs::snp::builtin::milan::ARK,
            sev::certs::snp::builtin::milan::ASK,
            include_bytes!("../asus_vcek.pem"),
        )
        .unwrap();

        println!(
            "{}",
            String::from_utf8(
                Certificate::from_der(include_bytes!("/tmp/out.der"))
                    .unwrap()
                    .to_pem()
                    .unwrap()
            )
            .unwrap()
        );

        let sec1 = Certificate::from_pem(include_bytes!("../asus_vcek.pem"))
            .unwrap()
            .public_key_sec1()
            .to_vec();
        let sec2 = Certificate::from_der(include_bytes!("/tmp/out.der"))
            .unwrap()
            .public_key_sec1()
            .to_vec();
        let sec3 = Certificate::from_der(include_bytes!("/tmp/out2.der"))
            .unwrap()
            .public_key_sec1()
            .to_vec();

        println!("sec1: {:?}", sec1);
        println!("sec2: {:?}", sec2);
        println!("sec3: {:?}", sec3);

        let attetestation_report_array = [
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0,
            0, 0, 0, 0, 14, 213, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            27, 83, 44, 231, 125, 5, 99, 245, 162, 210, 90, 73, 242, 245, 85, 143, 57, 54, 176, 93,
            129, 226, 185, 216, 103, 134, 201, 183, 216, 177, 198, 93, 4, 156, 13, 18, 181, 181,
            202, 124, 220, 148, 199, 222, 96, 124, 108, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 45,
            11, 19, 71, 48, 178, 141, 224, 161, 211, 164, 130, 185, 115, 88, 49, 87, 147, 0, 121,
            145, 237, 205, 134, 115, 89, 252, 191, 218, 246, 57, 125, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 3, 0, 0, 0, 0, 0, 14, 213, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 57, 150, 89, 197, 203, 114,
            32, 3, 254, 88, 202, 200, 134, 182, 187, 237, 234, 111, 202, 89, 110, 192, 71, 82, 215,
            98, 118, 69, 137, 238, 124, 95, 208, 63, 4, 53, 45, 139, 10, 215, 194, 57, 18, 1, 13,
            20, 18, 122, 211, 226, 223, 175, 121, 131, 30, 233, 251, 99, 246, 247, 123, 55, 4, 117,
            3, 0, 0, 0, 0, 0, 14, 213, 8, 55, 1, 0, 7, 55, 1, 0, 3, 0, 0, 0, 0, 0, 14, 213, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 5, 206, 62, 6, 163,
            83, 230, 27, 138, 209, 158, 46, 24, 132, 133, 159, 236, 191, 154, 187, 222, 17, 61,
            144, 129, 60, 87, 83, 233, 226, 171, 81, 212, 182, 199, 237, 13, 191, 216, 83, 205, 43,
            10, 217, 217, 73, 201, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 93, 165, 122, 98, 132, 54, 243, 53, 85, 136, 61, 0, 159, 241, 102, 123, 88,
            204, 132, 233, 8, 78, 66, 25, 114, 153, 23, 0, 169, 13, 130, 238, 59, 110, 253, 44, 68,
            40, 150, 232, 95, 6, 229, 47, 25, 143, 3, 27, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0,
        ];

        let chain = sev::certs::snp::Chain::from((
            Certificate::from_pem(sev::certs::snp::builtin::milan::ASK).unwrap(),
            Certificate::from_pem(sev::certs::snp::builtin::milan::ARK).unwrap(),
            Certificate::from_pem(include_bytes!("../asus_vcek.pem")).unwrap(),
        ));
        //     sev::certs::snp::builtin::milan::ARK,
        //     sev::certs::snp::builtin::milan::ASK,
        //     include_bytes!("../asus_vcek.pem"),
        // )
        //     .unwrap();

        let attestation_report =
            AttestationReport::from_bytes(&attetestation_report_array).unwrap();
        let mut v = vec![];
        attestation_report.write_bytes(&mut v);
        dbg!(&attetestation_report_array == v.as_slice());
        dbg!(&attestation_report);
        //
        // let verified = chain.verify().unwrap();

        let vcek = chain.verify().unwrap();

        (&chain, &attestation_report).verify().unwrap();

        // (verified, attestation_report.signature)

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
