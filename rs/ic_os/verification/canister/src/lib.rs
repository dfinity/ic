use crate::proto::NonceInfo;
use crate::signer::{Ed25519Signer, KeyName};
use anyhow::{Context, Result};
use attestation::protocol::{
    FetchAttestationTokenRequest, FetchAttestationTokenResponse, GenerateAttestationTokenChallenge,
    GenerateAttestationTokenRequest, GenerateAttestationTokenResponse,
    GenerateTlsCertificateRequest, GenerateTlsCertificateResponse,
    InitiateGenerateAttestationTokenRequest, InitiateGenerateAttestationTokenResponse,
    VerificationError, VerificationErrorDetail,
};
use attestation::verify::verify_generate_attestation_token_request;
use candid::{export_service, CandidType, Principal};
use ed25519::pkcs8::spki::AlgorithmIdentifierOwned;
use ed25519::signature::{Signer, SignerMut};
use ed25519::PublicKeyBytes;
use ic_cbor::CertificateToCbor;
use ic_cdk::api::management_canister::main::raw_rand;
use ic_cdk::api::management_canister::schnorr::{
    SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgument,
};
use ic_cdk::{export_candid, init, post_upgrade, query, update};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, Memory, StableBTreeMap, Storable};
use serde::Deserialize;
use std::cell::{Cell, OnceCell, RefCell};
use std::error::Error;
use std::fmt::Display;
use std::ops::Add;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::{BitString, UtcTime};
use x509_cert::der::pem::LineEnding;
use x509_cert::der::{Decode, DecodePem, EncodePem};
use x509_cert::ext::pkix::name::{GeneralName, GeneralNames};
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifier, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use x509_cert::Certificate;

mod proto;
mod signer;

const ATTESTATION_TOKEN_DEFAULT_EXPIRATION: Duration = Duration::from_secs(90 * 24 * 3600);
const MAX_NONCE_AGE: Duration = Duration::from_secs(300);

static ROOT_CA_PUBLIC_KEY: OnceLock<[u8; 32]> = OnceLock::new();
static ROOT_CERTIFICATE_PEM: OnceLock<String> = OnceLock::new();

thread_local! {
    static MEMORY_MANAGER: MemoryManager<DefaultMemoryImpl> = MemoryManager::init(DefaultMemoryImpl::default());

    static NONCES: RefCell<StableBTreeMap<Vec<u8>, NonceInfo, VirtualMemory<DefaultMemoryImpl>>> =
        RefCell::new(MEMORY_MANAGER.with(|memory| StableBTreeMap::init(memory.get(MemoryId::new(0)))));

    // cache the public key and certificate to avoid fetching them multiple times
}

fn now() -> SystemTime {
    UNIX_EPOCH.add(Duration::from_nanos(ic_cdk::api::time()))
}

#[init]
fn init() {
    ic_cdk::api::set_global_timer(1);
}

#[post_upgrade]
fn post_upgrade() {
    ic_cdk::api::set_global_timer(1);
}

#[export_name = "canister_global_timer"]
extern "C" fn global_timer() {
    ic_cdk::spawn(fetch_ca_public_key());
}

async fn fetch_ca_public_key() {
    let (res,) =
        ic_cdk::api::management_canister::schnorr::schnorr_public_key(SchnorrPublicKeyArgument {
            canister_id: ic_cdk::id().into(),
            derivation_path: vec![],
            key_id: SchnorrKeyId {
                algorithm: SchnorrAlgorithm::Ed25519,
                name: KeyName::DfxTestKey.as_str().into(),
            },
        })
        .await
        .expect("schnorr_public_key failed");

    ROOT_CA_PUBLIC_KEY
        .set(res.public_key.try_into().unwrap())
        .unwrap();
    // ROOT_CA_PUBLIC_KEY

    let root_cert = pem_certificate_signed_by_root_ca(
        Profile::Root,            // TODO
        SerialNumber::from(1u32), // TODO
        Validity {
            not_before: Time::UtcTime(
                UtcTime::from_unix_duration(Duration::from_nanos(ic_cdk::api::time()))
                    .expect("not_before"),
            ),
            not_after: Time::INFINITY,
        },
        Name::from_str("CN=IC Root,C=CH").unwrap(), // TODO,
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ed25519::pkcs8::ALGORITHM_OID.clone(),
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(ROOT_CA_PUBLIC_KEY.get().unwrap()).unwrap(),
        },
        None,
        &Ed25519Signer::new(
            KeyName::DfxTestKey,
            PublicKeyBytes(
                *ROOT_CA_PUBLIC_KEY
                    .get()
                    .expect("ROOT_CA_PUBLIC_KEY not set"),
            ),
        )
        .expect("Could not create Ed25519Signer"),
    )
    .await
    .expect("Could not fetch root CA certificate");

    ROOT_CERTIFICATE_PEM
        .set(root_cert.to_pem(LineEnding::LF).unwrap())
        .unwrap();

    ic_cdk::println!("FETCHED IT");
}

#[update]
async fn initiate_generate_attestation_token(
    request: InitiateGenerateAttestationTokenRequest,
) -> Result<InitiateGenerateAttestationTokenResponse, VerificationError> {
    let nonce = raw_rand()
        .await
        .map_err(|err| VerificationError::internal(err.1))?
        .0;
    NONCES.with_borrow_mut(|nonces| {
        nonces.insert(
            request.tls_public_key_pem.into_bytes(),
            NonceInfo {
                nonce: nonce.clone(),
                generated_at: Some(now().into()),
            },
        )
    });

    Ok(InitiateGenerateAttestationTokenResponse {
        challenge: GenerateAttestationTokenChallenge { nonce },
    })
}

#[update]
async fn generate_tls_certificate(
    request: GenerateTlsCertificateRequest,
) -> Result<GenerateTlsCertificateResponse, VerificationError> {
    let tls_certificate = pem_certificate_signed_by_root_ca(
        Profile::Leaf {
            issuer: Name::from_str("CN=IC Root,C=CH").unwrap(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        }, // TODO
        SerialNumber::from(1u32), // TODO
        Validity {
            not_before: Time::UtcTime(
                UtcTime::from_unix_duration(Duration::from_nanos(ic_cdk::api::time()))
                    .expect("not_before"),
            ),
            not_after: Time::UtcTime(
                UtcTime::from_unix_duration(
                    Duration::from_nanos(ic_cdk::api::time())
                        + ATTESTATION_TOKEN_DEFAULT_EXPIRATION,
                )
                .expect("not_after"),
            ),
        },
        Name::from_str("CN=localhost,C=US").expect("Subject Name parsing failed"), // TODO,
        SubjectPublicKeyInfoOwned::from_pem(&request.tls_public_key_pem).map_err(|err| {
            VerificationErrorDetail::UnsupportedTlsKey {
                message: err.to_string(),
            }
        })?,
        Some("localhost".into()),
        &Ed25519Signer::new(
            KeyName::DfxTestKey,
            PublicKeyBytes(
                *ROOT_CA_PUBLIC_KEY
                    .get()
                    .expect("ROOT_CA_PUBLIC_KEY not set"),
            ),
        )
        .map_err_to_internal_with_context("Could not create Ed25519Signer")?,
    )
    .await
    .map_err_to_internal()?;

    let mut tls_certificate_pem = tls_certificate
        .to_pem(LineEnding::LF)
        .map_err_to_internal()?;
    tls_certificate_pem += ROOT_CERTIFICATE_PEM.get().unwrap();

    println!("PEM: {}", tls_certificate_pem);

    Ok(GenerateTlsCertificateResponse {
        tls_certificate_pem,
    })
}

async fn pem_certificate_signed_by_root_ca(
    profile: Profile,
    serial_number: SerialNumber,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfoOwned,
    dns_name: Option<String>,
    signer: &Ed25519Signer,
) -> anyhow::Result<Certificate> {
    let mut builder = CertificateBuilder::<Ed25519Signer>::new(
        profile,
        serial_number,
        validity,
        subject,
        subject_public_key_info,
        signer,
    )
    .expect("Create certificate");

    if let Some(dns_name) = dns_name {
        builder.add_extension(&SubjectAltName(vec![GeneralName::DnsName(
            dns_name.try_into()?,
        )]))?;
    }

    let blob = builder
        .finalize()
        .context("failed to finalize certificate builder")?;

    let signature =
        BitString::from_bytes(&signer.sign(&blob).await?).context("wrong signature length")?;

    builder
        .assemble(signature)
        .context("failed to assemble certificate")
}

pub trait ToVerificationError<T> {
    fn map_err_to_internal(self) -> std::result::Result<T, VerificationError>;
    fn map_err_to_internal_with_context(
        self,
        context: &str,
    ) -> std::result::Result<T, VerificationError>;
}

impl<T, E: Display> ToVerificationError<T> for std::result::Result<T, E> {
    fn map_err_to_internal(self) -> std::result::Result<T, VerificationError> {
        self.map_err(|err| VerificationError::internal(err))
    }

    fn map_err_to_internal_with_context(
        self,
        context: &str,
    ) -> std::result::Result<T, VerificationError> {
        self.map_err(|err| VerificationError::internal(format!("{context}\n\nCaused by:\n{err}")))
    }
}
