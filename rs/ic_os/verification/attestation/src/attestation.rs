use der::asn1::OctetStringRef;
use der::Encode;
use std::error::Error;
use thiserror::Error;

#[derive(der::Sequence)]
pub struct GenerateAttestationTokenCustomData<'a> {
    pub nonce: OctetStringRef<'a>,
    pub tls_public_key: OctetStringRef<'a>,
}

pub struct StoreDiskEncryptionKeyCustomData {}

pub struct RetrieveDiskEncryptionKeyCustomData {}
