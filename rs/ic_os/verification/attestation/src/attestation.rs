use der::asn1::OctetStringRef;

#[derive(der::Sequence)]
pub struct GenerateAttestationTokenCustomData<'a> {
    pub nonce: OctetStringRef<'a>,
    pub tls_public_key: OctetStringRef<'a>,
}

pub struct StoreDiskEncryptionKeyCustomData {}

pub struct RetrieveDiskEncryptionKeyCustomData {}
