use der::asn1::OctetStringRef;

/// Data structures used to derive the attestation report custom data.
/// Changing the structure of these data structures will change the attestation report custom data
/// and lead to the failure of the attestation report verification.
/// If a change is needed, it's recommended to introduce a new data structure
/// (e.g. GetDiskEncryptionKeyTokenServerV2CustomData) and signal in the
/// attestation handshake which custom data is expected.

#[derive(der::Sequence, Debug, Eq, PartialEq)]
pub struct GetDiskEncryptionKeyTokenCustomData<'a> {
    pub tls_shared_key_for_attestation: OctetStringRef<'a>,
}
