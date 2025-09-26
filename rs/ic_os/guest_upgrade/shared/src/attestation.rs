use der::asn1::OctetStringRef;

/// Data structures used to derive the attestation report custom data.
/// Changing the structure of these data structures will change the attestation report custom data
/// and lead to the failure of the attestation report verification.
/// If a change is needed, it's recommended to introduce a new data structure
/// (e.g. GetDiskEncryptionKeyTokenServerV2CustomData) and signal in the
/// attestation handshake which custom data is expected.

#[derive(der::Sequence, Debug, Eq, PartialEq)]
pub struct GetDiskEncryptionKeyTokenCustomData<'a> {
    pub client_tls_public_key: OctetStringRef<'a>,
    pub server_tls_public_key: OctetStringRef<'a>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use attestation::custom_data::{DerEncodedCustomData, EncodeSevCustomData};

    #[test]
    fn test_get_disk_encryption_key_token_custom_data_is_stable() {
        let client_tls_public_key = OctetStringRef::new(&[1, 2, 3, 4]).unwrap();
        let server_tls_public_key = OctetStringRef::new(&[5, 6, 7, 8]).unwrap();
        let custom_data = DerEncodedCustomData(GetDiskEncryptionKeyTokenCustomData {
            client_tls_public_key,
            server_tls_public_key,
        });

        assert_eq!(
            &custom_data.encode_for_sev().unwrap().as_slice(),
            // The numbers below don't have any special meaning, but they should stay stable.
            // If the encoding below has to be changed, the attestation report verification will
            // probably fail because the old GuestOS version will still derive the previous
            // encoding, so take extra care!
            &[
                31, 13, 254, 213, 44, 96, 47, 104, 171, 127, 68, 166, 43, 242, 61, 116, 55, 229,
                214, 227, 107, 88, 24, 26, 223, 134, 119, 215, 136, 162, 198, 128, 60, 107, 133,
                229, 145, 220, 92, 231, 186, 211, 34, 11, 30, 155, 53, 20, 23, 114, 250, 74, 83,
                143, 28, 23, 30, 166, 65, 176, 215, 27, 136, 191
            ]
        );
    }
}
