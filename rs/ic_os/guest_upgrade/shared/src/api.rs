tonic::include_proto!("guest_upgrade.api");

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    /// `GetDiskEncryptionKeyResponse` as defined before `guestos_version` was added, i.e. as
    /// older GuestOS versions decode it.
    #[derive(Clone, PartialEq, prost::Message)]
    struct GetDiskEncryptionKeyResponseWithoutGuestosVersion {
        #[prost(bytes = "vec", optional, tag = "1")]
        key: Option<Vec<u8>>,
        #[prost(message, optional, tag = "2")]
        sev_attestation_package: Option<attestation::SevAttestationPackage>,
        #[prost(bytes = "vec", optional, tag = "3")]
        luks_header: Option<Vec<u8>>,
    }

    #[test]
    fn test_old_clients_ignore_guestos_version() {
        let response = GetDiskEncryptionKeyResponse {
            key: Some(b"key".to_vec()),
            sev_attestation_package: None,
            luks_header: Some(b"luks header".to_vec()),
            guestos_version: Some("guestos_version".to_string()),
        };

        let old_response = GetDiskEncryptionKeyResponseWithoutGuestosVersion::decode(
            response.encode_to_vec().as_slice(),
        )
        .unwrap();

        assert_eq!(
            old_response,
            GetDiskEncryptionKeyResponseWithoutGuestosVersion {
                key: Some(b"key".to_vec()),
                sev_attestation_package: None,
                luks_header: Some(b"luks header".to_vec()),
            }
        );
    }

    #[test]
    fn test_old_servers_do_not_report_guestos_version() {
        let old_response = GetDiskEncryptionKeyResponseWithoutGuestosVersion {
            key: Some(b"key".to_vec()),
            sev_attestation_package: None,
            luks_header: Some(b"luks header".to_vec()),
        };

        let response =
            GetDiskEncryptionKeyResponse::decode(old_response.encode_to_vec().as_slice()).unwrap();

        assert_eq!(
            response,
            GetDiskEncryptionKeyResponse {
                key: Some(b"key".to_vec()),
                sev_attestation_package: None,
                luks_header: Some(b"luks header".to_vec()),
                guestos_version: None,
            }
        );
    }
}
