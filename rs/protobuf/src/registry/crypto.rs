use crate::crypto::v1::NodePublicKeys;

#[rustfmt::skip]
#[allow(clippy::all)]
#[path = "../../gen/registry/registry.crypto.v1.rs"]
pub mod v1;

impl NodePublicKeys {
    pub fn get_pub_keys_and_cert_count(&self) -> u8 {
        let mut count: u8 = 0;
        if self.node_signing_pk.is_some() {
            count += 1;
        }
        if self.committee_signing_pk.is_some() {
            count += 1;
        }
        if self.tls_certificate.is_some() {
            count += 1;
        }
        if self.dkg_dealing_encryption_pk.is_some() {
            count += 1;
        }
        if self.idkg_dealing_encryption_pk.is_some() {
            count += 1;
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::v1::NodePublicKeys;
    use crate::registry::crypto::v1::{PublicKey, X509PublicKeyCert};

    const SOME_PUBLIC_KEY: Option<PublicKey> = Some(PublicKey {
        version: 0,
        algorithm: 0,
        key_value: vec![],
        proof_data: None,
    });
    const SOME_X509_CERT: Option<X509PublicKeyCert> = Some(X509PublicKeyCert {
        certificate_der: vec![],
    });

    #[test]
    fn should_count_correctly_empty_node_public_keys() {
        let node_public_keys = NodePublicKeys {
            version: 0,
            node_signing_pk: None,
            committee_signing_pk: None,
            tls_certificate: None,
            dkg_dealing_encryption_pk: None,
            idkg_dealing_encryption_pk: None,
        };
        assert_eq!(0, node_public_keys.get_pub_keys_and_cert_count());
    }

    #[test]
    fn should_count_correctly_full_node_public_keys() {
        let node_public_keys = NodePublicKeys {
            version: 0,
            node_signing_pk: SOME_PUBLIC_KEY,
            committee_signing_pk: SOME_PUBLIC_KEY,
            tls_certificate: SOME_X509_CERT,
            dkg_dealing_encryption_pk: SOME_PUBLIC_KEY,
            idkg_dealing_encryption_pk: SOME_PUBLIC_KEY,
        };
        assert_eq!(5, node_public_keys.get_pub_keys_and_cert_count());
    }

    #[test]
    fn should_count_correctly_partial_node_public_keys() {
        let node_public_keys = NodePublicKeys {
            version: 0,
            node_signing_pk: SOME_PUBLIC_KEY,
            committee_signing_pk: None,
            tls_certificate: SOME_X509_CERT,
            dkg_dealing_encryption_pk: None,
            idkg_dealing_encryption_pk: SOME_PUBLIC_KEY,
        };
        assert_eq!(3, node_public_keys.get_pub_keys_and_cert_count());
    }
}
