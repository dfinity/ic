use super::CertificationCrypto;
use ic_interfaces::{
    certification::{Verifier, VerifierError},
    validation::ValidationResult,
};
use ic_types::{consensus::certification::Certification, RegistryVersion, SubnetId};
use std::sync::Arc;

/// VerifierImpl implements the verification of state hash certifications.
pub struct VerifierImpl {
    crypto: Arc<dyn CertificationCrypto>,
}

impl VerifierImpl {
    /// Construct a new VerifierImpl.
    pub fn new(crypto: Arc<dyn CertificationCrypto>) -> Self {
        Self { crypto }
    }
}

impl Verifier for VerifierImpl {
    fn validate(
        &self,
        subnet_id: SubnetId,
        certification: &Certification,
        registry_version: RegistryVersion,
    ) -> ValidationResult<VerifierError> {
        // Check whether certification is cryptographically verifiable using the
        self.crypto
            .verify_combined_threshold_sig_by_public_key(
                &certification.signed.signature.signature,
                &certification.signed.content,
                subnet_id,
                registry_version,
            )
            .map_err(VerifierError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use ic_test_utilities::{
        consensus::fake::*, crypto::CryptoReturningOk, types::ids::subnet_test_id,
    };
    use ic_types::{
        consensus::certification::{Certification, CertificationContent},
        crypto::{
            threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
            CryptoHash, Signed,
        },
        signature::ThresholdSignature,
        CryptoHashOfPartialState, Height,
    };

    fn fake_dkg_id(h: u64) -> NiDkgId {
        NiDkgId {
            start_block_height: Height::from(h),
            dealer_subnet: subnet_test_id(0),
            dkg_tag: NiDkgTag::HighThreshold,
            target_subnet: NiDkgTargetSubnet::Local,
        }
    }

    fn fake_cert(height: Height, signer: NiDkgId, hash: CryptoHashOfPartialState) -> Certification {
        let mut signature = ThresholdSignature::fake();
        signature.signer = signer;
        Certification {
            height,
            signed: Signed {
                signature,
                content: CertificationContent::new(hash),
            },
        }
    }

    #[test]
    fn test_certification_valid() {
        let registry_version = RegistryVersion::from(1);
        let subnet_id = subnet_test_id(555);
        let hash = CryptoHashOfPartialState::from(CryptoHash(vec![88, 99, 00]));
        let certification = fake_cert(Height::from(2), fake_dkg_id(0), hash);

        let crypto = CryptoReturningOk::default();
        let verifier = VerifierImpl::new(Arc::new(crypto));

        assert_matches!(
            verifier.validate(subnet_id, &certification, registry_version),
            Ok(_)
        );
    }
}
