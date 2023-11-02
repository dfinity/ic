//! The crypto service provider API for querying public and secret keys in combination.
use crate::vault::api::{
    ExternalPublicKeyError, LocalPublicKeyError, NodeKeysError, NodeKeysErrors,
    PksAndSksContainsErrors, PublicAndSecretKeyStoreCspVault, SecretKeyError,
    ValidatePksAndSksError,
};
use crate::vault::local_csp_vault::LocalCspVault;
use crate::{CspPublicKey, ExternalPublicKeys, KeyId, SecretKeyStore};
use parking_lot::RwLockReadGuard;

use crate::keygen::utils::{mega_public_key_from_proto, MEGaPublicKeyFromProtoError};
use crate::public_key_store::PublicKeyStore;
use crate::types::conversions::CspPopFromPublicKeyProtoError;
use crate::types::CspPop;
use crate::vault::api::ValidatePksAndSksKeyPairError::{
    PublicKeyInvalid, PublicKeyNotFound, SecretKeyNotFound,
};
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_node_key_validation::{
    ValidCommitteeSigningPublicKey, ValidDkgDealingEncryptionPublicKey,
    ValidIDkgDealingEncryptionPublicKey, ValidNodePublicKeys, ValidNodeSigningPublicKey,
    ValidTlsCertificate,
};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_protobuf::registry::crypto::v1::{PublicKey as PublicKeyProto, X509PublicKeyCert};
use ic_types::crypto::AlgorithmId;
use ic_types::Time;
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    PublicAndSecretKeyStoreCspVault for LocalCspVault<R, S, C, P>
{
    fn pks_and_sks_contains(
        &self,
        external_public_keys: ExternalPublicKeys,
    ) -> Result<(), PksAndSksContainsErrors> {
        let key_ids = compute_key_ids(&external_public_keys);

        let (local_public_keys, secret_key_errors_result) = {
            let (sks_read_lock, pks_read_lock) = self.sks_and_pks_read_locks();
            (
                LocalNodePublicKeys::from_public_key_store(pks_read_lock),
                check_secret_keys_existence(sks_read_lock, &key_ids),
            )
        }; // drop read locks on SKS and PKS

        let local_public_key_errors_result =
            compare_public_keys(&external_public_keys, &local_public_keys);
        if key_ids.is_ok()
            && local_public_key_errors_result.is_ok()
            && secret_key_errors_result.is_ok()
        {
            Ok(())
        } else {
            Err(PksAndSksContainsErrors::NodeKeysErrors(combine_errors(
                key_ids,
                local_public_key_errors_result,
                secret_key_errors_result,
            )))
        }
    }

    fn validate_pks_and_sks(&self) -> Result<ValidNodePublicKeys, ValidatePksAndSksError> {
        let required_public_keys = {
            let (sks_read_lock, pks_read_lock) = self.sks_and_pks_read_locks();
            let all_local_public_keys = LocalNodePublicKeys::from_public_key_store(pks_read_lock);
            let required_public_keys = RequiredNodePublicKeys::try_from(all_local_public_keys)?;
            let key_ids = required_public_keys.compute_key_ids()?;
            key_ids.verify_contained_in_sks(sks_read_lock)?;
            required_public_keys
        };
        // Release both locks on SKS and PKS
        // before doing expensive computation (validation of public keys)
        required_public_keys.validate(self.time_source.get_relative_time())
    }
}

#[derive(Debug)]
struct LocalNodePublicKeyResults {
    node_signing_public_key_result: Result<(), LocalPublicKeyError>,
    committee_signing_public_key_result: Result<(), LocalPublicKeyError>,
    tls_certificate_public_key_result: Result<(), LocalPublicKeyError>,
    dkg_dealing_encryption_public_key_result: Result<(), LocalPublicKeyError>,
    idkg_dealing_encryption_public_key_result: Result<(), LocalPublicKeyError>,
}

impl LocalNodePublicKeyResults {
    pub fn is_ok(&self) -> bool {
        self.node_signing_public_key_result.is_ok()
            && self.committee_signing_public_key_result.is_ok()
            && self.tls_certificate_public_key_result.is_ok()
            && self.dkg_dealing_encryption_public_key_result.is_ok()
            && self.idkg_dealing_encryption_public_key_result.is_ok()
    }
}

struct KeyIds {
    node_signing_key_id: Result<KeyId, ExternalPublicKeyError>,
    committee_signing_key_id: Result<KeyId, ExternalPublicKeyError>,
    dkg_dealing_encryption_key_id: Result<KeyId, ExternalPublicKeyError>,
    tls_secret_key_id: Result<KeyId, ExternalPublicKeyError>,
    idkg_dealing_encryption_key_id: Result<KeyId, ExternalPublicKeyError>,
}

impl KeyIds {
    pub fn is_ok(&self) -> bool {
        self.node_signing_key_id.is_ok()
            && self.committee_signing_key_id.is_ok()
            && self.dkg_dealing_encryption_key_id.is_ok()
            && self.tls_secret_key_id.is_ok()
            && self.idkg_dealing_encryption_key_id.is_ok()
    }
}

fn compute_key_ids(external_public_keys: &ExternalPublicKeys) -> KeyIds {
    let node_signing_key_id =
        compute_node_signing_key_id(&external_public_keys.node_signing_public_key);
    let committee_signing_key_id =
        compute_committee_signing_key_id(&external_public_keys.committee_signing_public_key);
    let dkg_dealing_encryption_key_id = compute_dkg_dealing_encryption_key_id(
        &external_public_keys.dkg_dealing_encryption_public_key,
    );
    let tls_secret_key_id = compute_tls_certificate_key_id(&external_public_keys.tls_certificate);
    let idkg_dealing_encryption_key_id = compute_idkg_dealing_encryption_key_id(
        &external_public_keys.idkg_dealing_encryption_public_key,
    );

    KeyIds {
        node_signing_key_id,
        committee_signing_key_id,
        dkg_dealing_encryption_key_id,
        tls_secret_key_id,
        idkg_dealing_encryption_key_id,
    }
}

fn compute_node_signing_key_id(
    external_node_signing_public_key: &PublicKeyProto,
) -> Result<KeyId, ExternalPublicKeyError> {
    if AlgorithmId::from(external_node_signing_public_key.algorithm) != AlgorithmId::Ed25519 {
        return Err(ExternalPublicKeyError(Box::new(format!(
            "expected public key algorithm Ed25519, but found {:?}",
            AlgorithmId::from(external_node_signing_public_key.algorithm),
        ))));
    }
    let csp_key = CspPublicKey::try_from(external_node_signing_public_key)
        .map_err(|err| ExternalPublicKeyError(Box::new(format!("{:?}", err))))?;
    Ok(KeyId::try_from(&csp_key)?)
}

fn compute_committee_signing_key_id(
    external_committee_signing_public_key: &PublicKeyProto,
) -> Result<KeyId, ExternalPublicKeyError> {
    if AlgorithmId::from(external_committee_signing_public_key.algorithm)
        != AlgorithmId::MultiBls12_381
    {
        return Err(ExternalPublicKeyError(Box::new(format!(
            "expected public key algorithm MultiBls12_381, but found {:?}",
            AlgorithmId::from(external_committee_signing_public_key.algorithm),
        ))));
    }
    ensure_committee_signing_key_pop_is_well_formed(external_committee_signing_public_key)?;
    let csp_key = CspPublicKey::try_from(external_committee_signing_public_key)
        .map_err(|err| ExternalPublicKeyError(Box::new(format!("{:?}", err))))?;
    Ok(KeyId::try_from(&csp_key)?)
}

fn ensure_committee_signing_key_pop_is_well_formed(
    pk_proto: &PublicKeyProto,
) -> Result<(), ExternalPublicKeyError> {
    CspPop::try_from(pk_proto).map_err(|e| match e {
        CspPopFromPublicKeyProtoError::NoPopForAlgorithm { algorithm } => {
            ExternalPublicKeyError(Box::new(format!(
                "Malformed public key (No POP for algorithm {:?})",
                algorithm
            )))
        }
        CspPopFromPublicKeyProtoError::MissingProofData => ExternalPublicKeyError(Box::new(
            "Malformed public key (Missing proof data)".to_string(),
        )),
        CspPopFromPublicKeyProtoError::MalformedPop { .. } => {
            ExternalPublicKeyError(Box::new("Malformed public key (Malformed Pop)".to_string()))
        }
    })?;

    Ok(())
}

fn compute_dkg_dealing_encryption_key_id(
    external_dkg_dealing_encryption_public_key: &PublicKeyProto,
) -> Result<KeyId, ExternalPublicKeyError> {
    if AlgorithmId::from(external_dkg_dealing_encryption_public_key.algorithm)
        != AlgorithmId::Groth20_Bls12_381
    {
        return Err(ExternalPublicKeyError(Box::new(format!(
            "Malformed public key: Expected public key algorithm Groth20_Bls12_381, but found {:?}",
            AlgorithmId::from(external_dkg_dealing_encryption_public_key.algorithm),
        ))));
    }
    let _csp_pop = CspFsEncryptionPop::try_from(external_dkg_dealing_encryption_public_key)
        .map_err(|e| ExternalPublicKeyError(Box::new(format!("Malformed public key {:?}", e))))?;
    let csp_key = CspFsEncryptionPublicKey::try_from(external_dkg_dealing_encryption_public_key)
        .map_err(|e| {
            ExternalPublicKeyError(Box::new(format!(
                "Malformed public key ({:?}",
                e.internal_error
            )))
        })?;
    Ok(KeyId::from(&csp_key))
}

fn compute_idkg_dealing_encryption_key_id(
    external_idkg_dealing_encryption_public_key: &PublicKeyProto,
) -> Result<KeyId, ExternalPublicKeyError> {
    let idkg_dealing_encryption_pk = mega_public_key_from_proto(
        external_idkg_dealing_encryption_public_key,
    )
    .map_err(|e| match e {
        MEGaPublicKeyFromProtoError::UnsupportedAlgorithm { algorithm_id } => {
            ExternalPublicKeyError(Box::new(format!("Malformed public key: unsupported algorithm ({:?}) of I-DKG dealing encryption key",
                    algorithm_id,
                ),
            ))
        }
        MEGaPublicKeyFromProtoError::MalformedPublicKey { .. } => {
            ExternalPublicKeyError(Box::new("Malformed public key: I-DKG dealing encryption key malformed".to_string()))
        }
    })?;

    let key_id = KeyId::try_from(&idkg_dealing_encryption_pk).map_err(|error| {
        ExternalPublicKeyError(Box::new(format!(
            "Malformed public key: failed to derive key ID from MEGa public key: {}",
            error
        )))
    })?;
    Ok(key_id)
}

fn compute_tls_certificate_key_id(
    external_tls_certificate: &X509PublicKeyCert,
) -> Result<KeyId, ExternalPublicKeyError> {
    let public_key_cert = TlsPublicKeyCert::new_from_der(
        external_tls_certificate.certificate_der.clone(),
    )
    .map_err(|e| ExternalPublicKeyError(Box::new(format!("Malformed certificate: {:?}", e))))?;

    Ok(KeyId::try_from(&public_key_cert)?)
}

#[derive(Debug, Clone)]
struct LocalNodePublicKeys {
    pub node_signing_public_key: Option<PublicKeyProto>,
    pub committee_signing_public_key: Option<PublicKeyProto>,
    pub tls_certificate: Option<X509PublicKeyCert>,
    pub dkg_dealing_encryption_public_key: Option<PublicKeyProto>,
    pub idkg_dealing_encryption_public_keys: Vec<PublicKeyProto>,
}

impl LocalNodePublicKeys {
    fn from_public_key_store<P: PublicKeyStore>(pks_read_lock: RwLockReadGuard<'_, P>) -> Self {
        LocalNodePublicKeys {
            node_signing_public_key: pks_read_lock.node_signing_pubkey(),
            committee_signing_public_key: pks_read_lock.committee_signing_pubkey(),
            tls_certificate: pks_read_lock.tls_certificate(),
            dkg_dealing_encryption_public_key: pks_read_lock.ni_dkg_dealing_encryption_pubkey(),
            idkg_dealing_encryption_public_keys: pks_read_lock.idkg_dealing_encryption_pubkeys(),
        }
    }

    fn is_empty(&self) -> bool {
        self.node_signing_public_key.is_none()
            && self.committee_signing_public_key.is_none()
            && self.tls_certificate.is_none()
            && self.dkg_dealing_encryption_public_key.is_none()
            && self.idkg_dealing_encryption_public_keys.is_empty()
    }
}

#[derive(Debug)]
struct RequiredNodePublicKeys {
    node_signing_public_key: PublicKeyProto,
    committee_signing_public_key: PublicKeyProto,
    tls_certificate: X509PublicKeyCert,
    dkg_dealing_encryption_public_key: PublicKeyProto,
    /// Guaranteed to be non-empty
    idkg_dealing_encryption_public_keys: Vec<PublicKeyProto>,
}

impl TryFrom<LocalNodePublicKeys> for RequiredNodePublicKeys {
    type Error = ValidatePksAndSksError;

    fn try_from(local_public_keys: LocalNodePublicKeys) -> Result<Self, Self::Error> {
        if local_public_keys.is_empty() {
            return Err(ValidatePksAndSksError::EmptyPublicKeyStore);
        }
        let node_signing_public_key = local_public_keys.node_signing_public_key.ok_or(
            ValidatePksAndSksError::NodeSigningKeyError(PublicKeyNotFound),
        )?;
        let committee_signing_public_key = local_public_keys.committee_signing_public_key.ok_or(
            ValidatePksAndSksError::CommitteeSigningKeyError(PublicKeyNotFound),
        )?;
        let tls_certificate = local_public_keys.tls_certificate.ok_or(
            ValidatePksAndSksError::TlsCertificateError(PublicKeyNotFound),
        )?;
        let dkg_dealing_encryption_public_key =
            local_public_keys.dkg_dealing_encryption_public_key.ok_or(
                ValidatePksAndSksError::DkgDealingEncryptionKeyError(PublicKeyNotFound),
            )?;
        let idkg_dealing_encryption_public_keys =
            local_public_keys.idkg_dealing_encryption_public_keys;
        if idkg_dealing_encryption_public_keys.is_empty() {
            return Err(ValidatePksAndSksError::IdkgDealingEncryptionKeyError(
                PublicKeyNotFound,
            ));
        }
        Ok(RequiredNodePublicKeys {
            node_signing_public_key,
            committee_signing_public_key,
            tls_certificate,
            dkg_dealing_encryption_public_key,
            idkg_dealing_encryption_public_keys,
        })
    }
}

impl RequiredNodePublicKeys {
    fn compute_key_ids(&self) -> Result<RequiredKeyIds, ValidatePksAndSksError> {
        let node_signing_key_id = compute_node_signing_key_id(&self.node_signing_public_key)
            .map_err(|error| {
                ValidatePksAndSksError::NodeSigningKeyError(PublicKeyInvalid(error.0.to_string()))
            })?;
        let committee_signing_key_id = compute_committee_signing_key_id(
            &self.committee_signing_public_key,
        )
        .map_err(|error| {
            ValidatePksAndSksError::CommitteeSigningKeyError(PublicKeyInvalid(error.0.to_string()))
        })?;
        let tls_secret_key_id =
            compute_tls_certificate_key_id(&self.tls_certificate).map_err(|error| {
                ValidatePksAndSksError::TlsCertificateError(PublicKeyInvalid(error.0.to_string()))
            })?;
        let dkg_dealing_encryption_key_id =
            compute_dkg_dealing_encryption_key_id(&self.dkg_dealing_encryption_public_key)
                .map_err(|error| {
                    ValidatePksAndSksError::DkgDealingEncryptionKeyError(PublicKeyInvalid(
                        error.0.to_string(),
                    ))
                })?;
        let idkg_dealing_encryption_key_ids = self
            .idkg_dealing_encryption_public_keys
            .iter()
            .map(|public_key| {
                compute_idkg_dealing_encryption_key_id(public_key).map_err(|error| {
                    ValidatePksAndSksError::IdkgDealingEncryptionKeyError(PublicKeyInvalid(
                        error.0.to_string(),
                    ))
                })
            })
            .collect::<Result<Vec<KeyId>, ValidatePksAndSksError>>()?;
        Ok(RequiredKeyIds {
            node_signing_key_id,
            committee_signing_key_id,
            tls_secret_key_id,
            dkg_dealing_encryption_key_id,
            idkg_dealing_encryption_key_ids,
        })
    }

    fn validate(self, current_time: Time) -> Result<ValidNodePublicKeys, ValidatePksAndSksError> {
        let node_signing_public_key =
            ValidNodeSigningPublicKey::try_from(self.node_signing_public_key).map_err(|e| {
                ValidatePksAndSksError::NodeSigningKeyError(PublicKeyInvalid(e.error))
            })?;
        let node_id = node_signing_public_key.derived_node_id();
        let committee_signing_public_key = ValidCommitteeSigningPublicKey::try_from(
            self.committee_signing_public_key,
        )
        .map_err(|e| ValidatePksAndSksError::CommitteeSigningKeyError(PublicKeyInvalid(e.error)))?;
        let tls_certificate =
            ValidTlsCertificate::try_from((self.tls_certificate, *node_id, current_time)).map_err(
                |e| ValidatePksAndSksError::TlsCertificateError(PublicKeyInvalid(e.error)),
            )?;
        let dkg_dealing_encryption_public_key = ValidDkgDealingEncryptionPublicKey::try_from((
            self.dkg_dealing_encryption_public_key,
            *node_id,
        ))
        .map_err(|e| {
            ValidatePksAndSksError::DkgDealingEncryptionKeyError(PublicKeyInvalid(e.error))
        })?;
        let idkg_dealing_encryption_public_keys = self
            .idkg_dealing_encryption_public_keys
            .into_iter()
            .map(|pk| {
                ValidIDkgDealingEncryptionPublicKey::try_from(pk).map_err(|e| {
                    ValidatePksAndSksError::IdkgDealingEncryptionKeyError(PublicKeyInvalid(e.error))
                })
            })
            .collect::<Result<Vec<ValidIDkgDealingEncryptionPublicKey>, ValidatePksAndSksError>>(
            )?;
        let last_idkg_public_key = idkg_dealing_encryption_public_keys.last().cloned().ok_or(
            ValidatePksAndSksError::IdkgDealingEncryptionKeyError(PublicKeyNotFound),
        )?;
        Ok(ValidNodePublicKeys::from((
            node_signing_public_key,
            committee_signing_public_key,
            tls_certificate,
            dkg_dealing_encryption_public_key,
            last_idkg_public_key,
        )))
    }
}

#[derive(Debug)]
struct RequiredKeyIds {
    node_signing_key_id: KeyId,
    committee_signing_key_id: KeyId,
    tls_secret_key_id: KeyId,
    dkg_dealing_encryption_key_id: KeyId,
    idkg_dealing_encryption_key_ids: Vec<KeyId>,
}

impl RequiredKeyIds {
    fn verify_contained_in_sks<S: SecretKeyStore>(
        &self,
        sks_read_lock: RwLockReadGuard<'_, S>,
    ) -> Result<(), ValidatePksAndSksError> {
        if !sks_read_lock.contains(&self.node_signing_key_id) {
            return Err(ValidatePksAndSksError::NodeSigningKeyError(
                SecretKeyNotFound {
                    key_id: self.node_signing_key_id.to_string(),
                },
            ));
        }
        if !sks_read_lock.contains(&self.committee_signing_key_id) {
            return Err(ValidatePksAndSksError::CommitteeSigningKeyError(
                SecretKeyNotFound {
                    key_id: self.committee_signing_key_id.to_string(),
                },
            ));
        }
        if !sks_read_lock.contains(&self.tls_secret_key_id) {
            return Err(ValidatePksAndSksError::TlsCertificateError(
                SecretKeyNotFound {
                    key_id: self.tls_secret_key_id.to_string(),
                },
            ));
        }
        if !sks_read_lock.contains(&self.dkg_dealing_encryption_key_id) {
            return Err(ValidatePksAndSksError::DkgDealingEncryptionKeyError(
                SecretKeyNotFound {
                    key_id: self.dkg_dealing_encryption_key_id.to_string(),
                },
            ));
        }
        for idkg_key_id in &self.idkg_dealing_encryption_key_ids {
            if !sks_read_lock.contains(idkg_key_id) {
                return Err(ValidatePksAndSksError::IdkgDealingEncryptionKeyError(
                    SecretKeyNotFound {
                        key_id: idkg_key_id.to_string(),
                    },
                ));
            }
        }
        Ok(())
    }
}

fn compare_public_keys(
    external_public_keys: &ExternalPublicKeys,
    local_public_keys: &LocalNodePublicKeys,
) -> LocalNodePublicKeyResults {
    let node_signing_public_key_result = compare_local_and_external_public_keys(
        local_public_keys.node_signing_public_key.as_ref(),
        &external_public_keys.node_signing_public_key,
    );
    let committee_signing_public_key_result = compare_local_and_external_public_keys(
        local_public_keys.committee_signing_public_key.as_ref(),
        &external_public_keys.committee_signing_public_key,
    );
    let tls_certificate_public_key_result = compare_local_and_external_certificates(
        local_public_keys.tls_certificate.as_ref(),
        &external_public_keys.tls_certificate,
    );
    let dkg_dealing_encryption_public_key_result = compare_local_and_external_public_keys(
        local_public_keys.dkg_dealing_encryption_public_key.as_ref(),
        &external_public_keys.dkg_dealing_encryption_public_key,
    );
    let idkg_dealing_encryption_public_key_result = if !local_public_keys
        .idkg_dealing_encryption_public_keys
        .is_empty()
    {
        let found_idkg_key = local_public_keys
            .idkg_dealing_encryption_public_keys
            .iter()
            .any(|local_idkg_key| {
                local_idkg_key.equal_ignoring_timestamp(
                    &external_public_keys.idkg_dealing_encryption_public_key,
                )
            });
        if found_idkg_key {
            Ok(())
        } else {
            Err(LocalPublicKeyError::Mismatch)
        }
    } else {
        Err(LocalPublicKeyError::NotFound)
    };

    LocalNodePublicKeyResults {
        node_signing_public_key_result,
        committee_signing_public_key_result,
        tls_certificate_public_key_result,
        dkg_dealing_encryption_public_key_result,
        idkg_dealing_encryption_public_key_result,
    }
}

fn compare_local_and_external_public_keys(
    maybe_local_public_key: Option<&PublicKeyProto>,
    external_public_key: &PublicKeyProto,
) -> Result<(), LocalPublicKeyError> {
    if let Some(local_public_key) = maybe_local_public_key {
        let key_match = local_public_key.equal_ignoring_timestamp(external_public_key);
        if !key_match {
            return Err(LocalPublicKeyError::Mismatch);
        }
        return Ok(());
    }
    Err(LocalPublicKeyError::NotFound)
}

fn compare_local_and_external_certificates(
    maybe_local_cert: Option<&X509PublicKeyCert>,
    external_cert: &X509PublicKeyCert,
) -> Result<(), LocalPublicKeyError> {
    if let Some(local_cert) = maybe_local_cert {
        if local_cert != external_cert {
            return Err(LocalPublicKeyError::Mismatch);
        }
        return Ok(());
    }
    Err(LocalPublicKeyError::NotFound)
}

struct SecretKeyResults {
    pub node_signing_secret_key_result: Result<(), SecretKeyError>,
    pub committee_signing_secret_key_result: Result<(), SecretKeyError>,
    pub tls_certificate_secret_key_result: Result<(), SecretKeyError>,
    pub dkg_dealing_encryption_secret_key_result: Result<(), SecretKeyError>,
    pub idkg_dealing_encryption_secret_key_result: Result<(), SecretKeyError>,
}

impl SecretKeyResults {
    pub fn is_ok(&self) -> bool {
        self.node_signing_secret_key_result.is_ok()
            && self.committee_signing_secret_key_result.is_ok()
            && self.tls_certificate_secret_key_result.is_ok()
            && self.dkg_dealing_encryption_secret_key_result.is_ok()
            && self.idkg_dealing_encryption_secret_key_result.is_ok()
    }
}

fn check_secret_keys_existence<S: SecretKeyStore>(
    sks_read_lock: RwLockReadGuard<'_, S>,
    key_ids: &KeyIds,
) -> SecretKeyResults {
    let node_signing_secret_key_result =
        check_secret_key_existence(&sks_read_lock, &key_ids.node_signing_key_id);
    let committee_signing_secret_key_result =
        check_secret_key_existence(&sks_read_lock, &key_ids.committee_signing_key_id);
    let dkg_dealing_encryption_secret_key_result =
        check_secret_key_existence(&sks_read_lock, &key_ids.dkg_dealing_encryption_key_id);
    let tls_certificate_secret_key_result =
        check_secret_key_existence(&sks_read_lock, &key_ids.tls_secret_key_id);
    let idkg_dealing_encryption_secret_key_result =
        check_secret_key_existence(&sks_read_lock, &key_ids.idkg_dealing_encryption_key_id);

    SecretKeyResults {
        node_signing_secret_key_result,
        committee_signing_secret_key_result,
        tls_certificate_secret_key_result,
        dkg_dealing_encryption_secret_key_result,
        idkg_dealing_encryption_secret_key_result,
    }
}

fn check_secret_key_existence<S: SecretKeyStore>(
    sks_read_lock: &RwLockReadGuard<'_, S>,
    key_id_result: &Result<KeyId, ExternalPublicKeyError>,
) -> Result<(), SecretKeyError> {
    match key_id_result {
        Ok(key_id) => {
            if sks_read_lock.contains(key_id) {
                Ok(())
            } else {
                Err(SecretKeyError::NotFound)
            }
        }
        Err(_) => Err(SecretKeyError::CannotComputeKeyId),
    }
}

fn combine_errors(
    key_ids: KeyIds,
    local_public_key_results: LocalNodePublicKeyResults,
    secret_key_results: SecretKeyResults,
) -> NodeKeysErrors {
    NodeKeysErrors {
        node_signing_key_error: construct_check_key_pair_errors(
            key_ids.node_signing_key_id.err(),
            local_public_key_results
                .node_signing_public_key_result
                .err(),
            secret_key_results.node_signing_secret_key_result.err(),
        ),
        committee_signing_key_error: construct_check_key_pair_errors(
            key_ids.committee_signing_key_id.err(),
            local_public_key_results
                .committee_signing_public_key_result
                .err(),
            secret_key_results.committee_signing_secret_key_result.err(),
        ),
        tls_certificate_error: construct_check_key_pair_errors(
            key_ids.tls_secret_key_id.err(),
            local_public_key_results
                .tls_certificate_public_key_result
                .err(),
            secret_key_results.tls_certificate_secret_key_result.err(),
        ),
        dkg_dealing_encryption_key_error: construct_check_key_pair_errors(
            key_ids.dkg_dealing_encryption_key_id.err(),
            local_public_key_results
                .dkg_dealing_encryption_public_key_result
                .err(),
            secret_key_results
                .dkg_dealing_encryption_secret_key_result
                .err(),
        ),
        idkg_dealing_encryption_key_error: construct_check_key_pair_errors(
            key_ids.idkg_dealing_encryption_key_id.err(),
            local_public_key_results
                .idkg_dealing_encryption_public_key_result
                .err(),
            secret_key_results
                .idkg_dealing_encryption_secret_key_result
                .err(),
        ),
    }
}

fn construct_check_key_pair_errors(
    external_public_key_error: Option<ExternalPublicKeyError>,
    local_public_key_error: Option<LocalPublicKeyError>,
    secret_key_error: Option<SecretKeyError>,
) -> Option<NodeKeysError> {
    match (
        &external_public_key_error,
        &local_public_key_error,
        &secret_key_error,
    ) {
        (None, None, None) => None,
        _ => Some(NodeKeysError {
            external_public_key_error,
            local_public_key_error,
            secret_key_error,
        }),
    }
}
