use super::*;
use ic_crypto_internal_basic_sig_iccsa as iccsa;
use ic_crypto_internal_basic_sig_iccsa::types::PublicKeyBytes;
use ic_crypto_internal_basic_sig_iccsa::types::SignatureBytes;
use ic_registry_client_helpers::{crypto::CryptoRegistry, subnet::SubnetRegistry};
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;

pub fn verify_canister_sig<S: Signable>(
    registry: Arc<dyn RegistryClient>,
    signature: &CanisterSigOf<S>,
    message: &S,
    user_public_key: &UserPublicKey,
    registry_version: RegistryVersion,
) -> CryptoResult<()> {
    ensure_correct_algorithm_id(user_public_key.algorithm_id)?;
    let root_subnet_pubkey = get_root_subnet_pubkey(registry, registry_version)?;
    iccsa::verify(
        &message.as_signed_bytes(),
        SignatureBytes(signature.get_ref().0.clone()),
        PublicKeyBytes(user_public_key.key.clone()),
        &root_subnet_pubkey,
    )
}

fn ensure_correct_algorithm_id(algorithm_id: AlgorithmId) -> CryptoResult<()> {
    if algorithm_id != AlgorithmId::IcCanisterSignature {
        return Err(CryptoError::AlgorithmNotSupported {
            algorithm: algorithm_id,
            reason: format!("Expected {:?}", AlgorithmId::IcCanisterSignature),
        });
    }
    Ok(())
}

fn get_root_subnet_pubkey(
    registry: Arc<dyn RegistryClient>,
    registry_version: RegistryVersion,
) -> CryptoResult<ThresholdSigPublicKey> {
    let root_subnet_id = registry
        .get_root_subnet_id(registry_version)
        .map_err(CryptoError::RegistryClient)?
        .ok_or(CryptoError::RootSubnetPublicKeyNotFound { registry_version })?;
    registry
        .get_threshold_signing_public_key_for_subnet(root_subnet_id, registry_version)
        .map_err(CryptoError::RegistryClient)?
        .ok_or(CryptoError::RootSubnetPublicKeyNotFound { registry_version })
}
