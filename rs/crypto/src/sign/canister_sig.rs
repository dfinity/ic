use super::*;
use ic_crypto_internal_basic_sig_iccsa as iccsa;
use ic_crypto_internal_basic_sig_iccsa::types::PublicKeyBytes;
use ic_crypto_internal_basic_sig_iccsa::types::SignatureBytes;

pub fn verify_canister_sig<S: Signable>(
    signature: &CanisterSigOf<S>,
    message: &S,
    user_public_key: &UserPublicKey,
    root_of_trust: &IcRootOfTrust,
) -> CryptoResult<()> {
    ensure_correct_algorithm_id(user_public_key.algorithm_id)?;
    iccsa::verify(
        &message.as_signed_bytes(),
        SignatureBytes(signature.get_ref().0.clone()),
        PublicKeyBytes(user_public_key.key.clone()),
        root_of_trust.as_ref(),
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
