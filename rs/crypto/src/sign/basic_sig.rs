use super::*;
use ic_crypto_internal_csp::api::CspSigner;
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::types::SigConverter;
use ic_crypto_internal_csp::vault::api::PublicRandomSeedGeneratorError;

use std::time::Instant;
use std::time::Duration;

#[cfg(test)]
mod tests;

pub struct BasicSigVerifierInternal {}

impl BasicSigVerifierInternal {
    pub fn verify_basic_sig<S: CspSigner, H: Signable>(
        csp_signer: &S,
        registry: &dyn RegistryClient,
        signature: &BasicSigOf<H>,
        message: &H,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let pk_proto =
            key_from_registry(registry, signer, KeyPurpose::NodeSigning, registry_version)?;

        let algorithm_id = AlgorithmId::from(pk_proto.algorithm);
        let csp_sig = SigConverter::for_target(algorithm_id).try_from_basic(signature)?;
        let csp_pk = CspPublicKey::try_from(pk_proto)?;

        csp_signer.verify(&csp_sig, &message.as_signed_bytes(), algorithm_id, csp_pk)
    }

    pub fn combine_basic_sig<H: Signable>(
        signatures: BTreeMap<NodeId, &BasicSigOf<H>>,
    ) -> CryptoResult<BasicSignatureBatch<H>> {
        if signatures.is_empty() {
            return Err(CryptoError::InvalidArgument {
                message: "No signatures to combine in a batch. At least one signature is needed to create a batch"
                    .to_string(),
            });
        };
        let mut signatures_map = BTreeMap::new();
        for (signer, signature) in signatures.into_iter() {
            signatures_map.insert(signer, signature.clone());
        }

        Ok(BasicSignatureBatch { signatures_map })
    }

    pub fn verify_multi_message_sig_batch<H: Signable>(
        vault: &dyn CspVault,
        registry: &dyn RegistryClient,
        batches_by_message: &[(&H, &BasicSignatureBatch<H>)],
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let total_start = Instant::now();

        // Pre-calculate the total number of signatures for efficient vector allocation.
        let total_num_sigs: usize = batches_by_message
            .iter()
            .map(|(_, batch)| batch.signatures_map.len())
            .sum();
    
        if total_num_sigs == 0 {
            // This can happen if the top-level slice is empty or contains only empty batches.
            // In either case, there is nothing to verify, so we succeed.
            return Ok(());
        }
    
        // --- Phase 1: Serialize all messages to create stable, owned data ---
        let ser_start = Instant::now();
        let serialized_messages_owner: Vec<Vec<u8>> = batches_by_message
            .iter()
            .map(|(message, _)| message.as_signed_bytes())
            .collect();
        let message_ser_duration = ser_start.elapsed();
    
    
        // Allocate vectors with the exact capacity needed.
        let mut msgs: Vec<&[u8]> = Vec::with_capacity(total_num_sigs);
        let mut sigs: Vec<&[u8]> = Vec::with_capacity(total_num_sigs);
        let mut keys: Vec<ic_ed25519::PublicKey> = Vec::with_capacity(total_num_sigs);
    
        // --- Phase 2: Data Preparation Loop ---
        // Iterate over the original batches and the now-stable serialized messages together.
        let loop_start = Instant::now();
        let mut key_fetch_duration = Duration::new(0, 0);
        let mut key_deserialize_duration = Duration::new(0, 0);
    
        for ((_message, batch), message_slice) in batches_by_message.iter().zip(&serialized_messages_owner) {
            if batch.signatures_map.is_empty() {
                continue; // Skip empty batches within the collection.
            }
    
            // Inner loop over signatures for this specific message.
            for (signer, signature) in batch.signatures_map.iter() {
                let key_fetch_start = Instant::now();
                let pk_proto =
                    key_from_registry(registry, *signer, KeyPurpose::NodeSigning, registry_version)?;
                key_fetch_duration += key_fetch_start.elapsed();
    
                let pubkey_alg = AlgorithmId::from(pk_proto.algorithm);
                if pubkey_alg != AlgorithmId::Ed25519 {
                    println!(
                        "MultiMessageBatchedSigVerify(ERROR): reason=\"AlgorithmNotSupported\" algorithm={:?} total_us={}",
                        pubkey_alg,
                        total_start.elapsed().as_micros()
                    );
                    return Err(CryptoError::AlgorithmNotSupported {
                        algorithm: pubkey_alg,
                        reason: "Only Ed25519 is supported in batched basic sig verification.".to_string(),
                    });
                }
    
                let key_deserialize_start = Instant::now();
                let pk = ic_ed25519::PublicKey::deserialize_raw(&pk_proto.key_value).map_err(|e| {
                    CryptoError::MalformedPublicKey {
                        algorithm: AlgorithmId::Ed25519,
                        key_bytes: Some(pk_proto.key_value.clone()),
                        internal_error: e.to_string(),
                    }
                })?;
                key_deserialize_duration += key_deserialize_start.elapsed();
    
                // All signatures in this inner loop correspond to the same `message_slice`.
                msgs.push(message_slice);
                sigs.push(&signature.get_ref().0[..]);
                keys.push(pk);
            }
        }
        let loop_duration = loop_start.elapsed();
    
        // --- 3. Seed Generation ---
        let seed_gen_start = Instant::now();
        let seed = vault.new_public_seed().map_err(|e| match e {
            PublicRandomSeedGeneratorError::TransientInternalError { internal_error } => {
                CryptoError::TransientInternalError { internal_error }
            }
        })?;
        let seed_gen_duration = seed_gen_start.elapsed();
        let rng = &mut seed.into_rng();
    
        // --- 4. Core Cryptography ---
        let verification_start = Instant::now();
        let result = ic_ed25519::PublicKey::batch_verify(&msgs, &sigs, &keys, rng).map_err(|e| {
            CryptoError::SignatureVerification {
                algorithm: AlgorithmId::Ed25519,
                public_key_bytes: vec![], // Note: We lose which key/sig failed in a batch
                sig_bytes: vec![],
                internal_error: e.to_string(),
            }
        });
        let verification_duration = verification_start.elapsed();
        let total_duration = total_start.elapsed();
    
        // --- 5. Consolidated Logging ---
        println!(
            "MultiMessageBatchedSigVerify: result={} total_us={} num_messages={} total_sigs={} message_ser_us={} loop_us={} key_fetch_us={} key_deserialize_us={} seed_gen_us={} verification_us={}",
            if result.is_ok() { "OK" } else { "FAIL" },
            total_duration.as_micros(),
            batches_by_message.len(),
            total_num_sigs,
            message_ser_duration.as_micros(),
            loop_duration.as_micros(),
            key_fetch_duration.as_micros(),
            key_deserialize_duration.as_micros(),
            seed_gen_duration.as_micros(),
            verification_duration.as_micros(),
        );
    
        result
    }

    pub fn verify_basic_sig_batch<H: Signable>(
        vault: &dyn CspVault,
        registry: &dyn RegistryClient,
        signatures: &BasicSignatureBatch<H>,
        message: &H,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        let total_start = Instant::now();
    
        if signatures.signatures_map.is_empty() {
            return Err(CryptoError::InvalidArgument {
                message: "Empty BasicSignatureBatch. At least one signature should be included in the batch.".to_string(),
            });
        };
    
        // 1. Message Serialization
        let message_ser_start = Instant::now();
        let message_bytes = message.as_signed_bytes();
        let message_ser_duration = message_ser_start.elapsed();
    
        let num_sigs = signatures.signatures_map.len();
        let mut msgs = Vec::with_capacity(num_sigs);
        let mut sigs = Vec::with_capacity(num_sigs);
        let mut keys = Vec::with_capacity(num_sigs);
    
        // 2. Data Preparation Loop
        let loop_start = Instant::now();
        let mut key_fetch_duration = Duration::new(0, 0);
        let mut key_deserialize_duration = Duration::new(0, 0);
    
        for (signer, signature) in signatures.signatures_map.iter() {
            let key_fetch_start = Instant::now();
            let pk_proto =
                key_from_registry(registry, *signer, KeyPurpose::NodeSigning, registry_version)?;
            key_fetch_duration += key_fetch_start.elapsed();
    
            let pubkey_alg = AlgorithmId::from(pk_proto.algorithm);
            if pubkey_alg != AlgorithmId::Ed25519 {
                // Early exit, so we log what we have so far on a single line
                println!(
                    "BatchedSigVerify(ERROR): reason=\"AlgorithmNotSupported\" algorithm={:?} total_us={}",
                    pubkey_alg,
                    total_start.elapsed().as_micros()
                );
                return Err(CryptoError::AlgorithmNotSupported {
                    algorithm: pubkey_alg,
                    reason: "Only Ed25519 is supported in batched basic sig verification.".to_string(),
                });
            }
    
            let key_deserialize_start = Instant::now();
            let pk = ic_ed25519::PublicKey::deserialize_raw(&pk_proto.key_value).map_err(|e| {
                CryptoError::MalformedPublicKey {
                    algorithm: AlgorithmId::Ed25519,
                    key_bytes: Some(pk_proto.key_value.clone()),
                    internal_error: e.to_string(),
                }
            })?;
            key_deserialize_duration += key_deserialize_start.elapsed();
    
            msgs.push(&message_bytes[..]);
            sigs.push(&signature.get_ref().0[..]);
            keys.push(pk);
        }
        let loop_duration = loop_start.elapsed();
    
        // 3. Seed Generation
        let seed_gen_start = Instant::now();
        let seed = vault.new_public_seed().map_err(|e| match e {
            PublicRandomSeedGeneratorError::TransientInternalError { internal_error } => {
                CryptoError::TransientInternalError { internal_error }
            }
        })?;
        let seed_gen_duration = seed_gen_start.elapsed();
        let rng = &mut seed.into_rng();
    
        // 4. Core Cryptography
        let verification_start = Instant::now();
        let result = ic_ed25519::PublicKey::batch_verify(&msgs, &sigs, &keys, rng).map_err(|e| {
            CryptoError::SignatureVerification {
                algorithm: AlgorithmId::Ed25519,
                public_key_bytes: vec![], // Note: We lose which key/sig failed in a batch
                sig_bytes: vec![],
                internal_error: e.to_string(),
            }
        });
        let verification_duration = verification_start.elapsed();
        let total_duration = total_start.elapsed();
    
        // The single, one-line, consolidated log message
        println!(
            "BatchedSigVerify: result={} total_us={} message_ser_us={} loop_us={} sigs={} key_fetch_us={} key_deserialize_us={} seed_gen_us={} verification_us={}",
            if result.is_ok() { "OK" } else { "FAIL" },
            total_duration.as_micros(),
            message_ser_duration.as_micros(),
            loop_duration.as_micros(),
            num_sigs,
            key_fetch_duration.as_micros(),
            key_deserialize_duration.as_micros(),
            seed_gen_duration.as_micros(),
            verification_duration.as_micros(),
        );
    
        result
    }
}

pub struct BasicSignerInternal {}

impl BasicSignerInternal {
    pub fn sign_basic<S: CspSigner, H: Signable>(
        csp_signer: &S,
        registry: &dyn RegistryClient,
        message: &H,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<BasicSigOf<H>> {
        let pk_proto =
            key_from_registry(registry, signer, KeyPurpose::NodeSigning, registry_version)?;
        let algorithm_id = AlgorithmId::from(pk_proto.algorithm);
        let csp_pk = CspPublicKey::try_from(pk_proto)?;
        let key_id = KeyId::from(&csp_pk);
        let csp_sig = csp_signer.sign(algorithm_id, message.as_signed_bytes(), key_id)?;

        Ok(BasicSigOf::new(BasicSig(csp_sig.as_ref().to_vec())))
    }
}
