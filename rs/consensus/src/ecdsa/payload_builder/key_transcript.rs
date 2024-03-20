use ic_types::consensus::ecdsa::{self, EcdsaBlockReader, TranscriptAttributes};

use super::EcdsaPayloadError;

pub(super) fn get_created_key_transcript(
    key_transcript: &ecdsa::EcdsaKeyTranscript,
    block_reader: &dyn EcdsaBlockReader,
) -> Result<Option<ecdsa::UnmaskedTranscriptWithAttributes>, EcdsaPayloadError> {
    if let ecdsa::KeyTranscriptCreation::Created(unmasked) = &key_transcript.next_in_creation {
        let transcript = block_reader.transcript(unmasked.as_ref())?;
        Ok(Some(ecdsa::UnmaskedTranscriptWithAttributes::new(
            transcript.to_attributes(),
            *unmasked,
        )))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ic_crypto_test_utils_canister_threshold_sigs::{
        generate_key_transcript, CanisterThresholdSigTestEnvironment, IDkgParticipants,
    };
    use ic_crypto_test_utils_reproducible_rng::{reproducible_rng, ReproducibleRng};
    use ic_management_canister_types::EcdsaKeyId;
    use ic_types::{
        crypto::{canister_threshold_sig::idkg::IDkgTranscript, AlgorithmId},
        Height,
    };

    use crate::ecdsa::test_utils::TestEcdsaBlockReader;

    use super::*;

    #[test]
    fn get_created_key_transcript_returns_some_test() {
        let mut block_reader = TestEcdsaBlockReader::new();
        let mut rng = reproducible_rng();
        let key_transcript = create_key_transcript(&mut rng);
        let key_transcript_ref =
            ecdsa::UnmaskedTranscript::try_from((Height::from(0), &key_transcript)).unwrap();
        block_reader.add_transcript(*key_transcript_ref.as_ref(), key_transcript.clone());

        let current_key_transcript = ecdsa::EcdsaKeyTranscript {
            current: None,
            next_in_creation: ecdsa::KeyTranscriptCreation::Created(key_transcript_ref),
            key_id: EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
        };

        let created_key_transcript =
            get_created_key_transcript(&current_key_transcript, &block_reader)
                .expect("Should not fail");

        assert_eq!(
            created_key_transcript,
            Some(ecdsa::UnmaskedTranscriptWithAttributes::new(
                key_transcript.to_attributes(),
                key_transcript_ref
            ))
        );
    }

    #[test]
    fn get_created_key_transcript_returns_none_test() {
        let block_reader = TestEcdsaBlockReader::new();

        let key_transcript = ecdsa::EcdsaKeyTranscript {
            current: None,
            next_in_creation: ecdsa::KeyTranscriptCreation::Begin,
            key_id: EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
        };

        let created_key_transcript =
            get_created_key_transcript(&key_transcript, &block_reader).expect("Should not fail");

        assert!(created_key_transcript.is_none());
    }

    fn create_key_transcript(rng: &mut ReproducibleRng) -> IDkgTranscript {
        let env = CanisterThresholdSigTestEnvironment::new(4, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
        generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            rng,
        )
    }
}
