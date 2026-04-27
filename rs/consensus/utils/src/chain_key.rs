use ic_replicated_state::metadata_state::subnet_call_context_manager::{
    SignWithThresholdContext, ThresholdArguments,
};
use ic_types::{
    consensus::idkg::{
        RequestId,
        common::{BuildSignatureInputsError, ThresholdSigInputs},
    },
    crypto::{
        canister_threshold_sig::{ThresholdEcdsaSigInputs, ThresholdSchnorrSigInputs},
        vetkd::{VetKdArgs, VetKdDerivationContextRef},
    },
    messages::CallbackId,
};

/// Helper to build threshold signature inputs from the context
pub fn build_signature_inputs<'a>(
    callback_id: CallbackId,
    context: &'a SignWithThresholdContext,
) -> Result<(RequestId, ThresholdSigInputs<'a>), BuildSignatureInputsError> {
    match &context.args {
        ThresholdArguments::Ecdsa(args) => {
            let matched_data = args
                .pre_signature
                .as_ref()
                .ok_or(BuildSignatureInputsError::ContextIncomplete)?;
            let request_id = RequestId {
                callback_id,
                height: matched_data.height,
            };
            let nonce_ref = context
                .nonce
                .as_ref()
                .ok_or(BuildSignatureInputsError::ContextIncomplete)?;
            let inputs = ThresholdSigInputs::Ecdsa(
                ThresholdEcdsaSigInputs::new(
                    context.request.sender.get_ref(),
                    &context.derivation_path,
                    &args.message_hash,
                    nonce_ref,
                    matched_data.pre_signature.as_ref(),
                    matched_data.key_transcript.as_ref(),
                )
                .map_err(BuildSignatureInputsError::ThresholdEcdsaSigInputsCreationError)?,
            );
            Ok((request_id, inputs))
        }
        ThresholdArguments::Schnorr(args) => {
            let matched_data = args
                .pre_signature
                .as_ref()
                .ok_or(BuildSignatureInputsError::ContextIncomplete)?;
            let request_id = RequestId {
                callback_id,
                height: matched_data.height,
            };
            let nonce_ref = context
                .nonce
                .as_ref()
                .ok_or(BuildSignatureInputsError::ContextIncomplete)?;
            let inputs = ThresholdSigInputs::Schnorr(
                ThresholdSchnorrSigInputs::new(
                    context.request.sender.get_ref(),
                    &context.derivation_path,
                    &args.message,
                    args.taproot_tree_root.as_ref().map(|v| v.as_slice()),
                    nonce_ref,
                    matched_data.pre_signature.as_ref(),
                    matched_data.key_transcript.as_ref(),
                )
                .map_err(BuildSignatureInputsError::ThresholdSchnorrSigInputsCreationError)?,
            );
            Ok((request_id, inputs))
        }
        ThresholdArguments::VetKd(args) => {
            let request_id = RequestId {
                callback_id,
                height: args.height,
            };
            debug_assert_eq!(context.derivation_path.len(), 1);
            const EMPTY_VEC_REF: &Vec<u8> = &vec![];
            let inputs = ThresholdSigInputs::VetKd(VetKdArgs {
                context: VetKdDerivationContextRef {
                    caller: context.request.sender.get_ref(),
                    context: context.derivation_path.first().unwrap_or(EMPTY_VEC_REF),
                },
                ni_dkg_id: &args.ni_dkg_id,
                input: &args.input,
                transport_public_key: &args.transport_public_key,
            });
            Ok((request_id, inputs))
        }
    }
}
