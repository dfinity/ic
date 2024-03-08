use std::collections::{BTreeMap, BTreeSet};

use ic_logger::{warn, ReplicaLogger};
use ic_replicated_state::metadata_state::subnet_call_context_manager::EcdsaDealingsContext;
use ic_types::{
    consensus::ecdsa::{self, EcdsaBlockReader},
    crypto::canister_threshold_sig::{
        error::InitialIDkgDealingsValidationError, idkg::InitialIDkgDealings,
    },
    messages::CallbackId,
};

use crate::ecdsa::pre_signer::EcdsaTranscriptBuilder;

/// Checks for new reshare requests from execution and initiates the processing
/// by adding a new [`ecdsa::ReshareOfUnmaskedParams`] config to ongoing xnet reshares.
// TODO: in future, we may need to maintain a key transcript per supported key_id,
// and reshare the one specified by reshare_request.key_id.
pub(crate) fn initiate_reshare_requests(
    payload: &mut ecdsa::EcdsaPayload,
    reshare_requests: BTreeSet<ecdsa::EcdsaReshareRequest>,
) {
    let Some(key_transcript) = &payload.key_transcript.current else {
        return;
    };

    for request in reshare_requests {
        // Ignore requests we already know about
        if payload.ongoing_xnet_reshares.contains_key(&request)
            || payload.xnet_reshare_agreements.contains_key(&request)
        {
            continue;
        }

        // Set up the transcript params for the new request
        let transcript_id = payload.uid_generator.next_transcript_id();
        let receivers = request
            .receiving_node_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let transcript_params = ecdsa::ReshareOfUnmaskedParams::new(
            transcript_id,
            receivers,
            request.registry_version,
            key_transcript,
            key_transcript.unmasked_transcript(),
        );
        payload
            .ongoing_xnet_reshares
            .insert(request, transcript_params);
    }
}

pub(super) fn make_reshare_dealings_response(
    ecdsa_dealings_contexts: &'_ BTreeMap<CallbackId, EcdsaDealingsContext>,
) -> impl Fn(&ecdsa::EcdsaReshareRequest, &InitialIDkgDealings) -> Option<ic_types::messages::Response>
       + '_ {
    Box::new(
        move |request: &ecdsa::EcdsaReshareRequest, initial_dealings: &InitialIDkgDealings| {
            for (callback_id, context) in ecdsa_dealings_contexts.iter() {
                if request
                    == &(ecdsa::EcdsaReshareRequest {
                        key_id: context.key_id.clone(),
                        receiving_node_ids: context.nodes.iter().copied().collect(),
                        registry_version: context.registry_version,
                    })
                {
                    use ic_management_canister_types::ComputeInitialEcdsaDealingsResponse;
                    return Some(ic_types::messages::Response {
                        originator: context.request.sender,
                        respondent: ic_types::CanisterId::ic_00(),
                        originator_reply_callback: *callback_id,
                        refund: context.request.payment,
                        response_payload: ic_types::messages::Payload::Data(
                            ComputeInitialEcdsaDealingsResponse {
                                initial_dkg_dealings: initial_dealings.into(),
                            }
                            .encode(),
                        ),
                        // Not relevant, the consensus queue is flushed every round by the
                        // scheduler, which uses only the payload and originator callback.
                        deadline: context.request.deadline,
                    });
                }
            }
            None
        },
    )
}

/// Checks and updates the completed reshare requests by:
/// - getting the validated dealings for each ongoing xnet reshare transcript
/// - attempting to build the new [`InitialIDkgDealings`] (fails if there aren't enough dealings)
/// - if successful, moving the request to completed agreements as
///   [`ecdsa::CompletedReshareRequest::Unreported`].
pub(crate) fn update_completed_reshare_requests(
    payload: &mut ecdsa::EcdsaPayload,
    make_reshare_dealings_response: &dyn Fn(
        &ecdsa::EcdsaReshareRequest,
        &InitialIDkgDealings,
    ) -> Option<ic_types::messages::Response>,
    resolver: &dyn EcdsaBlockReader,
    transcript_builder: &dyn EcdsaTranscriptBuilder,
    log: &ReplicaLogger,
) {
    if payload.key_transcript.current.is_none() {
        return;
    }

    let mut completed_reshares = BTreeMap::new();
    for (request, reshare_param) in &payload.ongoing_xnet_reshares {
        // Get the verified dealings for this transcript
        let transcript_id = reshare_param.as_ref().transcript_id;
        let dealings = transcript_builder.get_validated_dealings(transcript_id);

        // Resolve the transcript param refs
        let transcript_params = match reshare_param.as_ref().translate(resolver) {
            Ok(params) => params,
            Err(err) => {
                warn!(
                    log,
                    "Failed to resolve reshare transcript params: {:?}", err
                );
                continue;
            }
        };

        // Build the initial dealings
        match InitialIDkgDealings::new(transcript_params, dealings) {
            Ok(dealings) => {
                completed_reshares.insert(request.clone(), dealings);
            }
            Err(InitialIDkgDealingsValidationError::UnsatisfiedCollectionThreshold { .. }) => (),
            Err(err) => {
                warn!(log, "Failed to create initial dealings: {:?}", err);
            }
        };
    }

    // Changed Unreported to Reported
    payload
        .xnet_reshare_agreements
        .iter_mut()
        .for_each(|(_, value)| *value = ecdsa::CompletedReshareRequest::ReportedToExecution);

    for (request, initial_dealings) in completed_reshares {
        if let Some(response) = make_reshare_dealings_response(&request, &initial_dealings) {
            payload.ongoing_xnet_reshares.remove(&request);
            payload.xnet_reshare_agreements.insert(
                request.clone(),
                ecdsa::CompletedReshareRequest::Unreported(response),
            );
        } else {
            warn!(
                log,
                "Cannot find the request for the initial dealings created: {:?}", request
            );
        }
    }
}

/// Translates the reshare requests in the replicated state to the internal format
pub(super) fn get_reshare_requests(
    ecdsa_dealings_contexts: &BTreeMap<CallbackId, EcdsaDealingsContext>,
) -> BTreeSet<ecdsa::EcdsaReshareRequest> {
    ecdsa_dealings_contexts
        .values()
        .map(|context| ecdsa::EcdsaReshareRequest {
            key_id: context.key_id.clone(),
            receiving_node_ids: context.nodes.iter().copied().collect(),
            registry_version: context.registry_version,
        })
        .collect()
}

#[cfg(test)]
pub mod test_utils {
    use ic_management_canister_types::EcdsaKeyId;
    use ic_test_utilities::types::ids::node_test_id;
    use ic_types::RegistryVersion;

    use super::*;

    pub fn create_reshare_request(
        key_id: EcdsaKeyId,
        num_nodes: u64,
        registry_version: u64,
    ) -> ecdsa::EcdsaReshareRequest {
        ecdsa::EcdsaReshareRequest {
            key_id,
            receiving_node_ids: (0..num_nodes).map(node_test_id).collect::<Vec<_>>(),
            registry_version: RegistryVersion::from(registry_version),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::test_utils::*;
    use super::*;

    use assert_matches::assert_matches;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_dealings;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_logger::replica_logger::no_op_logger;
    use ic_management_canister_types::EcdsaKeyId;
    use ic_test_utilities::types::ids::subnet_test_id;
    use ic_types::consensus::ecdsa::EcdsaPayload;

    use crate::ecdsa::test_utils::{
        empty_response, set_up_ecdsa_payload, TestEcdsaBlockReader, TestEcdsaTranscriptBuilder,
    };

    fn set_up(should_create_key_transcript: bool) -> (EcdsaPayload, TestEcdsaBlockReader) {
        let mut rng = reproducible_rng();
        let (ecdsa_payload, _env, block_reader) = set_up_ecdsa_payload(
            &mut rng,
            subnet_test_id(1),
            /*nodes_count=*/ 4,
            should_create_key_transcript,
        );

        (ecdsa_payload, block_reader)
    }

    #[test]
    fn test_ecdsa_initiate_reshare_requests_should_not_accept_when_key_transcript_not_created() {
        let (mut payload, _block_reader) = set_up(/*should_create_key_transcript=*/ false);
        let request =
            create_reshare_request(EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(), 1, 1);

        initiate_reshare_requests(&mut payload, BTreeSet::from([request]));

        assert!(payload.ongoing_xnet_reshares.is_empty());
        assert!(payload.xnet_reshare_agreements.is_empty());
    }

    #[test]
    fn test_ecdsa_initiate_reshare_requests_good_path() {
        let (mut payload, _block_reader) = set_up(/*should_create_key_transcript=*/ true);
        let request =
            create_reshare_request(EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(), 1, 1);

        initiate_reshare_requests(&mut payload, BTreeSet::from([request.clone()]));

        assert!(payload.ongoing_xnet_reshares.contains_key(&request));
        assert!(payload.xnet_reshare_agreements.is_empty());
    }

    #[test]
    fn test_ecdsa_initiate_reshare_requests_incremental() {
        let (mut payload, _block_reader) = set_up(/*should_create_key_transcript=*/ true);
        let key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
        let request = create_reshare_request(key_id.clone(), 1, 1);
        let request_2 = create_reshare_request(key_id.clone(), 2, 2);

        initiate_reshare_requests(&mut payload, BTreeSet::from([request.clone()]));
        initiate_reshare_requests(&mut payload, BTreeSet::from([request_2.clone()]));

        assert!(payload.ongoing_xnet_reshares.contains_key(&request));
        assert!(payload.ongoing_xnet_reshares.contains_key(&request_2));
        assert!(payload.xnet_reshare_agreements.is_empty());
    }

    #[test]
    fn test_ecdsa_initiate_reshare_requests_should_not_accept_already_completed() {
        let (mut payload, _block_reader) = set_up(/*should_create_key_transcript=*/ true);
        let request =
            create_reshare_request(EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(), 1, 1);
        payload.xnet_reshare_agreements.insert(
            request.clone(),
            ecdsa::CompletedReshareRequest::ReportedToExecution,
        );

        initiate_reshare_requests(&mut payload, BTreeSet::from([request]));

        assert!(payload.ongoing_xnet_reshares.is_empty());
        assert_eq!(payload.xnet_reshare_agreements.len(), 1);
    }

    #[test]
    fn test_ecdsa_update_completed_reshare_requests() {
        let (mut payload, block_reader) = set_up(/*should_create_key_transcript=*/ true);
        let transcript_builder = TestEcdsaTranscriptBuilder::new();

        let key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
        let request_1 = create_reshare_request(key_id.clone(), 1, 1);
        let request_2 = create_reshare_request(key_id.clone(), 2, 2);
        initiate_reshare_requests(
            &mut payload,
            BTreeSet::from([request_1.clone(), request_2.clone()]),
        );

        // Request 1 dealings are created, it should be moved from in
        // progress -> completed
        let reshare_params = payload
            .ongoing_xnet_reshares
            .get(&request_1)
            .unwrap()
            .as_ref();
        let dealings = dummy_dealings(reshare_params.transcript_id, &reshare_params.dealers);
        transcript_builder.add_dealings(reshare_params.transcript_id, dealings);
        update_completed_reshare_requests(
            &mut payload,
            &|_, _| Some(empty_response()),
            &block_reader,
            &transcript_builder,
            &no_op_logger(),
        );
        assert_eq!(payload.ongoing_xnet_reshares.len(), 1);
        assert!(payload.ongoing_xnet_reshares.contains_key(&request_2));
        assert_eq!(payload.xnet_reshare_agreements.len(), 1);
        assert_matches!(
            payload.xnet_reshare_agreements.get(&request_1).unwrap(),
            ecdsa::CompletedReshareRequest::Unreported(_)
        );

        // Request 2 dealings are created, it should be moved from in
        // progress -> completed
        let reshare_params = payload
            .ongoing_xnet_reshares
            .get(&request_2)
            .unwrap()
            .as_ref();
        let dealings = dummy_dealings(reshare_params.transcript_id, &reshare_params.dealers);
        transcript_builder.add_dealings(reshare_params.transcript_id, dealings);
        update_completed_reshare_requests(
            &mut payload,
            &|_, _| Some(empty_response()),
            &block_reader,
            &transcript_builder,
            &no_op_logger(),
        );
        assert!(payload.ongoing_xnet_reshares.is_empty());
        assert_eq!(payload.xnet_reshare_agreements.len(), 2);
        assert_matches!(
            payload.xnet_reshare_agreements.get(&request_1).unwrap(),
            ecdsa::CompletedReshareRequest::ReportedToExecution
        );
        assert_matches!(
            payload.xnet_reshare_agreements.get(&request_2).unwrap(),
            ecdsa::CompletedReshareRequest::Unreported(_)
        );

        update_completed_reshare_requests(
            &mut payload,
            &|_, _| Some(empty_response()),
            &block_reader,
            &transcript_builder,
            &no_op_logger(),
        );
        assert!(payload.ongoing_xnet_reshares.is_empty());
        assert_eq!(payload.xnet_reshare_agreements.len(), 2);
        assert_matches!(
            payload.xnet_reshare_agreements.get(&request_1).unwrap(),
            ecdsa::CompletedReshareRequest::ReportedToExecution
        );
        assert_matches!(
            payload.xnet_reshare_agreements.get(&request_2).unwrap(),
            ecdsa::CompletedReshareRequest::ReportedToExecution
        );
    }
}
