use crate::{payload_builder::IDkgDealingContext, pre_signer::IDkgTranscriptBuilder};
use ic_logger::{ReplicaLogger, warn};
use ic_management_canister_types_private::ReshareChainKeyResponse;
use ic_types::{
    batch::ConsensusResponse,
    consensus::idkg::{self, HasIDkgMasterPublicKeyId, IDkgBlockReader, IDkgReshareRequest},
    crypto::canister_threshold_sig::{
        error::InitialIDkgDealingsValidationError, idkg::InitialIDkgDealings,
    },
    messages::{CallbackId, Payload},
};
use std::collections::{BTreeMap, BTreeSet};

/// Checks for new reshare requests from execution and initiates the processing
/// by adding a new [`idkg::ReshareOfUnmaskedParams`] config to ongoing xnet reshares.
pub(crate) fn initiate_reshare_requests(
    payload: &mut idkg::IDkgPayload,
    reshare_requests: BTreeSet<idkg::IDkgReshareRequest>,
) {
    for request in reshare_requests {
        let Some(key_transcript) = payload
            .key_transcripts
            .get(&request.key_id())
            .and_then(|key_transcript| key_transcript.current.as_ref())
        else {
            continue;
        };

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
        let transcript_params = idkg::ReshareOfUnmaskedParams::new(
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

fn make_reshare_dealings_response(
    request: &IDkgReshareRequest,
    initial_dealings: &InitialIDkgDealings,
    idkg_dealings_contexts: &BTreeMap<CallbackId, IDkgDealingContext<'_>>,
) -> Option<ConsensusResponse> {
    idkg_dealings_contexts
        .iter()
        .find_map(|(callback_id, context)| {
            if *request == reshare_request_from_dealings_context(context) {
                Some(ConsensusResponse::new(
                    *callback_id,
                    Payload::Data(ReshareChainKeyResponse::IDkg(initial_dealings.into()).encode()),
                ))
            } else {
                None
            }
        })
}

/// Checks and updates the completed reshare requests by:
/// - getting the validated dealings for each ongoing xnet reshare transcript
/// - attempting to build the new [`InitialIDkgDealings`] (fails if there aren't enough dealings)
/// - if successful, moving the request to completed agreements as
///   [`idkg::CompletedReshareRequest::Unreported`].
pub(crate) fn update_completed_reshare_requests(
    payload: &mut idkg::IDkgPayload,
    idkg_dealings_contexts: &BTreeMap<CallbackId, IDkgDealingContext<'_>>,
    resolver: &dyn IDkgBlockReader,
    transcript_builder: &dyn IDkgTranscriptBuilder,
    log: &ReplicaLogger,
) {
    let mut completed_reshares = BTreeMap::new();
    for (request, reshare_param) in &payload.ongoing_xnet_reshares {
        if payload.current_key_transcript(&request.key_id()).is_none() {
            continue;
        }

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

    // We first clean up the existing xnet_reshare_agreements by keeping those requests
    // that can still be found in the idkg_dealings_contexts for dedup purpose.
    // We only need to keep the "Reported" status because the agreements would have
    // already been reported when the previous block became finalized.
    payload.xnet_reshare_agreements = payload
        .xnet_reshare_agreements
        .keys()
        .filter(|&request| {
            idkg_dealings_contexts
                .values()
                .any(|context| *request == reshare_request_from_dealings_context(context))
        })
        .cloned()
        .map(|request| (request, idkg::CompletedReshareRequest::ReportedToExecution))
        .collect();

    // Insert any newly completed reshares
    for (request, initial_dealings) in completed_reshares {
        if let Some(response) =
            make_reshare_dealings_response(&request, &initial_dealings, idkg_dealings_contexts)
        {
            payload.ongoing_xnet_reshares.remove(&request);
            payload
                .xnet_reshare_agreements
                .insert(request, idkg::CompletedReshareRequest::Unreported(response));
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
    idkg_dealings_contexts: &BTreeMap<CallbackId, IDkgDealingContext<'_>>,
) -> BTreeSet<idkg::IDkgReshareRequest> {
    idkg_dealings_contexts
        .values()
        .map(reshare_request_from_dealings_context)
        .collect()
}

fn reshare_request_from_dealings_context(
    context: &IDkgDealingContext<'_>,
) -> idkg::IDkgReshareRequest {
    idkg::IDkgReshareRequest {
        master_key_id: context.key_id(),
        receiving_node_ids: context.nodes.iter().copied().collect(),
        registry_version: context.registry_version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        payload_builder::filter_idkg_reshare_chain_key_contexts,
        test_utils::{
            TestIDkgBlockReader, TestIDkgTranscriptBuilder, create_reshare_request,
            set_up_idkg_payload,
        },
    };
    use assert_matches::assert_matches;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::{
        dummy_dealings, dummy_initial_idkg_dealing_for_tests,
    };
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_logger::replica_logger::no_op_logger;
    use ic_management_canister_types_private::ReshareChainKeyResponse;
    use ic_test_utilities_consensus::idkg::*;
    use ic_test_utilities_types::ids::subnet_test_id;
    use ic_types::{
        consensus::idkg::{IDkgMasterPublicKeyId, IDkgPayload},
        crypto::AlgorithmId,
    };

    fn set_up(
        key_ids: Vec<IDkgMasterPublicKeyId>,
        should_create_key_transcript: bool,
    ) -> (IDkgPayload, TestIDkgBlockReader) {
        let mut rng = reproducible_rng();
        let (idkg_payload, _env, block_reader) = set_up_idkg_payload(
            &mut rng,
            subnet_test_id(1),
            /*nodes_count=*/ 4,
            key_ids,
            should_create_key_transcript,
        );

        (idkg_payload, block_reader)
    }

    fn consensus_response(
        callback_id: ic_types::messages::CallbackId,
        initial_dealings: &InitialIDkgDealings,
    ) -> ic_types::batch::ConsensusResponse {
        ic_types::batch::ConsensusResponse::new(
            callback_id,
            ic_types::messages::Payload::Data(
                ReshareChainKeyResponse::IDkg(initial_dealings.into()).encode(),
            ),
        )
    }

    #[test]
    fn test_make_reshare_dealings_response() {
        let mut contexts = BTreeMap::new();
        let mut initial_dealings = BTreeMap::new();
        for (i, key_id) in fake_master_public_key_ids_for_all_idkg_algorithms()
            .iter()
            .enumerate()
        {
            let i = i as u64;
            let request = create_reshare_request(key_id.clone(), i, i);
            let context = dealings_context_from_reshare_request(request.clone());
            contexts.insert(CallbackId::from(i), context);
            initial_dealings.insert(
                i,
                dummy_initial_idkg_dealing_for_tests(
                    AlgorithmId::from(key_id.inner()),
                    &mut reproducible_rng(),
                ),
            );
        }
        let contexts = filter_idkg_reshare_chain_key_contexts(&contexts);

        for (i, key_id) in fake_master_public_key_ids_for_all_idkg_algorithms()
            .iter()
            .enumerate()
        {
            let i = i as u64;
            let request = create_reshare_request(key_id.clone(), i, i);
            let res = make_reshare_dealings_response(
                &request,
                initial_dealings.get(&i).unwrap(),
                &contexts,
            )
            .expect("Should get a response");
            assert_eq!(CallbackId::from(i), res.callback);

            let ic_types::messages::Payload::Data(data) = res.payload else {
                panic!("Request should have a data response");
            };

            let response =
                ReshareChainKeyResponse::decode(&data).expect("Failed to decode response");
            let ReshareChainKeyResponse::IDkg(initial_idkg_dealings) = response else {
                panic!("Expected an Idkg response");
            };
            let dealings = InitialIDkgDealings::try_from(&initial_idkg_dealings)
                .expect("Failed to convert dealings");
            assert_eq!(initial_dealings.get(&i).unwrap(), &dealings);
        }

        let fake_key = fake_ecdsa_idkg_master_public_key_id();
        assert_eq!(
            make_reshare_dealings_response(
                &create_reshare_request(fake_key, 10, 10),
                initial_dealings.get(&0).unwrap(),
                &contexts
            ),
            None
        );
    }

    #[test]
    fn test_initiate_reshare_requests_should_not_accept_when_key_transcript_not_created() {
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            let (mut payload, _block_reader) = set_up(
                vec![key_id.clone()],
                /*should_create_key_transcript=*/ false,
            );
            let request = create_reshare_request(key_id, 1, 1);

            initiate_reshare_requests(&mut payload, BTreeSet::from([request]));

            assert!(payload.ongoing_xnet_reshares.is_empty());
            assert!(payload.xnet_reshare_agreements.is_empty());
        }
    }

    #[test]
    fn test_initiate_reshare_requests_good_path() {
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            let (mut payload, _block_reader) = set_up(
                vec![key_id.clone()],
                /*should_create_key_transcript=*/ true,
            );
            let request = create_reshare_request(key_id.clone(), 1, 1);

            initiate_reshare_requests(&mut payload, BTreeSet::from([request.clone()]));

            let params = payload
                .ongoing_xnet_reshares
                .get(&request)
                .expect("should exist");
            assert_eq!(
                params.as_ref().algorithm_id,
                AlgorithmId::from(key_id.inner())
            );

            assert!(payload.xnet_reshare_agreements.is_empty());
        }
    }

    #[test]
    fn test_initiate_reshare_requests_incremental() {
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            let (mut payload, _block_reader) = set_up(
                vec![key_id.clone()],
                /*should_create_key_transcript=*/ true,
            );
            let request = create_reshare_request(key_id.clone(), 1, 1);
            let request_2 = create_reshare_request(key_id.clone(), 2, 2);

            initiate_reshare_requests(&mut payload, BTreeSet::from([request.clone()]));
            initiate_reshare_requests(&mut payload, BTreeSet::from([request_2.clone()]));

            let params = payload
                .ongoing_xnet_reshares
                .get(&request)
                .expect("should exist");
            assert_eq!(
                params.as_ref().algorithm_id,
                AlgorithmId::from(key_id.inner())
            );
            let params_2 = payload
                .ongoing_xnet_reshares
                .get(&request_2)
                .expect("should exist");
            assert_eq!(
                params_2.as_ref().algorithm_id,
                AlgorithmId::from(key_id.inner())
            );
            assert!(payload.xnet_reshare_agreements.is_empty());
        }
    }

    #[test]
    fn test_initiate_reshare_requests_should_not_accept_already_completed() {
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            let (mut payload, _block_reader) = set_up(
                vec![key_id.clone()],
                /*should_create_key_transcript=*/ true,
            );
            let request = create_reshare_request(key_id, 1, 1);
            payload.xnet_reshare_agreements.insert(
                request.clone(),
                idkg::CompletedReshareRequest::ReportedToExecution,
            );

            initiate_reshare_requests(&mut payload, BTreeSet::from([request]));

            assert!(payload.ongoing_xnet_reshares.is_empty());
            assert_eq!(payload.xnet_reshare_agreements.len(), 1);
        }
    }

    #[test]
    fn test_ecdsa_update_completed_reshare_requests_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            test_ecdsa_update_completed_reshare_requests(key_id);
        }
    }

    fn test_ecdsa_update_completed_reshare_requests(key_id: IDkgMasterPublicKeyId) {
        let (mut payload, block_reader) = set_up(
            vec![key_id.clone()],
            /*should_create_key_transcript=*/ true,
        );
        let transcript_builder = TestIDkgTranscriptBuilder::new();

        let request_1 = create_reshare_request(key_id.clone(), 1, 1);
        let request_2 = create_reshare_request(key_id.clone(), 2, 2);
        initiate_reshare_requests(
            &mut payload,
            BTreeSet::from([request_1.clone(), request_2.clone()]),
        );

        let callback_1 = ic_types::messages::CallbackId::new(1);
        let callback_2 = ic_types::messages::CallbackId::new(2);
        let contexts = BTreeMap::from([
            (
                callback_1,
                dealings_context_from_reshare_request(request_1.clone()),
            ),
            (
                callback_2,
                dealings_context_from_reshare_request(request_2.clone()),
            ),
        ]);
        let mut contexts = filter_idkg_reshare_chain_key_contexts(&contexts);

        // Request 1 dealings are created, it should be moved from in
        // progress -> completed (unreported)
        let reshare_params_1 = payload
            .ongoing_xnet_reshares
            .get(&request_1)
            .unwrap()
            .as_ref()
            .clone();
        assert_eq!(
            reshare_params_1.algorithm_id,
            AlgorithmId::from(key_id.inner())
        );
        let dealings_1 = dummy_dealings(reshare_params_1.transcript_id, &reshare_params_1.dealers);
        transcript_builder.add_dealings(reshare_params_1.transcript_id, dealings_1.clone());
        update_completed_reshare_requests(
            &mut payload,
            &contexts,
            &block_reader,
            &transcript_builder,
            &no_op_logger(),
        );
        assert_eq!(payload.ongoing_xnet_reshares.len(), 1);
        assert!(payload.ongoing_xnet_reshares.contains_key(&request_2));
        assert_eq!(payload.xnet_reshare_agreements.len(), 1);
        assert_eq!(
            *payload.xnet_reshare_agreements.get(&request_1).unwrap(),
            idkg::CompletedReshareRequest::Unreported(consensus_response(
                callback_1,
                &InitialIDkgDealings::new(
                    reshare_params_1.translate(&block_reader).unwrap(),
                    dealings_1.clone()
                )
                .unwrap()
            )),
        );

        // Request 2 dealings are created, it should be moved from in
        // progress -> completed (unreported)
        // Request 1 should be moved from completed (unreported) -> reported
        let reshare_params_2 = payload
            .ongoing_xnet_reshares
            .get(&request_2)
            .unwrap()
            .as_ref()
            .clone();
        assert_eq!(
            reshare_params_2.algorithm_id,
            AlgorithmId::from(key_id.inner())
        );
        let dealings_2 = dummy_dealings(reshare_params_2.transcript_id, &reshare_params_2.dealers);
        transcript_builder.add_dealings(reshare_params_2.transcript_id, dealings_2.clone());
        update_completed_reshare_requests(
            &mut payload,
            &contexts,
            &block_reader,
            &transcript_builder,
            &no_op_logger(),
        );
        assert!(payload.ongoing_xnet_reshares.is_empty());
        assert_eq!(payload.xnet_reshare_agreements.len(), 2);
        assert_eq!(
            *payload.xnet_reshare_agreements.get(&request_1).unwrap(),
            idkg::CompletedReshareRequest::ReportedToExecution
        );
        assert_eq!(
            *payload.xnet_reshare_agreements.get(&request_2).unwrap(),
            idkg::CompletedReshareRequest::Unreported(consensus_response(
                callback_2,
                &InitialIDkgDealings::new(
                    reshare_params_2.translate(&block_reader).unwrap(),
                    dealings_2.clone()
                )
                .unwrap()
            )),
        );

        // Request 2 should be moved from completed (unreported) -> reported
        // Request 1 was reported last round, but the context still exists,
        // therefore it should still be kept around for dedup purposes.
        update_completed_reshare_requests(
            &mut payload,
            &contexts,
            &block_reader,
            &transcript_builder,
            &no_op_logger(),
        );
        assert!(payload.ongoing_xnet_reshares.is_empty());
        assert_eq!(payload.xnet_reshare_agreements.len(), 2);
        assert_matches!(
            payload.xnet_reshare_agreements.get(&request_1).unwrap(),
            idkg::CompletedReshareRequest::ReportedToExecution
        );
        assert_matches!(
            payload.xnet_reshare_agreements.get(&request_2).unwrap(),
            idkg::CompletedReshareRequest::ReportedToExecution
        );

        // Agreement for request 1 was reported, and context is removed from state
        assert!(contexts.remove(&callback_1).is_some());

        // Request 1 was reported, and the corresponding context disappeared,
        // therefore the agreement can be purged from the payload.
        // Request 2 was reported last round, but the context still exists,
        // therefore it should still be kept around for dedup purposes.
        update_completed_reshare_requests(
            &mut payload,
            &contexts,
            &block_reader,
            &transcript_builder,
            &no_op_logger(),
        );
        assert!(payload.ongoing_xnet_reshares.is_empty());
        assert_eq!(payload.xnet_reshare_agreements.len(), 1);
        assert_matches!(
            payload.xnet_reshare_agreements.get(&request_2).unwrap(),
            idkg::CompletedReshareRequest::ReportedToExecution
        );
    }
}
