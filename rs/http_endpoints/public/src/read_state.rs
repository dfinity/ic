//! Module that deals with requests to /api/{v2,v3}/canister/.../read_state and /api/{v2,v3}/subnet/.../read_state

use crate::{
    HttpError, ReplicaHealthStatus,
    common::{Cbor, WithTimeout, build_validator, into_cbor, validation_error_to_http_error},
    metrics::HttpHandlerMetrics,
};
use axum::{
    Router,
    body::Body,
    extract::{DefaultBodyLimit, State},
    response::{IntoResponse, Response},
};
use crossbeam::atomic::AtomicCell;
use http::Request;
use hyper::StatusCode;
use ic_crypto_interfaces_sig_verification::IngressSigVerifier;
use ic_crypto_tree_hash::{
    Label, MatchPattern, Path, TooLongPathError, sparse_labeled_tree_from_paths,
};
use ic_interfaces::time_source::{SysTimeSource, TimeSource};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::{CertifiedStateSnapshot, StateReader};
use ic_logger::ReplicaLogger;
use ic_nns_delegation_manager::{CanisterRangesFilter, NNSDelegationReader};
use ic_registry_client_helpers::crypto::root_of_trust::RegistryRootOfTrustProvider;
use ic_replicated_state::{ReplicatedState, canister_state::execution_state::CustomSectionType};
use ic_types::{
    CanisterId, PrincipalId, SubnetId, UserId,
    crypto::threshold_sig::IcRootOfTrust,
    malicious_flags::MaliciousFlags,
    messages::{
        Blob, Certificate, CertificateDelegation, EXPECTED_MESSAGE_ID_LENGTH, HttpReadStateContent,
        HttpReadStateResponse, HttpRequest, HttpRequestEnvelope, MessageId, ReadState,
    },
};
use ic_validator::{CanisterIdSet, HttpRequestVerifier};
use std::{
    convert::{Infallible, TryFrom},
    sync::Arc,
};
use tower::{ServiceBuilder, util::BoxCloneService};

/// Distinguishes between the `/api/v{2,3}/canister/…/read_state` and
/// `/api/v{2,3}/subnet/…/read_state` endpoints.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Target {
    Canister,
    Subnet,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Version {
    /// Endpoint with the NNS delegation using the flat format of the canister ranges.
    /// `/subnet/<subnet_id>/canister_ranges` path is allowed
    V2,
    /// Endpoint with the NNS delegation using the tree format of the canister ranges (for
    /// `Target::Canister`) or with all canister ranges pruned out (for `Target::Subnet`).
    /// Explicitly requesting `/subnet/<subnet_id>/canister_ranges` path is NOT allowed
    /// except when `subnet_id == nns_subnet_id`. Moreover, all paths of the form
    /// `/subnet/<subnet_id>/canister_ranges`, where `subnet_id != nns_subnet_id`, are
    /// pruned from the returned certificate.
    V3,
}

#[derive(Clone)]
pub struct ReadStateService {
    log: ReplicaLogger,
    health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    metrics: HttpHandlerMetrics,
    nns_delegation_reader: NNSDelegationReader,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    time_source: Arc<dyn TimeSource>,
    validator: Arc<dyn HttpRequestVerifier<ReadState, RegistryRootOfTrustProvider>>,
    registry_client: Arc<dyn RegistryClient>,
    additional_root_of_trust: Option<IcRootOfTrust>,
    nns_subnet_id: SubnetId,
    version: Version,
    target: Target,
}

pub struct ReadStateServiceBuilder {
    log: ReplicaLogger,
    health_status: Option<Arc<AtomicCell<ReplicaHealthStatus>>>,
    metrics: HttpHandlerMetrics,
    malicious_flags: Option<MaliciousFlags>,
    nns_delegation_reader: NNSDelegationReader,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    time_source: Option<Arc<dyn TimeSource>>,
    ingress_verifier: Arc<dyn IngressSigVerifier>,
    registry_client: Arc<dyn RegistryClient>,
    additional_root_of_trust: Option<IcRootOfTrust>,
    nns_subnet_id: SubnetId,
    version: Version,
    target: Target,
}

impl ReadStateService {
    pub(crate) fn route(version: Version, target: Target) -> &'static str {
        match (version, target) {
            (Version::V2, Target::Canister) => {
                "/api/v2/canister/{effective_canister_id}/read_state"
            }
            (Version::V3, Target::Canister) => {
                "/api/v3/canister/{effective_canister_id}/read_state"
            }
            (Version::V2, Target::Subnet) => "/api/v2/subnet/{effective_canister_id}/read_state",
            (Version::V3, Target::Subnet) => "/api/v3/subnet/{effective_canister_id}/read_state",
        }
    }
}

impl ReadStateServiceBuilder {
    pub fn builder(
        log: ReplicaLogger,
        metrics: HttpHandlerMetrics,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        registry_client: Arc<dyn RegistryClient>,
        ingress_verifier: Arc<dyn IngressSigVerifier>,
        nns_delegation_reader: NNSDelegationReader,
        nns_subnet_id: SubnetId,
        version: Version,
        target: Target,
    ) -> Self {
        Self {
            log,
            health_status: None,
            metrics,
            malicious_flags: None,
            nns_delegation_reader,
            state_reader,
            time_source: None,
            ingress_verifier,
            registry_client,
            additional_root_of_trust: None,
            nns_subnet_id,
            version,
            target,
        }
    }

    pub fn with_malicious_flags(mut self, malicious_flags: MaliciousFlags) -> Self {
        self.malicious_flags = Some(malicious_flags);
        self
    }

    pub fn with_time_source(mut self, time_source: Arc<dyn TimeSource>) -> Self {
        self.time_source = Some(time_source);
        self
    }

    pub fn with_health_status(
        mut self,
        health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    ) -> Self {
        self.health_status = Some(health_status);
        self
    }

    pub fn with_additional_root_of_trust(
        mut self,
        additional_root_of_trust: IcRootOfTrust,
    ) -> Self {
        self.additional_root_of_trust = Some(additional_root_of_trust);
        self
    }

    pub(crate) fn build_router(self) -> Router {
        let version = self.version;
        let target = self.target;
        let state = ReadStateService {
            log: self.log,
            health_status: self
                .health_status
                .unwrap_or_else(|| Arc::new(AtomicCell::new(ReplicaHealthStatus::Healthy))),
            metrics: self.metrics,
            nns_delegation_reader: self.nns_delegation_reader,
            state_reader: self.state_reader,
            time_source: self.time_source.unwrap_or(Arc::new(SysTimeSource::new())),
            validator: build_validator(self.ingress_verifier, self.malicious_flags),
            registry_client: self.registry_client,
            additional_root_of_trust: self.additional_root_of_trust,
            nns_subnet_id: self.nns_subnet_id,
            version,
            target,
        };
        Router::new().route(
            ReadStateService::route(version, target),
            axum::routing::post(read_state)
                .with_state(state)
                .layer(ServiceBuilder::new().layer(DefaultBodyLimit::disable())),
        )
    }

    pub fn build_service(self) -> BoxCloneService<Request<Body>, Response, Infallible> {
        let router = self.build_router();
        BoxCloneService::new(router.into_service())
    }
}

pub(crate) async fn read_state(
    axum::extract::Path(effective_canister_id): axum::extract::Path<CanisterId>,
    State(ReadStateService {
        log,
        health_status,
        metrics,
        nns_delegation_reader,
        state_reader,
        time_source,
        validator,
        registry_client,
        additional_root_of_trust,
        nns_subnet_id,
        version,
        target,
    }): State<ReadStateService>,
    WithTimeout(Cbor(request)): WithTimeout<Cbor<HttpRequestEnvelope<HttpReadStateContent>>>,
) -> impl IntoResponse {
    if health_status.load() != ReplicaHealthStatus::Healthy {
        let status = StatusCode::SERVICE_UNAVAILABLE;
        let text = format!(
            "Replica is unhealthy: {:?}. Check the /api/v2/status for more information.",
            health_status.load(),
        );
        return (status, text).into_response();
    }

    // Convert the message to a strongly-typed struct.
    let request = match HttpRequest::<ReadState>::try_from(request) {
        Ok(request) => request,
        Err(e) => {
            let status = StatusCode::BAD_REQUEST;
            let text = format!("Malformed request: {e:?}");
            return (status, text).into_response();
        }
    };
    let read_state = request.content().clone();
    let registry_version = registry_client.get_latest_version();

    let root_of_trust_provider = if let Some(additional_root_of_trust) = additional_root_of_trust {
        RegistryRootOfTrustProvider::new_with_additional_root_of_trust(
            registry_client,
            registry_version,
            additional_root_of_trust,
        )
    } else {
        RegistryRootOfTrustProvider::new(registry_client, registry_version)
    };
    // Since spawn blocking requires 'static we can't use any references
    let request_c = request.clone();

    let response = tokio::task::spawn_blocking(move || {
        let targets = match validator.validate_request(
            &request_c,
            time_source.get_relative_time(),
            &root_of_trust_provider,
        ) {
            Ok(targets) => targets,
            Err(err) => {
                let http_err = validation_error_to_http_error(&request, err, &log);
                return (http_err.status, http_err.message).into_response();
            }
        };

        let Some(certified_state_reader) = state_reader.get_certified_state_snapshot() else {
            return make_service_unavailable_response();
        };

        // Verify authorization for requested paths.
        if let Err(HttpError { status, message }) = verify_paths(
            &metrics,
            target,
            version,
            certified_state_reader.get_state(),
            &read_state.source,
            &read_state.paths,
            &targets,
            effective_canister_id.into(),
            nns_subnet_id,
        ) {
            return (status, message).into_response();
        }

        let delegation_from_nns = match (version, target) {
            (Version::V2, _) => nns_delegation_reader.get_delegation(CanisterRangesFilter::Flat),
            (Version::V3, Target::Canister) => nns_delegation_reader
                .get_delegation(CanisterRangesFilter::Tree(effective_canister_id)),
            (Version::V3, Target::Subnet) => {
                nns_delegation_reader.get_delegation(CanisterRangesFilter::None)
            }
        };

        let maybe_nns_subnet_filter = match version {
            Version::V2 => DeprecatedCanisterRangesFilter::KeepAll,
            Version::V3 => DeprecatedCanisterRangesFilter::KeepOnlyNNS(nns_subnet_id),
        };

        get_certificate_and_create_response(
            read_state.paths,
            delegation_from_nns,
            certified_state_reader.as_ref(),
            maybe_nns_subnet_filter,
        )
    })
    .await;

    match response {
        Ok(res) => res,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn parse_principal_id(principal_id: &[u8]) -> Result<PrincipalId, HttpError> {
    match PrincipalId::try_from(principal_id) {
        Ok(principal_id) => Ok(principal_id),
        Err(err) => Err(HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Could not parse principal ID: {err}."),
        }),
    }
}

fn verify_principal_ids(
    principal_id: &PrincipalId,
    effective_principal_id: &PrincipalId,
) -> Result<(), HttpError> {
    if principal_id != effective_principal_id {
        return Err(HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!(
                "Effective principal id in URL {effective_principal_id} does \
                not match requested principal id: {principal_id}."
            ),
        });
    }
    Ok(())
}

fn make_service_unavailable_response() -> axum::response::Response {
    let status = StatusCode::SERVICE_UNAVAILABLE;
    let text = "Certified state is not available yet. Please try again...".to_string();
    (status, text).into_response()
}

/// Used to instruct the state reader to perhaps filter out the deprecated canister ranges paths
/// from the state tree.
enum DeprecatedCanisterRangesFilter {
    /// Will keep all paths of the form `/subnet/<subnet_id>/canister_ranges` for all subnet ids.
    KeepAll,
    /// Will prune all paths of the form `/subnet/<subnet_id>/canister_ranges` for all subnet ids
    /// except for the provided NNS subnet id.
    KeepOnlyNNS(SubnetId),
}

fn get_certificate_and_create_response(
    mut paths: Vec<Path>,
    delegation_from_nns: Option<CertificateDelegation>,
    certified_state_reader: &dyn CertifiedStateSnapshot<State = ReplicatedState>,
    deprecated_canister_ranges_filter: DeprecatedCanisterRangesFilter,
) -> axum::response::Response {
    // Create labeled tree. This may be an expensive operation and by
    // creating the labeled tree after verifying the paths we know that
    // the depth is max 4.
    // Always add "time" to the paths even if not explicitly requested.
    paths.push(Path::from(Label::from("time")));
    let labeled_tree = match sparse_labeled_tree_from_paths(&paths) {
        Ok(tree) => tree,
        Err(TooLongPathError) => {
            let status = StatusCode::BAD_REQUEST;
            let text = "Failed to parse requested paths: path is too long.".to_string();
            return (status, text).into_response();
        }
    };

    let exclusion_rule = match deprecated_canister_ranges_filter {
        DeprecatedCanisterRangesFilter::KeepAll => None,
        DeprecatedCanisterRangesFilter::KeepOnlyNNS(nns_subnet_id) => {
            let deprecated_canister_ranges_except_the_nns_subnet_id_pattern = vec![
                MatchPattern::Inclusive(Label::from("subnet")),
                MatchPattern::Exclusive(Label::from(nns_subnet_id.get_ref())),
                MatchPattern::Inclusive(Label::from("canister_ranges")),
            ];

            Some(deprecated_canister_ranges_except_the_nns_subnet_id_pattern)
        }
    };

    let Some((tree, certification)) = certified_state_reader
        .read_certified_state_with_exclusion(&labeled_tree, exclusion_rule.as_ref())
    else {
        return make_service_unavailable_response();
    };

    let signature = certification.signed.signature.signature.get().0;

    Cbor(HttpReadStateResponse {
        certificate: Blob(into_cbor(&Certificate {
            tree,
            signature: Blob(signature),
            delegation: delegation_from_nns,
        })),
    })
    .into_response()
}

// Verifies that the `user` is authorized to retrieve the `paths` requested.
fn verify_paths(
    metrics: &HttpHandlerMetrics,
    target: Target,
    version: Version,
    state: &ReplicatedState,
    user: &UserId,
    paths: &[Path],
    targets: &CanisterIdSet,
    effective_principal_id: PrincipalId,
    nns_subnet_id: SubnetId,
) -> Result<(), HttpError> {
    let endpoint = match target {
        Target::Canister => "canister",
        Target::Subnet => "subnet",
    };

    let mut last_request_status_id: Option<MessageId> = None;

    // Convert the paths to slices to make it easier to match below.
    let paths: Vec<Vec<&[u8]>> = paths
        .iter()
        .map(|path| path.iter().map(|label| label.as_bytes()).collect())
        .collect();

    for path in paths {
        match path.as_slice() {
            [b"time"] => {
                metrics.observe_read_state_path(endpoint, "time");
            }
            [b"canister", canister_id, b"controllers" | b"module_hash"]
                if target == Target::Canister =>
            {
                let canister_id = parse_principal_id(canister_id)?;
                verify_principal_ids(&canister_id, &effective_principal_id)?;
                metrics.observe_read_state_path(endpoint, "canister_info");
            }
            [b"canister", canister_id, b"metadata", name] if target == Target::Canister => {
                let name = String::from_utf8(Vec::from(*name)).map_err(|err| HttpError {
                    status: StatusCode::BAD_REQUEST,
                    message: format!("Could not parse the custom section name: {err}."),
                })?;
                // Get principal id from byte slice.
                let principal_id = parse_principal_id(canister_id)?;
                // Verify that canister id and effective canister id match.
                verify_principal_ids(&principal_id, &effective_principal_id)?;
                can_read_canister_metadata(
                    user,
                    &CanisterId::unchecked_from_principal(principal_id),
                    &name,
                    state,
                )?;
                metrics.observe_read_state_path(endpoint, "canister_metadata");
            }
            [b"api_boundary_nodes"] => {
                metrics.observe_read_state_path(endpoint, "api_boundary_nodes");
            }
            [b"api_boundary_nodes", _node_id]
            | [
                b"api_boundary_nodes",
                _node_id,
                b"domain" | b"ipv4_address" | b"ipv6_address",
            ] => {
                metrics.observe_read_state_path(endpoint, "api_boundary_nodes_info");
            }
            [b"subnet"] => {
                metrics.observe_read_state_path(endpoint, "subnet");
            }
            [b"subnet", _subnet_id] => {
                metrics.observe_read_state_path(endpoint, "subnet_info");
            }
            [b"subnet", _subnet_id, b"public_key"] => {
                metrics.observe_read_state_path(endpoint, "subnet_public_key");
            }
            [b"subnet", _subnet_id, b"type"] => {
                metrics.observe_read_state_path(endpoint, "subnet_type");
            }
            [b"subnet", subnet_id, b"metrics"] if target == Target::Subnet => {
                let principal_id = parse_principal_id(subnet_id)?;
                verify_principal_ids(&principal_id, &effective_principal_id)?;
                metrics.observe_read_state_path(endpoint, "subnet_metrics");
            }
            [b"subnet", _subnet_id, b"node"] => {
                metrics.observe_read_state_path(endpoint, "subnet_node");
            }
            [b"subnet", _subnet_id, b"node", _node_id] => {
                metrics.observe_read_state_path(endpoint, "subnet_node_info");
            }
            [b"subnet", _subnet_id, b"node", _node_id, b"public_key"] => {
                metrics.observe_read_state_path(endpoint, "subnet_node_public_key");
            }
            // `/subnet/<subnet_id>/canister_ranges` is always allowed on the `/api/v2` endpoint
            [b"subnet", _subnet_id, b"canister_ranges"] if version == Version::V2 => {
                metrics.observe_read_state_path(endpoint, "subnet_canister_ranges");
            }
            // `/subnet/<subnet_id>/canister_ranges` is allowed on the `/api/v3` endpoint
            // only when `subnet_id == nns_subnet_id`.
            [b"subnet", subnet_id, b"canister_ranges"]
                if version == Version::V3
                    && parse_principal_id(subnet_id)? == nns_subnet_id.get() =>
            {
                metrics.observe_read_state_path(endpoint, "subnet_canister_ranges");
            }
            [b"canister_ranges", _subnet_id] if target == Target::Subnet => {
                metrics.observe_read_state_path(endpoint, "canister_ranges");
            }
            [b"request_status", request_id]
            | [
                b"request_status",
                request_id,
                b"status" | b"reply" | b"reject_code" | b"reject_message" | b"error_code",
            ] if target == Target::Canister
                || (target == Target::Subnet && version == Version::V3) =>
            {
                let message_id = MessageId::try_from(*request_id).map_err(|_| HttpError {
                    status: StatusCode::BAD_REQUEST,
                    message: format!(
                        "Invalid request id in paths. \
                        Maybe the request ID is not \
                        of {EXPECTED_MESSAGE_ID_LENGTH} bytes in length?!"
                    ),
                })?;

                if let Some(x) = last_request_status_id
                    && x != message_id
                {
                    return Err(HttpError {
                        status: StatusCode::BAD_REQUEST,
                        message: format!(
                            "More than one non-unique request ID exists in \
                                request_status paths: {x} and {message_id}."
                        ),
                    });
                }
                last_request_status_id = Some(message_id.clone());

                // Verify that the request was signed by the same user.
                let ingress_status = state.get_ingress_status(&message_id);
                if let Some(ingress_user_id) = ingress_status.user_id()
                    && ingress_user_id != *user
                {
                    return Err(HttpError {
                        status: StatusCode::FORBIDDEN,
                        message: "The user tries to access Request ID not signed by the caller."
                            .to_string(),
                    });
                }

                if let Some(receiver) = ingress_status.receiver()
                    && !targets.contains(&receiver)
                {
                    return Err(HttpError {
                        status: StatusCode::FORBIDDEN,
                        message: "The user tries to access request IDs for canisters \
                                      not belonging to sender delegation targets."
                            .to_string(),
                    });
                }
                metrics.observe_read_state_path(endpoint, "request_status");
            }
            _ => {
                // All other paths are unsupported.
                return Err(HttpError {
                    status: StatusCode::NOT_FOUND,
                    message: "Invalid path requested.".to_string(),
                });
            }
        }
    }

    Ok(())
}

fn can_read_canister_metadata(
    user: &UserId,
    canister_id: &CanisterId,
    custom_section_name: &str,
    state: &ReplicatedState,
) -> Result<(), HttpError> {
    let canister = match state.canister_state(canister_id) {
        Some(canister) => canister,
        None => return Ok(()),
    };

    match &canister.execution_state {
        Some(execution_state) => {
            let custom_section = match execution_state
                .metadata
                .get_custom_section(custom_section_name)
            {
                Some(section) => section,
                None => return Ok(()),
            };

            // Only the controller can request this custom section.
            if custom_section.visibility() == CustomSectionType::Private
                && !canister.system_state.controllers.contains(&user.get())
            {
                return Err(HttpError {
                    status: StatusCode::FORBIDDEN,
                    message: format!(
                        "Custom section {custom_section_name:.100} can only be requested by the controllers of the canister."
                    ),
                });
            }

            Ok(())
        }
        None => Ok(()),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        HttpError,
        common::test::{array, assert_cbor_ser_equal, bytes, int},
    };
    use hyper::StatusCode;
    use ic_crypto_tree_hash::{Digest, Label, LabeledTree, MatchPatternPath, MixedHashTree, Path};
    use ic_metrics::MetricsRegistry;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{CanisterQueues, RefundPool, ReplicatedState, SystemMetadata};
    use ic_test_utilities_consensus::fake::Fake;
    use ic_test_utilities_state::insert_dummy_canister;
    use ic_test_utilities_types::ids::{
        SUBNET_0, SUBNET_1, canister_test_id, subnet_test_id, user_test_id,
    };
    use ic_types::{
        NumBytes, SubnetId,
        batch::RawQueryStats,
        consensus::certification::Certification,
        ingress::{IngressState, IngressStatus},
        time::UNIX_EPOCH,
    };
    use ic_validator::CanisterIdSet;
    use rstest::rstest;
    use serde_bytes::ByteBuf;
    use std::collections::BTreeMap;

    const NNS_SUBNET_ID: SubnetId = SUBNET_0;
    const APP_SUBNET_ID: SubnetId = SUBNET_1;

    fn test_metrics() -> HttpHandlerMetrics {
        HttpHandlerMetrics::new(&MetricsRegistry::new())
    }

    fn fake_replicated_state() -> ReplicatedState {
        let mut metadata = SystemMetadata::new(APP_SUBNET_ID, SubnetType::Application);
        metadata.batch_time = UNIX_EPOCH;
        ReplicatedState::new_from_checkpoint(
            BTreeMap::new(),
            metadata,
            CanisterQueues::default(),
            RefundPool::default(),
            RawQueryStats::default(),
        )
    }

    // --- get_certificate_and_create_response tests ---

    struct FakeCertifiedStateReader {
        expects_exclusion: bool,
    }

    impl CertifiedStateSnapshot for FakeCertifiedStateReader {
        type State = ReplicatedState;

        fn get_state(&self) -> &Self::State {
            unimplemented!("Not expected to be called")
        }

        fn get_height(&self) -> ic_types::Height {
            unimplemented!("Not expected to be called")
        }

        fn read_certified_state(
            &self,
            _paths: &LabeledTree<()>,
        ) -> Option<(MixedHashTree, Certification)> {
            unimplemented!("Not expected to be called")
        }

        fn read_certified_state_with_exclusion(
            &self,
            _paths: &LabeledTree<()>,
            exclusion: Option<&MatchPatternPath>,
        ) -> Option<(MixedHashTree, Certification)> {
            assert!(exclusion.is_some() == self.expects_exclusion);
            Some((MixedHashTree::Empty, Certification::fake()))
        }
    }

    #[test]
    fn test_does_not_request_to_exclude_paths_from_the_state_tree() {
        let reader = FakeCertifiedStateReader {
            expects_exclusion: false,
        };
        let response = get_certificate_and_create_response(
            Vec::new(),
            /*delegation_from_nns=*/ None,
            &reader,
            DeprecatedCanisterRangesFilter::KeepAll,
        );
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_requests_to_exclude_paths_from_the_state_tree() {
        let reader = FakeCertifiedStateReader {
            expects_exclusion: true,
        };
        let response = get_certificate_and_create_response(
            Vec::new(),
            /*delegation_from_nns=*/ None,
            &reader,
            DeprecatedCanisterRangesFilter::KeepOnlyNNS(NNS_SUBNET_ID),
        );
        assert_eq!(response.status(), StatusCode::OK);
    }

    // --- MixedHashTree encoding tests ---

    #[test]
    fn encoding_read_state_tree_empty() {
        let tree = MixedHashTree::Empty;
        assert_cbor_ser_equal(&tree, array(vec![int(0)]));
    }

    #[test]
    fn encoding_read_state_tree_leaf() {
        let tree = MixedHashTree::Leaf(vec![1, 2, 3]);
        assert_cbor_ser_equal(&tree, array(vec![int(3), bytes(&[1, 2, 3])]));
    }

    #[test]
    fn encoding_read_state_tree_pruned() {
        let tree = MixedHashTree::Pruned(Digest([1; 32]));
        assert_cbor_ser_equal(&tree, array(vec![int(4), bytes(&[1; 32])]));
    }

    #[test]
    fn encoding_read_state_tree_fork() {
        let tree = MixedHashTree::Fork(Box::new((
            MixedHashTree::Leaf(vec![1, 2, 3]),
            MixedHashTree::Leaf(vec![4, 5, 6]),
        )));
        assert_cbor_ser_equal(
            &tree,
            array(vec![
                int(1),
                array(vec![int(3), bytes(&[1, 2, 3])]),
                array(vec![int(3), bytes(&[4, 5, 6])]),
            ]),
        );
    }

    #[test]
    fn encoding_read_state_tree_mixed() {
        let tree = MixedHashTree::Fork(Box::new((
            MixedHashTree::Labeled(
                Label::from(vec![1, 2, 3]),
                Box::new(MixedHashTree::Pruned(Digest([2; 32]))),
            ),
            MixedHashTree::Leaf(vec![4, 5, 6]),
        )));
        assert_cbor_ser_equal(
            &tree,
            array(vec![
                int(1),
                array(vec![
                    int(2),
                    bytes(&[1, 2, 3]),
                    array(vec![int(4), bytes(&[2; 32])]),
                ]),
                array(vec![int(3), bytes(&[4, 5, 6])]),
            ]),
        );
    }

    // --- can_read_canister_metadata tests ---

    #[test]
    fn user_can_read_canister_metadata() {
        let canister_id = canister_test_id(100);
        let controller = user_test_id(24);
        let non_controller = user_test_id(20);

        let mut state = ReplicatedState::new(APP_SUBNET_ID, SubnetType::Application);
        insert_dummy_canister(&mut state, canister_id, controller.get());

        let public_name = "dummy";
        // Controller can read the public custom section
        assert!(can_read_canister_metadata(&controller, &canister_id, public_name, &state).is_ok());

        // Non-controller can read public custom section
        assert!(
            can_read_canister_metadata(&non_controller, &canister_id, public_name, &state).is_ok()
        );

        let private_name = "candid";
        // Controller can read private custom section
        assert!(
            can_read_canister_metadata(&controller, &canister_id, private_name, &state).is_ok()
        );
    }

    #[test]
    fn user_cannot_read_canister_metadata() {
        let canister_id = canister_test_id(100);
        let controller = user_test_id(24);
        let non_controller = user_test_id(20);

        let mut state = ReplicatedState::new(APP_SUBNET_ID, SubnetType::Application);
        insert_dummy_canister(&mut state, canister_id, controller.get());

        // Non-controller cannot read private custom section named `candid`.
        assert_eq!(
            can_read_canister_metadata(&non_controller, &canister_id, "candid", &state),
            Err(HttpError {
                status: StatusCode::FORBIDDEN,
                message: "Custom section candid can only be requested by the controllers of the canister."
                    .to_string()
            })
        );

        // Non existent public custom section.
        assert_eq!(
            can_read_canister_metadata(&non_controller, &canister_id, "unknown-name", &state),
            Ok(())
        );
    }

    // --- verify_paths tests ---

    #[rstest]
    fn test_verify_canister_path(#[values(Version::V2, Version::V3)] version: Version) {
        let metrics = test_metrics();
        let state = fake_replicated_state();
        let canister_id = canister_test_id(1);

        assert_eq!(
            verify_paths(
                &metrics,
                Target::Canister,
                version,
                &state,
                &user_test_id(1),
                &[Path::from(Label::from("time"))],
                &CanisterIdSet::all(),
                canister_id.get(),
                NNS_SUBNET_ID,
            ),
            Ok(())
        );

        // request_status allowed for canister on both V2 and V3
        assert_eq!(
            verify_paths(
                &metrics,
                Target::Canister,
                version,
                &state,
                &user_test_id(1),
                &[
                    Path::new(vec![
                        Label::from("request_status"),
                        [0; 32].into(),
                        Label::from("status")
                    ]),
                    Path::new(vec![
                        Label::from("request_status"),
                        [0; 32].into(),
                        Label::from("reply")
                    ]),
                ],
                &CanisterIdSet::all(),
                canister_id.get(),
                NNS_SUBNET_ID,
            ),
            Ok(())
        );

        // two different request IDs rejected
        let err = verify_paths(
            &metrics,
            Target::Canister,
            version,
            &state,
            &user_test_id(1),
            &[
                Path::new(vec![Label::from("request_status"), [0; 32].into()]),
                Path::new(vec![Label::from("request_status"), [1; 32].into()]),
            ],
            &CanisterIdSet::all(),
            canister_id.get(),
            NNS_SUBNET_ID,
        )
        .expect_err("Should fail");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);

        // canister_ranges not allowed on canister endpoint
        let err = verify_paths(
            &metrics,
            Target::Canister,
            version,
            &state,
            &user_test_id(1),
            &[Path::new(vec![
                Label::from("canister_ranges"),
                ByteBuf::from(subnet_test_id(1).get().to_vec()).into(),
            ])],
            &CanisterIdSet::all(),
            canister_id.get(),
            NNS_SUBNET_ID,
        )
        .expect_err("Should fail");
        assert_eq!(err.status, StatusCode::NOT_FOUND);

        // subnet/*/metrics not allowed on canister endpoint
        let err = verify_paths(
            &metrics,
            Target::Canister,
            version,
            &state,
            &user_test_id(1),
            &[Path::new(vec![
                Label::from("subnet"),
                APP_SUBNET_ID.get().to_vec().into(),
                Label::from("metrics"),
            ])],
            &CanisterIdSet::all(),
            canister_id.get(),
            NNS_SUBNET_ID,
        )
        .expect_err("Should fail");
        assert_eq!(err.status, StatusCode::NOT_FOUND);
    }

    #[rstest]
    fn test_verify_subnet_path(#[values(Version::V2, Version::V3)] version: Version) {
        let metrics = test_metrics();
        let state = fake_replicated_state();

        assert_eq!(
            verify_paths(
                &metrics,
                Target::Subnet,
                version,
                &state,
                &user_test_id(1),
                &[Path::from(Label::from("time"))],
                &CanisterIdSet::all(),
                APP_SUBNET_ID.get(),
                NNS_SUBNET_ID,
            ),
            Ok(())
        );

        assert_eq!(
            verify_paths(
                &metrics,
                Target::Subnet,
                version,
                &state,
                &user_test_id(1),
                &[Path::from(Label::from("subnet"))],
                &CanisterIdSet::all(),
                APP_SUBNET_ID.get(),
                NNS_SUBNET_ID,
            ),
            Ok(())
        );

        assert_eq!(
            verify_paths(
                &metrics,
                Target::Subnet,
                version,
                &state,
                &user_test_id(1),
                &[
                    Path::new(vec![
                        Label::from("subnet"),
                        APP_SUBNET_ID.get().to_vec().into(),
                        Label::from("public_key"),
                    ]),
                    Path::new(vec![
                        Label::from("subnet"),
                        APP_SUBNET_ID.get().to_vec().into(),
                        Label::from("metrics"),
                    ]),
                    Path::new(vec![
                        Label::from("canister_ranges"),
                        ByteBuf::from(subnet_test_id(1).get().to_vec()).into(),
                    ]),
                ],
                &CanisterIdSet::all(),
                APP_SUBNET_ID.get(),
                NNS_SUBNET_ID,
            ),
            Ok(())
        );

        // request_status not allowed on subnet V2 endpoint, allowed on V3
        let result = verify_paths(
            &metrics,
            Target::Subnet,
            version,
            &state,
            &user_test_id(1),
            &[Path::new(vec![
                Label::from("request_status"),
                [0; 32].into(),
                Label::from("status"),
            ])],
            &CanisterIdSet::all(),
            APP_SUBNET_ID.get(),
            NNS_SUBNET_ID,
        );
        match version {
            Version::V2 => {
                assert_eq!(
                    result.expect_err("Should fail").status,
                    StatusCode::NOT_FOUND
                )
            }
            Version::V3 => assert_eq!(result, Ok(())),
        }

        // canister/* not allowed on subnet endpoint
        let err = verify_paths(
            &metrics,
            Target::Subnet,
            version,
            &state,
            &user_test_id(1),
            &[Path::new(vec![
                Label::from("canister"),
                ByteBuf::from(canister_test_id(1).get().to_vec()).into(),
                Label::from("controllers"),
            ])],
            &CanisterIdSet::all(),
            APP_SUBNET_ID.get(),
            NNS_SUBNET_ID,
        )
        .expect_err("Should fail");
        assert_eq!(err.status, StatusCode::NOT_FOUND);

        // standalone canister_ranges (no subnet_id) not allowed
        let err = verify_paths(
            &metrics,
            Target::Subnet,
            version,
            &state,
            &user_test_id(1),
            &[Path::new(vec![Label::from("canister_ranges")])],
            &CanisterIdSet::all(),
            APP_SUBNET_ID.get(),
            NNS_SUBNET_ID,
        )
        .expect_err("Should fail");
        assert_eq!(err.status, StatusCode::NOT_FOUND);
    }

    #[rstest]
    fn deprecated_canister_ranges_path_is_not_allowed_on_the_v3_endpoint_except_for_the_nns_subnet(
        #[values(Target::Canister, Target::Subnet)] target: Target,
    ) {
        let metrics = test_metrics();
        let state = fake_replicated_state();
        let effective_principal_id = match target {
            Target::Canister => canister_test_id(1).get(),
            Target::Subnet => APP_SUBNET_ID.get(),
        };

        let err = verify_paths(
            &metrics,
            target,
            Version::V3,
            &state,
            &user_test_id(1),
            &[Path::new(vec![
                Label::from("subnet"),
                APP_SUBNET_ID.get().to_vec().into(),
                Label::from("canister_ranges"),
            ])],
            &CanisterIdSet::all(),
            effective_principal_id,
            NNS_SUBNET_ID,
        )
        .expect_err("Should fail");
        assert_eq!(err.status, StatusCode::NOT_FOUND);

        assert!(
            verify_paths(
                &metrics,
                target,
                Version::V3,
                &state,
                &user_test_id(1),
                &[Path::new(vec![
                    Label::from("subnet"),
                    NNS_SUBNET_ID.get().to_vec().into(),
                    Label::from("canister_ranges"),
                ])],
                &CanisterIdSet::all(),
                effective_principal_id,
                NNS_SUBNET_ID,
            )
            .is_ok()
        );
    }

    #[rstest]
    fn deprecated_canister_ranges_path_is_allowed_on_the_v2_endpoint(
        #[values(Target::Canister, Target::Subnet)] target: Target,
    ) {
        let metrics = test_metrics();
        let state = fake_replicated_state();
        let effective_principal_id = match target {
            Target::Canister => canister_test_id(1).get(),
            Target::Subnet => APP_SUBNET_ID.get(),
        };

        assert!(
            verify_paths(
                &metrics,
                target,
                Version::V2,
                &state,
                &user_test_id(1),
                &[Path::new(vec![
                    Label::from("subnet"),
                    APP_SUBNET_ID.get().to_vec().into(),
                    Label::from("canister_ranges"),
                ])],
                &CanisterIdSet::all(),
                effective_principal_id,
                NNS_SUBNET_ID,
            )
            .is_ok()
        );

        assert!(
            verify_paths(
                &metrics,
                target,
                Version::V2,
                &state,
                &user_test_id(1),
                &[Path::new(vec![
                    Label::from("subnet"),
                    NNS_SUBNET_ID.get().to_vec().into(),
                    Label::from("canister_ranges"),
                ])],
                &CanisterIdSet::all(),
                effective_principal_id,
                NNS_SUBNET_ID,
            )
            .is_ok()
        );
    }

    #[test]
    fn test_verify_paths_records_metrics() {
        let metrics = test_metrics();
        let state = fake_replicated_state();
        let canister_id = canister_test_id(1);

        // canister endpoint metrics
        verify_paths(
            &metrics,
            Target::Canister,
            Version::V2,
            &state,
            &user_test_id(1),
            &[
                Path::from(Label::from("time")),
                Path::new(vec![
                    Label::from("canister"),
                    canister_id.get().to_vec().into(),
                    Label::from("module_hash"),
                ]),
                Path::new(vec![Label::from("api_boundary_nodes")]),
                Path::new(vec![
                    Label::from("subnet"),
                    APP_SUBNET_ID.get().to_vec().into(),
                    Label::from("public_key"),
                ]),
                Path::new(vec![
                    Label::from("request_status"),
                    [0; 32].into(),
                    Label::from("status"),
                ]),
            ],
            &CanisterIdSet::all(),
            canister_id.get(),
            NNS_SUBNET_ID,
        )
        .unwrap();

        // subnet endpoint metrics
        verify_paths(
            &metrics,
            Target::Subnet,
            Version::V2,
            &state,
            &user_test_id(1),
            &[
                Path::new(vec![
                    Label::from("subnet"),
                    APP_SUBNET_ID.get().to_vec().into(),
                    Label::from("node"),
                    NNS_SUBNET_ID.get().to_vec().into(),
                    Label::from("public_key"),
                ]),
                Path::new(vec![
                    Label::from("subnet"),
                    APP_SUBNET_ID.get().to_vec().into(),
                    Label::from("canister_ranges"),
                ]),
            ],
            &CanisterIdSet::all(),
            APP_SUBNET_ID.get(),
            NNS_SUBNET_ID,
        )
        .unwrap();

        assert_eq!(
            metrics
                .read_state_path_type_total
                .with_label_values(&["canister", "time"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .read_state_path_type_total
                .with_label_values(&["canister", "canister_info"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .read_state_path_type_total
                .with_label_values(&["canister", "api_boundary_nodes"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .read_state_path_type_total
                .with_label_values(&["canister", "subnet_public_key"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .read_state_path_type_total
                .with_label_values(&["canister", "request_status"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .read_state_path_type_total
                .with_label_values(&["subnet", "subnet_node_public_key"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .read_state_path_type_total
                .with_label_values(&["subnet", "subnet_canister_ranges"])
                .get(),
            1
        );
    }

    fn state_with_ingress_status(
        message_id: MessageId,
        user_id: UserId,
        receiver: CanisterId,
    ) -> ReplicatedState {
        let mut state = fake_replicated_state();
        state.set_ingress_status(
            message_id,
            IngressStatus::Known {
                receiver: receiver.get(),
                user_id,
                time: UNIX_EPOCH,
                state: IngressState::Processing,
            },
            NumBytes::from(u64::MAX),
            |_| {},
        );
        state
    }

    #[rstest]
    #[case(Target::Canister, Version::V2, canister_test_id(1).get())]
    #[case(Target::Canister, Version::V3, canister_test_id(1).get())]
    #[case(Target::Subnet, Version::V3, APP_SUBNET_ID.get())]
    fn test_request_status_wrong_user_is_rejected(
        #[case] target: Target,
        #[case] version: Version,
        #[case] effective_principal_id: PrincipalId,
    ) {
        let metrics = test_metrics();
        let message_id = MessageId::from([0_u8; 32]);
        let state =
            state_with_ingress_status(message_id.clone(), user_test_id(1), canister_test_id(1));

        let err = verify_paths(
            &metrics,
            target,
            version,
            &state,
            &user_test_id(2),
            &[Path::new(vec![
                Label::from("request_status"),
                message_id.as_bytes().to_vec().into(),
            ])],
            &CanisterIdSet::all(),
            effective_principal_id,
            NNS_SUBNET_ID,
        )
        .expect_err("Should fail");
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(
            err.message,
            "The user tries to access Request ID not signed by the caller."
        );
    }

    #[rstest]
    #[case(Target::Canister, Version::V2, canister_test_id(1).get())]
    #[case(Target::Canister, Version::V3, canister_test_id(1).get())]
    #[case(Target::Subnet, Version::V3, APP_SUBNET_ID.get())]
    fn test_request_status_receiver_not_in_targets_is_rejected(
        #[case] target: Target,
        #[case] version: Version,
        #[case] effective_principal_id: PrincipalId,
    ) {
        let metrics = test_metrics();
        let message_id = MessageId::from([0_u8; 32]);
        let receiver = canister_test_id(1);
        let state = state_with_ingress_status(message_id.clone(), user_test_id(1), receiver);
        let other_canister = canister_test_id(2);

        let err = verify_paths(
            &metrics,
            target,
            version,
            &state,
            &user_test_id(1),
            &[Path::new(vec![
                Label::from("request_status"),
                message_id.as_bytes().to_vec().into(),
            ])],
            &CanisterIdSet::try_from_iter(vec![other_canister]).unwrap(),
            effective_principal_id,
            NNS_SUBNET_ID,
        )
        .expect_err("Should fail");
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(
            err.message,
            "The user tries to access request IDs for canisters \
                not belonging to sender delegation targets."
        );
    }
}
