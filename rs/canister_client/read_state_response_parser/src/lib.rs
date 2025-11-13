use ic_canonical_state::encoding::types::SubnetMetrics;
use ic_crypto_tree_hash::{LabeledTree, LookupStatus, MixedHashTree};
use ic_types::{
    CanisterId, SubnetId,
    crypto::threshold_sig::ThresholdSigPublicKey,
    messages::{HttpReadStateResponse, MessageId},
};
use serde::Deserialize;
use serde_cbor::value::Value as CBOR;
use std::collections::BTreeMap;
use std::convert::TryFrom;

// An auxiliary structure that mirrors the request statuses
// encoded in a certificate, starting from the root of the tree.
#[derive(Debug, Deserialize)]
struct RequestStatuses {
    request_status: Option<BTreeMap<MessageId, RequestStatus>>,
}

#[derive(Eq, PartialEq, Debug, Deserialize)]
pub struct RequestStatus {
    pub status: String,
    pub reply: Option<Vec<u8>>,
    pub reject_message: Option<String>,
}

impl RequestStatus {
    fn unknown() -> Self {
        RequestStatus {
            status: "unknown".to_string(),
            reply: None,
            reject_message: None,
        }
    }
}

/// Given a CBOR response from a `read_state` and a `request_id` extracts
/// the `RequestStatus` if available.
pub fn parse_read_state_response(
    request_id: &MessageId,
    effective_canister_id: &CanisterId,
    root_pk: Option<&ThresholdSigPublicKey>,
    message: CBOR,
) -> Result<RequestStatus, String> {
    let response = serde_cbor::value::from_value::<HttpReadStateResponse>(message)
        .map_err(|source| format!("decoding to HttpReadStateResponse failed: {source}"))?;

    let certificate = match root_pk {
        Some(pk) => {
            ic_certification::verify_certificate(&response.certificate, effective_canister_id, pk)
                .map_err(|source| format!("verifying certificate failed: {source}"))?
        }
        None => serde_cbor::from_slice(response.certificate.as_slice())
            .map_err(|source| format!("decoding Certificate failed: {source}"))?,
    };

    match certificate
        .tree
        .lookup(&[&b"request_status"[..], request_id.as_ref()])
    {
        LookupStatus::Found(_) => (),
        // TODO(MR-249): return an error in the Unknown case once the replica
        // implements absence proofs.
        LookupStatus::Absent | LookupStatus::Unknown => return Ok(RequestStatus::unknown()),
    }

    // Parse the tree.
    let tree = LabeledTree::try_from(certificate.tree)
        .map_err(|e| format!("parsing tree in certificate failed: {e:?}"))?;

    let request_statuses =
        RequestStatuses::deserialize(tree_deserializer::LabeledTreeDeserializer::new(&tree))
            .map_err(|err| format!("deserializing request statuses failed: {err:?}"))?;

    Ok(match request_statuses.request_status {
        Some(mut request_status_map) => request_status_map
            .remove(request_id)
            .unwrap_or_else(RequestStatus::unknown),
        None => RequestStatus::unknown(),
    })
}

/// Given a CBOR response from a subnet `read_state` and a `subnet_id` extracts
/// the `SubnetMetrics` if available.
pub fn parse_subnet_read_state_response(
    subnet_id: &SubnetId,
    root_pk: Option<&ThresholdSigPublicKey>,
    message: CBOR,
) -> Result<SubnetMetrics, String> {
    let response = serde_cbor::value::from_value::<HttpReadStateResponse>(message)
        .map_err(|source| format!("decoding to HttpReadStateResponse failed: {source}"))?;

    let certificate = match root_pk {
        Some(pk) => ic_certification::verify_certificate_for_subnet_read_state(
            &response.certificate,
            subnet_id,
            pk,
        )
        .map_err(|source| format!("verifying certificate failed: {source}"))?,
        None => serde_cbor::from_slice(response.certificate.as_slice())
            .map_err(|source| format!("decoding Certificate failed: {source}"))?,
    };

    let subnet_metrics_leaf =
        match certificate
            .tree
            .lookup(&[&b"subnet"[..], subnet_id.get().as_ref(), &b"metrics"[..]])
        {
            LookupStatus::Found(subnet_metrics_leaf) => subnet_metrics_leaf.clone(),
            LookupStatus::Absent | LookupStatus::Unknown => return Ok(SubnetMetrics::default()),
        };

    match subnet_metrics_leaf {
        MixedHashTree::Leaf(bytes) => {
            let subnet_metrics: SubnetMetrics = serde_cbor::from_slice(&bytes)
                .map_err(|err| format!("deserializing subnet_metrics failed: {err:?}"))?;
            Ok(subnet_metrics)
        }
        tree => Err(format!("Expected subnet metrics leaf but found {tree:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_certification_test_utils::CertificateBuilder;
    use ic_certification_test_utils::CertificateData;
    use ic_crypto_tree_hash::Digest;
    use ic_crypto_tree_hash::Label;
    use ic_types::CanisterId;
    use ic_types::messages::Blob;
    use serde::Serialize;

    fn to_self_describing_cbor<T: Serialize>(e: &T) -> serde_cbor::Result<Vec<u8>> {
        let mut serialized_bytes = Vec::new();
        let mut serializer = serde_cbor::Serializer::new(&mut serialized_bytes);
        serializer.self_describe()?;
        e.serialize(&mut serializer)?;
        Ok(serialized_bytes)
    }

    #[test]
    fn test_parse_read_state_response_unknown() {
        let labeled_tree = LabeledTree::try_from(MixedHashTree::Labeled(
            "time".into(),
            Box::new(MixedHashTree::Leaf(vec![1])),
        ))
        .unwrap();
        let data = CertificateData::CustomTree(labeled_tree);
        let (certificate, root_pk, _) = CertificateBuilder::new(data).build();

        let certificate_cbor: Vec<u8> = to_self_describing_cbor(&certificate).unwrap();

        let response = HttpReadStateResponse {
            certificate: Blob(certificate_cbor),
        };

        let response_cbor: Vec<u8> = to_self_describing_cbor(&response).unwrap();

        let response: CBOR = serde_cbor::from_slice(response_cbor.as_slice()).unwrap();

        let request_id: MessageId = MessageId::from([0; 32]);
        assert_eq!(
            parse_read_state_response(&request_id, &CanisterId::from(1), Some(&root_pk), response),
            Ok(RequestStatus::unknown())
        );
    }

    #[test]
    fn test_parse_read_state_response_replied() {
        let tree = MixedHashTree::Fork(Box::new((
            MixedHashTree::Labeled(
                "request_status".into(),
                Box::new(MixedHashTree::Labeled(
                    vec![
                        184, 255, 145, 192, 128, 156, 132, 76, 67, 213, 87, 237, 189, 136, 206,
                        184, 254, 192, 233, 210, 142, 173, 27, 123, 112, 187, 82, 222, 130, 129,
                        245, 41,
                    ]
                    .into(),
                    Box::new(MixedHashTree::Fork(Box::new((
                        MixedHashTree::Labeled(
                            "reply".into(),
                            Box::new(MixedHashTree::Leaf(vec![68, 73, 68, 76, 0, 0])),
                        ),
                        MixedHashTree::Labeled(
                            "status".into(),
                            Box::new(MixedHashTree::Leaf(b"replied".to_vec())),
                        ),
                    )))),
                )),
            ),
            MixedHashTree::Labeled("time".into(), Box::new(MixedHashTree::Leaf(vec![1]))),
        )));
        let labeled_tree = LabeledTree::try_from(tree).unwrap();
        let data = CertificateData::CustomTree(labeled_tree);
        let (certificate, root_pk, _) = CertificateBuilder::new(data).build();

        let certificate_cbor: Vec<u8> = to_self_describing_cbor(&certificate).unwrap();

        let response = HttpReadStateResponse {
            certificate: Blob(certificate_cbor),
        };

        let response_cbor: Vec<u8> = to_self_describing_cbor(&response).unwrap();

        let response: CBOR = serde_cbor::from_slice(response_cbor.as_slice()).unwrap();

        // Request ID that exists.
        let request_id: MessageId = MessageId::from([
            184, 255, 145, 192, 128, 156, 132, 76, 67, 213, 87, 237, 189, 136, 206, 184, 254, 192,
            233, 210, 142, 173, 27, 123, 112, 187, 82, 222, 130, 129, 245, 41,
        ]);

        assert_eq!(
            parse_read_state_response(
                &request_id,
                &CanisterId::from(1),
                Some(&root_pk),
                response.clone()
            ),
            Ok(RequestStatus {
                status: "replied".to_string(),
                reply: Some(vec![68, 73, 68, 76, 0, 0]),
                reject_message: None
            }),
        );

        // Request ID that doesn't exist.
        let request_id: MessageId = MessageId::from([0; 32]);
        assert_eq!(
            parse_read_state_response(&request_id, &CanisterId::from(1), Some(&root_pk), response),
            Ok(RequestStatus::unknown())
        );
    }

    #[test]
    fn test_parse_read_state_response_pruned() {
        fn mklabeled(l: impl Into<Label>, t: MixedHashTree) -> MixedHashTree {
            MixedHashTree::Labeled(l.into(), Box::new(t))
        }

        fn mkfork(l: MixedHashTree, r: MixedHashTree) -> MixedHashTree {
            MixedHashTree::Fork(Box::new((l, r)))
        }

        let tree = mkfork(
            mklabeled(
                "request_status",
                mkfork(
                    mklabeled(
                        vec![
                            184, 255, 145, 192, 128, 156, 132, 76, 67, 213, 87, 237, 189, 136, 206,
                            184, 254, 192, 233, 210, 142, 173, 27, 123, 112, 187, 82, 222, 130,
                            129, 245, 40,
                        ],
                        MixedHashTree::Pruned(Digest([0; 32])),
                    ),
                    mklabeled(
                        vec![
                            184, 255, 145, 192, 128, 156, 132, 76, 67, 213, 87, 237, 189, 136, 206,
                            184, 254, 192, 233, 210, 142, 173, 27, 123, 112, 187, 82, 222, 130,
                            129, 245, 42,
                        ],
                        MixedHashTree::Pruned(Digest([0; 32])),
                    ),
                ),
            ),
            mklabeled("time", MixedHashTree::Leaf(vec![1])),
        );

        let labeled_tree = LabeledTree::try_from(tree).unwrap();
        let data = CertificateData::CustomTree(labeled_tree);
        let (certificate, root_pk, _) = CertificateBuilder::new(data).build();

        let certificate_cbor: Vec<u8> = to_self_describing_cbor(&certificate).unwrap();

        let response = HttpReadStateResponse {
            certificate: Blob(certificate_cbor),
        };

        let response_cbor: Vec<u8> = to_self_describing_cbor(&response).unwrap();

        let response: CBOR = serde_cbor::from_slice(response_cbor.as_slice()).unwrap();

        // Request ID that is between two pruned labels.
        let request_id: MessageId = MessageId::from([
            184, 255, 145, 192, 128, 156, 132, 76, 67, 213, 87, 237, 189, 136, 206, 184, 254, 192,
            233, 210, 142, 173, 27, 123, 112, 187, 82, 222, 130, 129, 245, 41,
        ]);

        assert_eq!(
            parse_read_state_response(&request_id, &CanisterId::from(1), Some(&root_pk), response),
            Ok(RequestStatus::unknown())
        );
    }
}
