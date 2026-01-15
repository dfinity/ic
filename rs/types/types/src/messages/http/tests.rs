mod targets {
    use super::to_blob;
    use crate::Time;
    use crate::messages::{Blob, Delegation};
    use crate::time::GENESIS;
    use assert_matches::assert_matches;
    use ic_base_types::CanisterId;
    const CURRENT_TIME: Time = GENESIS;

    #[test]
    fn should_error_when_canister_id_invalid() {
        let invalid_canister_id = Blob([1_u8; 30].to_vec());
        let delegation = Delegation {
            pubkey: Blob(vec![]),
            expiration: CURRENT_TIME,
            targets: Some(vec![
                to_blob(CanisterId::from(1)),
                invalid_canister_id,
                to_blob(CanisterId::from(3)),
            ]),
        };

        let targets = delegation.targets();

        assert_matches!(targets, Err(msg) if msg.contains("longer than 29 bytes"))
    }

    #[test]
    fn should_eliminate_duplicated_canister_ids() {
        let canister_id_1 = CanisterId::from(1);
        let canister_id_2 = CanisterId::from(2);
        let canister_id_3 = CanisterId::from(3);
        let delegation = Delegation {
            pubkey: Blob(vec![]),
            expiration: CURRENT_TIME,
            targets: Some(vec![
                to_blob(canister_id_3),
                to_blob(canister_id_3),
                to_blob(canister_id_1),
                to_blob(canister_id_2),
                to_blob(canister_id_2),
                to_blob(canister_id_3),
                to_blob(canister_id_1),
            ]),
        };

        let targets = delegation.targets().expect("invalid targets");

        assert_matches!(targets, Some(computed_targets)
            if computed_targets.len() == 3 &&
            computed_targets.contains(&canister_id_1) &&
            computed_targets.contains(&canister_id_2) &&
            computed_targets.contains(&canister_id_3))
    }
}

mod try_from {
    mod call {
        use super::super::to_blob;
        use super::*;
        use crate::UserId;
        use crate::messages::http::{Authentication, HttpCallContent, HttpRequestError};
        use crate::messages::{
            Blob, HttpCanisterUpdate, HttpRequest, HttpRequestEnvelope, SignedIngressContent,
            UserSignature,
        };
        use assert_matches::assert_matches;

        fn default_call_content() -> HttpCanisterUpdate {
            HttpCanisterUpdate {
                canister_id: to_blob(fixed::canister_id()),
                method_name: fixed::method_name(),
                arg: fixed::arg(),
                sender: Blob(fixed::principal_id().to_vec()),
                ingress_expiry: fixed::ingress_expiry(),
                nonce: Some(Blob(fixed::nonce())),
            }
        }

        fn default_signed_ingress_content() -> SignedIngressContent {
            SignedIngressContent::new(
                UserId::from(fixed::principal_id()),
                fixed::canister_id(),
                fixed::method_name(),
                fixed::arg().0,
                fixed::ingress_expiry(),
                Some(fixed::nonce()),
            )
        }

        #[test]
        fn should_successfully_create_unauthenticated_http_request_for_valid_data() {
            let envelope = HttpRequestEnvelope {
                content: HttpCallContent::Call {
                    update: default_call_content(),
                },
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            };

            let request = HttpRequest::try_from(envelope);

            assert_eq!(
                request,
                Ok(HttpRequest {
                    content: default_signed_ingress_content(),
                    auth: Authentication::Anonymous,
                })
            )
        }

        #[test]
        fn should_successfully_create_authenticated_http_request_for_valid_data() {
            for (sender_pubkey, sender_sig, sender_delegation) in [
                (Some(Blob(fixed::pubkey())), Some(Blob(fixed::sig())), None),
                (
                    Some(Blob(fixed::pubkey())),
                    Some(Blob(fixed::sig())),
                    fixed::delegation(),
                ),
            ] {
                let envelope = HttpRequestEnvelope {
                    content: HttpCallContent::Call {
                        update: default_call_content(),
                    },
                    sender_pubkey,
                    sender_sig,
                    sender_delegation: sender_delegation.clone(),
                };

                let request = HttpRequest::try_from(envelope);

                assert_eq!(
                    request,
                    Ok(HttpRequest {
                        content: default_signed_ingress_content(),
                        auth: Authentication::Authenticated(UserSignature {
                            signature: fixed::sig(),
                            signer_pubkey: fixed::pubkey(),
                            sender_delegation: sender_delegation
                                .map(|_| fixed::delegation().unwrap())
                        }),
                    })
                )
            }
        }

        #[test]
        fn should_fail_creating_http_requests_with_invalid_canister_id_data() {
            let envelope = HttpRequestEnvelope {
                content: HttpCallContent::Call {
                    update: HttpCanisterUpdate {
                        canister_id: fixed::invalid_serialized_printipal_id(),
                        ..default_call_content()
                    },
                },
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            };

            let request = HttpRequest::try_from(envelope);

            assert_matches!(request, Err(HttpRequestError::InvalidPrincipalId(_)));
        }

        #[test]
        fn should_fail_creating_http_requests_with_invalid_sender_data() {
            let envelope = HttpRequestEnvelope {
                content: HttpCallContent::Call {
                    update: HttpCanisterUpdate {
                        sender: fixed::invalid_serialized_printipal_id(),
                        ..default_call_content()
                    },
                },
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            };

            let request = HttpRequest::try_from(envelope);

            assert_matches!(request, Err(HttpRequestError::InvalidPrincipalId(_)));
        }

        #[test]
        fn should_fail_creating_http_requests_with_partially_missing_authentication_data() {
            for (sender_pubkey, sender_sig, sender_delegation) in
                fixed::partially_missing_authentication_data()
            {
                let envelope = HttpRequestEnvelope {
                    content: HttpCallContent::Call {
                        update: default_call_content(),
                    },
                    sender_pubkey,
                    sender_sig,
                    sender_delegation,
                };

                let request = HttpRequest::try_from(envelope);

                assert_matches!(request, Err(HttpRequestError::MissingPubkeyOrSignature(_)));
            }
        }
    }

    mod read_state {
        use super::*;
        use crate::UserId;
        use crate::messages::http::{Authentication, HttpReadStateContent, HttpRequestError};
        use crate::messages::{
            Blob, HttpReadState, HttpRequest, HttpRequestEnvelope, ReadState, UserSignature,
        };
        use assert_matches::assert_matches;

        fn default_http_read_state() -> HttpReadState {
            HttpReadState {
                sender: Blob(fixed::principal_id().to_vec()),
                paths: fixed::paths(),
                nonce: Some(Blob(fixed::nonce())),
                ingress_expiry: fixed::ingress_expiry(),
            }
        }

        fn default_read_state() -> ReadState {
            ReadState {
                source: UserId::from(fixed::principal_id()),
                paths: fixed::paths(),
                ingress_expiry: fixed::ingress_expiry(),
                nonce: Some(fixed::nonce()),
            }
        }

        #[test]
        fn should_successfully_create_unauthenticated_http_request_for_valid_data() {
            let envelope = HttpRequestEnvelope {
                content: HttpReadStateContent::ReadState {
                    read_state: default_http_read_state(),
                },
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            };

            let request = HttpRequest::try_from(envelope);

            assert_eq!(
                request,
                Ok(HttpRequest {
                    content: default_read_state(),
                    auth: Authentication::Anonymous,
                })
            )
        }

        #[test]
        fn should_successfully_create_authenticated_http_request_for_valid_data() {
            for (sender_pubkey, sender_sig, sender_delegation) in [
                (Some(Blob(fixed::pubkey())), Some(Blob(fixed::sig())), None),
                (
                    Some(Blob(fixed::pubkey())),
                    Some(Blob(fixed::sig())),
                    fixed::delegation(),
                ),
            ] {
                let envelope = HttpRequestEnvelope {
                    content: HttpReadStateContent::ReadState {
                        read_state: default_http_read_state(),
                    },
                    sender_pubkey,
                    sender_sig,
                    sender_delegation: sender_delegation.clone(),
                };

                let request = HttpRequest::try_from(envelope);

                assert_eq!(
                    request,
                    Ok(HttpRequest {
                        content: default_read_state(),
                        auth: Authentication::Authenticated(UserSignature {
                            signature: fixed::sig(),
                            signer_pubkey: fixed::pubkey(),
                            sender_delegation: sender_delegation
                                .map(|_| fixed::delegation().unwrap())
                        }),
                    })
                );
            }
        }

        #[test]
        fn should_fail_creating_http_requests_with_invalid_sender_data() {
            let envelope = HttpRequestEnvelope {
                content: HttpReadStateContent::ReadState {
                    read_state: HttpReadState {
                        sender: fixed::invalid_serialized_printipal_id(),
                        ..default_http_read_state()
                    },
                },
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            };

            let request = HttpRequest::try_from(envelope);

            assert_matches!(request, Err(HttpRequestError::InvalidPrincipalId(_)));
        }

        #[test]
        fn should_fail_creating_http_requests_with_partially_missing_authentication_data() {
            for (sender_pubkey, sender_sig, sender_delegation) in
                fixed::partially_missing_authentication_data()
            {
                let envelope = HttpRequestEnvelope {
                    content: HttpReadStateContent::ReadState {
                        read_state: HttpReadState {
                            sender: fixed::invalid_serialized_printipal_id(),
                            ..default_http_read_state()
                        },
                    },
                    sender_pubkey,
                    sender_sig,
                    sender_delegation,
                };

                let request = HttpRequest::try_from(envelope);

                assert_matches!(request, Err(HttpRequestError::MissingPubkeyOrSignature(_)));
            }
        }
    }

    pub(super) mod query {
        use super::super::to_blob;
        use super::*;
        use crate::UserId;
        use crate::messages::http::{
            Authentication, HttpQueryContent, HttpRequestError, HttpUserQuery,
        };
        use crate::messages::{
            Blob, HttpRequest, HttpRequestEnvelope, Query, QuerySource, UserSignature,
        };
        use assert_matches::assert_matches;

        fn default_http_user_query_content() -> HttpUserQuery {
            HttpUserQuery {
                canister_id: to_blob(fixed::canister_id()),
                method_name: fixed::method_name(),
                arg: fixed::arg(),
                sender: Blob(fixed::principal_id().to_vec()),
                ingress_expiry: fixed::ingress_expiry(),
                nonce: Some(Blob(fixed::nonce())),
            }
        }

        pub fn default_user_query_content() -> Query {
            Query {
                source: QuerySource::User {
                    user_id: UserId::from(fixed::principal_id()),
                    ingress_expiry: fixed::ingress_expiry(),
                    nonce: Some(fixed::nonce()),
                },
                receiver: fixed::canister_id(),
                method_name: fixed::method_name(),
                method_payload: fixed::arg().0,
            }
        }

        #[test]
        fn should_successfully_create_unauthenticated_http_request_for_valid_data() {
            let envelope = HttpRequestEnvelope {
                content: HttpQueryContent::Query {
                    query: default_http_user_query_content(),
                },
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            };

            let request = HttpRequest::try_from(envelope);

            assert_eq!(
                request,
                Ok(HttpRequest {
                    content: default_user_query_content(),
                    auth: Authentication::Anonymous,
                })
            )
        }

        #[test]
        fn should_successfully_create_authenticated_http_request_for_valid_data() {
            for (sender_pubkey, sender_sig, sender_delegation) in [
                (Some(Blob(fixed::pubkey())), Some(Blob(fixed::sig())), None),
                (
                    Some(Blob(fixed::pubkey())),
                    Some(Blob(fixed::sig())),
                    fixed::delegation(),
                ),
            ] {
                let envelope = HttpRequestEnvelope {
                    content: HttpQueryContent::Query {
                        query: default_http_user_query_content(),
                    },
                    sender_pubkey,
                    sender_sig,
                    sender_delegation: sender_delegation.clone(),
                };

                let request = HttpRequest::try_from(envelope);

                assert_eq!(
                    request,
                    Ok(HttpRequest {
                        content: default_user_query_content(),
                        auth: Authentication::Authenticated(UserSignature {
                            signature: fixed::sig(),
                            signer_pubkey: fixed::pubkey(),
                            sender_delegation: sender_delegation
                                .map(|_| fixed::delegation().unwrap())
                        }),
                    })
                );
            }
        }

        #[test]
        fn should_fail_creating_http_requests_with_invalid_canister_id_data() {
            let envelope = HttpRequestEnvelope {
                content: HttpQueryContent::Query {
                    query: HttpUserQuery {
                        canister_id: fixed::invalid_serialized_printipal_id(),
                        ..default_http_user_query_content()
                    },
                },
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            };

            let request = HttpRequest::try_from(envelope);

            assert_matches!(request, Err(HttpRequestError::InvalidPrincipalId(_)));
        }

        #[test]
        fn should_fail_creating_http_requests_with_invalid_sender_data() {
            let envelope = HttpRequestEnvelope {
                content: HttpQueryContent::Query {
                    query: HttpUserQuery {
                        sender: fixed::invalid_serialized_printipal_id(),
                        ..default_http_user_query_content()
                    },
                },
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            };

            let request = HttpRequest::try_from(envelope);

            assert_matches!(request, Err(HttpRequestError::InvalidPrincipalId(_)));
        }

        #[test]
        fn should_fail_creating_http_requests_with_partially_missing_authentication_data() {
            for (sender_pubkey, sender_sig, sender_delegation) in
                fixed::partially_missing_authentication_data()
            {
                let envelope = HttpRequestEnvelope {
                    content: HttpQueryContent::Query {
                        query: default_http_user_query_content(),
                    },
                    sender_pubkey,
                    sender_sig,
                    sender_delegation,
                };

                let request = HttpRequest::try_from(envelope);

                assert_matches!(request, Err(HttpRequestError::MissingPubkeyOrSignature(_)));
            }
        }
    }

    pub mod fixed_test_values {
        use crate::messages::{Blob, SignedDelegation};
        use ic_crypto_tree_hash::{Label, Path};

        pub fn delegation() -> Option<Vec<SignedDelegation>> {
            Some(Vec::<SignedDelegation>::default())
        }

        /// A [`Blob`] whose value will not be checked.
        pub fn no_meaning_blob() -> Blob {
            Blob(vec![])
        }

        type AuthenticationData = (Option<Blob>, Option<Blob>, Option<Vec<SignedDelegation>>);
        pub fn partially_missing_authentication_data() -> Vec<AuthenticationData> {
            vec![
                (None, None, delegation()),
                (Some(no_meaning_blob()), None, None),
                (None, Some(no_meaning_blob()), None),
                (Some(no_meaning_blob()), None, delegation()),
                (None, Some(no_meaning_blob()), delegation()),
            ]
        }

        pub fn invalid_serialized_printipal_id() -> Blob {
            // max byte size of a principal id is 29
            Blob(vec![0; 100])
        }

        pub fn method_name() -> String {
            String::from("dummy_method")
        }

        pub fn arg() -> Blob {
            Blob(b"dummy_arg".to_vec())
        }

        pub fn canister_id() -> crate::CanisterId {
            crate::CanisterId::from_u64(1)
        }

        pub fn principal_id() -> crate::PrincipalId {
            crate::PrincipalId::new_anonymous()
        }

        pub fn ingress_expiry() -> u64 {
            2
        }

        pub fn nonce() -> Vec<u8> {
            b"dummy_nonce".to_vec()
        }

        pub fn pubkey() -> Vec<u8> {
            vec![3]
        }

        pub fn sig() -> Vec<u8> {
            vec![4]
        }

        pub fn paths() -> Vec<Path> {
            vec![Path::from(vec![Label::from([5]), Label::from([6])])]
        }
    }
    // In this way, the IDE will show the full name of the module as a hint.
    pub use fixed_test_values as fixed;
}

mod hashing {
    use super::try_from::query;
    use crate::{
        Time,
        messages::{Blob, HttpQueryResponse, HttpQueryResponseReply, QueryResponseHash},
    };
    use hex_literal::hex;

    #[test]
    fn hashing_query_response_reply() {
        let time = 2614;
        let query_response = HttpQueryResponse::Replied {
            reply: HttpQueryResponseReply {
                arg: Blob(b"some_bytes".to_vec()),
            },
        };
        let user_query = query::default_user_query_content();
        let query_response_hash = QueryResponseHash::new(
            &query_response,
            &user_query,
            Time::from_nanos_since_unix_epoch(time),
        );
        assert_eq!(
            query_response_hash.as_bytes(),
            &hex!("7e94e73d1647506682a6300385bc99a63d1ef655222e5a3235f784ca3e80dca4")
        );
    }

    #[test]
    fn hashing_query_response_reject() {
        let time = 2614;
        let query_response = HttpQueryResponse::Rejected {
            reject_code: 1,
            reject_message: "system error".to_string(),
            error_code: "IC500".to_string(),
        };
        let user_query = query::default_user_query_content();
        let query_response_hash = QueryResponseHash::new(
            &query_response,
            &user_query,
            Time::from_nanos_since_unix_epoch(time),
        );
        assert_eq!(
            query_response_hash.as_bytes(),
            &hex!("bd80f930dfd3eafdf2d5c03031da9b5ec62963701abcb217d31c84005bd8db87")
        );
    }
}

mod cbor_serialization {
    use crate::{
        AmountOf, Time,
        messages::{
            Blob, Delegation, HttpQueryResponse, HttpQueryResponseReply, HttpStatusResponse,
            ReplicaHealthStatus, SignedDelegation,
            http::{HttpSignedQueryResponse, NodeSignature, btreemap},
        },
        time::UNIX_EPOCH,
    };

    use candid::Principal;
    use ic_base_types::{NodeId, PrincipalId};
    use pretty_assertions::assert_eq;
    use serde::Serialize;
    use serde_cbor::Value;

    /// Makes sure that the serialized CBOR version of `obj` is the same as
    /// `Value`. Used when testing _outgoing_ messages from the HTTP
    /// Handler's point of view
    fn assert_cbor_ser_equal<T>(obj: &T, val: Value)
    where
        for<'de> T: Serialize,
    {
        assert_eq!(serde_cbor::value::to_value(obj).unwrap(), val)
    }

    fn text(text: &'static str) -> Value {
        Value::Text(text.to_string())
    }

    fn int(i: u64) -> Value {
        Value::Integer(i.into())
    }

    fn bytes(bs: &[u8]) -> Value {
        Value::Bytes(bs.to_vec())
    }

    fn vec<const N: usize>(values: [Value; N]) -> Value {
        Value::Array(Vec::from(values))
    }

    /// Returns a [`NodeId`] and its underlying byte array representation.
    pub fn node_id_and_bytes_repr() -> (NodeId, [u8; 8]) {
        let node_id_bytes: [u8; 8] = [15, 0, 0, 0, 0, 0, 0, 0];
        let principal_id = PrincipalId(Principal::from_slice(&node_id_bytes));

        let node_id = NodeId::from(principal_id);

        (node_id, node_id_bytes)
    }

    #[test]
    fn encoding_read_query_response() {
        let (node_id, node_id_bytes) = node_id_and_bytes_repr();

        let time = 2614;
        assert_cbor_ser_equal(
            &HttpSignedQueryResponse {
                response: HttpQueryResponse::Replied {
                    reply: HttpQueryResponseReply {
                        arg: Blob(b"some_bytes".to_vec()),
                    },
                },
                node_signature: NodeSignature {
                    timestamp: Time::from_nanos_since_unix_epoch(time),
                    signature: Blob(b"Some node signature bytes.".to_vec()),
                    identity: node_id,
                },
            },
            Value::Map(btreemap! {
                text("status") => text("replied"),
                text("reply") => Value::Map(btreemap!{
                    text("arg") => bytes(b"some_bytes")
                }),
                text("signatures") => vec([
                    Value::Map(btreemap!{
                        text("timestamp") => int(time),
                        text("signature") => bytes(b"Some node signature bytes."),
                        text("identity") => bytes(&node_id_bytes),
                    })
                ]),
            }),
        );
    }

    #[test]
    fn encoding_read_query_reject() {
        let (node_id, node_id_bytes) = node_id_and_bytes_repr();

        let time = 2614;

        assert_cbor_ser_equal(
            &HttpSignedQueryResponse {
                response: HttpQueryResponse::Rejected {
                    reject_code: 1,
                    reject_message: "system error".to_string(),
                    error_code: "IC500".to_string(),
                },
                node_signature: NodeSignature {
                    timestamp: Time::from_nanos_since_unix_epoch(time),
                    signature: Blob(b"Some node signature bytes.".to_vec()),
                    identity: node_id,
                },
            },
            Value::Map(btreemap! {
                text("status") => text("rejected"),
                text("reject_code") => int(1),
                text("reject_message") => text("system error"),
                text("error_code") => text("IC500"),
                text("signatures") => vec([
                    Value::Map(btreemap!{
                        text("timestamp") => int(time),
                        text("signature") => bytes(b"Some node signature bytes."),
                        text("identity") => bytes(&node_id_bytes),
                    })
                ]),
            }),
        );
    }

    #[test]
    fn encoding_status_without_root_key() {
        assert_cbor_ser_equal(
            &HttpStatusResponse {
                root_key: None,
                impl_version: Some("0.0".to_string()),
                impl_hash: None,
                replica_health_status: Some(ReplicaHealthStatus::Starting),
                certified_height: None,
            },
            Value::Map(btreemap! {
                text("impl_version") => text("0.0"),
                text("replica_health_status") => text("starting"),
            }),
        );
    }

    #[test]
    fn encoding_status_with_root_key() {
        assert_cbor_ser_equal(
            &HttpStatusResponse {
                root_key: Some(Blob(vec![1, 2, 3])),
                impl_version: Some("0.0".to_string()),
                impl_hash: None,
                replica_health_status: Some(ReplicaHealthStatus::Healthy),
                certified_height: None,
            },
            Value::Map(btreemap! {
                text("root_key") => bytes(&[1, 2, 3]),
                text("impl_version") => text("0.0"),
                text("replica_health_status") => text("healthy"),
            }),
        );
    }

    #[test]
    fn encoding_status_without_health_status() {
        assert_cbor_ser_equal(
            &HttpStatusResponse {
                root_key: Some(Blob(vec![1, 2, 3])),
                impl_version: Some("0.0".to_string()),
                impl_hash: None,
                replica_health_status: None,
                certified_height: None,
            },
            Value::Map(btreemap! {
                text("root_key") => bytes(&[1, 2, 3]),
                text("impl_version") => text("0.0"),
            }),
        );
    }

    #[test]
    fn encoding_status_with_certified_height() {
        assert_cbor_ser_equal(
            &HttpStatusResponse {
                root_key: Some(Blob(vec![1, 2, 3])),
                impl_version: Some("0.0".to_string()),
                impl_hash: None,
                replica_health_status: Some(ReplicaHealthStatus::Healthy),
                certified_height: Some(AmountOf::new(1)),
            },
            Value::Map(btreemap! {
                text("root_key") => bytes(&[1, 2, 3]),
                text("impl_version") => text("0.0"),
                text("replica_health_status") => text("healthy"),
                text("certified_height") => serde_cbor::Value::Integer(1),
            }),
        );
    }

    #[test]
    fn encoding_delegation() {
        assert_cbor_ser_equal(
            &Delegation {
                pubkey: Blob(vec![1, 2, 3]),
                expiration: UNIX_EPOCH,
                targets: None,
            },
            Value::Map(btreemap! {
                text("pubkey") => bytes(&[1, 2, 3]),
                text("expiration") => int(0),
                text("targets") => Value::Null,
            }),
        );

        assert_cbor_ser_equal(
            &Delegation {
                pubkey: Blob(vec![1, 2, 3]),
                expiration: UNIX_EPOCH,
                targets: Some(vec![Blob(vec![4, 5, 6])]),
            },
            Value::Map(btreemap! {
                text("pubkey") => bytes(&[1, 2, 3]),
                text("expiration") => int(0),
                text("targets") => Value::Array(vec![bytes(&[4, 5, 6])]),
            }),
        );
    }

    #[test]
    fn encoding_signed_delegation() {
        assert_cbor_ser_equal(
            &SignedDelegation {
                delegation: Delegation {
                    pubkey: Blob(vec![1, 2, 3]),
                    expiration: UNIX_EPOCH,
                    targets: None,
                },
                signature: Blob(vec![4, 5, 6]),
            },
            Value::Map(btreemap! {
                text("delegation") => Value::Map(btreemap! {
                    text("pubkey") => bytes(&[1, 2, 3]),
                    text("expiration") => int(0),
                    text("targets") => Value::Null,
                }),
                text("signature") => bytes(&[4, 5, 6]),
            }),
        );
    }
}

mod to_authentication {
    use crate::Time;
    use crate::messages::{
        Authentication, Blob, Delegation, HttpQueryContent, HttpRequestEnvelope, HttpRequestError,
        HttpUserQuery, SignedDelegation, UserSignature, http::to_authentication,
    };
    use assert_matches::assert_matches;

    #[test]
    fn should_successfully_convert_user_signature_with_delegation() {
        let sender_delegation = dummy_delegation();
        let setup = Setup::new(sender_delegation.clone());
        let envelope = construct_envelope(
            Some(setup.sender_pubkey),
            Some(setup.sender_sig),
            sender_delegation,
        );

        assert_eq!(to_authentication(&envelope), Ok(setup.authentication));
    }

    #[test]
    fn should_successfully_convert_user_signature_without_delegation() {
        let setup = Setup::new(None);
        let envelope = construct_envelope(Some(setup.sender_pubkey), Some(setup.sender_sig), None);

        assert_eq!(to_authentication(&envelope), Ok(setup.authentication));
    }

    #[test]
    fn should_successfully_convert_anonymous_request() {
        let envelope = construct_envelope(None, None, None);

        assert_eq!(to_authentication(&envelope), Ok(Authentication::Anonymous));
    }

    #[test]
    fn should_return_error_if_insufficient_subset_of_parameters_specified() {
        for sender_pubkey in &[Some(dummy_sender_pubkey()), None] {
            for sender_sig in &[Some(dummy_signature()), None] {
                for sender_delegation in &[dummy_delegation(), None] {
                    if !((sender_pubkey.is_some() && sender_sig.is_some())
                        || (sender_pubkey.is_none()
                            && sender_sig.is_none()
                            && sender_delegation.is_none()))
                    {
                        let envelope = construct_envelope(
                            sender_pubkey.clone(),
                            sender_sig.clone(),
                            sender_delegation.clone(),
                        );

                        assert_matches!(
                            to_authentication(&envelope),
                            Err(HttpRequestError::MissingPubkeyOrSignature(err))
                            if err.starts_with("Got ")
                        );
                    }
                }
            }
        }
    }

    struct Setup {
        sender_pubkey: Blob,
        sender_sig: Blob,
        authentication: Authentication,
    }

    impl Setup {
        fn new(sender_delegation: Option<Vec<SignedDelegation>>) -> Setup {
            let signature = dummy_signature();
            let signer_pubkey = dummy_sender_pubkey();
            let authentication = Authentication::Authenticated(UserSignature {
                signature: signature.to_vec(),
                signer_pubkey: signer_pubkey.to_vec(),
                sender_delegation: sender_delegation.clone(),
            });
            Setup {
                sender_pubkey: signer_pubkey,
                sender_sig: signature,
                authentication,
            }
        }
    }

    fn construct_envelope(
        sender_pubkey: Option<Blob>,
        sender_sig: Option<Blob>,
        sender_delegation: Option<Vec<SignedDelegation>>,
    ) -> HttpRequestEnvelope<HttpQueryContent> {
        HttpRequestEnvelope {
            content: HttpQueryContent::Query {
                query: HttpUserQuery {
                    canister_id: Blob(vec![]),
                    method_name: "query".to_string(),
                    arg: Blob(vec![]),
                    sender: Blob(vec![4]),
                    ingress_expiry: 0,
                    nonce: None,
                },
            },
            sender_delegation,
            sender_pubkey,
            sender_sig,
        }
    }

    fn dummy_signature() -> Blob {
        Blob(vec![1, 2, 3])
    }
    fn dummy_sender_pubkey() -> Blob {
        Blob(vec![4, 5, 6])
    }

    fn dummy_delegation() -> Option<Vec<SignedDelegation>> {
        let delegation_pubkey = Blob(vec![7, 8, 9]);
        let delegation_signature = Blob(vec![10, 11, 12]);
        let expiration = 54378u64;
        Some(vec![SignedDelegation::new(
            Delegation::new(
                delegation_pubkey.to_vec(),
                Time::from_nanos_since_unix_epoch(expiration),
            ),
            delegation_signature.to_vec(),
        )])
    }
}

fn to_blob(id: crate::CanisterId) -> crate::messages::Blob {
    crate::messages::Blob(id.get().to_vec())
}
