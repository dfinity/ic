use crate::{
    http::{
        json::{
            ConstantSizeId, CreateJsonRpcIdFilter, HttpBatchJsonRpcRequest,
            HttpBatchJsonRpcResponse, HttpJsonRpcRequest, HttpJsonRpcResponse, Id,
            JsonConversionLayer, JsonRequestConverter, JsonResponseConverter, JsonRpcError,
            JsonRpcRequest, JsonRpcResponse, Version,
        },
        HttpRequest, HttpResponse,
    },
    ConvertServiceBuilder,
};
use assert_matches::assert_matches;
use http::HeaderValue;
use itertools::Itertools;
use proptest::{prelude::any, prop_assert_eq, proptest};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;
use std::{
    fmt::Debug,
    hash::{DefaultHasher, Hash},
};
use tower::{BoxError, Service, ServiceBuilder, ServiceExt};

const URL: &str = "https://internetcomputer.org/";

mod json_rpc {
    use super::*;

    #[test]
    fn should_parse_null_id() {
        let id: Id = serde_json::from_value(json!(null)).unwrap();
        assert_eq!(id, Id::Null);
    }

    #[test]
    fn should_parse_numeric_id() {
        let id: Id = serde_json::from_value(json!(42)).unwrap();
        assert_eq!(id, Id::Number(42));
    }

    #[test]
    fn should_parse_string_id() {
        let id: Id = serde_json::from_value(json!("forty two")).unwrap();
        assert_eq!(id, Id::String("forty two".into()));
    }

    #[test]
    fn should_fail_to_parse_id_from_wrong_types() {
        for value in [json!(true), json!(["array"]), json!({"an": "object"})] {
            let _error = serde_json::from_value::<Id>(value).expect_err("should fail");
        }
    }

    #[test]
    fn should_serialize_request() {
        let request = JsonRpcRequest::new("subtract", [43, 23]).with_id(Id::from(1_u8));
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({"jsonrpc": "2.0", "method": "subtract", "params": [43, 23], "id": 1})
        )
    }

    #[test]
    fn should_deserialize_json_ok_response() {
        let error_response = json!({ "jsonrpc": "2.0", "result": 366632694, "id": 0 });

        let json_response: JsonRpcResponse<u64> = serde_json::from_value(error_response).unwrap();
        let (id, result) = json_response.into_parts();

        assert_eq!(id, Id::ZERO);
        assert_eq!(result, Ok(366632694));
    }

    #[test]
    fn should_deserialize_json_error_response() {
        fn check<T: DeserializeOwned + PartialEq + Debug>() {
            let error_response =
                json!({"jsonrpc":"2.0", "id":0, "error": {"code":123, "message":"Error message"}});

            let json_response: JsonRpcResponse<T> = serde_json::from_value(error_response).unwrap();
            let (id, result) = json_response.into_parts();

            assert_eq!(id, Id::ZERO);
            assert_eq!(result, Err(JsonRpcError::new(123, "Error message")));
        }

        // The type of the OK result should not influence the deserialization of the error.
        check::<serde_json::Value>();
        check::<Option<serde_json::Value>>();
        check::<Result<serde_json::Value, String>>();
    }

    #[test]
    fn should_serialize_version() {
        assert_eq!(serde_json::to_value(Version::V2).unwrap(), json!("2.0"));
    }

    #[test]
    fn should_deserialize_version() {
        let version: Version = serde_json::from_value(json!("2.0")).unwrap();
        assert_eq!(version, Version::V2);
    }

    #[test]
    fn should_fail_to_deserialize_unknown_versions() {
        for version in [json!("1.0"), json!("3.0"), json!("unexpected")] {
            assert_matches!(serde_json::from_value::<Version>(version), Err(_));
        }
    }

    #[test]
    fn should_map_json_rpc_response() {
        let response = JsonRpcResponse::from_ok(Id::Number(0), 0);

        assert_eq!(
            response.map(|value| value + 1),
            JsonRpcResponse::from_ok(Id::Number(0), 1)
        );
    }
}

mod constant_size_id {
    use super::*;

    #[test]
    fn should_add_padding_to_the_left() {
        let one = ConstantSizeId::from(1_u8);
        assert_eq!(one.to_string(), "00000000000000000001")
    }

    #[test]
    fn should_have_only_necessary_padding() {
        let zero = ConstantSizeId::ZERO.to_string();
        let max = ConstantSizeId::MAX.to_string();
        assert_eq!(zero.len(), max.len());

        let u64_max = u64::MAX.to_string();
        assert_eq!(u64_max, max);
    }

    proptest! {
        #[test]
        fn should_have_constant_size_when_serialized(id in any::<u64>()) {
            let id = Id::from(ConstantSizeId::from(id));
            let bytes = serde_json::to_vec(&id).unwrap();
            prop_assert_eq!(bytes.len(), 22);
        }

        #[test]
        fn should_parse_string_value_and_ignore_extra_padding(id in any::<u64>(), extra_padding_len in any::<u8>()) {
            let id = ConstantSizeId::from(id);
            let s = id.to_string();
            prop_assert_eq!(id.clone(), s.parse().unwrap());

            let padded = format!("{}{}", "0".repeat(extra_padding_len as usize), s);
            prop_assert_eq!(id, padded.parse().unwrap());
        }
    }
}

#[tokio::test]
async fn should_convert_json_request() {
    let url = URL;
    let mut service = ServiceBuilder::new()
        .convert_request(JsonRequestConverter::<serde_json::Value>::new())
        .service_fn(echo_request);

    let body = json!({"foo": "bar"});
    let request = http::Request::post(url).body(body.clone()).unwrap();

    let converted_request = service.ready().await.unwrap().call(request).await.unwrap();

    assert_eq!(
        serde_json::to_vec(&body).unwrap(),
        converted_request.into_body()
    );
}

#[tokio::test]
async fn should_add_content_type_header_if_missing() {
    let url = URL;
    let mut service = ServiceBuilder::new()
        .convert_request(JsonRequestConverter::<serde_json::Value>::new())
        .service_fn(echo_request);

    for (request_content_type, expected_content_type) in [
        (None, "application/json"),
        (Some("wrong-value"), "wrong-value"), //do not overwrite explicitly set header
        (Some("application/json"), "application/json"),
    ] {
        let mut builder = http::Request::post(url);
        if let Some(request_content_type) = request_content_type {
            builder = builder.header(http::header::CONTENT_TYPE, request_content_type);
        }
        let request = builder
            .header("other-header", "should-remain")
            .body(json!({"foo": "bar"}))
            .unwrap();

        let converted_request = service
            .ready()
            .await
            .unwrap()
            .call(request.clone())
            .await
            .unwrap();

        let (mut request_parts, _body) = request.into_parts();
        let (mut converted_request_parts, _body) = converted_request.into_parts();

        assert_eq!(request_parts.method, converted_request_parts.method);
        assert_eq!(request_parts.uri, converted_request_parts.uri);
        assert_eq!(request_parts.version, converted_request_parts.version);

        // Headers should be identical, excepted for content-type
        request_parts.headers.remove(http::header::CONTENT_TYPE);
        let converted_request_content_type = converted_request_parts
            .headers
            .remove(http::header::CONTENT_TYPE)
            .unwrap();
        assert_eq!(
            converted_request_content_type,
            HeaderValue::from_static(expected_content_type)
        );

        assert_eq!(request_parts.headers, converted_request_parts.headers);
    }
}

#[tokio::test]
async fn should_convert_json_response() {
    let mut service = ServiceBuilder::new()
        .convert_response(JsonResponseConverter::<serde_json::Value>::new())
        .service_fn(echo_response);

    let expected_response = json!({"foo": "bar"});
    let response = http::Response::new(serde_json::to_vec(&expected_response).unwrap());

    let converted_response = service.ready().await.unwrap().call(response).await.unwrap();

    assert_eq!(converted_response.into_body(), expected_response);
}

#[tokio::test]
async fn should_convert_both_request_and_response() {
    let mut service = ServiceBuilder::new()
        .layer(JsonConversionLayer::<serde_json::Value, serde_json::Value>::new())
        .service_fn(forward_body);

    let response = service
        .ready()
        .await
        .unwrap()
        .call(
            http::Request::post(URL)
                .body(json!({"foo": "bar"}))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.into_body(), json!({"foo": "bar"}));
}

mod filter_json_rpc_id {
    use super::*;
    use std::hash::Hasher;

    #[tokio::test]
    async fn should_check_json_rpc_id_is_consistent() {
        async fn check(
            request_id: Id,
            response: JsonRpcResponse<serde_json::Value>,
            expected_result: Result<(), String>,
        ) {
            let request = http::Request::post(URL)
                .body(
                    JsonRpcRequest::new("foo", json!(["param1", "param2"]))
                        .with_id(request_id.clone()),
                )
                .unwrap();
            let mut service = ServiceBuilder::new()
                .filter_response(CreateJsonRpcIdFilter::new())
                .service_fn(|_request: HttpJsonRpcRequest<serde_json::Value>| async {
                    Ok::<_, BoxError>(http::Response::new(response.clone()))
                });

            let service_result = service.ready().await.unwrap().call(request).await;

            assert_expected_result(service_result, expected_result.map(|_| response));
        }

        check(
            Id::from(42_u64),
            JsonRpcResponse::from_ok(Id::from(42_u64), json!(1)),
            Ok(()),
        )
        .await;
        check(
            Id::from(42_u64),
            JsonRpcResponse::from_ok(Id::from(43_u64), json!(1)),
            Err("expected response ID".to_string()),
        )
        .await;
        check(
            Id::from(42_u64),
            JsonRpcResponse::from_error(
                Id::Null,
                JsonRpcError {
                    code: -32700,
                    message: "Parse error".to_string(),
                    data: None,
                },
            ),
            Ok(()),
        )
        .await;
        check(
            Id::from(42_u64),
            JsonRpcResponse::from_error(
                Id::Null,
                JsonRpcError {
                    code: -32600,
                    message: "Invalid request".to_string(),
                    data: None,
                },
            ),
            Ok(()),
        )
        .await;
    }

    #[tokio::test]
    async fn should_check_json_rpc_batch_ids_are_consistent() {
        async fn check(
            request_ids: Vec<Id>,
            responses: Vec<JsonRpcResponse<serde_json::Value>>,
            expected_result: Result<(), String>,
        ) {
            assert_eq!(request_ids.len(), responses.len());

            let request = http::Request::post(URL)
                .body(
                    request_ids
                        .into_iter()
                        .enumerate()
                        .map(|(i, id)| {
                            JsonRpcRequest::new("foo", json!(["param1", {"param2": i}])).with_id(id)
                        })
                        .collect(),
                )
                .unwrap();
            let mut service = ServiceBuilder::new()
                .filter_response(CreateJsonRpcIdFilter::new())
                .map_response(shuffle_json_rpc_batch_responses)
                .service_fn(
                    |_request: HttpBatchJsonRpcRequest<serde_json::Value>| async {
                        Ok::<_, BoxError>(http::Response::new(responses.clone()))
                    },
                );

            let service_result = service.ready().await.unwrap().call(request).await;

            assert_expected_result(service_result, expected_result.map(|_| responses));
        }

        check(
            vec![Id::from(42_u64), Id::from(43_u64), Id::from(44_u64)],
            vec![
                JsonRpcResponse::from_ok(Id::from(42_u64), json!(1)),
                JsonRpcResponse::from_ok(Id::from(43_u64), json!(2)),
                JsonRpcResponse::from_error(
                    Id::Null,
                    JsonRpcError {
                        code: -32600,
                        message: "Invalid Request".to_string(),
                        data: None,
                    },
                ),
            ],
            Ok(()),
        )
        .await;
        check(
            vec![Id::from(42_u64), Id::from(43_u64), Id::from(44_u64)],
            vec![
                JsonRpcResponse::from_ok(Id::from(42_u64), json!(1)),
                JsonRpcResponse::from_ok(Id::from(43_u64), json!(2)),
                JsonRpcResponse::from_error(
                    Id::Null,
                    JsonRpcError {
                        code: -32601,
                        message: "Method not found".to_string(),
                        data: None,
                    },
                ),
            ],
            Err("expected batch response IDs".to_string()),
        )
        .await;
        check(
            vec![Id::from(42_u64), Id::from(43_u64), Id::from(44_u64)],
            vec![
                JsonRpcResponse::from_ok(Id::from(42_u64), json!(1)),
                JsonRpcResponse::from_ok(Id::from(43_u64), json!(1)),
                JsonRpcResponse::from_ok(Id::from(45_u64), json!(1)),
            ],
            Err("expected batch response IDs".to_string()),
        )
        .await;
    }

    #[tokio::test]
    #[should_panic(expected = "ERROR: a null request ID")]
    async fn should_panic_when_request_id_null() {
        let mut service = ServiceBuilder::new()
            .filter_response(CreateJsonRpcIdFilter::new())
            .service_fn(echo_json_rpc_request_id);

        let request = JsonRpcRequest::new("foo", json!(["param1", "param2"])).with_id(Id::Null);

        let _response = service
            .ready()
            .await
            .unwrap()
            .call(http::Request::post(URL).body(request).unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Expected batch to not be empty")]
    async fn should_panic_when_json_rpc_batch_empty() {
        let mut service = ServiceBuilder::new()
            .filter_response(CreateJsonRpcIdFilter::new())
            .service_fn(echo_json_rpc_batch_request_ids);

        let _response = service
            .ready()
            .await
            .unwrap()
            .call(http::Request::post(URL).body(vec![]).unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Expected request IDs to be unique")]
    async fn should_panic_when_request_ids_not_unique() {
        let mut service = ServiceBuilder::new()
            .filter_response(CreateJsonRpcIdFilter::new())
            .service_fn(echo_json_rpc_batch_request_ids);

        let request = vec![
            JsonRpcRequest::new("foo", json!(["param1", "param2"])).with_id(Id::from(100_u64)),
            JsonRpcRequest::new("bar", json!(["param3", "param4"])).with_id(Id::from(101_u64)),
            JsonRpcRequest::new("bar", json!(["param3", "param4"])).with_id(Id::from(101_u64)),
        ];

        let _response = service
            .ready()
            .await
            .unwrap()
            .call(http::Request::post(URL).body(request).unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "ERROR: a null request ID")]
    async fn should_panic_when_json_rpc_batch_contains_null_id() {
        let mut service = ServiceBuilder::new()
            .filter_response(CreateJsonRpcIdFilter::new())
            .service_fn(echo_json_rpc_batch_request_ids);

        let request = vec![
            JsonRpcRequest::new("foo", json!(["param1", "param2"])).with_id(Id::from(100_u64)),
            JsonRpcRequest::new("bar", json!(["param3", "param4"])).with_id(Id::from(101_u64)),
            JsonRpcRequest::new("bar", json!(["param3", "param4"])).with_id(Id::Null),
        ];

        let _response = service
            .ready()
            .await
            .unwrap()
            .call(http::Request::post(URL).body(request).unwrap())
            .await
            .unwrap();
    }

    fn assert_expected_result<T: Debug + PartialEq>(
        service_result: Result<http::Response<T>, BoxError>,
        expected_result: Result<T, String>,
    ) {
        match expected_result {
            Ok(expected_response) => {
                let service_response = service_result
                    .unwrap_or_else(|error| panic!("Expected ok, but got: {error}"))
                    .into_body();
                assert_eq!(
                    service_response, expected_response,
                    "Expected response: {expected_response:?}, but got {service_response:?}"
                );
            }
            Err(expected_error) => {
                let service_error = match service_result {
                    Ok(response) => {
                        panic!("Expected error, but got {:?}", response.into_body())
                    }
                    Err(error) => error,
                };
                assert!(
                    service_error.to_string().contains(&expected_error),
                    "Expected error: {expected_error}, but got {service_error}",
                );
            }
        }
    }

    async fn echo_json_rpc_request_id(
        request: HttpJsonRpcRequest<serde_json::Value>,
    ) -> Result<HttpJsonRpcResponse<serde_json::Value>, BoxError> {
        Ok(http::Response::new(JsonRpcResponse::from_ok(
            request.body().id().clone(),
            json!("echo"),
        )))
    }

    fn shuffle_json_rpc_batch_responses<T: Serialize>(
        response: HttpBatchJsonRpcResponse<T>,
    ) -> HttpBatchJsonRpcResponse<T> {
        response.map(|responses| {
            responses
                .into_iter()
                // Sort responses in a JSON-RPC batch by hash to simulate random shuffling
                .sorted_by_key(|r| {
                    let mut hasher = DefaultHasher::new();
                    serde_json::to_string(r).unwrap().hash(&mut hasher);
                    hasher.finish()
                })
                .collect()
        })
    }

    async fn echo_json_rpc_batch_request_ids(
        request: HttpBatchJsonRpcRequest<serde_json::Value>,
    ) -> Result<HttpBatchJsonRpcResponse<serde_json::Value>, BoxError> {
        let responses = request
            .into_body()
            .iter()
            .map(|request| JsonRpcResponse::from_ok(request.id().clone(), json!("echo")))
            .collect();
        Ok(http::Response::new(responses))
    }
}

async fn echo_request(request: HttpRequest) -> Result<HttpRequest, BoxError> {
    Ok(request)
}

async fn echo_response(response: HttpResponse) -> Result<HttpResponse, BoxError> {
    Ok(response)
}

async fn forward_body(request: HttpRequest) -> Result<HttpResponse, BoxError> {
    Ok(http::Response::new(request.into_body()))
}
