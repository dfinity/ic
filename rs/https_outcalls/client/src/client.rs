use crate::metrics::Metrics;
use candid::Encode;
use futures::future::TryFutureExt;
use ic_error_types::{RejectCode, UserError};
use ic_https_outcalls_service::{
    canister_http_service_client::CanisterHttpServiceClient, CanisterHttpSendRequest,
    CanisterHttpSendResponse, HttpHeader, HttpMethod,
};
use ic_interfaces::execution_environment::AnonymousQueryService;
use ic_interfaces_adapter_client::{NonBlockingChannel, SendError, TryReceiveError};
use ic_management_canister_types::{CanisterHttpResponsePayload, TransformArgs};
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    canister_http::{
        validate_http_headers_and_body, CanisterHttpMethod, CanisterHttpReject,
        CanisterHttpRequest, CanisterHttpRequestContext, CanisterHttpResponse,
        CanisterHttpResponseContent, Transform, MAX_CANISTER_HTTP_RESPONSE_BYTES,
    },
    messages::{AnonymousQuery, AnonymousQueryResponse, Request},
    CanisterId, NumBytes,
};
use std::time::Instant;
use tokio::{
    runtime::Handle,
    sync::mpsc::{
        channel,
        error::{TryRecvError, TrySendError},
        Receiver, Sender,
    },
};
use tonic::{transport::Channel, Code};
use tower::util::Oneshot;

/// This client is returned if we fail to make connection to canister http adapter.
pub struct BrokenCanisterHttpClient {}

impl NonBlockingChannel<CanisterHttpRequest> for BrokenCanisterHttpClient {
    type Response = CanisterHttpResponse;
    fn send(
        &self,
        _canister_http_request: CanisterHttpRequest,
    ) -> Result<(), SendError<CanisterHttpRequest>> {
        Err(SendError::BrokenConnection)
    }

    fn try_receive(&mut self) -> Result<CanisterHttpResponse, TryReceiveError> {
        Err(TryReceiveError::Empty)
    }
}

/// The interface provides two non-blocking function - "send" and "try_receive".
pub struct CanisterHttpAdapterClientImpl {
    rt_handle: Handle,
    grpc_channel: Channel,
    tx: Sender<CanisterHttpResponse>,
    rx: Receiver<CanisterHttpResponse>,
    anonymous_query_service: AnonymousQueryService,
    metrics: Metrics,
    subnet_type: SubnetType,
}

impl CanisterHttpAdapterClientImpl {
    pub fn new(
        rt_handle: Handle,
        grpc_channel: Channel,
        anonymous_query_service: AnonymousQueryService,
        inflight_requests: usize,
        metrics_registry: MetricsRegistry,
        subnet_type: SubnetType,
    ) -> Self {
        let (tx, rx) = channel(inflight_requests);
        let metrics = Metrics::new(&metrics_registry);
        Self {
            rt_handle,
            grpc_channel,
            tx,
            rx,
            anonymous_query_service,
            metrics,
            subnet_type,
        }
    }
}

impl NonBlockingChannel<CanisterHttpRequest> for CanisterHttpAdapterClientImpl {
    type Response = CanisterHttpResponse;
    /// Enqueues a request that will be send to the canister http adapter iff we don't have
    /// more than 'inflight_requests' requests waiting to be consumed by the
    /// client.
    fn send(
        &self,
        canister_http_request: CanisterHttpRequest,
    ) -> Result<(), SendError<CanisterHttpRequest>> {
        // Accept the request iff we can secure capacity for sending the response back.
        let permit = match self.tx.clone().try_reserve_owned() {
            Ok(permit) => permit,
            Err(err) => {
                return match err {
                    TrySendError::Full(_) => Err(SendError::Full(canister_http_request)),
                    // In the code we never close the channel and we always have at receiver as data member of self.
                    TrySendError::Closed(_) => {
                        panic!("Consensus<->Canister Http client channel should never be closed")
                    }
                };
            }
        };

        // Tonic clients use &mut self and can only send one request at a time.
        // It is suggested to clone the underlying channel which is cheap.
        // https://docs.rs/tonic/latest/tonic/transport/struct.Channel.html
        let mut http_adapter_client = CanisterHttpServiceClient::new(self.grpc_channel.clone());
        let anonymous_query_handler = self.anonymous_query_service.clone();
        let metrics = self.metrics.clone();
        let subnet_type = self.subnet_type;

        // Spawn an async task that sends the canister http request to the adapter and awaits the response.
        // After receiving the response from the adapter an optional transform is applied by doing an upcall to execution.
        // Once final response is available send the response over to the channel making it available to the client.
        self.rt_handle.spawn(async move {
            // Destruct canister http request to avoid partial moves of the canister http request.
            let CanisterHttpRequest {
                id: request_id,
                timeout: request_timeout,
                context:
                    CanisterHttpRequestContext {
                        request:
                            Request {
                                sender: request_sender,
                                ..
                            },
                        url: request_url,
                        headers: request_headers,
                        body: request_body,
                        http_method: request_http_method,
                        max_response_bytes: request_max_response_bytes,
                        transform: request_transform,
                        ..
                    },
            } = canister_http_request;

            let adapter_req_timer = Instant::now();
            // Build future that sends and transforms request.
            let adapter_canister_http_response = http_adapter_client
                .canister_http_send(CanisterHttpSendRequest {
                    url: request_url,
                    method: match request_http_method{
                        CanisterHttpMethod::GET => HttpMethod::Get.into(),
                        CanisterHttpMethod::POST => HttpMethod::Post.into(),
                        CanisterHttpMethod::HEAD => HttpMethod::Head.into(),
                    },
                    max_response_size_bytes: request_max_response_bytes.unwrap_or(NumBytes::new(MAX_CANISTER_HTTP_RESPONSE_BYTES)).get(),
                    headers: request_headers
                        .into_iter()
                        .map(|h| HttpHeader {
                            name: h.name,
                            value: h.value,
                        })
                        .collect(),
                    body: request_body.unwrap_or_default(),
                    // Socks proxy is only enabled on system subnets.
                    socks_proxy_allowed: matches!(subnet_type, SubnetType::System)
                })
                .map_err(|grpc_status| {
                    (
                        grpc_status_code_to_reject(grpc_status.code()),
                        grpc_status.message().to_string(),
                    )
                })
                .and_then(|adapter_response| async move {

                    let CanisterHttpSendResponse { status, headers, content: body} = adapter_response.into_inner();

                    let canister_http_payload = CanisterHttpResponsePayload{
                        status: status as u128,
                        headers: headers.into_iter().map(|HttpHeader { name, value }| {
                                    ic_management_canister_types::HttpHeader { name, value }
                                }).collect(),
                        body,
                    };

                    metrics.http_request_duration
                        .with_label_values(&[&status.to_string()])
                        .observe(adapter_req_timer.elapsed().as_secs_f64());

                    validate_http_headers_and_body(&canister_http_payload.headers, &canister_http_payload.body).map_err(|e| (RejectCode::SysFatal, UserError::from(e).description().to_string()))?;

                    // Only apply the transform if a function name is specified
                    let transform_timer = metrics.transform_execution_duration.start_timer();
                    let transform_response = match &request_transform {
                        Some(transform) => {
                            transform_adapter_response(
                                anonymous_query_handler,
                                canister_http_payload,
                                request_sender,
                                transform,
                            )
                            .await?
                        }
                        None => Encode!(&canister_http_payload)
                        .map_err(|encode_error| {
                            (
                                RejectCode::SysFatal,
                                format!(
                                    "Failed to parse adapter http response to 'http_response' candid: {}",
                                    encode_error
                                ),
                            )
                        })?,
                    };

                    transform_timer.observe_duration();
                    if transform_response.len() > (MAX_CANISTER_HTTP_RESPONSE_BYTES as usize) {
                        let err_msg = match request_transform {
                            Some(_) => format!(
                                "Transformed http response exceeds limit: {}", MAX_CANISTER_HTTP_RESPONSE_BYTES
                            ),
                            None => format!(
                                "Http response exceeds limit: {}. Apply a transform function to the http response.", MAX_CANISTER_HTTP_RESPONSE_BYTES
                            ),
                        };
                        return Err(
                            (
                                RejectCode::SysFatal,
                                err_msg
                            )
                        );
                    }

                    Ok(transform_response)
                });

            // Drive created future to completion and make response available on the channel.
            permit.send(CanisterHttpResponse {
                id: request_id,
                timeout: request_timeout,
                canister_id: request_sender,
                content: match adapter_canister_http_response.await {
                    Ok(resp) => {
                        metrics.request_total.with_label_values(&["success"]).inc();
                        CanisterHttpResponseContent::Success(resp)
                    },
                    Err((reject_code, message)) => {
                        metrics.request_total.with_label_values(&[&reject_code.to_string()]).inc();
                        CanisterHttpResponseContent::Reject(CanisterHttpReject {
                        reject_code,
                        message,
                    })},
                }
            });
        });
        Ok(())
    }

    /// Returns an available canister http response.
    fn try_receive(&mut self) -> Result<Self::Response, TryReceiveError> {
        self.rx.try_recv().map_err(|e| match e {
            TryRecvError::Empty => TryReceiveError::Empty,
            TryRecvError::Disconnected => {
                // In the code we never close the channel and we always have at least one sender stored as data member of self.
                panic!("Consensus<->Canister Http client channel should never be closed")
            }
        })
    }
}

/// Make upcall to execution to transform the response.
/// This gives the ability to prune volatile fields before passing the response to consensus.
async fn transform_adapter_response(
    anonymous_query_handler: AnonymousQueryService,
    canister_http_response: CanisterHttpResponsePayload,
    transform_canister: CanisterId,
    transform: &Transform,
) -> Result<Vec<u8>, (RejectCode, String)> {
    let transform_args = TransformArgs {
        response: canister_http_response,
        context: transform.context.clone(),
    };
    let method_payload = Encode!(&transform_args).map_err(|encode_error| {
        (
            RejectCode::SysFatal,
            format!(
                "Failed to parse http response to 'http_response' candid: {}",
                encode_error
            ),
        )
    })?;

    // Query to execution.
    let anonymous_query = AnonymousQuery {
        receiver: transform_canister,
        method_name: transform.method_name.to_string(),
        method_payload,
    };

    match Oneshot::new(anonymous_query_handler, anonymous_query).await {
        Ok(query_response) => match query_response {
            AnonymousQueryResponse::Rejected {
                reject_code,
                reject_message,
            } => Err((reject_code, reject_message)),
            AnonymousQueryResponse::Replied { reply } => Ok(reply.arg.to_vec()),
        },
        Err(err) => Err((
            RejectCode::SysFatal,
            format!(
                "Calling transform function '{}' failed: {}",
                transform.method_name, err
            ),
        )),
    }
}

fn grpc_status_code_to_reject(code: Code) -> RejectCode {
    match code {
        // TODO: Is unavailable really transient
        Code::Unavailable => RejectCode::SysTransient,
        Code::InvalidArgument => RejectCode::SysFatal,
        _ => RejectCode::SysFatal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_https_outcalls_service::{
        canister_http_service_server::{CanisterHttpService, CanisterHttpServiceServer},
        CanisterHttpSendRequest, CanisterHttpSendResponse,
    };
    use ic_test_utilities_types::messages::RequestBuilder;
    use ic_types::canister_http::Transform;
    use ic_types::{
        canister_http::CanisterHttpMethod,
        messages::{Blob, CallbackId},
        time::UNIX_EPOCH,
        Time,
    };
    use std::convert::TryFrom;
    use std::time::Duration;
    use tonic::{
        transport::{Channel, Endpoint, Server, Uri},
        Request, Response, Status,
    };
    use tower::{service_fn, util::BoxCloneService, Service, ServiceExt};
    use tower_test::mock::Handle;

    #[derive(Clone)]
    pub struct SingleResponseAdapter {
        response: Result<CanisterHttpSendResponse, (Code, String)>,
    }

    impl SingleResponseAdapter {
        fn new(response: Result<CanisterHttpSendResponse, (Code, String)>) -> Self {
            Self { response }
        }
    }

    #[tonic::async_trait]
    impl CanisterHttpService for SingleResponseAdapter {
        async fn canister_http_send(
            &self,
            _request: Request<CanisterHttpSendRequest>,
        ) -> Result<Response<CanisterHttpSendResponse>, Status> {
            match self.response.clone() {
                Ok(resp) => Ok(Response::new(resp)),
                Err((code, msg)) => Err(Status::new(code, msg)),
            }
        }
    }

    async fn setup_adapter_mock(
        adapter_response: Result<CanisterHttpSendResponse, (Code, String)>,
    ) -> Channel {
        let (client, server) = tokio::io::duplex(1024);
        let mock_adapter = SingleResponseAdapter::new(adapter_response);
        tokio::spawn(async move {
            Server::builder()
                .add_service(CanisterHttpServiceServer::new(mock_adapter))
                .serve_with_incoming(futures::stream::iter(vec![Ok::<_, std::io::Error>(server)]))
                .await
        });

        let mut client = Some(client);
        Endpoint::try_from("http://[::]:50051")
            .unwrap()
            .connect_with_connector(service_fn(move |_: Uri| {
                let client = client.take();

                async move {
                    if let Some(client) = client {
                        Ok(client)
                    } else {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Client already taken",
                        ))
                    }
                }
            }))
            .await
            .unwrap()
    }

    fn build_mock_canister_http_request(
        request_id: u64,
        request_timeout: Time,
        transform_method: Option<String>,
    ) -> CanisterHttpRequest {
        CanisterHttpRequest {
            id: CallbackId::from(request_id),
            timeout: request_timeout,
            context: CanisterHttpRequestContext {
                request: RequestBuilder::default()
                    .receiver(CanisterId::from(1))
                    .sender(CanisterId::from(1))
                    .build(),
                url: "http://notused.com".to_string(),
                max_response_bytes: None,
                headers: Vec::new(),
                body: None,
                http_method: CanisterHttpMethod::GET,
                transform: transform_method.map(|method_name| Transform {
                    method_name,
                    context: vec![],
                }),
                time: UNIX_EPOCH,
            },
        }
    }

    fn build_mock_canister_http_response_reject(
        request_id: u64,
        request_timeout: Time,
        reject_code: RejectCode,
        reject_message: String,
    ) -> CanisterHttpResponse {
        CanisterHttpResponse {
            id: CallbackId::from(request_id),
            timeout: request_timeout,
            canister_id: ic_types::CanisterId::from(1),
            content: CanisterHttpResponseContent::Reject(CanisterHttpReject {
                reject_code,
                message: reject_message,
            }),
        }
    }

    fn build_mock_canister_http_response_success(
        request_id: u64,
        request_timeout: Time,
        status: u128,
        headers: Vec<HttpHeader>,
        body: Vec<u8>,
    ) -> CanisterHttpResponse {
        CanisterHttpResponse {
            id: CallbackId::from(request_id),
            timeout: request_timeout,
            canister_id: ic_types::CanisterId::from(1),
            content: CanisterHttpResponseContent::Success(
                Encode!(&ic_management_canister_types::CanisterHttpResponsePayload {
                    status,
                    headers: headers
                        .into_iter()
                        .map(|HttpHeader { name, value }| {
                            ic_management_canister_types::HttpHeader { name, value }
                        })
                        .collect(),
                    body,
                })
                .unwrap(),
            ),
        }
    }

    fn setup_anonymous_query_mock() -> (
        AnonymousQueryService,
        Handle<AnonymousQuery, AnonymousQueryResponse>,
    ) {
        let (service, handle) = tower_test::mock::pair::<AnonymousQuery, AnonymousQueryResponse>();

        let infallible_service = tower::service_fn(move |request: AnonymousQuery| {
            let mut service_clone = service.clone();
            async move {
                Ok::<AnonymousQueryResponse, std::convert::Infallible>({
                    service_clone
                        .ready()
                        .await
                        .expect("Mocking Infallible service. Waiting for readiness failed.")
                        .call(request)
                        .await
                        .expect("Mocking Infallible service and can therefore not return an error.")
                })
            }
        });
        (BoxCloneService::new(infallible_service), handle)
    }

    /// Test canister http client send/receive without transform.
    #[tokio::test]
    async fn test_client_happy_path() {
        // Define response from adapter. This should also be returned by the client.
        let adapter_body = "<html>
            <body>
            <h1>Hello, World!</h1>
            </body>
            </html>"
            .to_string()
            .as_bytes()
            .to_vec();
        let adapter_headers = vec![HttpHeader {
            name: "Content-Type".to_string(),
            value: "text/html; charset=utf-8".to_string(),
        }];

        // Adapter mock setup
        let mock_grpc_channel = setup_adapter_mock(Ok(CanisterHttpSendResponse {
            status: 200,
            headers: adapter_headers.clone(),
            content: adapter_body.clone(),
        }))
        .await;

        // Asynchronous query handler mock setup. Does not serve any purpose in this test case.
        let (svc, mut handle) = setup_anonymous_query_mock();

        tokio::spawn(async move {
            let (_, rsp) = handle.next_request().await.unwrap();
            rsp.send_response(AnonymousQueryResponse::Rejected {
                reject_code: RejectCode::SysFatal,
                reject_message: "dsf".to_string(),
            });
        });

        let mut client = CanisterHttpAdapterClientImpl::new(
            tokio::runtime::Handle::current(),
            mock_grpc_channel,
            svc,
            100,
            MetricsRegistry::default(),
            SubnetType::Application,
        );

        assert_eq!(client.try_receive(), Err(TryReceiveError::Empty));
        // Send request to client without any transform function specified.
        assert_eq!(
            client.send(build_mock_canister_http_request(420, UNIX_EPOCH, None)),
            Ok(())
        );
        // Yield to execute the request on the client.
        loop {
            match client.try_receive() {
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                Ok(r) => {
                    assert_eq!(
                        r,
                        build_mock_canister_http_response_success(
                            420,
                            UNIX_EPOCH,
                            200,
                            adapter_headers,
                            adapter_body
                        )
                    );
                    break;
                }
            }
        }
        assert_eq!(client.try_receive(), Err(TryReceiveError::Empty));
    }

    /// Test case where adapter encounters an UNAVAILABLE  error in executing the http request.
    /// This should be reported as a transient error.
    #[tokio::test]
    async fn test_client_unavailable_adapter_response() {
        // Adapter mock setup.
        let mock_grpc_channel =
            setup_adapter_mock(Err((Code::Unavailable, "adapter unavailable".to_string()))).await;
        // Asynchronous query handler mock setup. Does not serve any purpose in this test case.
        let (svc, mut handle) = setup_anonymous_query_mock();

        tokio::spawn(async move {
            let (_, rsp) = handle.next_request().await.unwrap();
            rsp.send_response(AnonymousQueryResponse::Rejected {
                reject_code: RejectCode::SysFatal,
                reject_message: "dsf".to_string(),
            });
        });

        let mut client = CanisterHttpAdapterClientImpl::new(
            tokio::runtime::Handle::current(),
            mock_grpc_channel,
            svc,
            100,
            MetricsRegistry::default(),
            SubnetType::Application,
        );

        assert_eq!(
            client.send(build_mock_canister_http_request(420, UNIX_EPOCH, None)),
            Ok(())
        );
        // Yield to execute the request on the client.
        loop {
            match client.try_receive() {
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                Ok(r) => {
                    assert_eq!(
                        r,
                        build_mock_canister_http_response_reject(
                            420,
                            UNIX_EPOCH,
                            RejectCode::SysTransient,
                            "adapter unavailable".to_string()
                        )
                    );
                    break;
                }
            }
        }
    }

    /// Test case where transformed response exceeds consensus limit.
    #[tokio::test]
    async fn test_client_transformed_limit() {
        // Adapter mock setup
        let mock_grpc_channel = setup_adapter_mock(Ok(CanisterHttpSendResponse {
            status: 200,
            headers: Vec::new(),
            content: Vec::new(),
        }))
        .await;
        // Asynchronous query handler mock setup. Does not serve any purpose in this test case.
        let (svc, mut handle) = setup_anonymous_query_mock();

        tokio::spawn(async move {
            let (req, rsp) = handle.next_request().await.unwrap();
            println!("{:?}", req);
            rsp.send_response(AnonymousQueryResponse::Replied {
                reply: ic_types::messages::AnonymousQueryResponseReply {
                    arg: Blob(vec![0; (MAX_CANISTER_HTTP_RESPONSE_BYTES as usize) + 1]),
                },
            });
        });

        let mut client = CanisterHttpAdapterClientImpl::new(
            tokio::runtime::Handle::current(),
            mock_grpc_channel,
            svc,
            100,
            MetricsRegistry::default(),
            SubnetType::Application,
        );

        assert_eq!(
            client.send(build_mock_canister_http_request(
                420,
                UNIX_EPOCH,
                Some("transform".to_string())
            )),
            Ok(())
        );
        // Yield to execute the request on the client.
        loop {
            match client.try_receive() {
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                Ok(r) => {
                    assert_eq!(
                        r,
                        build_mock_canister_http_response_reject(
                            420,
                            UNIX_EPOCH,
                            RejectCode::SysFatal,
                            format!(
                                "Transformed http response exceeds limit: {}",
                                MAX_CANISTER_HTTP_RESPONSE_BYTES
                            )
                        )
                    );
                    break;
                }
            }
        }
    }

    /// Test case where adapter encounters an INVALID_ARGUMENT  error in executing the http request.
    /// This should be reported as a fatal error.
    #[tokio::test]
    async fn test_client_invalid_argument_adapter_response() {
        // Adapter mock setup. Return an INVALID_ARGUMENT error.
        let mock_grpc_channel = setup_adapter_mock(Err((
            Code::InvalidArgument,
            "adapter invalid argument".to_string(),
        )))
        .await;
        // Asynchronous query handler mock setup. Does not serve any purpose in this test case.
        let (svc, mut handle) = setup_anonymous_query_mock();

        tokio::spawn(async move {
            let (_, rsp) = handle.next_request().await.unwrap();
            rsp.send_response(AnonymousQueryResponse::Rejected {
                reject_code: RejectCode::SysFatal,
                reject_message: "dsf".to_string(),
            });
        });

        let mut client = CanisterHttpAdapterClientImpl::new(
            tokio::runtime::Handle::current(),
            mock_grpc_channel,
            svc,
            100,
            MetricsRegistry::default(),
            SubnetType::Application,
        );

        assert_eq!(
            client.send(build_mock_canister_http_request(420, UNIX_EPOCH, None)),
            Ok(())
        );
        // Yield to execute the request on the client.
        loop {
            match client.try_receive() {
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                Ok(r) => {
                    assert_eq!(
                        r,
                        build_mock_canister_http_response_reject(
                            420,
                            UNIX_EPOCH,
                            RejectCode::SysFatal,
                            "adapter invalid argument".to_string()
                        )
                    );
                    break;
                }
            }
        }
        assert_eq!(client.try_receive(), Err(TryReceiveError::Empty));
    }

    /// Test client with a specified transform function.
    #[tokio::test]
    async fn test_client_no_op_transform() {
        let adapter_body = "<html>
            <body>
            <h1>Hello, World!</h1>
            </body>
            </html>"
            .to_string()
            .as_bytes()
            .to_vec();
        let adapter_headers = vec![HttpHeader {
            name: "Content-Type".to_string(),
            value: "text/html; charset=utf-8".to_string(),
        }];

        // Adapter mock setup.
        let mock_grpc_channel = setup_adapter_mock(Ok(CanisterHttpSendResponse {
            status: 200,
            headers: adapter_headers.clone(),
            content: adapter_body.clone(),
        }))
        .await;
        // Asynchronous query handler mock setup. Does not serve any purpose in this test case.
        let (svc, mut handle) = setup_anonymous_query_mock();

        let adapter_h = adapter_headers.clone();
        let adapter_b = adapter_body.clone();
        tokio::spawn(async move {
            let (_, rsp) = handle.next_request().await.unwrap();
            rsp.send_response(AnonymousQueryResponse::Replied {
                reply: ic_types::messages::AnonymousQueryResponseReply {
                    arg: Blob(
                        Encode!(&ic_management_canister_types::CanisterHttpResponsePayload {
                            status: 200_u128,
                            headers: adapter_h
                                .clone()
                                .into_iter()
                                .map(|HttpHeader { name, value }| {
                                    ic_management_canister_types::HttpHeader { name, value }
                                })
                                .collect(),
                            body: adapter_b.clone(),
                        })
                        .unwrap(),
                    ),
                },
            });
        });

        let mut client = CanisterHttpAdapterClientImpl::new(
            tokio::runtime::Handle::current(),
            mock_grpc_channel,
            svc,
            100,
            MetricsRegistry::default(),
            SubnetType::Application,
        );

        // Specify a transform_method name such that the client calls the anonymous query handler.
        assert_eq!(
            client.send(build_mock_canister_http_request(
                420,
                UNIX_EPOCH,
                Some("transform".to_string())
            )),
            Ok(())
        );
        // Yield to execute the request on the client.
        // Expect unmodified adapter response.
        loop {
            match client.try_receive() {
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                Ok(r) => {
                    assert_eq!(
                        r,
                        build_mock_canister_http_response_success(
                            420,
                            UNIX_EPOCH,
                            200,
                            adapter_headers,
                            adapter_body
                        )
                    );
                    break;
                }
            }
        }
        assert_eq!(client.try_receive(), Err(TryReceiveError::Empty));
    }

    // Test case for anonymous query rejection. The client should pass through the rejection received from the query handler.
    #[tokio::test]
    async fn test_client_transform_reject() {
        let adapter_body = "<html>
            <body>
            <h1>Hello, World!</h1>
            </body>
            </html>"
            .to_string()
            .as_bytes()
            .to_vec();
        let adapter_headers = vec![HttpHeader {
            name: "Content-Type".to_string(),
            value: "text/html; charset=utf-8".to_string(),
        }];

        // Adapter mock setup. Not relevant for client response in this test case.
        let mock_grpc_channel = setup_adapter_mock(Ok(CanisterHttpSendResponse {
            status: 200,
            headers: adapter_headers.clone(),
            content: adapter_body.clone(),
        }))
        .await;
        // Asynchronous query handler mock setup. Does not serve any purpose in this test case.
        let (svc, mut handle) = setup_anonymous_query_mock();

        tokio::spawn(async move {
            let (_, rsp) = handle.next_request().await.unwrap();
            rsp.send_response(AnonymousQueryResponse::Rejected {
                reject_code: RejectCode::SysFatal,
                reject_message: "test fail".to_string(),
            });
        });

        let mut client = CanisterHttpAdapterClientImpl::new(
            tokio::runtime::Handle::current(),
            mock_grpc_channel,
            svc,
            100,
            MetricsRegistry::default(),
            SubnetType::Application,
        );

        // Specify a transform_method name such that the client calls the anonymous query handler.
        assert_eq!(
            client.send(build_mock_canister_http_request(
                420,
                UNIX_EPOCH,
                Some("transform".to_string())
            )),
            Ok(())
        );
        // Yield to execute the request on the client.
        loop {
            match client.try_receive() {
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                Ok(r) => {
                    assert_eq!(
                        r,
                        build_mock_canister_http_response_reject(
                            420,
                            UNIX_EPOCH,
                            RejectCode::SysFatal,
                            "test fail".to_string(),
                        )
                    );
                    break;
                }
            }
        }
        assert_eq!(client.try_receive(), Err(TryReceiveError::Empty));
    }

    // Test client capacity. The capicity of the client is specified by the channel size.
    #[tokio::test]
    async fn test_client_at_capacity() {
        // Adapter mock setup. Not relevant for client response in this test case.
        let mock_grpc_channel =
            setup_adapter_mock(Err((Code::Unavailable, "adapter unavailable".to_string()))).await;
        // Asynchronous query handler mock setup. Does not serve any purpose in this test case.
        let (svc, mut handle) = setup_anonymous_query_mock();

        tokio::spawn(async move {
            let (_, rsp) = handle.next_request().await.unwrap();
            rsp.send_response(AnonymousQueryResponse::Rejected {
                reject_code: RejectCode::SysFatal,
                reject_message: "test fail".to_string(),
            });
        });

        // Create a client with a capacity of 2.
        let mut client = CanisterHttpAdapterClientImpl::new(
            tokio::runtime::Handle::current(),
            mock_grpc_channel,
            svc,
            2,
            MetricsRegistry::default(),
            SubnetType::Application,
        );

        assert_eq!(client.try_receive(), Err(TryReceiveError::Empty));
        assert_eq!(
            client.send(build_mock_canister_http_request(420, UNIX_EPOCH, None)),
            Ok(())
        );
        assert_eq!(
            client.send(build_mock_canister_http_request(421, UNIX_EPOCH, None)),
            Ok(())
        );
        // Make a request on a already full channel.
        assert_eq!(
            client.send(build_mock_canister_http_request(422, UNIX_EPOCH, None)),
            Err(SendError::Full(build_mock_canister_http_request(
                422, UNIX_EPOCH, None
            )))
        );

        // We must yield in order to allow the client to execute the request.
        loop {
            match client.try_receive() {
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                Ok(r) => {
                    assert_eq!(
                        r,
                        build_mock_canister_http_response_reject(
                            420,
                            UNIX_EPOCH,
                            RejectCode::SysTransient,
                            "adapter unavailable".to_string()
                        )
                    );
                    break;
                }
            }
        }

        assert_eq!(
            client.send(build_mock_canister_http_request(423, UNIX_EPOCH, None)),
            Ok(())
        );
        // We must yield in order to allow the client to execute the request.
        loop {
            match client.try_receive() {
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                Ok(r) => {
                    assert_eq!(
                        r,
                        build_mock_canister_http_response_reject(
                            421,
                            UNIX_EPOCH,
                            RejectCode::SysTransient,
                            "adapter unavailable".to_string()
                        )
                    );
                    break;
                }
            }
        }
        loop {
            match client.try_receive() {
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                Ok(r) => {
                    assert_eq!(
                        r,
                        build_mock_canister_http_response_reject(
                            423,
                            UNIX_EPOCH,
                            RejectCode::SysTransient,
                            "adapter unavailable".to_string()
                        )
                    );
                    break;
                }
            }
        }
        assert_eq!(client.try_receive(), Err(TryReceiveError::Empty));
    }

    // Test the maximum number of bytes allowed by consensus to represent the serialized HTTP response if no transform is specified.
    #[tokio::test]
    async fn test_max_response_size() {
        use ic_types::batch::MAX_CANISTER_HTTP_PAYLOAD_SIZE;
        use ic_types::canister_http::{
            MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH, MAX_CANISTER_HTTP_HEADER_NUM,
            MAX_CANISTER_HTTP_HEADER_TOTAL_SIZE,
        };
        let mut headers: Vec<HttpHeader> = vec![];
        /*  We produce MAX_CANISTER_HTTP_HEADER_NUM headers of total size equal to MAX_CANISTER_HTTP_HEADER_TOTAL_SIZE,
            where the i-th header's name and value each have the length n and the form:
              [8-byte binary encoding of i] [(n - 8) occurrences of the character 'x']
        */
        let n = MAX_CANISTER_HTTP_HEADER_TOTAL_SIZE / (2 * MAX_CANISTER_HTTP_HEADER_NUM);
        assert!(n <= MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH);
        for i in 0..MAX_CANISTER_HTTP_HEADER_NUM {
            let h = format!("{:08}{}", i, "x".repeat(n - 8));
            headers.push(HttpHeader {
                name: h.clone(),
                value: h,
            });
        }
        let x = build_mock_canister_http_response_success(
            420,
            UNIX_EPOCH,
            200,
            headers,
            vec![
                0;
                (MAX_CANISTER_HTTP_RESPONSE_BYTES as usize) - MAX_CANISTER_HTTP_HEADER_TOTAL_SIZE
            ],
        );
        if let CanisterHttpResponseContent::Success(content) = x.content {
            // Subtract 50Kb for consensus overhead (CallbackID, Time, CanisterId, CanisterHttpResponseProof)
            assert!(content.len() <= MAX_CANISTER_HTTP_PAYLOAD_SIZE - 50 * 1024);
        } else {
            panic!("build_mock_canister_http_response_success should not return this case");
        }
    }
}
