use candid::Encode;
use futures::future::TryFutureExt;
use ic_canister_http_service::{
    canister_http_service_client::CanisterHttpServiceClient, CanisterHttpSendRequest,
    CanisterHttpSendResponse, HttpHeader,
};
use ic_error_types::RejectCode;
use ic_interfaces::execution_environment::AnonymousQueryService;
use ic_interfaces_canister_http_adapter_client::{NonBlockingChannel, SendError, TryReceiveError};
use ic_types::{
    canister_http::{
        CanisterHttpReject, CanisterHttpRequest, CanisterHttpRequestContext, CanisterHttpRequestId,
        CanisterHttpResponse, CanisterHttpResponseContent,
    },
    messages::{AnonymousQuery, AnonymousQueryResponse, Request},
    CanisterId, Time,
};
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

/// This client is returend if we fail to make connection to canister http adapter.
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
}

impl CanisterHttpAdapterClientImpl {
    pub fn new(
        rt_handle: Handle,
        grpc_channel: Channel,
        anonymous_query_service: AnonymousQueryService,
        inflight_requests: usize,
    ) -> Self {
        let (tx, rx) = channel(inflight_requests);
        Self {
            rt_handle,
            grpc_channel,
            tx,
            rx,
            anonymous_query_service,
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

        // Spawn an async task that sends the canister http request to the adapter and awaits the response.
        // After receving the response from the adapter an option transform is applied by doing an upcall to execution.
        // Once final response is available send the response over to the channel making it available to the client.
        self.rt_handle.spawn(async move {
            // Destruct canister http request to avoid partial moves of the canister http request.
            let CanisterHttpRequest {
                id: request_id,
                timeout: request_timeout,
                content:
                    CanisterHttpRequestContext {
                        request:
                            Request {
                                receiver: request_receiver,
                                ..
                            },
                        url: request_url,
                        headers: request_headers,
                        body: request_body,
                        http_method: _request_http_method,
                        transform_method_name: request_transform_method,
                        ..
                    },
            } = canister_http_request;

            // Build future that sends and transforms request.
            let adapter_canister_http_response = http_adapter_client
                .canister_http_send(CanisterHttpSendRequest {
                    url: request_url,
                    headers: request_headers
                        .into_iter()
                        .map(|h| HttpHeader {
                            name: h.name,
                            value: h.value,
                        })
                        .collect(),
                    body: request_body.unwrap_or_default(),
                })
                .map_err(|grpc_status| {
                    (
                        grpc_status_code_to_reject(grpc_status.code()),
                        grpc_status.message().to_string(),
                    )
                })
                .and_then(|adapter_response| async move {
                    let adapter_response = adapter_response.into_inner();
                    // Only apply the transform if a function name is specified
                    let transform_response = match request_transform_method {
                        Some(transform_method) => {
                            transform_adapter_response(
                                anonymous_query_handler,
                                adapter_response,
                                request_receiver,
                                transform_method,
                            )
                            .await?
                        }
                        None => Encode!(&ic_ic00_types::CanisterHttpResponsePayload {
                            status: adapter_response.status as u64,
                            headers: adapter_response
                                .headers
                                .into_iter()
                                .map(|HttpHeader { name, value }| {
                                    ic_ic00_types::HttpHeader { name, value }
                                })
                                .collect(),
                            body: adapter_response.content,
                        })
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

                    Ok(transform_response)
                });

            // Drive created future to completion and make response available on the channel.
            permit.send(match adapter_canister_http_response.await {
                Ok(resp) => build_canister_http_success(request_id, request_timeout, resp),
                Err(err) => build_canister_http_reject(request_id, request_timeout, err.0, err.1),
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
    adapter_response: CanisterHttpSendResponse,
    transform_canister: CanisterId,
    transform_method: String,
) -> Result<Vec<u8>, (RejectCode, String)> {
    // TODO: Protobuf to conversion via from/into trait to avoid having ic00 as a dependency.
    // CanisterHttpResponsePayload type is part of the public API and need to encode the adapter response into the public API candid.
    let method_payload = Encode!(&ic_ic00_types::CanisterHttpResponsePayload {
        status: adapter_response.status as u64,
        headers: adapter_response
            .headers
            .into_iter()
            .map(|HttpHeader { name, value }| { ic_ic00_types::HttpHeader { name, value } })
            .collect(),
        body: adapter_response.content,
    })
    .map_err(|encode_error| {
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
        method_name: transform_method.clone(),
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
                transform_method, err
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

fn build_canister_http_success(
    request_id: CanisterHttpRequestId,
    request_timeout: Time,
    transform_response: Vec<u8>,
) -> CanisterHttpResponse {
    CanisterHttpResponse {
        id: request_id,
        timeout: request_timeout,
        content: CanisterHttpResponseContent::Success(transform_response),
    }
}

fn build_canister_http_reject(
    request_id: CanisterHttpRequestId,
    request_timeout: Time,
    reject_code: RejectCode,
    reject_message: String,
) -> CanisterHttpResponse {
    CanisterHttpResponse {
        id: request_id,
        timeout: request_timeout,
        content: CanisterHttpResponseContent::Reject(CanisterHttpReject {
            reject_code,
            message: reject_message,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_canister_http_service::{
        canister_http_service_server::{CanisterHttpService, CanisterHttpServiceServer},
        CanisterHttpSendRequest, CanisterHttpSendResponse,
    };
    use ic_test_utilities::{mock_time, types::messages::RequestBuilder};
    use ic_types::{
        canister_http::CanisterHttpMethod,
        messages::{Blob, CallbackId},
    };
    use std::{
        convert::Infallible,
        future::Future,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };
    use tonic::{
        transport::{Channel, Endpoint, Server, Uri},
        Request, Response, Status,
    };
    use tower::{service_fn, util::BoxService, Service, ServiceBuilder};

    struct SingleResponseAnonymousQueryService {
        response: AnonymousQueryResponse,
    }

    // Can specify anonymous query response at creation.
    impl SingleResponseAnonymousQueryService {
        fn new(resp: AnonymousQueryResponse) -> Self {
            Self { response: resp }
        }
    }

    impl Service<AnonymousQuery> for SingleResponseAnonymousQueryService {
        type Response = AnonymousQueryResponse;
        type Error = Infallible;
        #[allow(clippy::type_complexity)]
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _anonymous_query: AnonymousQuery) -> Self::Future {
            let response = self.response.clone();
            Box::pin(async move { Ok(response) })
        }
    }

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
            content: CanisterHttpRequestContext {
                request: RequestBuilder::default().build(),
                url: "http://notused.com".to_string(),
                headers: Vec::new(),
                body: None,
                http_method: CanisterHttpMethod::GET,
                transform_method_name: transform_method,
                time: mock_time(),
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
            content: CanisterHttpResponseContent::Reject(CanisterHttpReject {
                reject_code,
                message: reject_message,
            }),
        }
    }

    fn build_mock_canister_http_response_success(
        request_id: u64,
        request_timeout: Time,
        status: u64,
        headers: Vec<HttpHeader>,
        body: Vec<u8>,
    ) -> CanisterHttpResponse {
        CanisterHttpResponse {
            id: CallbackId::from(request_id),
            timeout: request_timeout,
            content: CanisterHttpResponseContent::Success(
                Encode!(&ic_ic00_types::CanisterHttpResponsePayload {
                    status,
                    headers: headers
                        .into_iter()
                        .map(|HttpHeader { name, value }| {
                            ic_ic00_types::HttpHeader { name, value }
                        })
                        .collect(),
                    body,
                })
                .unwrap(),
            ),
        }
    }

    /// Test canister http client send/receive without transform.  
    #[tokio::test]
    async fn test_client_happy_path() {
        // Define response from adpater. This should also be returned by the client.
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
        let mock_anon_svc =
            SingleResponseAnonymousQueryService::new(AnonymousQueryResponse::Rejected {
                reject_code: RejectCode::SysFatal,
                reject_message: "dsf".to_string(),
            });
        let base_service = BoxService::new(ServiceBuilder::new().service(mock_anon_svc));
        let svc = ServiceBuilder::new().buffer(1).service(base_service);

        let mut client = CanisterHttpAdapterClientImpl::new(
            tokio::runtime::Handle::current(),
            mock_grpc_channel,
            svc,
            100,
        );

        assert_eq!(client.try_receive(), Err(TryReceiveError::Empty));
        // Send request to client without any transform function specified.
        assert_eq!(
            client.send(build_mock_canister_http_request(420, mock_time(), None)),
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
                            mock_time(),
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
        let mock_anon_svc =
            SingleResponseAnonymousQueryService::new(AnonymousQueryResponse::Rejected {
                reject_code: RejectCode::SysFatal,
                reject_message: "dsf".to_string(),
            });
        let base_service = BoxService::new(ServiceBuilder::new().service(mock_anon_svc));
        let svc = ServiceBuilder::new().buffer(1).service(base_service);

        let mut client = CanisterHttpAdapterClientImpl::new(
            tokio::runtime::Handle::current(),
            mock_grpc_channel,
            svc,
            100,
        );

        assert_eq!(
            client.send(build_mock_canister_http_request(420, mock_time(), None)),
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
                            mock_time(),
                            RejectCode::SysTransient,
                            "adapter unavailable".to_string()
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
        let mock_anon_svc =
            SingleResponseAnonymousQueryService::new(AnonymousQueryResponse::Rejected {
                reject_code: RejectCode::SysFatal,
                reject_message: "dsf".to_string(),
            });
        let base_service = BoxService::new(ServiceBuilder::new().service(mock_anon_svc));
        let svc = ServiceBuilder::new().buffer(1).service(base_service);

        let mut client = CanisterHttpAdapterClientImpl::new(
            tokio::runtime::Handle::current(),
            mock_grpc_channel,
            svc,
            100,
        );

        assert_eq!(
            client.send(build_mock_canister_http_request(420, mock_time(), None)),
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
                            mock_time(),
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
        // Asynchronous query handler mock setup. Return unmodified adapter reponse but encoded in 'http_response' candid.
        let mock_anon_svc =
            SingleResponseAnonymousQueryService::new(AnonymousQueryResponse::Replied {
                reply: ic_types::messages::AnonymousQueryResponseReply {
                    arg: Blob(
                        Encode!(&ic_ic00_types::CanisterHttpResponsePayload {
                            status: 200_u64,
                            headers: adapter_headers
                                .clone()
                                .into_iter()
                                .map(|HttpHeader { name, value }| {
                                    ic_ic00_types::HttpHeader { name, value }
                                })
                                .collect(),
                            body: adapter_body.clone(),
                        })
                        .unwrap(),
                    ),
                },
            });
        let base_service = BoxService::new(ServiceBuilder::new().service(mock_anon_svc));
        let svc = ServiceBuilder::new().buffer(1).service(base_service);

        let mut client = CanisterHttpAdapterClientImpl::new(
            tokio::runtime::Handle::current(),
            mock_grpc_channel,
            svc,
            100,
        );

        // Specify a transform_method name such that the client calls the anonymous query handler.
        assert_eq!(
            client.send(build_mock_canister_http_request(
                420,
                mock_time(),
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
                            mock_time(),
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
        // Asynchronous query handler mock setup. Returns a rejection with some reason.
        let mock_anon_svc =
            SingleResponseAnonymousQueryService::new(AnonymousQueryResponse::Rejected {
                reject_code: RejectCode::SysFatal,
                reject_message: "test fail".to_string(),
            });
        let base_service = BoxService::new(ServiceBuilder::new().service(mock_anon_svc));
        let svc = ServiceBuilder::new().buffer(1).service(base_service);

        let mut client = CanisterHttpAdapterClientImpl::new(
            tokio::runtime::Handle::current(),
            mock_grpc_channel,
            svc,
            100,
        );

        // Specify a transform_method name such that the client calls the anonymous query handler.
        assert_eq!(
            client.send(build_mock_canister_http_request(
                420,
                mock_time(),
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
                            mock_time(),
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
        // Asynchronous query handler mock setup. No relevance in this test case.
        let mock_anon_svc =
            SingleResponseAnonymousQueryService::new(AnonymousQueryResponse::Rejected {
                reject_code: RejectCode::SysFatal,
                reject_message: "dsf".to_string(),
            });
        let base_service = BoxService::new(ServiceBuilder::new().service(mock_anon_svc));
        let svc = ServiceBuilder::new().buffer(1).service(base_service);

        // Create a client with a capacity of 2.
        let mut client = CanisterHttpAdapterClientImpl::new(
            tokio::runtime::Handle::current(),
            mock_grpc_channel,
            svc,
            2,
        );

        assert_eq!(client.try_receive(), Err(TryReceiveError::Empty));
        assert_eq!(
            client.send(build_mock_canister_http_request(420, mock_time(), None)),
            Ok(())
        );
        assert_eq!(
            client.send(build_mock_canister_http_request(421, mock_time(), None)),
            Ok(())
        );
        // Make a request on a already full channel.
        assert_eq!(
            client.send(build_mock_canister_http_request(422, mock_time(), None)),
            Err(SendError::Full(build_mock_canister_http_request(
                422,
                mock_time(),
                None
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
                            mock_time(),
                            RejectCode::SysTransient,
                            "adapter unavailable".to_string()
                        )
                    );
                    break;
                }
            }
        }

        assert_eq!(
            client.send(build_mock_canister_http_request(423, mock_time(), None)),
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
                            mock_time(),
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
                            mock_time(),
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
}
