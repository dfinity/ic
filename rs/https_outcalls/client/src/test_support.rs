//! In-process HTTPS outcalls adapter mocks, shared by the client tests.

use ic_https_outcalls_service::{
    HttpsOutcallRequest, HttpsOutcallResponse, HttpsOutcallResult, https_outcall_result,
    https_outcalls_service_server::{HttpsOutcallsService, HttpsOutcallsServiceServer},
};
use std::sync::{Arc, Mutex};
use tonic::{
    Code, Request, Response, Status,
    transport::{Channel, Endpoint, Server, Uri},
};
use tower::service_fn;

/// Answers every call with the same canned response, recording the requests.
#[derive(Clone)]
pub struct SingleResponseAdapter {
    /// `None` never responds at all, so that only the client's deadline can end
    /// the call.
    response: Option<Result<HttpsOutcallResult, (Code, String)>>,
    requests: Arc<Mutex<Vec<HttpsOutcallRequest>>>,
    /// Delay before answering, to exercise client-side deadlines.
    delay: Option<std::time::Duration>,
}

impl SingleResponseAdapter {
    pub fn new(response: Result<HttpsOutcallResult, (Code, String)>) -> Self {
        Self {
            response: Some(response),
            requests: Arc::new(Mutex::new(Vec::new())),
            delay: None,
        }
    }

    pub fn hanging() -> Self {
        Self {
            response: None,
            requests: Arc::new(Mutex::new(Vec::new())),
            delay: None,
        }
    }

    pub fn with_delay(mut self, delay: std::time::Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    /// The requests this adapter has received so far.
    pub fn requests(&self) -> Arc<Mutex<Vec<HttpsOutcallRequest>>> {
        Arc::clone(&self.requests)
    }
}

#[tonic::async_trait]
impl HttpsOutcallsService for SingleResponseAdapter {
    async fn https_outcall(
        &self,
        request: Request<HttpsOutcallRequest>,
    ) -> Result<Response<HttpsOutcallResult>, Status> {
        self.requests.lock().unwrap().push(request.into_inner());
        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }
        match self.response.clone() {
            Some(Ok(resp)) => Ok(Response::new(resp)),
            Some(Err((code, msg))) => Err(Status::new(code, msg)),
            None => std::future::pending().await,
        }
    }
}

/// Serves `mock_adapter` over an in-memory gRPC connection.
pub async fn serve_mock_adapter(mock_adapter: SingleResponseAdapter) -> Channel {
    let (client, server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        Server::builder()
            .add_service(HttpsOutcallsServiceServer::new(mock_adapter))
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
                    Ok(hyper_util::rt::TokioIo::new(client))
                } else {
                    Err(std::io::Error::other("Client already taken"))
                }
            }
        }))
        .await
        .unwrap()
}

pub async fn setup_adapter_mock(
    adapter_response: Result<HttpsOutcallResult, (Code, String)>,
) -> Channel {
    serve_mock_adapter(SingleResponseAdapter::new(adapter_response)).await
}

/// Never answers, so only the client's deadline can end the call.
pub async fn setup_hanging_adapter_mock() -> Channel {
    serve_mock_adapter(SingleResponseAdapter::hanging()).await
}

pub fn create_result_from_response(response: HttpsOutcallResponse) -> HttpsOutcallResult {
    HttpsOutcallResult {
        metrics: None,
        result: Some(https_outcall_result::Result::Response(response)),
    }
}
