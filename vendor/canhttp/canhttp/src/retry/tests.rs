use crate::{
    client::IcError, http::HttpRequest, retry::DoubleMaxResponseBytes, HttpsOutcallError,
    MaxResponseBytesRequestExtension,
};
use assert_matches::assert_matches;
use ic_error_types::RejectCode;
use std::{
    future,
    sync::mpsc::{self, Sender},
    task::{Context, Poll},
};
use tower::{Service, ServiceBuilder, ServiceExt};

#[tokio::test]
async fn should_retry_until_max() {
    let (requests_tx, requests_rx) = mpsc::channel::<HttpRequest>();

    let mut service =
        ServiceBuilder::new()
            .retry(DoubleMaxResponseBytes)
            .service(StoreRequestServiceAndError::<HttpRequest>::always_error(
                requests_tx.clone(),
            ));

    let request = http::Request::post("https://internetcomputer.org/")
        .max_response_bytes(0)
        .body(vec![])
        .unwrap();

    let response = service
        .ready()
        .await
        .unwrap()
        .call(request)
        .await
        .unwrap_err();
    assert!(response.is_response_too_large());

    let all_requests: Vec<_> = requests_rx.try_iter().collect();

    assert_eq!(all_requests.len(), 12);
    assert_eq!(
        all_requests
            .into_iter()
            .map(|r| r.get_max_response_bytes().unwrap())
            .collect::<Vec<_>>(),
        vec![
            0,
            1024 << 1,
            1024 << 2,
            1024 << 3,
            1024 << 4,
            1024 << 5,
            1024 << 6,
            1024 << 7,
            1024 << 8,
            1024 << 9,
            1024 << 10,
            2_000_000
        ]
    );
}

#[tokio::test]
async fn should_not_retry() {
    for max_response_bytes in [Some(2_000_000_u64), None] {
        let (requests_tx, requests_rx) = mpsc::channel::<HttpRequest>();

        let mut service = ServiceBuilder::new().retry(DoubleMaxResponseBytes).service(
            StoreRequestServiceAndError::<HttpRequest>::always_error(requests_tx.clone()),
        );

        let mut builder = http::Request::post("https://internetcomputer.org/");
        if let Some(max_response_bytes) = max_response_bytes {
            builder = builder.max_response_bytes(max_response_bytes);
        }
        let request = builder.body(vec![]).unwrap();

        let response = service
            .ready()
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap_err();
        assert!(response.is_response_too_large());

        let all_requests: Vec<_> = requests_rx.try_iter().collect();
        assert_eq!(all_requests.len(), 1);
    }
}

#[tokio::test]
async fn should_stop_retrying_when_ok() {
    let (requests_tx, requests_rx) = mpsc::channel::<HttpRequest>();

    let num_errors = 3;
    let mut service =
        ServiceBuilder::new()
            .retry(DoubleMaxResponseBytes)
            .service(StoreRequestServiceAndError::<HttpRequest>::error_n_times(
                requests_tx.clone(),
                num_errors,
            ));

    let request = http::Request::post("https://internetcomputer.org/")
        .max_response_bytes(0)
        .body(vec![])
        .unwrap();

    let response = service.ready().await.unwrap().call(request).await;
    assert_matches!(response, Ok(_));

    let all_requests: Vec<_> = requests_rx.try_iter().collect();

    assert_eq!(all_requests.len(), (num_errors + 1) as usize);
    assert_eq!(
        all_requests
            .into_iter()
            .map(|r| r.get_max_response_bytes().unwrap())
            .collect::<Vec<_>>(),
        vec![0, 1024 << 1, 1024 << 2, 1024 << 3]
    );
}

#[derive(Clone, Debug)]
pub struct StoreRequestServiceAndError<T> {
    requests: Sender<T>,
    num_calls: u8,
    num_errors_before_ok: u8,
}

impl<T> StoreRequestServiceAndError<T> {
    pub fn always_error(requests: Sender<T>) -> Self {
        Self {
            requests,
            num_calls: 0,
            num_errors_before_ok: u8::MAX,
        }
    }

    pub fn error_n_times(requests: Sender<T>, num_errors: u8) -> Self {
        Self {
            requests,
            num_calls: 0,
            num_errors_before_ok: num_errors,
        }
    }
}

impl<Request> Service<Request> for StoreRequestServiceAndError<Request>
where
    Request: Clone,
{
    type Response = Request;
    type Error = IcError;
    type Future = future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        self.num_calls = self
            .num_calls
            .checked_add(1)
            .expect("Unexpected large number of calls to service");
        self.requests.send(req.clone()).unwrap();
        if self.num_calls <= self.num_errors_before_ok {
            future::ready(Err(response_is_too_large_error()))
        } else {
            future::ready(Ok(req))
        }
    }
}

fn response_is_too_large_error() -> IcError {
    let error = IcError::CallRejected {
        code: RejectCode::SysFatal,
        message: "Http body exceeds size limit".to_string(),
    };
    assert!(error.is_response_too_large());
    error
}
