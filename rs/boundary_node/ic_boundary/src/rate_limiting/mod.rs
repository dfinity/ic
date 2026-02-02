use std::{net::IpAddr, sync::Arc};

use anyhow::bail;
use axum::Router;
use candid::Principal;
use http::request::Request;
use ic_bn_lib_common::types::http::ConnInfo;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, time::Duration};
use tower::ServiceBuilder;
use tower_governor::{
    GovernorLayer, errors::GovernorError, governor::GovernorConfigBuilder,
    key_extractor::KeyExtractor,
};

use crate::snapshot::Subnet;

pub struct RateLimit {
    requests_per_second: u32, // requests per second allowed
}

impl TryFrom<u32> for RateLimit {
    type Error = anyhow::Error;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == 0 {
            bail!("rate limit cannot be 0")
        } else {
            Ok(RateLimit {
                requests_per_second: value,
            })
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
struct SubnetKeyExtractor;

impl KeyExtractor for SubnetKeyExtractor {
    type Key = Principal;

    fn extract<B>(&self, req: &Request<B>) -> Result<Self::Key, GovernorError> {
        // This should always work, because we extract the subnet id after preprocess_request puts it there.
        Ok(req
            .extensions()
            .get::<Arc<Subnet>>()
            .ok_or(GovernorError::UnableToExtractKey)?
            .id)
    }
}

#[derive(Clone)]
struct IpKeyExtractor;

impl KeyExtractor for IpKeyExtractor {
    type Key = IpAddr;

    fn extract<B>(&self, req: &Request<B>) -> Result<Self::Key, GovernorError> {
        req.extensions()
            .get::<Arc<ConnInfo>>()
            .map(|x| x.remote_addr.ip())
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

impl RateLimit {
    /// Allow requests_per_second requests per IP
    pub fn add_ip_rate_limiting(&self, router: Router) -> Router {
        let interval = Duration::from_secs(1)
            .checked_div(self.requests_per_second)
            .unwrap();

        let governor_conf = GovernorConfigBuilder::default()
            .per_nanosecond(interval.as_nanos().try_into().unwrap())
            .burst_size(self.requests_per_second)
            .key_extractor(IpKeyExtractor)
            .finish()
            .unwrap();

        router.layer(ServiceBuilder::new().layer(GovernorLayer {
            config: Arc::new(governor_conf),
        }))
    }

    /// Allow requests_per_second requests per subnet
    pub fn add_subnet_rate_limiting(&self, router: Router) -> Router {
        let interval = Duration::from_secs(1)
            .checked_div(self.requests_per_second)
            .unwrap();

        let governor_conf = GovernorConfigBuilder::default()
            .per_nanosecond(interval.as_nanos().try_into().unwrap())
            .burst_size(self.requests_per_second)
            .key_extractor(SubnetKeyExtractor)
            .finish()
            .unwrap();

        router.layer(ServiceBuilder::new().layer(GovernorLayer {
            config: Arc::new(governor_conf),
        }))
    }
}

pub mod fetcher;
pub mod generic;
pub mod sharded;

#[cfg(test)]
mod test {
    use super::*;

    use anyhow::Error;
    use axum::{
        Router,
        body::Body,
        extract::Request,
        middleware::Next,
        middleware::{self},
        response::IntoResponse,
        routing::method_routing::post,
    };
    use http::StatusCode;
    use ic_bn_lib_common::{principal, types::http::ConnInfo};
    use ic_types::{
        CanisterId,
        messages::{Blob, HttpCallContent, HttpCanisterUpdate, HttpRequestEnvelope},
    };
    use tower::Service;

    use crate::{
        errors::ApiError, persist::test::generate_test_subnets, test_utils::setup_test_router,
    };

    async fn dummy_call(_request: Request<Body>) -> Result<impl IntoResponse, ApiError> {
        Ok("foo".into_response())
    }

    async fn body_to_subnet_context(
        request: Request,
        next: Next,
    ) -> Result<impl IntoResponse, ApiError> {
        let (parts, body) = request.into_parts();
        let body_vec = axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let subnet_id = String::from_utf8(body_vec.clone()).unwrap();
        let mut subnet = generate_test_subnets(0)[0].clone();
        subnet.id = principal!(subnet_id);

        let mut request = Request::from_parts(parts, axum::body::Body::from(body_vec));
        request.extensions_mut().insert(Arc::new(subnet));
        let resp = next.run(request).await;
        Ok(resp)
    }

    async fn add_ip_to_request(
        mut request: Request,
        next: Next,
    ) -> Result<impl IntoResponse, ApiError> {
        request
            .extensions_mut()
            .insert(Arc::new(ConnInfo::default()));
        let resp = next.run(request).await;
        Ok(resp)
    }

    fn request_with_subnet_id(subnet_id: &str) -> Request<Body> {
        Request::post("/")
            .body(Body::from(String::from(subnet_id)))
            .unwrap()
    }

    #[tokio::test]
    async fn test_no_rate_limit() -> Result<(), Error> {
        let app = Router::new().route("/", post(dummy_call));

        let mut app = app
            .layer(middleware::from_fn(body_to_subnet_context))
            .layer(middleware::from_fn(add_ip_to_request));

        let subnet_id_1 = "f7crg-kabae";
        let request1 = request_with_subnet_id(subnet_id_1);
        let response1 = app.call(request1).await.unwrap();
        let request2 = request_with_subnet_id(subnet_id_1);
        let response2 = app.call(request2).await.unwrap();
        let request3 = request_with_subnet_id(subnet_id_1);
        let response3 = app.call(request3).await.unwrap();
        assert_eq!(response1.status(), StatusCode::OK);
        assert_eq!(response2.status(), StatusCode::OK);
        assert_eq!(response3.status(), StatusCode::OK);

        Ok(())
    }

    #[tokio::test]
    async fn test_ip_rate_limit() -> Result<(), Error> {
        let app = Router::new().route("/", post(dummy_call));
        let app = RateLimit::try_from(2).unwrap().add_ip_rate_limiting(app);
        let mut app = app
            .layer(middleware::from_fn(body_to_subnet_context))
            .layer(middleware::from_fn(add_ip_to_request));

        let subnet_id_1 = "f7crg-kabae";
        let request1 = request_with_subnet_id(subnet_id_1);
        let response1 = app.call(request1).await.unwrap();
        let request2 = request_with_subnet_id(subnet_id_1);
        let response2 = app.call(request2).await.unwrap();
        let request3 = request_with_subnet_id(subnet_id_1);
        let response3 = app.call(request3).await.unwrap();
        assert_eq!(response1.status(), StatusCode::OK);
        assert_eq!(response2.status(), StatusCode::OK);
        assert_eq!(response3.status(), StatusCode::TOO_MANY_REQUESTS);

        Ok(())
    }

    #[tokio::test]
    async fn test_subnet_rate_limit() -> Result<(), Error> {
        let app = Router::new().route("/", post(dummy_call));
        let app = RateLimit::try_from(2)
            .unwrap()
            .add_subnet_rate_limiting(app);
        let mut app = app
            .layer(middleware::from_fn(body_to_subnet_context))
            .layer(middleware::from_fn(add_ip_to_request));

        let subnet_id_1 = "f7crg-kabae";
        let subnet_id_2 = "sqjm4-qahae-aq";
        let request1 = request_with_subnet_id(subnet_id_1);
        let response1 = app.call(request1).await.unwrap();
        let request2 = request_with_subnet_id(subnet_id_1);
        let response2 = app.call(request2).await.unwrap();

        let request3 = request_with_subnet_id(subnet_id_2);
        let response3 = app.call(request3).await.unwrap();
        let request4 = request_with_subnet_id(subnet_id_2);
        let response4 = app.call(request4).await.unwrap();

        let request5 = request_with_subnet_id(subnet_id_1);
        let response5 = app.call(request5).await.unwrap();
        let request6 = request_with_subnet_id(subnet_id_2);
        let response6 = app.call(request6).await.unwrap();

        assert_eq!(response1.status(), StatusCode::OK);
        assert_eq!(response2.status(), StatusCode::OK);
        assert_eq!(response3.status(), StatusCode::OK);
        assert_eq!(response4.status(), StatusCode::OK);
        assert_eq!(response5.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response6.status(), StatusCode::TOO_MANY_REQUESTS);

        Ok(())
    }

    #[tokio::test]
    async fn test_subnet_rate_limit_with_router() -> Result<(), Error> {
        let (mut app, _) = setup_test_router(false, false, 10, 1, 1024, Some(1));

        let sender = principal!("sqjm4-qahae-aq");
        let canister_id = CanisterId::from_u64(100);

        let content = HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(canister_id.get().as_slice().to_vec()),
                method_name: "foobar".to_string(),
                arg: Blob(vec![]),
                sender: Blob(sender.as_slice().to_vec()),
                nonce: None,
                ingress_expiry: 1234,
            },
        };

        let envelope = HttpRequestEnvelope::<HttpCallContent> {
            content,
            sender_delegation: None,
            sender_pubkey: None,
            sender_sig: None,
        };

        let body = serde_cbor::to_vec(&envelope).unwrap();

        // Test call #1 (should work)
        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "http://localhost/api/v2/canister/{canister_id}/call"
            ))
            .body(Body::from(body.clone()))
            .unwrap();

        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Test call #2 (should fail)
        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "http://localhost/api/v2/canister/{canister_id}/call"
            ))
            .body(Body::from(body))
            .unwrap();

        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        Ok(())
    }

    #[tokio::test]
    async fn test_subnet_rate_limit_with_router_v3() -> Result<(), Error> {
        let (mut app, _) = setup_test_router(false, false, 10, 1, 1024, Some(1));

        let sender = principal!("sqjm4-qahae-aq");
        let canister_id = CanisterId::from_u64(100);

        let content = HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(canister_id.get().as_slice().to_vec()),
                method_name: "foobar".to_string(),
                arg: Blob(vec![]),
                sender: Blob(sender.as_slice().to_vec()),
                nonce: None,
                ingress_expiry: 1234,
            },
        };

        let envelope = HttpRequestEnvelope::<HttpCallContent> {
            content,
            sender_delegation: None,
            sender_pubkey: None,
            sender_sig: None,
        };

        let body = serde_cbor::to_vec(&envelope).unwrap();

        // Test call #1 (should work)
        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "http://localhost/api/v3/canister/{canister_id}/call"
            ))
            .body(Body::from(body.clone()))
            .unwrap();

        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Test call #2 (should fail)
        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "http://localhost/api/v3/canister/{canister_id}/call"
            ))
            .body(Body::from(body))
            .unwrap();

        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        Ok(())
    }
}
