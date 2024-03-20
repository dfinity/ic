use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::anyhow;
use axum::{
    error_handling::HandleErrorLayer, extract::ConnectInfo, response::IntoResponse, BoxError,
    Router,
};
use http::request::Request;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, time::Duration};
use tower::ServiceBuilder;
use tower_governor::{
    errors::GovernorError, governor::GovernorConfigBuilder, key_extractor::KeyExtractor,
    GovernorLayer,
};

use crate::{persist::RouteSubnet, routes::ApiError, socket::TcpConnectInfo};

pub struct RateLimit {
    requests_per_second: u32, // requests per second allowed
}

impl TryFrom<u32> for RateLimit {
    type Error = anyhow::Error;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == 0 {
            Err(anyhow!("rate limit cannot be 0"))
        } else {
            Ok(RateLimit {
                requests_per_second: value,
            })
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
struct SubnetRateToken;

impl KeyExtractor for SubnetRateToken {
    type Key = String;

    fn extract<B>(&self, req: &Request<B>) -> Result<Self::Key, GovernorError> {
        // This should always work, because we extract the subnet id after preprocess_request puts it there.
        Ok(req
            .extensions()
            .get::<Arc<RouteSubnet>>()
            .ok_or(GovernorError::UnableToExtractKey)?
            .id
            .clone())
    }
}

#[derive(Clone)]
struct IpKeyExtractor;

impl KeyExtractor for IpKeyExtractor {
    type Key = IpAddr;

    fn extract<B>(&self, req: &Request<B>) -> Result<Self::Key, GovernorError> {
        req.extensions()
            .get::<ConnectInfo<TcpConnectInfo>>()
            .map(|x| (x.0).0)
            .or(req
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|x| x.0))
            .map(|x| x.ip())
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

impl RateLimit {
    // Per IP rate limiting.

    // Allow requests_per_second requests per IP. Refill the rate over 1 second.
    pub fn add_ip_rate_limiting(&self, router: Router) -> Router {
        let interval = Duration::from_secs(1)
            .checked_div(self.requests_per_second)
            .unwrap();

        let governor_conf = Box::new(
            GovernorConfigBuilder::default()
                .per_nanosecond(interval.as_nanos().try_into().unwrap())
                .burst_size(self.requests_per_second)
                .key_extractor(IpKeyExtractor)
                .finish()
                .unwrap(),
        );

        router.layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|e: BoxError| async move {
                    ApiError::from(e).into_response()
                }))
                .layer(GovernorLayer {
                    config: Box::leak(governor_conf),
                }),
        )
    }

    // Per subnet rate limiting.

    // Allow requests_per_second requests per subnet. Refill the rate over 1 second.
    pub fn add_subnet_rate_limiting(&self, router: Router) -> Router {
        let interval = Duration::from_secs(1)
            .checked_div(self.requests_per_second)
            .unwrap();

        let governor_conf = Box::new(
            GovernorConfigBuilder::default()
                .per_nanosecond(interval.as_nanos().try_into().unwrap())
                .burst_size(self.requests_per_second)
                .key_extractor(SubnetRateToken)
                .finish()
                .unwrap(),
        );

        router.layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|e: BoxError| async move {
                    ApiError::from(e).into_response()
                }))
                .layer(GovernorLayer {
                    config: Box::leak(governor_conf),
                }),
        )
    }
}

#[cfg(test)]
pub mod test;
