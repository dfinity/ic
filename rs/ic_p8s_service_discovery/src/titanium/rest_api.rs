//! Expose a list of PrometheusTargetGroup over a REST-API as specified under:
//! https://prometheus.io/docs/prometheus/latest/http_sd/
//!
//! The Rest API exposes one endpoint per job_name. The requested job name is
//! given as the path of the URL. E.g.:
//!
//! http://[::]:11235/replica
//!

use anyhow::Result;
use hyper::server::conn::AddrStream;
use hyper::service::Service;
use hyper::{Body, Request, Response};
use slog::{info, warn};
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::future::{Future, Ready};
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;

use crate::titanium::{
    ic_discovery::{IcServiceDiscovery, IcServiceDiscoveryError, PrometheusTargetGroup},
    service_discovery_record::ServiceDiscoveryRecord,
};

pub async fn start_http_server<F>(
    log: slog::Logger,
    scraper: Arc<dyn IcServiceDiscovery>,
    socket_addr: SocketAddr,
    shutdown_signal: F,
) -> Result<()>
where
    F: Future<Output = ()>,
{
    hyper::Server::bind(&socket_addr)
        .serve(RestApiFactory { log, scraper })
        .with_graceful_shutdown(shutdown_signal)
        .await?;
    Ok(())
}

struct RestApiFactory {
    log: slog::Logger,
    scraper: Arc<dyn IcServiceDiscovery>,
}

impl Service<&AddrStream> for RestApiFactory {
    type Response = RestApi;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, conn: &AddrStream) -> Self::Future {
        info!(self.log, "Accepting a new connection from {:?}", conn);
        std::future::ready(Ok(RestApi {
            log: self.log.clone(),
            scraper: self.scraper.clone(),
        }))
    }
}

struct RestApi {
    log: slog::Logger,
    scraper: Arc<dyn IcServiceDiscovery>,
}

impl RestApi {
    fn target_groups_to_response(
        &self,
        target_groups: Result<BTreeSet<PrometheusTargetGroup>, IcServiceDiscoveryError>,
    ) -> Result<Response<Body>, hyper::http::Error> {
        let groups = target_groups.map(|l| -> Vec<_> {
            l.into_iter()
                .map(ServiceDiscoveryRecord::from)
                .collect::<Vec<_>>()
        });
        match groups {
            Ok(groups) => {
                let response = serde_json::to_vec(&groups).unwrap();
                Response::builder()
                    .status(200)
                    .header("Content-Type", "application/json; charset=utf-8")
                    .body(response.into())
            }
            Err(e) => {
                warn!(self.log, "Error when serving scrape targets: {:?}", e);
                Response::builder()
                    .status(500)
                    .header("Content-Type", "text/plain; charset=utf-8")
                    .body(e.to_string().into())
            }
        }
    }
}

impl Service<Request<Body>> for RestApi {
    type Response = Response<Body>;
    type Error = hyper::http::Error;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        fn is_ident(c: u8) -> bool {
            c == b'_' || c.is_ascii_alphanumeric()
        }

        let res = match req.uri().path() {
            s if !s.is_empty() && (&s[1..]).bytes().all(is_ident) => {
                // strip leading `/`
                let job_name = &s[1..];
                let targets = self.scraper.get_prometheus_target_groups(job_name);
                self.target_groups_to_response(targets)
            }
            path => {
                warn!(self.log, "Path not found: {:?}", path);
                Response::builder()
                    .status(404)
                    .header("Content-Type", "text/plain; charset=utf-8")
                    .body(format!("path not found: {}", req.uri().path()).into())
            }
        };
        std::future::ready(res)
    }
}
