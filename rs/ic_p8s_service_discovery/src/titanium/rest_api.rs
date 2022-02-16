//! Expose a list of PrometheusTargetGroup over a REST-API as specified under:
//! https://prometheus.io/docs/prometheus/latest/http_sd/
//!
//! The Rest API exposes one endpoint per job_name. The target IP addresses and
//! labels are the same for all endpoints, except that the host IPv6 addresses
//! for `host_node_exporter` are inferred from the the one used for `replica`
//! according to a fixed address schema. The ports are set as follows:
//!
//! * `/host_node_exporter` -> 9100
//! * `/node_exporter`      -> 9100
//! * `/orchestrator`       -> 9091
//! * `/replica`            -> 9090

use anyhow::Result;
use hyper::server::conn::AddrStream;
use hyper::service::Service;
use hyper::{Body, Request, Response};
use serde::{Deserialize, Serialize};
use slog::{info, warn};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::future::Ready;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::task::Poll;

use crate::titanium::ic_discovery::{
    IcServiceDiscovery, IcServiceDiscoveryError, PrometheusTargetGroup,
};

pub async fn start_http_server(
    log: slog::Logger,
    scraper: Arc<dyn IcServiceDiscovery>,
    socket_addr: SocketAddr,
) -> Result<()> {
    hyper::Server::bind(&socket_addr)
        .serve(RestApiFactory { log, scraper })
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
        target_groups: Result<Vec<PrometheusTargetGroup>, IcServiceDiscoveryError>,
    ) -> Result<Response<Body>, hyper::http::Error> {
        let groups = target_groups.map(|l| {
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
        let res = match req.uri().path() {
            "/host_node_exporter" => {
                let map_socket_addr =
                    |sockaddr: SocketAddr| guest_to_host_address((set_port(9100))(sockaddr));
                let target_hosts = self
                    .scraper
                    .get_prometheus_target_groups()
                    .map(map_target_addresses(map_socket_addr));
                self.target_groups_to_response(target_hosts)
            }
            "/node_exporter" => {
                let target_hosts = self
                    .scraper
                    .get_prometheus_target_groups()
                    .map(map_target_addresses(set_port(9100)));
                self.target_groups_to_response(target_hosts)
            }
            "/orchestrator" => {
                let target_hosts = self
                    .scraper
                    .get_prometheus_target_groups()
                    .map(map_target_addresses(set_port(9091)));
                self.target_groups_to_response(target_hosts)
            }
            "/replica" => {
                let target_hosts = self
                    .scraper
                    .get_prometheus_target_groups()
                    .map(map_target_addresses(set_port(9090)));
                self.target_groups_to_response(target_hosts)
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

fn map_target_addresses<F>(
    f: F,
) -> impl Fn(Vec<PrometheusTargetGroup>) -> Vec<PrometheusTargetGroup>
where
    F: Fn(SocketAddr) -> SocketAddr + Copy,
{
    move |groups| {
        groups
            .into_iter()
            .map(move |target_group| {
                let targets: Vec<_> = target_group.targets.into_iter().map(f).collect();
                PrometheusTargetGroup {
                    targets,
                    ..target_group
                }
            })
            .collect::<Vec<_>>()
    }
}

fn set_port(port: u16) -> impl Fn(SocketAddr) -> SocketAddr + Copy {
    move |mut sockaddr: SocketAddr| {
        sockaddr.set_port(port);
        sockaddr
    }
}

/// By convention, the first two bytes of the host-part of the replica's IP
/// address are 0x6801. The corresponding segment for the host is 0x6800.
///
/// (The MAC starts with 0x6a00. The 7'th bit of the first byte is flipped. See
/// https://en.wikipedia.org/wiki/MAC_address)
fn guest_to_host_address(sockaddr: SocketAddr) -> SocketAddr {
    let ip = match sockaddr.ip() {
        IpAddr::V6(a) if a.segments()[4] == 0x6801 => {
            let s = a.segments();
            let new_addr = Ipv6Addr::new(s[0], s[1], s[2], s[3], 0x6800, s[5], s[6], s[7]);
            IpAddr::V6(new_addr)
        }
        ip => ip,
    };
    SocketAddr::new(ip, sockaddr.port())
}

/// Record of the shape as described in
/// https://prometheus.io/docs/prometheus/latest/http_sd/
#[derive(Serialize, Deserialize, Debug, Default)]
struct ServiceDiscoveryRecord {
    targets: Vec<String>,             // targets: ["ip:port"]
    labels: BTreeMap<String, String>, // labels: { k: v, k : v}
}

impl From<PrometheusTargetGroup> for ServiceDiscoveryRecord {
    fn from(group: PrometheusTargetGroup) -> Self {
        let targets: Vec<_> = group.targets.into_iter().map(|x| x.to_string()).collect();
        let mut labels = BTreeMap::new();

        labels.insert(IC_NAME.into(), group.ic_name);
        labels.insert(IC_NODE.into(), group.node_id.to_string());
        if let Some(subnet_id) = group.subnet_id {
            labels.insert(IC_SUBNET.into(), subnet_id.to_string());
        }
        Self { targets, labels }
    }
}

// Default labels
const IC_NAME: &str = "ic";
const IC_NODE: &str = "ic_node";
const IC_SUBNET: &str = "ic_subnet";
