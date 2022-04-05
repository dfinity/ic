use ic_base_types::NodeId;
use nix::unistd::Pid;
use rand::Rng;
use url::{Host, Url};

use crate::iterator::{InfStreamOf, PermOf};
use crate::pot;
use anyhow::Result;
use ic_prep_lib::prep_state_directory::IcPrepStateDir;
use ic_registry_subnet_type::SubnetType;
use ic_types::messages::{HttpStatusResponse, ReplicaHealthStatus};
use ic_types::SubnetId;
use slog::info;
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};
use tokio::{net::TcpStream, time};

pub const READY_WAIT_TIMEOUT: Duration = Duration::from_secs(120);
pub const READY_RESPONSE_TIMEOUT: Duration = Duration::from_secs(6);

/// A handle used by tests to interact with the IC.
///
/// The provided information is kept as general and simple as possible.
/// Currently, the structure only exposes the list of URLs. It also exposes the
/// path to the working directory as prepared by `ic-prep`. This can be used,
/// e.g., to read the initial registry local store.
///
/// While the IcHandle will always present a list of Urls to the test author,
/// any additional fields might change and are implementation specific. This is
/// on purpose as we do not want to overspecify this interface, as the needs of
/// test authors is likely vary across both components/teams and time. Test
/// owners can build their own abstractions on top of this Handle and also
/// change `ic-prep` if necessary.
#[derive(Clone, Debug)]
pub struct IcHandle {
    /// The list of Public API endpoints of this IC.
    pub public_api_endpoints: Vec<IcEndpoint>,
    /// The list of Public API endpoints of malicious nodes of this IC.
    pub malicious_public_api_endpoints: Vec<IcEndpoint>,
    /// Path to the working dir as prepared by `ic-prep`.
    pub ic_prep_working_dir: Option<IcPrepStateDir>,
}

#[derive(Clone, Debug)]
pub enum RuntimeDescriptor {
    Process(Pid),
    Vm(FarmInfo),
    Unknown,
}

#[derive(Clone, Debug)]
pub struct FarmInfo {
    pub url: Url,
    pub vm_name: String,
    pub group_name: String,
}

#[derive(Clone, Debug)]
pub struct IcSubnet {
    pub id: SubnetId,
    pub type_of: SubnetType,
}

pub type PrivateKeyFileContent = Vec<u8>;
pub type PublicKeyFileContent = Vec<u8>;

#[derive(Clone, Debug)]
pub struct IcEndpoint {
    /// A descriptor of this endpoint. This is public to give us a simple
    /// way of restarting. See node_restart_test for an example.
    pub runtime_descriptor: RuntimeDescriptor,

    /// A URL pointing to an endpoint that implements the Public Spec.
    pub url: Url,
    /// A URL pointing to an endpoint hosting the metrics for the replica.
    pub metrics_url: Option<Url>,

    /// Set if `url` points to the public endpoint of the root subnet.
    ///
    /// # Note
    ///
    /// This coincides with the NNS subnet, if an NNS subnet is present. Note
    /// that the root subnet is a protocol level concept while the NNS is an
    /// application level concept.
    ///
    /// See also: https://docs.dfinity.systems/spec/public/#certification-delegation
    pub is_root_subnet: bool,

    /// The subnet that the node was initially assigned to. `None` if the
    /// respective node was unassigned when the IC was bootstrapped.
    pub subnet: Option<IcSubnet>,

    /// A timestamp when a node gets started.
    pub started_at: Instant,

    /// The node id
    pub node_id: NodeId,
}

impl<'a> IcHandle {
    /// Returns and transfer ownership of one [IcEndpoint], removing it
    /// from the handle. If no endpoints are available it returns [None].
    pub fn take_one<R: Rng>(&mut self, rng: &mut R) -> Option<IcEndpoint> {
        if !self.public_api_endpoints.is_empty() {
            // gen_range(low, high) generates a number n s.t. low <= n < high
            Some(
                self.public_api_endpoints
                    .remove(rng.gen_range(0..self.public_api_endpoints.len())),
            )
        } else {
            None
        }
    }

    /// Returns a permutation of the available [IcEndpoint]. The [PermOf] type
    /// implements [Iterator], and hence, can be used like any other iterator.
    ///
    /// No endpoints are returned that belong to nodes that were configured with
    /// malicious behaviour!
    pub fn as_permutation<R: Rng>(&'a self, rng: &mut R) -> PermOf<'a, IcEndpoint> {
        PermOf::new(&self.public_api_endpoints, rng)
    }

    /// Returns an infinite iterator over the available [IcEndpoint]. The
    /// [InfStreamOf] type implements [Iterator], and hence, can be used
    /// like any other iterator.
    ///
    /// No endpoints are returned that belong to nodes that were configured with
    /// malicious behaviour!
    ///
    /// CAUTION: [InfStreamOf::next] never returns [None], which means calling
    /// `collect` or doing a `for i in hd.into_random_iter(rng)` will loop.
    pub fn as_random_iter<R: Rng>(&'a self, rng: &mut R) -> InfStreamOf<'a, IcEndpoint> {
        InfStreamOf::new(&self.public_api_endpoints, rng)
    }

    /// Returns and transfer ownership of one [IcEndpoint], removing it
    /// from the handle. If no endpoints are available it returns [None].
    pub fn take_one_malicious<R: Rng>(&mut self, rng: &mut R) -> Option<IcEndpoint> {
        if !self.malicious_public_api_endpoints.is_empty() {
            // gen_range(low, high) generates a number n s.t. low <= n < high
            Some(
                self.malicious_public_api_endpoints
                    .remove(rng.gen_range(0..self.malicious_public_api_endpoints.len())),
            )
        } else {
            None
        }
    }

    /// Returns a permutation of the available malicious [IcEndpoint]. The
    /// [PermOf] type implements [Iterator], and hence, can be used like any
    /// other iterator.
    ///
    /// Only endpoints are returned that belong to nodes that were configured
    /// with malicious behaviour!
    pub fn as_permutation_malicious<R: Rng>(&'a self, rng: &mut R) -> PermOf<'a, IcEndpoint> {
        PermOf::new(&self.malicious_public_api_endpoints, rng)
    }

    /// Returns an infinite iterator over the available malicious [IcEndpoint].
    /// The [InfStreamOf] type implements [Iterator], and hence, can be used
    /// like any other iterator.
    ///
    /// Only endpoints are returned that belong to nodes that were configured
    /// with malicious behaviour!
    ///
    /// CAUTION: [InfStreamOf::next] never returns [None], which means calling
    /// `collect` or doing a `for i in hd.into_random_iter(rng)` will loop.
    pub fn as_random_iter_malicious<R: Rng>(&'a self, rng: &mut R) -> InfStreamOf<'a, IcEndpoint> {
        InfStreamOf::new(&self.malicious_public_api_endpoints, rng)
    }
}

impl<'a> IcEndpoint {
    /// Returns the status of a replica. It is requested from a public API.
    pub async fn status(&self) -> Result<HttpStatusResponse> {
        let response = reqwest::Client::builder()
            .timeout(READY_RESPONSE_TIMEOUT)
            .build()
            .expect("cannot build a reqwest client")
            .get(
                self.url
                    .clone()
                    .join("api/v2/status")
                    .expect("failed to join URLs"),
            )
            .send()
            .await?;

        let cbor_response = serde_cbor::from_slice(
            &response
                .bytes()
                .await
                .expect("failed to convert a response to bytes")
                .to_vec(),
        )
        .expect("response is not encoded as cbor");
        let status = serde_cbor::value::from_value::<HttpStatusResponse>(cbor_response)
            .expect("failed to deserialize a response to HttpStatusResponse");

        Ok(status)
    }

    /// Returns true if [IcEndpoint] is healthy, i.e. up and running and ready
    /// for interaction. A status of the endpoint is requested from the
    /// public API.
    pub async fn healthy(&self) -> Result<(bool, Option<Vec<u8>>)> {
        //        pub async fn healthy(&self) -> Result<bool> {
        let status = self.status().await?;
        //Ok(Some(ReplicaHealthStatus::Healthy) == status.replica_health_status)
        let root_key = status.root_key.map(|x| x.0);
        let is_healthy = Some(ReplicaHealthStatus::Healthy) == status.replica_health_status;
        Ok((is_healthy, root_key))
    }

    /// Returns `Ok(true)` if a TCP-connection to port 22 can be established.
    pub async fn ssh_open(&self) -> Result<(bool, Option<Vec<u8>>)> {
        let ip_str = format!("[{}]:22", self.ip_address().unwrap());
        TcpStream::connect(ip_str)
            .await
            .map_err(anyhow::Error::new)?;
        Ok((true, None))
    }

    /// Returns as soon as [IcEndpoint] is ready, panics if it didn't come up
    /// before a given deadline. Readiness of assigned nodes is checked through
    /// either active polling of the public API or--in the case of unassiged
    /// nodes--via establishing a connection to port 22.
    pub async fn assert_ready(&self, ctx: &pot::Context) {
        self.assert_ready_with_start(self.started_at, ctx).await;
    }

    /// Same as `assert_ready`, except that the time offset from which the
    /// timeout is measured is defined by `start` and not the IcEndpoint's
    /// `started_at`.
    pub async fn assert_ready_with_start(&self, start: Instant, ctx: &pot::Context) {
        let mut interval = time::interval(Duration::from_secs(1));
        loop {
            info!(
                ctx.logger,
                "Checking readiness of [{:?}]...",
                self.url.as_str()
            );

            // If the node is a member of the subnet, check if it is healthy. Otherwise,
            // check if it is reachable on port 22.
            let ready = match &self.subnet {
                Some(_) => self.healthy().await,
                None => self.ssh_open().await,
            };

            match ready {
                Ok((true, root_key)) => {
                    info!(
                        ctx.logger,
                        "Node [{:?}] is ready! root_key: {:?}",
                        self.url.as_str(),
                        root_key
                    );
                    return;
                }
                Ok((false, _)) => {
                    info!(
                        ctx.logger,
                        "Node [{:?}] is responsive but reports 'unhealthy'.",
                        self.url.as_str()
                    );
                }
                Err(e) => {
                    info!(
                        ctx.logger,
                        "Node [{:?}] is not yet ready and/or unreachable: {:?}",
                        self.url.as_str(),
                        e
                    );
                }
            }
            if Instant::now().duration_since(start) > READY_WAIT_TIMEOUT {
                panic!("the IcEndpoint didn't come up within a time limit");
            }
            interval.tick().await;
        }
    }

    /// An IpAddress assigned to the Virtual Machine of the corresponding node,
    /// if available.
    pub fn ip_address(&self) -> Option<IpAddr> {
        self.url.host().and_then(|h| match h {
            Host::Domain(_) => None,
            Host::Ipv4(ip_addr) => Some(IpAddr::V4(ip_addr)),
            Host::Ipv6(ip_addr) => Some(IpAddr::V6(ip_addr)),
        })
    }

    /// Returns the hostname assigned to the Virtual Machine of the
    /// corresponding node, if available.
    fn hostname(&self) -> Option<String> {
        self.url.host().and_then(|h| match h {
            Host::Domain(s) => Some(s.to_string()),
            Host::Ipv4(_) => None,
            Host::Ipv6(_) => None,
        })
    }

    /// Returns the `SubnetId` of this [IcEndpoint] if it exists.
    pub fn subnet_id(&self) -> Option<SubnetId> {
        self.subnet.as_ref().map(|s| s.id)
    }

    /// Creates a new instance of this IcEndpoint structure with the subnet
    /// `subnet` and the `started_at` instant set to `Instant::now()`.
    pub fn recreate_with_subnet(&self, subnet: IcSubnet) -> IcEndpoint {
        Self {
            subnet: Some(subnet),
            started_at: Instant::now(),
            ..self.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, time::Instant};

    use crate::ic_manager::{IcSubnet, RuntimeDescriptor};
    use ic_registry_subnet_type::SubnetType;
    use ic_test_utilities::types::ids::{node_test_id, subnet_test_id};
    use url::Url;

    use super::IcEndpoint;
    #[test]
    fn returns_ipv4_and_ipv6_address() {
        let hostname = "some_host.com".to_string();
        let ipv6_addr: IpAddr = "2607:fb58:9005:42:5000:93ff:fe0b:5527".parse().unwrap();
        let ipv4_addr: IpAddr = "192.168.0.1".parse().unwrap();

        let handle = IcEndpoint {
            runtime_descriptor: RuntimeDescriptor::Unknown,
            url: Url::parse(&format!("http://{}:8080/", hostname)).unwrap(),
            metrics_url: None,
            is_root_subnet: false,
            subnet: Some(IcSubnet {
                id: subnet_test_id(1),
                type_of: SubnetType::Application,
            }),
            started_at: Instant::now(),
            node_id: node_test_id(1),
        };

        assert_eq!(handle.hostname().unwrap(), hostname);
        let handle = IcEndpoint {
            url: Url::parse(&format!("http://{}:8080/", ipv4_addr)).unwrap(),
            ..handle
        };
        assert_eq!(handle.ip_address().unwrap(), ipv4_addr);
        let handle = IcEndpoint {
            url: Url::parse(&format!("http://[{}]:8080/", ipv6_addr)).unwrap(),
            ..handle
        };
        assert_eq!(handle.ip_address().unwrap(), ipv6_addr);
    }
}
