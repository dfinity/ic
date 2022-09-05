use std::{
    collections::HashMap,
    net::Ipv6Addr,
    path::Path,
    time::{Duration, Instant},
};

use crate::driver::ic::{AmountOfMemoryKiB, NrOfVCPUs, VmAllocationStrategy};
use anyhow::Result;
use reqwest::blocking::{multipart, Client, RequestBuilder};
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use slog::{error, info, warn, Logger};
use std::io::Write;
use thiserror::Error;
use url::Url;

use super::ic::ImageSizeGiB;

pub type FarmResult<T> = Result<T, FarmError>;

/// Some requests like createVm might take a long time to complete.
const TIMEOUT_SETTINGS_LONG: TimeoutSettings = TimeoutSettings {
    retry_timeout: Duration::from_secs(500),
    min_http_timeout: Duration::from_secs(20),
    max_http_timeout: Duration::from_secs(400),
    linear_backoff: Duration::from_secs(10),
};

const TIMEOUT_SETTINGS: TimeoutSettings = TimeoutSettings {
    retry_timeout: Duration::from_secs(120),
    min_http_timeout: Duration::from_secs(5),
    max_http_timeout: Duration::from_secs(60),
    linear_backoff: Duration::from_secs(5),
};

/// Farm managed resources that make up the Internet Computer under test. The
/// `Farm`-structure translates abstract requests (for resources) to concrete
/// http-requests.
#[derive(Clone, Debug)]
pub struct Farm {
    pub base_url: Url,
    pub logger: Logger,
    client: Client,
}

impl Farm {
    pub fn new(base_url: Url, logger: Logger) -> Self {
        let client = reqwest::blocking::ClientBuilder::new()
            .timeout(TIMEOUT_SETTINGS.max_http_timeout)
            .build()
            .expect("This should not fail.");
        Farm {
            base_url,
            client,
            logger,
        }
    }

    pub fn create_group(&self, group_name: &str, ttl: Duration, spec: GroupSpec) -> FarmResult<()> {
        let path = format!("group/{}", group_name);
        let ttl = ttl.as_secs() as u32;
        let body = CreateGroupRequest { ttl, spec };
        let rb = Self::json(self.post(&path), &body);
        let _resp = self.retry_until_success(rb)?;
        Ok(())
    }

    /// creates a vm under the group `group_name` and returns the associated
    /// IpAddr
    pub fn create_vm(&self, group_name: &str, vm: CreateVmRequest) -> FarmResult<VMCreateResponse> {
        let path = format!("group/{}/vm/{}", group_name, &vm.name);
        let rb = Self::json(self.post(&path), &vm);
        let resp = self.retry_until_success_long(rb)?;
        let created_vm = resp.json::<VMCreateResponse>()?;
        let ipv6 = created_vm.ipv6;
        info!(
            self.logger,
            "VM({}) Host: {} IPv6: {}", &vm.name, created_vm.hostname, &ipv6,
        );
        Ok(created_vm)
    }

    /// uploads an image an returns the image id
    pub fn upload_file<P: AsRef<Path>>(&self, path: P, filename: &str) -> FarmResult<String> {
        let form = multipart::Form::new()
            .file(filename.to_string(), path)
            .expect("could not create multipart for image");
        let rb = self.post("file").multipart(form);
        let resp = rb.send()?;
        let mut file_ids = resp.json::<ImageUploadResponse>()?.image_ids;
        if file_ids.len() != 1 || !file_ids.contains_key(filename) {
            return Err(FarmError::InvalidResponse {
                message: format!(
                    "Response has invalid length or does not contain file id for '{}'",
                    filename
                ),
            });
        }
        Ok(file_ids.remove(filename).unwrap())
    }

    pub fn attach_disk_image(
        &self,
        group_name: &str,
        vm_name: &str,
        template_name: &str,
        image_id: String,
    ) -> FarmResult<()> {
        let path = format!(
            "group/{}/vm/{}/drive-templates/{}",
            group_name, vm_name, template_name
        );
        let req = self.put(&path);
        let image_spec = AttachImageSpec::new(image_id);
        let attach_drives_req = AttachDrivesRequest {
            drives: vec![image_spec],
        };
        let rb = Self::json(req, &attach_drives_req);
        let _resp = self.retry_until_success(rb)?;
        Ok(())
    }

    pub fn start_vm(&self, group_name: &str, vm_name: &str) -> FarmResult<()> {
        let path = format!("group/{}/vm/{}/start", group_name, vm_name);
        let rb = self.put(&path);
        let _resp = self.retry_until_success(rb)?;
        info!(
            self.logger,
            "Console: {}",
            self.url_from_path(&format!("group/{}/vm/{}/console/", group_name, vm_name)[..])
        );
        Ok(())
    }

    pub fn destroy_vm(&self, group_name: &str, vm_name: &str) -> FarmResult<()> {
        let path = format!("group/{}/vm/{}/destroy", group_name, vm_name);
        let rb = self.put(&path);
        let _resp = self.retry_until_success(rb)?;
        Ok(())
    }

    pub fn reboot_vm(&self, group_name: &str, vm_name: &str) -> FarmResult<()> {
        let path = format!("group/{}/vm/{}/reboot", group_name, vm_name);
        let rb = self.put(&path);
        let _resp = self.retry_until_success(rb)?;
        Ok(())
    }

    pub fn delete_group(&self, group_name: &str) -> FarmResult<()> {
        let path = format!("group/{}", group_name);
        let rb = self.delete(&path);
        let _resp = self.retry_until_success(rb)?;
        Ok(())
    }

    pub fn set_group_ttl(&self, group_name: &str, duration: Duration) -> FarmResult<()> {
        let path = format!("group/{}/ttl/{}", group_name, duration.as_secs());
        let rb = self.put(&path);
        let _resp = self.retry_until_success(rb)?;
        Ok(())
    }

    fn post(&self, path: &str) -> RequestBuilder {
        let url = self.url_from_path(path);
        self.client.post(url)
    }

    fn put(&self, path: &str) -> RequestBuilder {
        let url = self.url_from_path(path);
        self.client.put(url)
    }

    fn delete(&self, path: &str) -> RequestBuilder {
        let url = self.url_from_path(path);
        self.client.delete(url)
    }

    pub fn download_file(&self, url: Url, mut sink: Box<dyn std::io::Write>) -> FarmResult<()> {
        let resp = self.client.get(url).send()?;
        sink.write_all(resp.bytes().expect("failed to get bytes").as_ref())?;
        Ok(())
    }

    fn json<T: Serialize + ?Sized>(rb: RequestBuilder, json: &T) -> RequestBuilder {
        rb.header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(json)
    }

    fn url_from_path(&self, path: &str) -> Url {
        Url::parse(&format!("{}{}", self.base_url, path)).expect("should not fail!")
    }

    fn retry_until_success_long(
        &self,
        rb: RequestBuilder,
    ) -> FarmResult<reqwest::blocking::Response> {
        self.retry_until_success_(rb, TIMEOUT_SETTINGS_LONG)
    }

    fn retry_until_success(&self, rb: RequestBuilder) -> FarmResult<reqwest::blocking::Response> {
        self.retry_until_success_(rb, TIMEOUT_SETTINGS)
    }

    fn retry_until_success_(
        &self,
        rb: RequestBuilder,
        t_settings: TimeoutSettings,
    ) -> FarmResult<reqwest::blocking::Response> {
        let started_at = Instant::now();
        loop {
            let mut req = rb.try_clone().expect("could not clone a request builder");
            let http_timeout = match t_settings.retry_timeout.checked_sub(started_at.elapsed()) {
                Some(t) if t > t_settings.min_http_timeout => t.min(t_settings.max_http_timeout),
                _ => break,
            };
            // cond: MIN_HTTP_REQ_TIMEOUT < http_timeout <= MAX_HTTP_REQ_TIMEOUT
            req = req.timeout(http_timeout);
            match req.send() {
                Err(e) => {
                    error!(self.logger, "sending a request to Farm failed: {:?}", e);
                }
                Ok(r) => {
                    if r.status().is_success() {
                        return Ok(r);
                    };
                    if r.status().is_server_error() {
                        error!(self.logger, "unexpected response from Farm: {:?}", r.text());
                    } else {
                        warn!(self.logger, "unexpected response from Farm: {:?}", r.text());
                    }
                }
            }
            std::thread::sleep(t_settings.linear_backoff);
        }
        Err(FarmError::TooManyRetries {
            message: String::from(
                "sending a request to Farm retried too many times without success",
            ),
        })
    }
}

struct TimeoutSettings {
    /// The maximum duration for which a request is being retried.
    retry_timeout: Duration,
    /// The maximum http request timeout.
    min_http_timeout: Duration,
    /// The minimum http request timeout.
    max_http_timeout: Duration,
    linear_backoff: Duration,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct CreateGroupRequest {
    pub ttl: u32,
    pub spec: GroupSpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct GroupSpec {
    #[serde(rename = "vmAllocation")]
    pub vm_allocation: Option<VmAllocationStrategy>,
    #[serde(rename = "requiredHostFeatures")]
    pub required_host_features: Vec<HostFeature>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostFeature {
    DC(String),
    Host(String),
    AmdSevSnp,
}

impl Serialize for HostFeature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            HostFeature::DC(dc) => {
                let mut host_feature: String = "dc=".to_owned();
                host_feature.push_str(dc);
                serializer.serialize_str(&host_feature)
            }
            HostFeature::Host(host) => {
                let mut host_feature: String = "host=".to_owned();
                host_feature.push_str(host);
                serializer.serialize_str(&host_feature)
            }
            HostFeature::AmdSevSnp => serializer.serialize_str(AMD_SEV_SNP),
        }
    }
}

const AMD_SEV_SNP: &str = "AMD-SEV-SNP";

impl<'de> Deserialize<'de> for HostFeature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input: String = Deserialize::deserialize(deserializer)?;
        if let Some(("", dc)) = input.split_once("dc=") {
            Ok(HostFeature::DC(dc.to_owned()))
        } else if let Some(("", host)) = input.split_once("host=") {
            Ok(HostFeature::Host(host.to_owned()))
        } else if input == AMD_SEV_SNP {
            Ok(HostFeature::AmdSevSnp)
        } else {
            Err(Error::unknown_variant(
                &input,
                &["dc=<dc-name>", "host=<host-name>"],
            ))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct CreateVmRequest {
    #[serde(skip)]
    name: String,
    #[serde(rename = "type")]
    pub vm_type: VmType,
    #[serde(rename = "vCPUs")]
    pub vcpus: NrOfVCPUs,
    #[serde(rename = "memoryKiB")]
    pub memory_kibibytes: AmountOfMemoryKiB,
    #[serde(rename = "qemuCliArgs")]
    pub qemu_cli_args: Vec<String>,
    #[serde(rename = "primaryImage")]
    pub primary_image: ImageLocation,
    #[serde(rename = "primaryImageMinimalSizeGiB")]
    pub primary_image_minimal_size_gibibytes: Option<ImageSizeGiB>,
    #[serde(rename = "hasIPv4")]
    pub has_ipv4: bool,
    #[serde(rename = "vmAllocation")]
    pub vm_allocation: Option<VmAllocationStrategy>,
    #[serde(rename = "requiredHostFeatures")]
    pub required_host_features: Vec<HostFeature>,
}

impl CreateVmRequest {
    pub fn new(
        name: String,
        vm_type: VmType,
        vcpus: NrOfVCPUs,
        memory_kibibytes: AmountOfMemoryKiB,
        qemu_cli_args: Vec<String>,
        primary_image: ImageLocation,
        primary_image_minimal_size_gibibytes: Option<ImageSizeGiB>,
        has_ipv4: bool,
        vm_allocation: Option<VmAllocationStrategy>,
        required_host_features: Vec<HostFeature>,
    ) -> Self {
        Self {
            name,
            vm_type,
            vcpus,
            memory_kibibytes,
            qemu_cli_args,
            primary_image,
            primary_image_minimal_size_gibibytes,
            has_ipv4,
            vm_allocation,
            required_host_features,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum VmType {
    Production,
    Test,
    Sev,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "_tag")]
#[serde(rename_all = "camelCase")]
pub enum ImageLocation {
    ImageViaId { id: String },
    ImageViaUrl { url: Url, sha256: String },
    IcOsImageViaId { id: String },
    IcOsImageViaUrl { url: Url, sha256: String },
}

#[derive(Error, Debug)]
pub enum FarmError {
    #[error(transparent)]
    ApiError(#[from] reqwest::Error),

    #[error(transparent)]
    SerdeError(#[from] serde_json::error::Error),

    #[error(transparent)]
    AddrParseError(#[from] std::net::AddrParseError),

    #[error("Invalid response: {message}")]
    InvalidResponse { message: String },

    #[error("Retried too many times: {message}")]
    TooManyRetries { message: String },

    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VMCreateResponse {
    pub ipv6: Ipv6Addr,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImageUploadResponse {
    image_ids: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AttachDrivesRequest {
    pub drives: Vec<AttachImageSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AttachImageSpec {
    pub _tag: String,
    pub id: String,
}

impl AttachImageSpec {
    pub fn new(id: String) -> Self {
        Self {
            _tag: "imageViaId".to_string(),
            id,
        }
    }
}
