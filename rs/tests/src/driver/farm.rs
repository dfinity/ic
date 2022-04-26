use std::{
    collections::HashMap,
    net::Ipv6Addr,
    path::Path,
    time::{Duration, Instant},
};

use crate::driver::ic::{AmountOfMemoryKiB, NrOfVCPUs, VmAllocationStrategy};
use anyhow::Result;
use reqwest::blocking::{multipart, Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use slog::{error, info, warn, Logger};
use std::io::Write;
use thiserror::Error;
use url::Url;

pub type FarmResult<T> = Result<T, FarmError>;

const DEFAULT_REQ_TIMEOUT: Duration = Duration::from_secs(300);
const LINEAR_BACKOFF_RETRY_DELAY: Duration = Duration::from_millis(1500);
const MAX_NUMBER_OF_RETRIES: usize = 3;

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
            .timeout(DEFAULT_REQ_TIMEOUT)
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
        let resp = self.retry_until_success(rb)?;
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

    fn retry_until_success(&self, rb: RequestBuilder) -> FarmResult<reqwest::blocking::Response> {
        let started_at = Instant::now();
        for _ in 0..MAX_NUMBER_OF_RETRIES {
            let mut req = rb.try_clone().expect("could not clone a request builder");
            if let Some(t) = DEFAULT_REQ_TIMEOUT.checked_sub(started_at.elapsed()) {
                req = req.timeout(t);
            } else {
                break;
            }
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
            std::thread::sleep(LINEAR_BACKOFF_RETRY_DELAY);
        }
        Err(FarmError::TooManyRetries {
            message: String::from(
                "sending a request to Farm retried too many times without success",
            ),
        })
    }
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
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct CreateVmRequest {
    #[serde(skip)]
    name: String,
    #[serde(rename = "type")]
    pub _type: String,
    #[serde(rename = "vCPUs")]
    pub vcpus: NrOfVCPUs,
    #[serde(rename = "memoryKiB")]
    pub memory_kibibytes: AmountOfMemoryKiB,
    #[serde(rename = "primaryImage")]
    pub primary_image: ImageLocation,
    #[serde(rename = "hasIPv4")]
    pub has_ipv4: bool,
}

impl CreateVmRequest {
    pub fn new(
        name: String,
        vcpus: NrOfVCPUs,
        memory_kibibytes: AmountOfMemoryKiB,
        primary_image: ImageLocation,
        has_ipv4: bool,
    ) -> Self {
        Self {
            name,
            vcpus,
            memory_kibibytes,
            primary_image,
            has_ipv4,
            _type: "production".to_string(),
        }
    }
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
