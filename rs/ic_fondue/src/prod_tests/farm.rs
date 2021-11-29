use std::{
    collections::HashMap,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::internet_computer::{AmountOfMemoryKiB, NrOfVCPUs, VmAllocation};
use anyhow::Result;
use reqwest::blocking::{multipart, Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

pub type FarmResult<T> = Result<T, FarmError>;

const DEFAULT_REQ_TIMEOUT: Duration = Duration::from_secs(120);

/// Farm managed resources that make up the Internet Computer under test. The
/// `Farm`-structure translates abstract requests (for resources) to concrete
/// http-requests.
#[derive(Clone, Debug)]
pub struct Farm {
    pub base_url: Url,
    client: Client,
}

impl Farm {
    pub fn new(base_url: Url) -> Self {
        let client = reqwest::blocking::ClientBuilder::new()
            .timeout(DEFAULT_REQ_TIMEOUT)
            .build()
            .expect("This should not fail.");
        Farm { base_url, client }
    }

    pub fn create_group(&self, group_name: &str, ttl: Duration, spec: GroupSpec) -> FarmResult<()> {
        let path = format!("group/{}", group_name);
        let ttl = ttl.as_secs() as u32;
        let body = CreateGroupRequest { ttl, spec };
        let _req = Self::json(self.post(&path), &body).send()?;
        Ok(())
    }

    /// creates a vm under the group `group_name` and returns the associated
    /// IpAddr
    pub fn create_vm(&self, group_name: &str, vm: CreateVmRequest) -> FarmResult<IpAddr> {
        let path = format!("group/{}/vm/{}", group_name, vm.name);
        let resp = Self::json(self.post(&path), &vm).send()?;
        let created_vm = resp.json::<VMCreateResponse>()?;
        Ok(created_vm.ipv6.parse()?)
    }

    /// uploads an image an returns the image id
    pub fn upload_image<P: AsRef<Path>>(
        &self,
        group_name: &str,
        path: P,
        filename: String,
    ) -> FarmResult<String> {
        let url_path = format!("group/{}/image", group_name);
        let target_file = PathBuf::from(path.as_ref());
        let form = multipart::Form::new()
            .file(filename.clone(), target_file)
            .expect("could not create multipart for image");
        let resp = self.post(&url_path).multipart(form).send()?;
        let mut image_ids = resp.json::<ImageUploadResponse>()?.image_ids;
        if image_ids.len() != 1 || !image_ids.contains_key(&filename) {
            return Err(FarmError::InvalidResponse {
                message: format!(
                    "Response has invalid length or does not contain image id for '{}'",
                    filename
                ),
            });
        }
        Ok(image_ids.remove(&filename).unwrap())
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
        let _resp = Self::json(req, &attach_drives_req).send()?;

        Ok(())
    }

    pub fn start_vm(&self, group_name: &str, vm_name: &str) -> FarmResult<()> {
        let path = format!("group/{}/vm/{}/start", group_name, vm_name);

        let req = self.put(&path);
        let _resp = req.send()?;
        Ok(())
    }

    pub fn destroy_vm(&self, group_name: &str, vm_name: &str) -> FarmResult<()> {
        let path = format!("group/{}/vm/{}/destroy", group_name, vm_name);
        let req = self.put(&path);
        let _resp = req.send()?;
        Ok(())
    }

    pub fn reboot_vm(&self, group_name: &str, vm_name: &str) -> FarmResult<()> {
        let path = format!("group/{}/vm/{}/reboot", group_name, vm_name);
        let req = self.put(&path);
        let _resp = req.send()?;
        Ok(())
    }

    pub fn delete_group(&self, group_name: &str) -> FarmResult<()> {
        let path = format!("group/{}", group_name);
        let _resp = self.delete(&path).send()?;
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

    fn json<T: Serialize + ?Sized>(rb: RequestBuilder, json: &T) -> RequestBuilder {
        rb.header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(json)
    }

    fn url_from_path(&self, path: &str) -> Url {
        Url::parse(&format!("{}{}", self.base_url, path)).expect("should not fail!")
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
    pub vm_allocation: Option<VmAllocation>,
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
    pub primary_image: PrimaryImage,
}

impl CreateVmRequest {
    pub fn new(
        name: String,
        vcpus: NrOfVCPUs,
        memory_kibibytes: AmountOfMemoryKiB,
        primary_image: PrimaryImage,
    ) -> Self {
        Self {
            name,
            vcpus,
            memory_kibibytes,
            primary_image,
            _type: "production".to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrimaryImage {
    pub _tag: String,
    pub url: Url,
    pub sha256: String,
}

impl PrimaryImage {
    pub fn new(url: Url, sha256: String) -> Self {
        Self {
            _tag: "icOsImageViaUrl".to_string(),
            url,
            sha256,
        }
    }
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VMCreateResponse {
    ipv6: String,
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
