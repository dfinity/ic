use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::driver::ic::{AmountOfMemoryKiB, NrOfVCPUs, VmAllocationStrategy};
use crate::driver::log_events;
use crate::driver::test_env::{RequiredHostFeaturesFromCmdLine, TestEnvAttribute};
use crate::driver::test_env_api::{HasFarmUrl, read_dependency_to_string};
use anyhow::Result;
use chrono::{DateTime, Utc};
use ic_crypto_sha2::Sha256;
use reqwest::blocking::{Client, RequestBuilder, multipart};
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use slog::info;
use slog::{Logger, error, warn};
use std::fmt;
use std::io::Write;
use thiserror::Error;
use url::Url;

use crate::driver::{ic::ImageSizeGiB, test_env::TestEnv};

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
// Be mindful when modifying these constants, as the events can be consumed by other parties.
const FARM_VM_CREATED_EVENT_NAME: &str = "farm_vm_created_event";
const VM_CONSOLE_LINK_CREATED_EVENT_NAME: &str = "vm_console_link_created_event";

/// Farm managed resources that make up the Internet Computer under test. The
/// `Farm`-structure translates abstract requests (for resources) to concrete
/// http-requests.
#[derive(Clone, Debug)]
pub struct Farm {
    pub base_url: Url,
    pub logger: Logger,
    client: Client,
    pub override_host_features: Option<Vec<HostFeature>>,
}

impl Farm {
    pub fn new(base_url: Url, logger: Logger) -> Self {
        let client = reqwest::blocking::ClientBuilder::new()
            .timeout(TIMEOUT_SETTINGS.max_http_timeout)
            .build()
            .expect("This should not fail.");
        Farm {
            base_url,
            logger,
            client,
            override_host_features: None,
        }
    }

    pub fn from_test_env(env: &TestEnv, context: &str) -> Self {
        let client = reqwest::blocking::ClientBuilder::new()
            .timeout(TIMEOUT_SETTINGS.max_http_timeout)
            .build()
            .expect("This should not fail.");
        Farm {
            base_url: env.get_farm_url().unwrap(),
            logger: env.logger(),
            client,
            override_host_features: env.read_host_features(context),
        }
    }

    pub fn acquire_playnet_certificate(&self, group_name: &str) -> FarmResult<PlaynetCertificate> {
        let path = format!("group/{group_name}/playnet/certificate");
        let rb = self.post(&path);
        let rbb = || rb.try_clone().expect("could not clone a request builder");
        let resp = self.retry_until_success_long(rbb)?;
        let playnet_cert = resp.json::<PlaynetCertificate>()?;
        Ok(playnet_cert)
    }

    pub fn create_group(
        &self,
        group_base_name: &str,
        group_name: &str,
        ttl: Option<Duration>,
        mut spec: GroupSpec,
    ) -> FarmResult<()> {
        spec.required_host_features = self
            .override_host_features
            .clone()
            .unwrap_or_else(|| spec.required_host_features.clone());
        let path = format!("group/{group_name}");
        let ttl = ttl.map(|ttl| ttl.as_secs() as u32);
        let spec = spec.add_meta(group_base_name);
        let body = CreateGroupRequest { ttl, spec };
        let rb = Self::json(self.post(&path), &body);
        let rbb = || rb.try_clone().expect("could not clone a request builder");
        let _resp = self.retry_until_success(rbb)?;
        Ok(())
    }

    /// creates a vm under the group `group_name` and returns the associated
    /// IpAddr
    pub fn create_vm(
        &self,
        group_name: &str,
        mut vm: CreateVmRequest,
    ) -> FarmResult<VMCreateResponse> {
        vm.required_host_features = self
            .override_host_features
            .clone()
            .unwrap_or_else(|| vm.required_host_features.clone());
        let path = format!("group/{}/vm/{}", group_name, &vm.name);
        let rb = Self::json(self.post(&path), &vm);
        let rbb = || rb.try_clone().expect("could not clone a request builder");
        let resp = self.retry_until_success_long(rbb)?;
        let created_vm = resp.json::<VMCreateResponse>()?;
        // Emit a json log event, to be consumed by log post-processing tools.
        let ipv6 = created_vm.ipv6;
        emit_vm_created_event(
            &self.logger,
            &vm.name,
            &created_vm.hostname,
            ipv6,
            created_vm.spec.v_cpus,
            created_vm.spec.memory_ki_b,
        );
        Ok(created_vm)
    }

    pub fn claim_file(&self, group_name: &str, file_id: &FileId) -> FarmResult<ClaimResult> {
        let path = format!("group/{group_name}/file/{file_id}");
        let rb = self.put(&path);
        let rbb = || rb.try_clone().expect("could not clone a request builder");
        match self.retry_until_success(rbb) {
            Ok(resp) => {
                let expiration = resp.json::<FileExpiration>()?;
                Ok(ClaimResult::FileClaimed(expiration))
            }
            Err(FarmError::NotFound { message: _ }) => Ok(ClaimResult::FileNotFound),
            Err(e) => Err(e),
        }
    }

    /// uploads an image an returns the image id
    pub fn upload_file<P: AsRef<Path>>(
        &self,
        group_name: &str,
        path: P,
        filename: &str,
    ) -> FarmResult<FileId> {
        let size = std::fs::metadata(&path).map_err(FarmError::IoError)?.len();
        info!(
            self.logger,
            "Uploading file: {} of size {} bytes ...", filename, size
        );
        let rb = self
            .post(&format!("group/{group_name}/file"))
            .timeout(TIMEOUT_SETTINGS_LONG.max_http_timeout);
        let path = (&path).to_owned();
        let rbb = || {
            let form = multipart::Form::new()
                .file(filename.to_string(), path)
                .expect("could not create multipart for image");
            rb.try_clone()
                .expect("could not clone a request builder")
                .multipart(form)
        };
        let resp = self.retry_until_success_long(rbb)?;
        let mut file_ids = resp.json::<ImageUploadResponse>()?.image_ids;
        if file_ids.len() != 1 || !file_ids.contains_key(filename) {
            return Err(FarmError::InvalidResponse {
                message: format!(
                    "Response has invalid length or does not contain file id for '{filename}'"
                ),
            });
        }
        Ok(FileId(file_ids.remove(filename).unwrap()))
    }

    pub fn attach_disk_images(
        &self,
        group_name: &str,
        vm_name: &str,
        template_name: &str,
        image_specs: Vec<AttachImageSpec>,
    ) -> FarmResult<()> {
        let path = format!("group/{group_name}/vm/{vm_name}/drive-templates/{template_name}");
        let req = self.put(&path);
        let attach_drives_req = AttachDrivesRequest {
            drives: image_specs,
        };
        let rb = Self::json(req, &attach_drives_req);
        let rbb = || rb.try_clone().expect("could not clone a request builder");
        let _resp = self.retry_until_success_long(rbb)?;
        Ok(())
    }

    pub fn start_vm(&self, group_name: &str, vm_name: &str) -> FarmResult<()> {
        let path = format!("group/{group_name}/vm/{vm_name}/start");
        let rb = self.put(&path);
        let rbb = || rb.try_clone().expect("could not clone a request builder");
        let _resp = self.retry_until_success(rbb)?;
        let url = self.url_from_path(&format!("group/{group_name}/vm/{vm_name}/console/")[..]);
        emit_vm_console_link_event(&self.logger, url, vm_name);
        Ok(())
    }

    pub fn destroy_vm(&self, group_name: &str, vm_name: &str) -> FarmResult<()> {
        let path = format!("group/{group_name}/vm/{vm_name}/destroy");
        let rb = self.put(&path);
        let rbb = || rb.try_clone().expect("could not clone a request builder");
        let _resp = self.retry_until_success(rbb)?;
        Ok(())
    }

    pub fn reboot_vm(&self, group_name: &str, vm_name: &str) -> FarmResult<()> {
        let path = format!("group/{group_name}/vm/{vm_name}/reboot");
        let rb = self.put(&path);
        let rbb = || rb.try_clone().expect("could not clone a request builder");
        let _resp = self.retry_until_success(rbb)?;
        Ok(())
    }

    // delete with large timeout but only one attempt, because it takes a long time and farm's
    // garbage collector would interfere with retries.
    pub fn delete_group(&self, group_name: &str) {
        // bump TTL, so that farm garbage collector does not remove while we remove
        if self
            .set_group_ttl(group_name, Duration::from_secs(120))
            .is_err()
        {
            warn!(self.logger, "Failed to bump TTL before deleting group.");
        }
        let path = format!("group/{group_name}");
        let mut req = self.delete(&path);
        req = req.timeout(Duration::from_secs(130)); // longer than VM soft shutdown timeout (120s)
        match req.send() {
            Err(e) => error!(self.logger, "Sending a request to Farm failed: {:?}", e),
            Ok(r) if !r.status().is_success() => warn!(
                self.logger,
                "unexpected response from Farm: {:?}",
                r.text().unwrap()
            ),
            _ => {}
        };
    }

    /// Creates DNS records under the suffix: `.<group-name>.farm.dfinity.systems`.
    /// The records will be garbage collected some time after the group has expired.
    /// The suffix will be returned from this function such that the FQDNs can be constructed.
    pub fn create_dns_records(
        &self,
        group_name: &str,
        dns_records: Vec<DnsRecord>,
    ) -> FarmResult<String> {
        let path = format!("group/{group_name}/dns");
        let rb = Self::json(self.post(&path), &dns_records);
        let rbb = || rb.try_clone().expect("could not clone a request builder");
        let resp = self.retry_until_success_long(rbb)?;
        let create_dns_records_result = resp.json::<CreateDnsRecordsResult>()?;
        Ok(create_dns_records_result.suffix)
    }

    /// Creates DNS records under the suffix: `ic{ix}.farm.dfinity.systems`
    /// where ix is the index of the acquired playnet of the given group.
    /// The records will be garbage collected some time after the group has expired.
    /// The suffix will be returned from this function such that the FQDNs can be constructed.
    pub fn create_playnet_dns_records(
        &self,
        group_name: &str,
        dns_records: Vec<DnsRecord>,
    ) -> FarmResult<String> {
        let path = format!("group/{group_name}/playnet/dns");
        let rb = Self::json(self.post(&path), &dns_records);
        let rbb = || rb.try_clone().expect("could not clone a request builder");
        let resp = self.retry_until_success_long(rbb)?;
        let create_dns_records_result = resp.json::<CreateDnsRecordsResult>()?;
        Ok(create_dns_records_result.suffix)
    }

    pub fn set_group_ttl(&self, group_name: &str, duration: Duration) -> FarmResult<()> {
        let path = format!("group/{}/ttl/{}", group_name, duration.as_secs());
        let rb = self.put(&path);
        let rbb = || rb.try_clone().expect("could not clone a request builder");
        let _resp = self.retry_until_success(rbb)?;
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

    fn retry_until_success_long<F: Fn() -> RequestBuilder>(
        &self,
        rbb: F,
    ) -> FarmResult<reqwest::blocking::Response> {
        self.retry_until_success_(rbb, TIMEOUT_SETTINGS_LONG)
    }

    fn retry_until_success<F: Fn() -> RequestBuilder>(
        &self,
        rbb: F,
    ) -> FarmResult<reqwest::blocking::Response> {
        self.retry_until_success_(rbb, TIMEOUT_SETTINGS)
    }

    fn retry_until_success_<F: Fn() -> RequestBuilder>(
        &self,
        rbb: F,
        t_settings: TimeoutSettings,
    ) -> FarmResult<reqwest::blocking::Response> {
        let started_at = Instant::now();
        let mut req_sent_successfully = false;
        loop {
            let mut req = rbb();
            let http_timeout = match t_settings.retry_timeout.checked_sub(started_at.elapsed()) {
                Some(t) if t > t_settings.min_http_timeout => t.min(t_settings.max_http_timeout),
                _ => break,
            };
            // cond: MIN_HTTP_REQ_TIMEOUT < http_timeout <= MAX_HTTP_REQ_TIMEOUT
            req = req.timeout(http_timeout);
            match req.send() {
                Err(e) => {
                    req_sent_successfully = false;
                    error!(self.logger, "sending a request to Farm failed: {:?}", e);
                }
                Ok(r) => {
                    req_sent_successfully = true;
                    if r.status().is_success() {
                        return Ok(r);
                    };
                    if r.status().as_u16() == 404 {
                        let body = r.text().unwrap_or_default();
                        return Err(FarmError::NotFound { message: body });
                    }
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
            message: String::from(if req_sent_successfully {
                "processing a request on Farm"
            } else {
                "sending a request to Farm"
            }),
        })
    }
}

pub enum ClaimResult {
    FileNotFound,
    FileClaimed(FileExpiration),
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub struct FileExpiration {
    pub expiration: Option<DateTime<Utc>>,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub struct FileId(String);

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub fn id_of_file(file: PathBuf) -> Result<FileId> {
    let mut reader = std::fs::File::open(file)?;
    let mut sha256_hasher = Sha256::new();
    std::io::copy(&mut reader, &mut sha256_hasher).unwrap();
    let digest = sha256_hasher.finish();
    Ok(FileId(hex::encode(digest)))
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

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
struct CreateGroupRequest {
    pub ttl: Option<u32>,
    pub spec: GroupSpec,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub struct GroupSpec {
    #[serde(rename = "vmAllocation")]
    pub vm_allocation: Option<VmAllocationStrategy>,
    #[serde(rename = "requiredHostFeatures")]
    pub required_host_features: Vec<HostFeature>,
    #[serde(rename = "preferredNetwork")]
    pub preferred_network: Option<String>,
    #[serde(rename = "metadata")]
    pub metadata: Option<GroupMetadata>,
}

impl GroupSpec {
    pub fn add_meta(mut self, group_base_name: &str) -> Self {
        // Acquire bazel's stable status containing key value pairs like user and job name:
        let farm_metadata_path = std::env::var("FARM_METADATA_PATH")
            .expect("Expected the environment variable FARM_METADATA_PATH to be defined!");
        let farm_metadata = read_dependency_to_string(&farm_metadata_path)
            .unwrap_or_else(|e| {
                panic!("Couldn't read content of the status file {farm_metadata_path}: {e:?}")
            })
            .trim_end()
            .to_string();
        let runtime_args_map = parse_farm_metadata_file(farm_metadata);

        // Read values from the runtime args and use sensible defaults if unset
        let user = runtime_args_map
            .get("STABLE_FARM_USER") // Always set by bazel
            .cloned()
            .unwrap_or("CI".to_string());
        let job_schedule = runtime_args_map
            .get("STABLE_FARM_JOB_NAME") // Injected by workspace status
            .cloned()
            .unwrap_or("manual".to_string());
        let metadata = GroupMetadata {
            user,
            job_schedule,
            test_name: group_base_name.to_string(),
        };
        self.metadata = Some(metadata);
        self
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub struct GroupMetadata {
    #[serde(rename = "user")]
    pub user: String,
    #[serde(rename = "jobSchedule")]
    pub job_schedule: String,
    #[serde(rename = "testName")]
    pub test_name: String,
}

fn parse_farm_metadata_file(input: String) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let lines = input.split('\n');
    for line in lines {
        if let Some((key, value)) = line.split_once(' ') {
            map.insert(String::from(key), String::from(value));
        }
    }
    map
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub enum HostFeature {
    DC(String),
    Host(String),
    AmdSevSnp,
    Performance,
    IoPerformance,
    Dell,
    Supermicro,
    DMZ,
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
            HostFeature::Performance => serializer.serialize_str(PERFORMANCE),
            HostFeature::IoPerformance => serializer.serialize_str(IO_PERFORMANCE),
            HostFeature::Dell => serializer.serialize_str(DLL),
            HostFeature::Supermicro => serializer.serialize_str(SPM),
            HostFeature::DMZ => serializer.serialize_str(DMZ),
        }
    }
}

const AMD_SEV_SNP: &str = "AMD-SEV-SNP";
const PERFORMANCE: &str = "performance";
const IO_PERFORMANCE: &str = "io-performance";
const DLL: &str = "dll";
const SPM: &str = "spm";
const DMZ: &str = "dmz";

impl<'de> Deserialize<'de> for HostFeature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input: String = Deserialize::deserialize(deserializer)?;
        match input.split_once('=') {
            Some(("dc", dc)) => Ok(HostFeature::DC(dc.to_owned())),
            Some(("host", host)) => Ok(HostFeature::Host(host.to_owned())),
            _ => match input.as_str() {
                AMD_SEV_SNP => Ok(HostFeature::AmdSevSnp),
                PERFORMANCE => Ok(HostFeature::Performance),
                IO_PERFORMANCE => Ok(HostFeature::IoPerformance),
                DLL => Ok(HostFeature::Dell),
                SPM => Ok(HostFeature::Supermicro),
                DMZ => Ok(HostFeature::DMZ),
                _ => Err(Error::unknown_variant(
                    &input,
                    &[
                        "dc=<dc-name>",
                        "host=<host-name>",
                        AMD_SEV_SNP,
                        PERFORMANCE,
                        IO_PERFORMANCE,
                        DLL,
                        SPM,
                        DMZ,
                    ],
                )),
            },
        }
    }
}

impl TestEnvAttribute for Vec<HostFeature> {
    fn attribute_name() -> String {
        String::from("required_host_features")
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub struct CreateVmRequest {
    #[serde(skip)]
    pub name: String,
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

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VmType {
    Production,
    Test,
    Sev,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
#[serde(tag = "_tag")]
#[serde(rename_all = "camelCase")]
pub enum ImageLocation {
    ImageViaId { id: FileId },
    ImageViaUrl { url: Url, sha256: String },
    IcOsImageViaId { id: FileId },
    IcOsImageViaUrl { url: Url, sha256: String },
}

#[derive(Debug, Error)]
pub enum FarmError {
    #[error("Not found: {message}")]
    NotFound { message: String },

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

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct VMCreateResponse {
    pub ipv6: Ipv6Addr,
    #[serde(default)]
    pub ipv4: Option<Ipv4Addr>,
    pub mac6: String,
    pub hostname: String,
    pub spec: VmSpec,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct VmSpec {
    #[serde(rename = "vCPUs")]
    pub v_cpus: u64,
    #[serde(rename = "memoryKiB")]
    pub memory_ki_b: u64,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageUploadResponse {
    image_ids: HashMap<String, String>,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
struct AttachDrivesRequest {
    pub drives: Vec<AttachImageSpec>,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct AttachImageSpec {
    pub _tag: String,
    pub id: Option<FileId>,
    pub url: Option<Url>,
    pub sha256: Option<String>,
}

impl AttachImageSpec {
    pub fn new(id: FileId) -> Self {
        Self {
            _tag: "imageViaId".to_string(),
            id: Some(id),
            sha256: None,
            url: None,
        }
    }

    pub fn via_url(url: Url, sha256: String) -> Self {
        Self {
            _tag: "icOsImageViaUrl".to_string(),
            id: None,
            url: Some(url),
            sha256: Some(sha256),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct PlaynetCertificate {
    pub playnet: String,
    pub cert: Certificate,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct Certificate {
    #[serde(rename = "privKeyPem")]
    pub priv_key_pem: String,
    #[serde(rename = "certPem")]
    pub cert_pem: String,
    #[serde(rename = "chainPem")]
    pub chain_pem: String,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct DnsRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: DnsRecordType,
    pub records: Vec<String>,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub enum DnsRecordType {
    A,
    AAAA,
    CAA,
    CNAME,
    MX,
    NS,
    NAPTR,
    PTR,
    SOA,
    SPF,
    SRV,
    TXT,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
struct CreateDnsRecordsResult {
    suffix: String,
}

fn emit_vm_console_link_event(log: &Logger, url: Url, vm_name: &str) {
    #[derive(Deserialize, Serialize)]
    struct ConsoleLink {
        url: Url,
        vm_name: String,
    }
    let event = log_events::LogEvent::new(
        VM_CONSOLE_LINK_CREATED_EVENT_NAME.to_string(),
        ConsoleLink {
            url,
            vm_name: vm_name.to_string(),
        },
    );
    event.emit_log(log);
}

pub fn emit_vm_created_event(
    log: &Logger,
    vm_name: &str,
    hostname: &str,
    ipv6: Ipv6Addr,
    v_cpus: u64,
    memory_ki_b: u64,
) {
    #[derive(Deserialize, Serialize)]
    pub struct FarmVMCreated {
        vm_name: String,
        hostname: String,
        ipv6: Ipv6Addr,
        v_cpus: u64,
        memory_ki_b: u64,
    }
    let event = log_events::LogEvent::new(
        FARM_VM_CREATED_EVENT_NAME.to_string(),
        FarmVMCreated {
            vm_name: vm_name.to_string(),
            hostname: hostname.to_string(),
            v_cpus,
            memory_ki_b,
            ipv6,
        },
    );
    event.emit_log(log);
}
