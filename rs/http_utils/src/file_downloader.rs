use flate2::read::GzDecoder;
use http::Method;
use ic_crypto_sha2::Sha256;
use ic_logger::{info, warn, ReplicaLogger};
use reqwest::{Client, Response};
use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tar::Archive;

/// Streams HTTP response bodies to files
pub struct FileDownloader {
    client: Client,
    logger: Option<ReplicaLogger>,
    /// This is a timeout that is applied to the downloading each chunk that is
    /// yielded, not to the entire downloading of the file.
    timeout: Duration,
    allow_redirects: bool,
}

impl FileDownloader {
    pub fn new(logger: Option<ReplicaLogger>) -> Self {
        Self::new_with_timeout(logger, Duration::from_secs(15), false)
    }

    pub fn new_with_timeout(
        logger: Option<ReplicaLogger>,
        timeout: Duration,
        allow_redirects: bool,
    ) -> Self {
        Self {
            client: Client::new(),
            logger,
            timeout,
            allow_redirects,
        }
    }

    pub fn follow_redirects(mut self) -> FileDownloader {
        self.allow_redirects = true;
        self
    }

    /// Download a .tar.gz file from `url`, verify its hash if given, and
    /// extract the file into `target_dir`
    pub async fn download_and_extract_tar_gz(
        &self,
        url: &str,
        target_dir: &Path,
        expected_sha256_hex: Option<String>,
    ) -> FileDownloadResult<()> {
        let tar_gz_path = target_dir.join("tmp.tar.gz");
        self.download_file(url, &tar_gz_path, expected_sha256_hex)
            .await?;
        extract_tar_gz_into_dir(&tar_gz_path, target_dir)?;
        fs::remove_file(&tar_gz_path)
            .map_err(|e| FileDownloadError::file_remove_error(&tar_gz_path, e))?;

        Ok(())
    }

    /// Make a GET HTTP request to `url`, stream the response body to
    /// `file_path` and verify that the resulting file has hash
    /// `expected_sha256_hex`.
    ///
    /// Returns immediately if the file already exists with the given hash.
    ///
    /// Deletes an existing file with an incorrect file hash or no
    /// hash is given to this function.
    ///
    /// Since existing files get deleted if they have an incorrect hash,
    /// this code will also work if a crash happens throughout execution
    /// leading to inconsistent data.
    pub async fn download_file(
        &self,
        url: &str,
        file_path: &Path,
        expected_sha256_hex: Option<String>,
    ) -> FileDownloadResult<()> {
        // In case the file already exists, check the file hash.
        if file_path.exists() {
            if let Some(expected_hash) = expected_sha256_hex.as_ref() {
                match check_file_hash(file_path, expected_hash) {
                    Ok(()) => {
                        if let Some(logger) = &self.logger {
                            info!(logger, "File already exists: {}", url);
                        }
                        return Ok(());
                    }
                    Err(e) => {
                        if let Some(logger) = &self.logger {
                            warn!(
                                logger,
                                "File already exists, but hash check failed: {:?} - deleting file",
                                e
                            );
                        }
                        fs::remove_file(file_path)
                            .map_err(|e| FileDownloadError::file_remove_error(file_path, e))?;
                    }
                }
            } else {
                fs::remove_file(file_path)
                    .map_err(|e| FileDownloadError::file_remove_error(file_path, e))?;
            }
        }

        if let Some(logger) = &self.logger {
            info!(logger, "Downloading file from: {}", url);
        }
        let response = self.http_get(url).await?;
        if let Some(logger) = &self.logger {
            info!(
                logger,
                "Download request initiated to {:?}, headers: {:?}",
                response.remote_addr(),
                response.headers()
            );
        }
        self.stream_response_body_to_file(response, file_path)
            .await?;
        if let Some(logger) = &self.logger {
            info!(logger, "Response read");
        }

        if let Some(expected_hash) = expected_sha256_hex.as_ref() {
            check_file_hash(file_path, expected_hash)
        } else {
            Ok(())
        }
    }

    /// Perform a HTTP GET against the given URL
    async fn http_get(&self, url: &str) -> FileDownloadResult<Response> {
        let response = self.client.get(url).timeout(self.timeout).send().await?;

        if response.status().is_success() {
            return Ok(response);
        }

        if response.status().is_redirection() && self.allow_redirects {
            match response.headers().get(http::header::LOCATION) {
                Some(url) => {
                    let url = url.to_str().unwrap();
                    let response = self.client.get(url).timeout(self.timeout).send().await?;
                    if response.status().is_success() {
                        return Ok(response);
                    }
                    return Err(FileDownloadError::HttpError(HttpError::NonSuccessResponse(
                        Method::GET,
                        response,
                    )));
                }
                None => {
                    return Err(FileDownloadError::HttpError(
                        HttpError::RedirectMissingHeader(
                            Method::GET,
                            http::header::LOCATION,
                            response.status(),
                        ),
                    ))
                }
            }
        }

        Err(FileDownloadError::HttpError(HttpError::NonSuccessResponse(
            Method::GET,
            response,
        )))
    }

    /// Stream the bytes of a given HTTP response body into the given file
    async fn stream_response_body_to_file(
        &self,
        mut response: Response,
        file_path: &Path,
    ) -> FileDownloadResult<()> {
        let mut output_file = File::create(file_path)
            .map_err(|e| FileDownloadError::file_create_error(file_path, e))?;

        while let Some(chunk) = tokio::time::timeout(self.timeout, response.chunk())
            .await
            .map_err(|_| FileDownloadError::TimeoutError)??
        {
            output_file
                .write_all(&chunk)
                .map_err(|e| FileDownloadError::file_write_error(file_path, e))?;
        }
        Ok(())
    }
}

/// Compute the SHA256 of a file and return a hex-encoded string of the hash
pub fn compute_sha256_hex(path: &Path) -> FileDownloadResult<String> {
    let mut binary_file =
        fs::File::open(path).map_err(|e| FileDownloadError::file_open_error(path, e))?;

    let mut hasher = Sha256::new();
    std::io::copy(&mut binary_file, &mut hasher)
        .map_err(|e| FileDownloadError::compute_hash_error(path, e))?;

    Ok(hex::encode(hasher.finish()))
}

/// Assert that the given file has the given hash
pub fn check_file_hash(path: &Path, expected_sha256_hex: &str) -> FileDownloadResult<()> {
    let computed_sha256_hex = compute_sha256_hex(path)?;

    if computed_sha256_hex != expected_sha256_hex {
        Err(FileDownloadError::file_hash_mismatch_error(
            computed_sha256_hex,
            expected_sha256_hex.into(),
            path.to_path_buf(),
        ))
    } else {
        Ok(())
    }
}

/// Extract the contents of a given .tar.gz file into `target_dir`
pub fn extract_tar_gz_into_dir(tar_gz_path: &Path, target_dir: &Path) -> FileDownloadResult<()> {
    let map_to_untar_error = |e| FileDownloadError::untar_error(tar_gz_path, e);

    let tar_gz_file =
        File::open(tar_gz_path).map_err(|e| FileDownloadError::file_open_error(tar_gz_path, e))?;

    let tar = GzDecoder::new(tar_gz_file);
    let mut archive = Archive::new(tar);
    archive.unpack(target_dir).map_err(map_to_untar_error)?;
    Ok(())
}

pub type FileDownloadResult<T> = Result<T, FileDownloadError>;

/// Enumerates the possible errors that Orchestrator may encounter
#[derive(Debug)]
pub enum FileDownloadError {
    /// An IO error occurred
    IoError(String, io::Error),

    /// An error occurred when making an HTTP request for a binary
    HttpError(HttpError),

    /// A file's computed hash did not match the expected hash
    FileHashMismatchError {
        computed_hash: String,
        expected_hash: String,
        file_path: PathBuf,
    },
    TimeoutError,
}

impl FileDownloadError {
    pub fn file_create_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to create file: {:?}", file_path), e)
    }

    pub fn file_write_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to write to file: {:?}", file_path), e)
    }

    pub fn file_open_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to open file: {:?}", file_path), e)
    }

    pub fn file_remove_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to remove file: {:?}", file_path), e)
    }

    pub fn file_copy_error(src: &Path, dest: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(
            format!("Failed to copy file from {:?} to {:?}", src, dest),
            e,
        )
    }

    pub fn file_set_permissions_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(
            format!("Failed to set permissions on file: {:?}", file_path),
            e,
        )
    }

    pub fn dir_create_error(dir: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to create dir: {:?}", dir), e)
    }

    pub fn untar_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to unpack tar file: {:?}", file_path), e)
    }

    pub fn tar_gz_temp_dir_error(e: io::Error) -> Self {
        FileDownloadError::IoError("Failed to create .tar.gz extraction tmpdir".into(), e)
    }

    pub fn bad_url(url: &str, e: http::uri::InvalidUri) -> Self {
        FileDownloadError::HttpError(HttpError::MalformedUrl(url.to_string(), e))
    }

    pub fn compute_hash_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to hash of: {:?}", file_path), e)
    }

    pub fn file_hash_mismatch_error(
        computed_hash: String,
        expected_hash: String,
        file_path: PathBuf,
    ) -> Self {
        FileDownloadError::FileHashMismatchError {
            computed_hash,
            expected_hash,
            file_path,
        }
    }
}

impl fmt::Display for FileDownloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileDownloadError::IoError(msg, e) => write!(
                f,
                "IO error, message: {}, error: {:?}",
                msg, e
            ),
            FileDownloadError::HttpError(HttpError::MalformedUrl(bad_url, e)) => write!(
                f,
                "Unable to parse URL: {}, error: {:?}",
                bad_url, e
            ),
            FileDownloadError::HttpError(HttpError::ReqwestError(e)) => write!(
                f,
                "Encountered error when making Reqwest request: {}",
                e
            ),
            FileDownloadError::HttpError(HttpError::NonSuccessResponse(method, response)) => write!(
                f,
                "Received non-success response from endpoint: method: {}, uri: {}, remote_addr: {:?}, status_code: {}, headers: {:?}",
                method.as_str(), response.url(), response.remote_addr(), response.status(), response.headers()
            ),
            FileDownloadError::HttpError(HttpError::RedirectMissingHeader(method, header, status_code)) => write!(
                f,
                "Received a redirect response from endpoint but a header is missing: method: {}, header: {}, status_code: {}",
                method.as_str(), header, status_code
            ),
            FileDownloadError::FileHashMismatchError { computed_hash, expected_hash, file_path } =>
                write!(
                    f,
                    "File failed hash validation: computed_hash: {}, expected_hash: {}, file: {:?}",
                    computed_hash, expected_hash, file_path
                ),
            FileDownloadError::TimeoutError =>
                write!(
                    f,
                    "File downloader timed out."
                )
        }
    }
}

impl From<reqwest::Error> for FileDownloadError {
    fn from(e: reqwest::Error) -> Self {
        FileDownloadError::HttpError(HttpError::ReqwestError(e))
    }
}

impl Error for FileDownloadError {}

/// An HTTP error that File Downloader may encounter
#[derive(Debug)]
pub enum HttpError {
    /// Failed to parse this String as a URL
    MalformedUrl(String, http::uri::InvalidUri),

    /// A reqwest HTTP client produced an error
    ReqwestError(reqwest::Error),

    /// A non-success HTTP response was received from the given URI
    NonSuccessResponse(http::Method, Response),

    /// A redirect response without a required header
    RedirectMissingHeader(http::Method, http::HeaderName, http::StatusCode),
}
