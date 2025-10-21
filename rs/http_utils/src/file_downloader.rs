use flate2::read::GzDecoder;
use http::Method;
use ic_crypto_sha2::Sha256;
use ic_logger::{ReplicaLogger, info, log};
use reqwest::{Client, Response};
use slog::Level;
use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::io::prelude::*;
use std::io::{BufReader, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tar::Archive;
use zstd::stream::read::Decoder as ZstdDecoder;

const OVERALL_TIMEOUT_MULTIPLIER: f32 = 10.0;

/// Streams HTTP response bodies to files
pub struct FileDownloader {
    client: Client,
    logger: Option<ReplicaLogger>,
    /// This is a timeout that is applied to the downloading each chunk that is
    /// yielded, not to the entire downloading of the file.
    chunk_timeout: Duration,
    /// This is a timeout that is applied to the whole operation of downloading
    /// a specific resource.
    overall_timeout: Duration,
}

macro_rules! maybe_log {
    ($logger:expr, $level:expr, $($arg:tt)+) => {
        if let Some(logger) = $logger.as_ref() {
            log!(logger, $level, $($arg)+);
        }
    };
}

macro_rules! maybe_info {
    (every_n_seconds => $seconds:expr, $logger:expr, $($arg:tt)+) => {
        if let Some(logger) = $logger.as_ref() {
            info!(every_n_seconds => $seconds, logger, $($arg)+);
        }
    };
    ($logger:expr, $($arg:tt)+) => {
        maybe_log!($logger, Level::Info, $($arg)+);
    };
}

macro_rules! maybe_warn {
    (every_n_seconds => $seconds:expr, $logger:expr, $($arg:tt)+) => {
        if let Some(logger) = $logger.as_ref() {
            warn!(every_n_seconds => $seconds, logger, $($arg)+);
        }
    };
    ($logger:expr, $($arg:tt)+) => {
        maybe_log!($logger, Level::Warning, $($arg)+);
    };
}

impl FileDownloader {
    pub fn new(logger: Option<ReplicaLogger>) -> Self {
        Self::new_with_timeout(logger, Duration::from_secs(15))
    }

    /// Creates a new `FileDownloader` with a specified `chunk_timeout`. By default
    /// `overall_timeout` will be set to `chunk_timeout * OVERALL_TIMEOUT_MULTIPLIER`
    pub fn new_with_timeout(logger: Option<ReplicaLogger>, chunk_timeout: Duration) -> Self {
        Self {
            client: Client::new(),
            logger,
            chunk_timeout,
            overall_timeout: chunk_timeout.mul_f32(OVERALL_TIMEOUT_MULTIPLIER),
        }
    }

    /// Download a .tar.gz or .tar.zst file from `url`, verify its hash if given, and
    /// extract the file into `target_dir`
    pub async fn download_and_extract_tar(
        &self,
        url: &str,
        target_dir: &Path,
        expected_sha256_hex: Option<String>,
    ) -> FileDownloadResult<()> {
        let tar_path = target_dir.join("tmp-tar");
        self.download_file(url, &tar_path, expected_sha256_hex)
            .await?;
        extract_tar_into_dir(&tar_path, target_dir)?;
        fs::remove_file(&tar_path)
            .map_err(|e| FileDownloadError::file_remove_error(&tar_path, e))?;

        Ok(())
    }

    /// Make a GET HTTP request to `url`, stream the response body to
    /// `file_path` and verify that the resulting file has hash
    /// `expected_sha256_hex`.
    ///
    /// If the `expected_sha256_hex` is specified and the file exists,
    /// resuming download will be performed, fetching only the missing
    /// parts of the file (if any) with the [`Range`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Range)
    /// header.
    ///
    /// If the `expected_sha256_hex` isn't specified and the file already
    /// exists, the file will be removed and the download will be executed.
    ///
    /// Since existing files get deleted if they have an incorrect hash,
    /// this code will also work if a crash or a timeout happens
    /// throughout execution leading to inconsistent data.
    pub async fn download_file(
        &self,
        url: &str,
        file_path: &Path,
        expected_sha256_hex: Option<String>,
    ) -> FileDownloadResult<()> {
        match expected_sha256_hex.as_ref() {
            // If the file is already present on disk and
            // a hash check is required, try the hash check
            // first to save time if possible.
            Some(hash) if file_path.exists() => {
                maybe_info!(self.logger, "File already exists. Checking hash.");
                match check_file_hash(file_path, hash) {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        maybe_warn!(
                            self.logger,
                            "Hash mismatch. Assuming incomplete file. Error: {:?}",
                            e
                        );
                    }
                }
            }
            // If the hash check wasn't required assume that
            // the file on the disk is stale and remove it.
            None if file_path.exists() => {
                maybe_info!(
                    self.logger,
                    "Expected hash not provided and the file already exist. Removing file."
                );
                fs::remove_file(file_path)
                    .map_err(|e| FileDownloadError::file_remove_error(file_path, e))?;
            }
            _ => {}
        }

        let offset = if file_path.exists() {
            let metadata = fs::metadata(file_path).map_err(|e| {
                FileDownloadError::IoError(
                    format!("Failed to read metadata from path: {}", file_path.display()),
                    e,
                )
            })?;
            // We have some parts of the file but still require to fetch the
            // rest from the server.
            let offset = metadata.len();
            maybe_info!(
                self.logger,
                "Resuming downloading file from {} starting from byte {}",
                url,
                offset
            );
            offset
        } else {
            maybe_info!(self.logger, "Downloading file from: {}", url);
            0
        };

        let maybe_response = self.resuming_http_get(url, offset).await?;

        // There are new bytes that should be written
        if let Some(response) = maybe_response {
            maybe_info!(
                self.logger,
                "Download request initiated to {:?}, headers: {:?}",
                response.remote_addr(),
                response.headers()
            );
            let file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(file_path)
                .map_err(|e| FileDownloadError::file_open_error(file_path, e))?;

            self.stream_response_body_to_file(response, file, file_path)
                .await?;
        }

        match expected_sha256_hex.as_ref() {
            Some(expected_hash) => {
                maybe_info!(self.logger, "Response read. Checking hash.");
                match check_file_hash(file_path, expected_hash) {
                    Ok(()) => {
                        maybe_info!(self.logger, "Hash check passed successfully.");
                        Ok(())
                    }
                    Err(hash_invalid_err) => {
                        maybe_warn!(
                            self.logger,
                            "Hash check failed: {:?} - deleting file",
                            hash_invalid_err
                        );
                        fs::remove_file(file_path)
                            .map_err(|err| FileDownloadError::file_remove_error(file_path, err))?;
                        Err(hash_invalid_err)
                    }
                }
            }
            None => {
                maybe_info!(
                    self.logger,
                    "Response read. Skipping hash verification since it wasn't provided."
                );
                Ok(())
            }
        }
    }

    async fn resuming_http_get(
        &self,
        url: &str,
        offset: u64,
    ) -> FileDownloadResult<Option<Response>> {
        let response = self
            .client
            .get(url)
            .header("range", format!("bytes={offset}-"))
            .timeout(self.overall_timeout)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(Some(response))
        } else if response.status() == http::StatusCode::RANGE_NOT_SATISFIABLE {
            maybe_warn!(
                self.logger,
                "Requesting resource '{}' from offset {}, resulted in `RANGE_NOT_SATISFIABLE`",
                url,
                offset,
            );
            Ok(None)
        } else {
            Err(FileDownloadError::NonSuccessResponse(
                Method::GET,
                Box::new(response),
            ))
        }
    }

    /// Stream the bytes of a given HTTP response body into the given file
    async fn stream_response_body_to_file(
        &self,
        mut response: Response,
        mut file: fs::File,
        file_path: &Path,
    ) -> FileDownloadResult<()> {
        let mut chunks_cnt: i32 = 0;
        let mut chunks_total_len: usize = 0;
        while let Some(chunk) = tokio::time::timeout(self.chunk_timeout, response.chunk())
            .await
            // This error comes from `tokio::time::timeout`
            .map_err(|_| FileDownloadError::TimeoutError)?
            // Since we use streaming, this error can only be one of:
            //   * `overall_timeout` - client side
            //   * 5xx error from the server or proxy serving the chunks
            .map_err(|e| {
                if e.is_timeout() {
                    FileDownloadError::TimeoutError
                } else {
                    FileDownloadError::ReqwestError(e)
                }
            })?
        {
            chunks_cnt += 1;
            chunks_total_len += chunk.len();
            maybe_info!(
                every_n_seconds => 1,
                self.logger,
                "Streaming {} bytes to {:?} (this is chunk #{} from the beginning).",
                chunk.len(),
                file_path,
                chunks_cnt
            );
            file.write_all(&chunk)
                .map_err(|e| FileDownloadError::file_write_error(file_path, e))?;
        }
        maybe_info!(
            self.logger,
            "Streamed {} chunks totalling {} bytes to file {:?}.",
            chunks_cnt,
            chunks_total_len,
            file_path
        );
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
        Err(FileDownloadError::FileHashMismatchError {
            computed_hash: computed_sha256_hex,
            expected_hash: expected_sha256_hex.into(),
            file_path: path.to_path_buf(),
        })
    } else {
        Ok(())
    }
}

/// Check if the file is in Gzip format by verifying the first 2 bytes
fn is_gz_file<R: Read + Seek>(reader: &mut R) -> io::Result<bool> {
    reader.seek(SeekFrom::Start(0))?;
    let mut buffer = [0; 2];
    reader.read_exact(&mut buffer)?;
    reader.seek(SeekFrom::Start(0))?;
    Ok(buffer == [0x1f, 0x8b])
}

/// Check if the file is in Zstandard format by verifying the first 4 bytes
fn is_zst_file<R: Read + Seek>(reader: &mut R) -> io::Result<bool> {
    reader.seek(SeekFrom::Start(0))?;
    let mut buffer = [0; 4];
    reader.read_exact(&mut buffer)?;
    reader.seek(SeekFrom::Start(0))?;
    Ok(buffer == [0x28, 0xb5, 0x2f, 0xfd])
}

/// Extract the contents of a given .tar.gz or tar.zst file into `target_dir`
pub fn extract_tar_into_dir(tar_path: &Path, target_dir: &Path) -> FileDownloadResult<()> {
    let map_to_untar_error = |e| FileDownloadError::untar_error(tar_path, e);

    let tar_file =
        File::open(tar_path).map_err(|e| FileDownloadError::file_open_error(tar_path, e))?;
    let mut buf_reader = BufReader::new(tar_file);

    if is_gz_file(&mut buf_reader).map_err(map_to_untar_error)? {
        let tar = GzDecoder::new(buf_reader);
        let mut archive = Archive::new(tar);
        archive.unpack(target_dir).map_err(map_to_untar_error)
    } else if is_zst_file(&mut buf_reader).map_err(map_to_untar_error)? {
        let tar = ZstdDecoder::new(buf_reader).map_err(map_to_untar_error)?;
        let mut archive = Archive::new(tar);
        archive.unpack(target_dir).map_err(map_to_untar_error)
    } else {
        Err(FileDownloadError::untar_error(
            tar_path,
            io::Error::other("Unrecognized file type"),
        ))
    }
}

pub type FileDownloadResult<T> = Result<T, FileDownloadError>;

/// Enumerates the possible errors that Orchestrator may encounter
#[derive(Debug)]
pub enum FileDownloadError {
    /// An IO error occurred
    IoError(String, io::Error),

    /// A reqwest HTTP client produced an error
    ReqwestError(reqwest::Error),

    /// A non-success HTTP response was received from the given URI
    NonSuccessResponse(http::Method, Box<Response>),

    /// A file's computed hash did not match the expected hash
    FileHashMismatchError {
        computed_hash: String,
        expected_hash: String,
        file_path: PathBuf,
    },
    TimeoutError,
}

impl FileDownloadError {
    pub(crate) fn file_write_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to write to file: {file_path:?}"), e)
    }

    pub(crate) fn file_open_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to open file: {file_path:?}"), e)
    }

    pub(crate) fn file_remove_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to remove file: {file_path:?}"), e)
    }

    pub(crate) fn untar_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to unpack tar file: {file_path:?}"), e)
    }

    pub(crate) fn compute_hash_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to hash of: {file_path:?}"), e)
    }
}

impl fmt::Display for FileDownloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileDownloadError::IoError(msg, e) => {
                write!(f, "IO error, message: {msg}, error: {e:?}")
            }
            FileDownloadError::ReqwestError(e) => {
                write!(f, "Encountered error when making Http request: {e}")
            }
            FileDownloadError::NonSuccessResponse(method, response) => write!(
                f,
                "Received non-success response from endpoint: method: {}, uri: {}, remote_addr: {:?}, status_code: {}, headers: {:?}",
                method.as_str(),
                response.url(),
                response.remote_addr(),
                response.status(),
                response.headers()
            ),
            FileDownloadError::FileHashMismatchError {
                computed_hash,
                expected_hash,
                file_path,
            } => write!(
                f,
                "File failed hash validation: computed_hash: {computed_hash}, expected_hash: {expected_hash}, file: {file_path:?}"
            ),
            FileDownloadError::TimeoutError => write!(f, "File downloader timed out."),
        }
    }
}

impl From<reqwest::Error> for FileDownloadError {
    fn from(e: reqwest::Error) -> Self {
        FileDownloadError::ReqwestError(e)
    }
}

impl Error for FileDownloadError {}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use ic_test_utilities_in_memory_logger::{InMemoryReplicaLogger, assertions::LogEntriesAssert};
    use mockito::{Mock, Request, ServerGuard};
    use slog::Level;
    use tar::Builder;
    use tempfile::tempdir;
    use tempfile::{NamedTempFile, TempPath};
    use tokio::test;
    use zstd::stream::write::Encoder as ZstdEncoder;

    use super::*;

    struct Setup {
        pub server: ServerGuard,
        pub data: Mock,
        pub redirect: Mock,
        pub data_out_of_range: Mock,
        pub bad_request: Mock,
        pub temp: TempPath,
        pub logger: InMemoryReplicaLogger,
    }

    fn extract_offset(request: &Request) -> usize {
        let header = request.header("range");
        println!("Received request for headers: {header:?}");
        match header.first() {
            Some(h) => h
                .to_str()
                .unwrap()
                .trim_start_matches("bytes=")
                .trim_end_matches("-")
                .parse()
                .unwrap(),

            None => 0,
        }
    }

    impl Setup {
        async fn new(body: &str) -> Self {
            let mut server = mockito::Server::new_async().await;
            let redirect = server
                .mock("GET", "/redirect")
                .with_status(301)
                .with_header("Location", &server.url())
                .create_async()
                .await;
            let body_owned = body.to_string();
            let data = server
                .mock("GET", "/")
                .match_header("range", mockito::Matcher::Regex(r"bytes=.*-".to_string()))
                .with_status(200)
                .with_body_from_request(move |request| {
                    let offset = extract_offset(request);
                    if offset > body_owned.len() {
                        vec![]
                    } else {
                        body_owned[offset..].into()
                    }
                })
                .create_async()
                .await;

            let data_out_of_range = server
                .mock("GET", "/out-of-range")
                .match_header("range", mockito::Matcher::Regex(r"bytes=.*-".to_string()))
                .with_status(416)
                .with_body(vec![])
                .create_async()
                .await;

            let bad_request = server
                .mock("GET", "/badrequest")
                .match_header("range", mockito::Matcher::Regex(r"bytes=.*-".to_string()))
                .with_status(400)
                .with_body(vec![])
                .create_async()
                .await;

            let temp = NamedTempFile::new()
                .expect("Failed to create tmp file")
                .into_temp_path();
            std::fs::remove_file(&temp).expect("Failed to remove file");

            Self {
                server,
                data,
                redirect,
                temp,
                data_out_of_range,
                bad_request,
                logger: InMemoryReplicaLogger::new(),
            }
        }

        fn expect_routes(
            mut self,
            data_hits: usize,
            redirect_hits: usize,
            data_out_of_range_hits: usize,
            bad_request_hits: usize,
        ) -> Self {
            self.data = self.data.expect(data_hits);
            self.redirect = self.redirect.expect(redirect_hits);
            self.data_out_of_range = self.data_out_of_range.expect(data_out_of_range_hits);
            self.bad_request = self.bad_request.expect(bad_request_hits);
            self
        }

        fn url(&self) -> String {
            self.server.url()
        }

        fn assert(&self) {
            self.data.assert();
            self.redirect.assert();
            self.data_out_of_range.assert();
            self.bad_request.assert();
        }
    }

    fn hash(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher
            .write_all(data.as_bytes())
            .expect("Failed to write data");
        hex::encode(hasher.finish())
    }

    #[test]
    async fn test_file_downloader_handles_redirects() {
        let body = String::from("Success");
        let hash = hash(&body);
        let setup = Setup::new(&body).await.expect_routes(1, 1, 0, 0);

        let downloader = FileDownloader::new(None);
        downloader
            .download_file(
                &format!("{}/redirect", setup.url()),
                &setup.temp,
                Some(hash),
            )
            .await
            .expect("Download failed");

        let result = std::fs::read_to_string(&setup.temp).expect("Failed to read file");
        assert_eq!(result, body);
        setup.assert();
    }

    #[test]
    async fn test_invalid_file_can_be_overwritten() {
        let body = String::from("Success");
        let hash = hash(&body);
        let invalid_hash = format!("invalid_{hash}");
        let setup = Setup::new(&body).await.expect_routes(1, 0, 0, 0);

        let downloader = FileDownloader::new(Some(ReplicaLogger::from(&setup.logger)));

        let result = downloader
            .download_file(&setup.url(), &setup.temp, Some(invalid_hash))
            .await;
        assert_matches!(result, Err(FileDownloadError::FileHashMismatchError { .. }));

        setup.assert();

        let logs = setup.logger.drain_logs();
        LogEntriesAssert::assert_that(logs)
            .has_only_one_message_containing(&Level::Info, "Response read. Checking hash.");

        assert!(!setup.temp.exists())
    }

    #[test]
    async fn test_download_succeeds_if_file_exists() {
        let body = String::from("Success");
        let hash = hash(&body);

        let setup = Setup::new(&body).await.expect_routes(1, 0, 0, 0);

        // Correct file already exists
        std::fs::write(&setup.temp, &body).unwrap();

        // Download the file without expected hash (it should be overwritten)
        let logger = InMemoryReplicaLogger::new();
        let downloader = FileDownloader::new(Some(ReplicaLogger::from(&logger)));
        downloader
            .download_file(&setup.url(), &setup.temp, None)
            .await
            .expect("Download failed");

        let result = std::fs::read_to_string(&setup.temp).expect("Failed to read file");
        assert_eq!(result, body);

        let logs = logger.drain_logs();
        LogEntriesAssert::assert_that(logs)
            .has_exactly_n_messages_containing(0, &Level::Info, "File already exists")
            .has_only_one_message_containing(
                &Level::Info,
                "Response read. Skipping hash verification since it wasn't provided.",
            );

        // Download it again, this time expecting the correct hash
        let logger = InMemoryReplicaLogger::new();
        let downloader = FileDownloader::new(Some(ReplicaLogger::from(&logger)));
        downloader
            .download_file(&setup.url(), &setup.temp, Some(hash))
            .await
            .expect("Download failed");

        let result = std::fs::read_to_string(&setup.temp).expect("Failed to read file");
        assert_eq!(result, body);

        // We should not download anything, as the file already exists.
        let logs = logger.drain_logs();
        LogEntriesAssert::assert_that(logs)
            .has_only_one_message_containing(&Level::Info, "File already exists")
            .has_exactly_n_messages_containing(0, &Level::Info, "Response read. Checking hash.");

        setup.assert();
    }

    #[test]
    async fn test_download_overwrites_existing_file() {
        let body = String::from("Success");
        let hash = hash(&body);

        let setup = Setup::new(&body).await.expect_routes(2, 0, 0, 0);

        // An unexpected file already exists
        std::fs::write(&setup.temp, "unexpected content").unwrap();

        // It should be overwritten with the correct file
        let downloader = FileDownloader::new(Some(ReplicaLogger::from(&setup.logger)));
        let mismatch = downloader
            .download_file(&setup.url(), &setup.temp, Some(hash.clone()))
            .await;
        // Since there is bad content first download will result in a mismatch
        assert_matches!(
            mismatch,
            Err(FileDownloadError::FileHashMismatchError { .. })
        );

        assert!(!setup.temp.exists());

        downloader
            .download_file(&setup.url(), &setup.temp, Some(hash))
            .await
            .expect("Failed to download");

        let result = std::fs::read_to_string(&setup.temp).expect("Failed to read file");
        assert_eq!(result, body);

        setup.assert();

        let logs = setup.logger.drain_logs();
        LogEntriesAssert::assert_that(logs)
            .has_only_one_message_containing(&Level::Warning, "Hash check failed");
    }

    #[test]
    async fn test_range_not_satisfiable() {
        let body = String::from("Success");
        let hash = hash(&body);

        let setup = Setup::new(&body).await.expect_routes(1, 0, 1, 0);

        // An unexpected file with content lenght greater than `body`
        std::fs::write(&setup.temp, "unexpected longer content").unwrap();

        let downloader = FileDownloader::new(Some(ReplicaLogger::from(&setup.logger)));
        let url = format!("{}/out-of-range", setup.url());
        let mismatch = downloader
            .download_file(&url, &setup.temp, Some(hash.clone()))
            .await;

        // Since there is bad content first download will result in a mismatch
        assert_matches!(
            mismatch,
            Err(FileDownloadError::FileHashMismatchError { .. })
        );

        assert!(!setup.temp.exists());

        let logs = setup.logger.drain_logs();
        LogEntriesAssert::assert_that(logs)
            .has_only_one_message_containing(&Level::Warning, "Requesting resource '")
            .has_only_one_message_containing(&Level::Warning, "Hash check failed")
            .has_only_one_message_containing(
                &Level::Warning,
                "Hash mismatch. Assuming incomplete file",
            )
            .has_exactly_n_messages_containing(1, &Level::Info, "Response read. Checking hash");
    }

    #[test]
    async fn test_bad_request() {
        let body = String::from("Success");

        let setup = Setup::new(&body).await.expect_routes(0, 0, 0, 1);
        let hash = hash(&body);

        // An unexpected file with content lenght greater than `body`
        std::fs::write(&setup.temp, "unexpected longer content").unwrap();

        let downloader = FileDownloader::new(Some(ReplicaLogger::from(&setup.logger)));
        let url = format!("{}/badrequest", setup.url());
        let mismatch = downloader
            .download_file(&url, &setup.temp, Some(hash))
            .await;

        // No hash check is required and the server returned a 400, the file
        // will should not be deleted
        assert_matches!(mismatch, Err(FileDownloadError::NonSuccessResponse(_, _)));

        let logs = setup.logger.drain_logs();
        assert!(setup.temp.exists());

        LogEntriesAssert::assert_that(logs)
            .has_only_one_message_containing(&Level::Info, "File already exists. Checking hash.")
            .has_only_one_message_containing(
                &Level::Warning,
                "Hash mismatch. Assuming incomplete file.",
            )
            .has_only_one_message_containing(&Level::Info, "Resuming downloading file");
    }

    fn create_tar<W: Write>(writer: W) -> io::Result<()> {
        let mut tar = Builder::new(writer);
        let mut header = tar::Header::new_gnu();
        header.set_path("test.txt")?;
        header.set_size("Hello, world!".len() as u64);
        header.set_cksum();
        tar.append(&header, "Hello, world!".as_bytes())?;
        tar.finish()?;
        Ok(())
    }

    #[test]
    async fn test_is_gz_file() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.tar.gz");

        let tar_gz = File::create(&file_path).unwrap();
        let mut encoder = GzEncoder::new(tar_gz, Compression::default());
        create_tar(&mut encoder).unwrap();
        encoder.finish().unwrap();

        let mut file = File::open(&file_path).unwrap();
        assert!(is_gz_file(&mut file).unwrap());
    }

    #[test]
    async fn test_is_zst_file() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.tar.zst");

        let tar_zst = File::create(&file_path).unwrap();
        let mut encoder = ZstdEncoder::new(tar_zst, 0).unwrap();
        create_tar(&mut encoder).unwrap();
        encoder.finish().unwrap();

        let mut file = File::open(&file_path).unwrap();
        assert!(is_zst_file(&mut file).unwrap());
    }

    #[test]
    async fn test_extract_tar_into_dir_gz() {
        let temp_dir = tempdir().unwrap();
        let tar_path = temp_dir.path().join("test.tar.gz");
        let extract_dir = temp_dir.path().join("extract");

        let tar_gz = File::create(&tar_path).unwrap();
        let mut encoder = GzEncoder::new(tar_gz, Compression::default());
        create_tar(&mut encoder).unwrap();
        encoder.finish().unwrap();

        extract_tar_into_dir(&tar_path, &extract_dir).unwrap();

        let extracted_file = extract_dir.join("test.txt");
        let contents = std::fs::read_to_string(extracted_file).unwrap();
        assert_eq!(contents, "Hello, world!");
    }

    #[test]
    async fn test_extract_tar_into_dir_zst() {
        let temp_dir = tempdir().unwrap();
        let tar_path = temp_dir.path().join("test.tar.zst");
        let extract_dir = temp_dir.path().join("extract");

        let tar_zst = File::create(&tar_path).unwrap();
        let mut encoder = ZstdEncoder::new(tar_zst, 0).unwrap();
        create_tar(&mut encoder).unwrap();
        encoder.finish().unwrap();

        extract_tar_into_dir(&tar_path, &extract_dir).unwrap();

        let extracted_file = extract_dir.join("test.txt");
        let contents = std::fs::read_to_string(extracted_file).unwrap();
        assert_eq!(contents, "Hello, world!");
    }

    #[test]
    async fn test_extract_tar_into_dir_unsupported_file_format() {
        let temp_dir = tempdir().unwrap();
        let tar_path = temp_dir.path().join("test.unsupported");
        let extract_dir = temp_dir.path().join("extract");

        let mut file = File::create(&tar_path).unwrap();
        file.write_all(b"unsupported content").unwrap();

        let result = extract_tar_into_dir(&tar_path, &extract_dir);

        match result {
            Err(FileDownloadError::IoError(message, _)) => {
                assert_eq!(message, format!("Failed to unpack tar file: {tar_path:?}"));
            }
            _ => panic!("Expected FileDownloadError::IoError"),
        }
    }
}
