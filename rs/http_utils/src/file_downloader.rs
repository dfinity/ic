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
use std::io::{BufReader, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tar::Archive;
use zstd::stream::read::Decoder as ZstdDecoder;

/// Streams HTTP response bodies to files
pub struct FileDownloader {
    client: Client,
    logger: Option<ReplicaLogger>,
    /// This is a timeout that is applied to the downloading each chunk that is
    /// yielded, not to the entire downloading of the file.
    timeout: Duration,
}

impl FileDownloader {
    pub fn new(logger: Option<ReplicaLogger>) -> Self {
        Self::new_with_timeout(logger, Duration::from_secs(15))
    }

    pub fn new_with_timeout(logger: Option<ReplicaLogger>, timeout: Duration) -> Self {
        Self {
            client: Client::new(),
            logger,
            timeout,
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
            Ok(response)
        } else {
            Err(FileDownloadError::NonSuccessResponse(Method::GET, response))
        }
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
            io::Error::new(io::ErrorKind::Other, "Unrecognized file type"),
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
    NonSuccessResponse(http::Method, Response),

    /// A file's computed hash did not match the expected hash
    FileHashMismatchError {
        computed_hash: String,
        expected_hash: String,
        file_path: PathBuf,
    },
    TimeoutError,
}

impl FileDownloadError {
    pub(crate) fn file_create_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to create file: {:?}", file_path), e)
    }

    pub(crate) fn file_write_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to write to file: {:?}", file_path), e)
    }

    pub(crate) fn file_open_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to open file: {:?}", file_path), e)
    }

    pub(crate) fn file_remove_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to remove file: {:?}", file_path), e)
    }

    pub(crate) fn untar_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to unpack tar file: {:?}", file_path), e)
    }

    pub(crate) fn compute_hash_error(file_path: &Path, e: io::Error) -> Self {
        FileDownloadError::IoError(format!("Failed to hash of: {:?}", file_path), e)
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
            FileDownloadError::ReqwestError(e) => write!(
                f,
                "Encountered error when making Http request: {}",
                e
            ),
            FileDownloadError::NonSuccessResponse(method, response) => write!(
                f,
                "Received non-success response from endpoint: method: {}, uri: {}, remote_addr: {:?}, status_code: {}, headers: {:?}",
                method.as_str(), response.url(), response.remote_addr(), response.status(), response.headers()
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
        FileDownloadError::ReqwestError(e)
    }
}

impl Error for FileDownloadError {}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use ic_test_utilities_in_memory_logger::{assertions::LogEntriesAssert, InMemoryReplicaLogger};
    use mockito::{Mock, ServerGuard};
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
        pub temp: TempPath,
        pub logger: InMemoryReplicaLogger,
    }

    impl Setup {
        fn new(body: &str) -> Self {
            let mut server = mockito::Server::new();
            let redirect = server
                .mock("GET", "/redirect")
                .with_status(301)
                .with_header("Location", &server.url())
                .create();
            let data = server
                .mock("GET", "/")
                .with_status(200)
                .with_body(body)
                .create();

            let temp = NamedTempFile::new()
                .expect("Failed to create tmp file")
                .into_temp_path();
            std::fs::remove_file(&temp).expect("Failed to remove file");

            Self {
                server,
                data,
                redirect,
                temp,
                logger: InMemoryReplicaLogger::new(),
            }
        }

        fn expect_routes(mut self, data_hits: usize, redirect_hits: usize) -> Self {
            self.data = self.data.expect(data_hits);
            self.redirect = self.redirect.expect(redirect_hits);
            self
        }

        fn url(&self) -> String {
            self.server.url()
        }

        fn assert(&self) {
            self.data.assert();
            self.redirect.assert();
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
        let setup = Setup::new(&body).expect_routes(1, 1);

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
    async fn test_hash_mismatch_returns_error() {
        let body = String::from("Success");
        let hash = hash(&body);
        let invalid_hash = format!("invalid_{}", hash);
        let setup = Setup::new(&body).expect_routes(1, 0);

        let downloader = FileDownloader::new(Some(ReplicaLogger::from(&setup.logger)));

        let result = downloader
            .download_file(&setup.url(), &setup.temp, Some(invalid_hash))
            .await;
        assert_matches!(result, Err(FileDownloadError::FileHashMismatchError { .. }));

        setup.assert();

        let logs = setup.logger.drain_logs();
        LogEntriesAssert::assert_that(logs)
            .has_only_one_message_containing(&Level::Info, "Response read");
    }

    #[test]
    async fn test_download_succeeds_if_file_exists() {
        let body = String::from("Success");
        let hash = hash(&body);

        let setup = Setup::new(&body).expect_routes(1, 0);

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
            .has_only_one_message_containing(&Level::Info, "Response read");

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
            .has_exactly_n_messages_containing(0, &Level::Info, "Response read");

        setup.assert();
    }

    #[test]
    async fn test_download_overwrites_existing_file() {
        let body = String::from("Success");
        let hash = hash(&body);

        let setup = Setup::new(&body).expect_routes(1, 0);

        // An unexpected file already exists
        std::fs::write(&setup.temp, "unexpected content").unwrap();

        // It should be overwritten with the correct file
        let downloader = FileDownloader::new(Some(ReplicaLogger::from(&setup.logger)));
        downloader
            .download_file(&setup.url(), &setup.temp, Some(hash))
            .await
            .expect("Download failed");

        let result = std::fs::read_to_string(&setup.temp).expect("Failed to read file");
        assert_eq!(result, body);

        setup.assert();

        let logs = setup.logger.drain_logs();
        LogEntriesAssert::assert_that(logs).has_only_one_message_containing(
            &Level::Warning,
            "File already exists, but hash check failed",
        );
    }

    fn create_tar<W: Write>(writer: W) -> io::Result<()> {
        let mut tar = Builder::new(writer);
        let mut header = tar::Header::new_gnu();
        header.set_path("test.txt")?;
        header.set_size("Hello, world!".as_bytes().len() as u64);
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
                assert_eq!(
                    message,
                    format!("Failed to unpack tar file: {:?}", tar_path)
                );
            }
            _ => panic!("Expected FileDownloadError::IoError"),
        }
    }
}
