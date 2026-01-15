use std::{path::PathBuf, str::FromStr};

use assert_matches::assert_matches;
use ic_http_utils::file_downloader::{FileDownloadError, FileDownloader};

async fn get_hash(downloader: FileDownloader, version: &str) -> String {
    let url =
        format!("https://download.dfinity.systems/ic/{version}/guest-os/update-img/SHA256SUMS");

    let file_path = std::path::Path::new("/tmp/shasums");
    downloader
        .download_file(&url, file_path, None)
        .await
        .unwrap();

    std::fs::read_to_string(file_path)
        .unwrap()
        .lines()
        .find(|line| line.ends_with("update-img.tar.zst"))
        .map(|line| line.split_once(' ').unwrap().0)
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn test_large_file_download() {
    // Known commit where the artifacts have been uploaded
    let version = "6a5718d4e45acc80a26506f34d1525c482330b56".to_string();

    // Use a normal downloader since hash is required for further testing.
    let downloader = FileDownloader::new_with_timeout(None, std::time::Duration::from_secs(30));
    let hash = get_hash(downloader, version.as_ref()).await;

    let url = format!(
        "https://download.dfinity.systems/ic/{version}/guest-os/update-img/update-img.tar.zst"
    );
    let downloader = FileDownloader::new_with_timeout(None, std::time::Duration::from_secs(2));

    let output = PathBuf::from_str("/tmp/replica").unwrap();
    let mut last_iteration_size = 0;
    loop {
        let response = downloader
            .download_file(url.as_str(), output.as_path(), Some(hash.clone()))
            .await;
        if response.is_ok() {
            break;
        }

        assert_matches!(response, Err(FileDownloadError::TimeoutError));

        let metadata = std::fs::metadata(&output).unwrap();
        assert!(
            metadata.len() > last_iteration_size,
            "No data downloaded in this iteration, meaning that either s3 has a bug, timeout is too low or there is a bug in the code"
        );
        last_iteration_size = metadata.len();
    }
}
