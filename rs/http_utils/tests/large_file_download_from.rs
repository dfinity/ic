use std::sync::Arc;
use std::time::Duration;

use assert_matches::assert_matches;
use ic_http_utils::file_downloader::{FileDownloadError, FileDownloader, compute_sha256_hex};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Total size of the bogus file served by the local test web-server.
const FILE_SIZE: usize = 512 * 1024;
/// Number of bytes the server hands out per request before stalling, forcing
/// the downloader to time out and later resume the download.
const CHUNK_SIZE: usize = 128 * 1024;

/// Fill a buffer with deterministic pseudo-random data (xorshift64).
fn bogus_data(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut data = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        data.push((state & 0xff) as u8);
    }
    data
}

/// Read the HTTP request headers from `stream` and return the start offset
/// requested via the `Range: bytes=<offset>-` header (0 if absent).
async fn read_request_offset(stream: &mut TcpStream) -> usize {
    let mut buf = Vec::new();
    let mut byte = [0_u8; 1];
    // Read until the end of the HTTP request headers.
    while !buf.ends_with(b"\r\n\r\n") {
        if stream.read_exact(&mut byte).await.is_err() {
            break;
        }
        buf.push(byte[0]);
    }
    let request = String::from_utf8_lossy(&buf);
    request
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("range") {
                value
                    .trim()
                    .trim_start_matches("bytes=")
                    .trim_end_matches('-')
                    .parse()
                    .ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

/// Handle a single connection: serve at most `CHUNK_SIZE` bytes starting at the
/// requested offset. If bytes remain afterwards, stall so that the client times
/// out (leaving the partial file on disk to be resumed). Otherwise serve the
/// remaining bytes and let the response complete normally.
async fn handle_connection(mut stream: TcpStream, data: Arc<Vec<u8>>) {
    let offset = read_request_offset(&mut stream).await.min(data.len());
    let remaining = data.len() - offset;
    let to_send = remaining.min(CHUNK_SIZE);

    // Advertise the full remaining length so the client keeps waiting for the
    // bytes we withhold when stalling.
    let header =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {remaining}\r\nConnection: close\r\n\r\n");
    if stream.write_all(header.as_bytes()).await.is_err() {
        return;
    }
    if stream
        .write_all(&data[offset..offset + to_send])
        .await
        .is_err()
    {
        return;
    }
    let _ = stream.flush().await;

    if to_send < remaining {
        // Withhold the rest of the body so the download times out, keeping the
        // partial file on disk for the next (resuming) request.
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

/// Verify that `FileDownloader` correctly resumes an interrupted download.
///
/// Rather than downloading a real (large) image over the network, this test
/// serves a bogus file of random data from a local web-server. The server hands
/// out the file in pieces, stalling in between so that the downloader times out
/// repeatedly. Each timeout must leave the already-downloaded bytes on disk so
/// that the next request resumes where the previous one left off, until the
/// whole file has been fetched and its hash matches.
#[tokio::test]
async fn test_resuming_download() {
    let data = Arc::new(bogus_data(FILE_SIZE));

    let dir = tempdir().unwrap();

    // Compute the expected hash of the full file.
    let source_path = dir.path().join("source");
    std::fs::write(&source_path, data.as_ref()).unwrap();
    let hash = compute_sha256_hex(&source_path).unwrap();

    // Start a local web-server serving the bogus file with stalls.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_data = data.clone();
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(handle_connection(stream, server_data.clone()));
        }
    });

    let url = format!("http://{addr}/");
    let downloader = FileDownloader::new_with_timeout(None, Duration::from_secs(2));

    let output = dir.path().join("download");
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
            "No data downloaded in this iteration, meaning that either the server has a bug, the timeout is too low or there is a bug in the code"
        );
        last_iteration_size = metadata.len();
    }

    // The fully downloaded file must match the served bogus file.
    assert_eq!(std::fs::read(&output).unwrap(), *data);

    server.abort();
}
