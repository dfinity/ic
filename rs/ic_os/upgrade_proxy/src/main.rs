use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use anyhow::Result;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use tiny_http::{Header, Response, Server};

const ADDR: &str = "[::]:19300";
const CACHE_ARTIFACT: LazyLock<PathBuf> =
    LazyLock::new(|| PathBuf::from("/var/upgrade-cache/artifact"));

fn main() {
    let server = Server::http(ADDR).expect("Unable to attatch to '{ADDR}'");
    eprintln!("Listening on: '{ADDR}'");

    let mut artifact_hash: Option<String> = None;

    if CACHE_ARTIFACT.exists() {
        artifact_hash =
            Some(sha256_hex(&CACHE_ARTIFACT).expect("Unable to calculate artifact hash."));
    }

    for req in server.incoming_requests() {
        let Some((url, hash)) = req.url().trim_start_matches('/').split_once('/') else {
            if let Err(e) =
                req.respond(Response::from_string("usage: GET /hash/URL\n").with_status_code(400))
            {
                eprintln!("Invalid usage response failed: {e}");
            }
            continue;
        };

        if Some(hash) != artifact_hash.as_deref() {
            if let Err(e) = download(&url, &CACHE_ARTIFACT) {
                eprintln!("Download from '{url}' failed: {e}");
                if let Err(e) = req.respond(
                    Response::from_string(format!("download failed: {e}\n")).with_status_code(502),
                ) {
                    eprintln!("Download failed response, failed: {e}");
                }
                continue;
            }
            artifact_hash =
                Some(sha256_hex(&CACHE_ARTIFACT).expect("Unable to calculate artifact hash."));
        } else {
            eprintln!("Cache hit for '{hash}'");
        }

        let file = File::open(&*CACHE_ARTIFACT).expect("Unable to open cached artifact.");
        if let Err(e) =
            req.respond(Response::from_file(file).with_header(
                Header::from_bytes("Content-Type", "application/octet-stream").unwrap(),
            ))
        {
            eprintln!("Serving proxied resource failed: {e}");
        }
    }
}

fn download(url: &str, dest: &Path) -> Result<()> {
    let mut body = ureq::get(url).call()?.into_body().into_reader();
    let mut temp_file = NamedTempFile::with_prefix_in("artifact", dest.parent().unwrap())?;
    io::copy(&mut body, &mut temp_file)?;
    temp_file.persist(dest)?;

    Ok(())
}

pub fn sha256_hex(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;

    Ok(hex::encode(hasher.finalize()))
}
