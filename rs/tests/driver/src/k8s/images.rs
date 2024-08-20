use anyhow::{anyhow, Result};
use reqwest::Body;
use std::path::Path;
use tokio_util::codec::{BytesCodec, FramedRead};
use tracing::*;

pub async fn upload_image<P: AsRef<Path>>(path: P, url: &str) -> Result<()> {
    let client = reqwest::Client::new();
    info!(
        "Uploading {} to {}",
        path.as_ref().display().to_string(),
        url
    );
    let file = tokio::fs::File::open(path.as_ref()).await?;
    let res = client
        .put(url)
        .body({
            let stream = FramedRead::new(file, BytesCodec::new());
            Body::wrap_stream(stream)
        })
        .send()
        .await?;
    debug!("Upload's put response: {:?}", res);
    if res.status().as_u16() != 200 {
        return Err(anyhow!(
            "Failed to upload {} to {}",
            path.as_ref().display(),
            url
        ));
    }
    Ok(())
}
