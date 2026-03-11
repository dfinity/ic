use crate::storage::read_blob_store;
use askama::Template;

#[cfg(test)]
mod tests;

mod filters {
    #[askama::filter_fn]
    pub fn timestamp_to_datetime<T: std::fmt::Display>(
        timestamp: T,
        _env: &dyn askama::Values,
    ) -> askama::Result<String> {
        let input = timestamp.to_string();
        let ts: i128 = input
            .parse()
            .map_err(|e| askama::Error::Custom(Box::new(e)))?;
        let dt_offset = time::OffsetDateTime::from_unix_timestamp_nanos(ts).unwrap();
        let format =
            time::format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]+00:00")
                .unwrap();
        Ok(dt_offset.format(&format).unwrap())
    }
}

#[derive(Template)]
#[template(path = "dashboard.html", whitespace = "suppress")]
pub struct DashboardTemplate {
    pub total_blobs: u64,
    pub total_size_bytes: u64,
    pub blobs: Vec<DashboardBlob>,
}

pub struct DashboardBlob {
    pub hash: String,
    pub uploader: String,
    pub size: u64,
    pub inserted_at_ns: u64,
    pub tags: Vec<String>,
}

pub fn dashboard() -> DashboardTemplate {
    read_blob_store(|store| {
        let mut total_size_bytes = 0u64;
        let blobs: Vec<DashboardBlob> = store
            .iter_metadata()
            .map(|(hash, metadata)| {
                total_size_bytes += metadata.size;
                DashboardBlob {
                    hash: hash.to_string(),
                    uploader: metadata.uploader.to_string(),
                    size: metadata.size,
                    inserted_at_ns: metadata.inserted_at_ns,
                    tags: metadata.tags.into_iter().map(|t| t.to_string()).collect(),
                }
            })
            .collect();
        DashboardTemplate {
            total_blobs: store.len(),
            total_size_bytes,
            blobs,
        }
    })
}
