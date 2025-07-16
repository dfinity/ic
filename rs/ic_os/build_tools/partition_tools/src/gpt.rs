use std::format;
use std::path::Path;

use anyhow::{Context, Result};

/// Check the byte offset of a given partition from the GPT table
pub async fn check_offset(disk_image: &Path, index: usize) -> Result<u64> {
    let gpt = gpt::disk::read_disk(disk_image).context("Could not read GPT from device")?;
    let partition = gpt
        .partitions()
        .iter()
        .map(|(_, v)| v)
        .nth(index)
        .with_context(|| format!("Could not find partition '{index}'"))?;

    Ok(partition.bytes_start(*gpt.logical_block_size())?)
}

/// Check the byte offset of a given partition from the GPT table
pub async fn check_length(disk_image: &Path, index: usize) -> Result<u64> {
    let gpt = gpt::disk::read_disk(disk_image).context("Could not read GPT from device")?;

    let partition = gpt
        .partitions()
        .iter()
        .map(|(_, v)| v)
        .nth(index)
        .with_context(|| format!("Could not find partition '{index}'"))?;

    Ok(partition.bytes_len(*gpt.logical_block_size())?)
}
