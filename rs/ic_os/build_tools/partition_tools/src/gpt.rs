use std::format;
use std::path::Path;

use anyhow::{Context, Result};

/// Check the byte offset of a given partition from the GPT table. Index is 1-based.
pub fn get_partition_offset(disk_image: &Path, index: u32) -> Result<u64> {
    let gpt = gpt::disk::read_disk(disk_image).context("Could not read GPT from device")?;
    let partition = gpt
        .partitions()
        .get(&index)
        .with_context(|| format!("Could not find partition '{index}'"))?;

    Ok(partition.bytes_start(*gpt.logical_block_size())?)
}

/// Check the byte offset of a given partition from the GPT table. Index is 1-based.
pub fn get_partition_length(disk_image: &Path, index: u32) -> Result<u64> {
    let gpt = gpt::disk::read_disk(disk_image).context("Could not read GPT from device")?;

    let partition = gpt
        .partitions()
        .get(&index)
        .with_context(|| format!("Could not find partition '{index}'"))?;

    Ok(partition.bytes_len(*gpt.logical_block_size())?)
}
