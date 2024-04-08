use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;

use anyhow::{bail, Result};
use tar::{Builder, EntryType, GnuExtSparseHeader, GnuSparseHeader, Header, HeaderMode};

mod tar_util;
mod types;
use types::{Block, State};

/// Scan through a file looking for empty sections by collecting only regions
/// containing data, taking advantage of SEEK_DATA/SEEK_HOLE.
pub fn scan_file_for_holes(source: &mut File, name: String) -> Result<State> {
    let file_metadata = source.metadata()?;

    if !file_metadata.is_file() {
        bail!("Input '{}' is not a file", name);
    }

    let mut state = State::new(name);

    let mut file_offset = 0;
    let file_size = file_metadata.len();

    // Until the whole file is read, find and scan through data sections, collecting only regions with non-zero data.
    while file_offset < file_size {
        let mut start;
        if let Some(offset) = seek_data(source, file_offset) {
            start = offset
        } else {
            // There is no more data in the file, but we haven't read it all. Mark the end as sparse.
            state.terminate_list(file_size);
            break;
        };
        let end = seek_hole(source, start);

        // Scan through this data section looking for any empty blocks.
        while start < end {
            // NOTE: This will always be less than 512, so should totally fit into usize.
            let to_read = std::cmp::min(end - start, 512);
            let mut buffer = vec![0; to_read as usize];

            source.seek(SeekFrom::Start(start))?;
            source.read_exact(&mut buffer)?;

            // Transition from non-empty to empty - wrap the current block.
            if is_empty(&buffer) {
                if state.is_in_block() {
                    state.end_block(start);
                }
            } else {
                // Transition from empty to non-empty - start a new block.
                if !state.is_in_block() {
                    state.start_block(start);
                }
            }

            start += to_read;
        }

        // If we were in a block at the end of this data section, close it out.
        if state.is_in_block() {
            state.end_block(end);
        } else {
            // If we were not in a block, but this was the end of the file, close it out.
            if end == file_size {
                state.terminate_list(file_size);
            }
        }

        file_offset = end;
    }

    Ok(state)
}

/// Add a file to this archive, removing any holes by formatting as sparse.
pub fn add_file_to_archive<W: Write>(
    source: &mut File,
    dest: &mut Builder<W>,
    state: State,
) -> Result<()> {
    let mut header = Header::new_gnu();

    let State {
        name,
        blocks,
        stripped_size,
        ..
    } = state;

    // Fill out the file header with basic information.
    let file_metadata = source.metadata()?;
    header.set_metadata_in_mode(&file_metadata, HeaderMode::Deterministic);

    // Add custom fields to mark file as sparse
    header.set_entry_type(EntryType::GNUSparse);
    header
        .as_gnu_mut()
        .unwrap() // We made this header, so we know it is GNU
        .realsize = header.as_gnu_mut().unwrap().size;
    header.set_size(stripped_size);

    // Include the sparse table.
    header.as_gnu_mut().unwrap().sparse = collect_to_header_array(blocks.iter());
    if blocks.len() > 4 {
        header.as_gnu_mut().unwrap().isextended = [1];
    }

    let empty_data: &[u8] = &[];
    dest.append_data(&mut header, name, empty_data)?;

    // Copy any additional sparse headers and the file data directly, as the
    // tar-rs crate doen't handle this.
    let dest_raw = dest.get_mut();

    if blocks.len() > 4 {
        let mut chunks = blocks[4..].chunks(21).peekable();
        while let Some(chunk) = chunks.next() {
            let mut header = GnuExtSparseHeader::new();
            header.sparse = collect_to_header_array(chunk.iter());

            if chunks.peek().is_some() {
                header.isextended = [1];
            }

            dest_raw.write_all(header.as_bytes())?;
        }
    }

    for block in blocks {
        // Copy all of the data blocks from the file into place
        source.seek(SeekFrom::Start(block.offset))?;
        std::io::copy(&mut Read::by_ref(source).take(block.size), dest_raw)?;
    }

    Ok(())
}

// Convert blocks to sparse headers, and pad to the requested size with empty ones.
fn collect_to_header_array<'a, I, const N: usize>(input: I) -> [GnuSparseHeader; N]
where
    I: IntoIterator<Item = &'a Block>,
{
    input
        .into_iter()
        .map(|v| v.to_gnu_sparse())
        .chain(std::iter::repeat_with(|| GnuSparseHeader {
            offset: [0; 12],
            numbytes: [0; 12],
        }))
        .take(N)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap() // By taking N above, we'll always have enough to fill the N sized array
}

// null check from tar-rs
fn is_empty(block: &[u8]) -> bool {
    block.iter().all(|i| *i == 0)
}

fn seek_hole(file: &File, from: u64) -> u64 {
    // NOTE: u64 does not fully fit in i64, but i64::MAX is 9_223_372_036_854_775_807
    // (8 exbibytes) and we won't be seeing files this large any time soon.
    let unsized_from = from.try_into().unwrap();

    let out = unsafe { libc::lseek(file.as_raw_fd(), unsized_from, libc::SEEK_HOLE) };

    out.try_into().unwrap()
}

fn seek_data(file: &File, from: u64) -> Option<u64> {
    // NOTE: u64 does not fully fit in i64, but i64::MAX is 9_223_372_036_854_775_807
    // (8 exbibytes) and we won't be seeing files this large any time soon.
    let unsized_from = from.try_into().unwrap();

    let out = unsafe { libc::lseek(file.as_raw_fd(), unsized_from, libc::SEEK_DATA) };

    if out == -1 {
        return None;
    }

    Some(out.try_into().unwrap())
}
