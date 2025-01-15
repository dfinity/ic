use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read, SeekFrom};
use std::os::fd::AsRawFd;

fn main() {
    // let mut digest = Sha256::new();
    let mut hasher = blake3::Hasher::new();
    let empty = [0u8; 1024 * 1024];
    for _ in 0..160000 {
        hasher.update(&empty);
        // Digest::update(&mut digest, &empty);
    }
    // println!("{:?}", digest.finalize())
    println!("{:?}", hasher.finalize())
}
//
//
// const MAX_BLOCK_SIZE: usize = 512;
//
// enum Block {
//     Empty()
// }
//
// /// Scan through a file looking for empty sections by collecting only regions
// /// containing data, taking advantage of SEEK_DATA/SEEK_HOLE.
// pub fn scan_file_for_holes(source: &mut File, impl Fn(Section)) {
//     let file_metadata = source.metadata()?;
//
//     let mut file_offset = 0;
//     let file_size = file_metadata.len();
//
//     // Until the whole file is read, find and scan through data sections, collecting only regions with non-zero data.
//     while file_offset < file_size {
//         let mut start;
//         if let Some(offset) = seek_data(source, file_offset) {
//             start = offset
//         } else {
//             // There is no more data in the file, but we haven't read it all. Mark the end as sparse.
//             state.terminate_list(file_size);
//             break;
//         };
//         let end = seek_hole(source, start);
//
//         let mut reader = BufReader::new(Read::by_ref(source));
//         reader.seek(SeekFrom::Start(start))?;
//
//         // Read buffer that is reused across iterations.
//         let mut buffer = [0; MAX_BLOCK_SIZE];
//         // Scan through this data section looking for any empty blocks.
//         while start < end {
//             let to_read = std::cmp::min(end - start, MAX_BLOCK_SIZE as u64);
//             // We fill the first `to_read` bytes of the buffer. Casting `to_read` to usize is valid,
//             // since its max value is `MAX_BLOCK_SIZE` which itself is a usize.
//             let buffer_slice = &mut buffer[..to_read as usize];
//             reader.read_exact(buffer_slice)?;
//
//             // Transition from non-empty to empty - wrap the current block.
//             if is_empty(buffer_slice) {
//                 if state.is_in_block() {
//                     state.end_block(start);
//                 }
//             } else {
//                 // Transition from empty to non-empty - start a new block.
//                 if !state.is_in_block() {
//                     state.start_block(start);
//                 }
//             }
//
//             start += to_read;
//         }
//
//         // If we were in a block at the end of this data section, close it out.
//         if state.is_in_block() {
//             state.end_block(end);
//         } else {
//             // If we were not in a block, but this was the end of the file, close it out.
//             if end == file_size {
//                 state.terminate_list(file_size);
//             }
//         }
//
//         file_offset = end;
//     }
//
//     Ok(state)
// }
//
// // null check from tar-rs
// fn is_empty(block: &[u8]) -> bool {
//     // Efficiently check whether all elements are 0.
//     block == &[0; MAX_BLOCK_SIZE][..block.len()]
// }
//
// fn seek_hole(file: &mut File, from: u64) -> u64 {
//     // NOTE: u64 does not fully fit in i64, but i64::MAX is 9_223_372_036_854_775_807
//     // (8 exbibytes) and we won't be seeing files this large any time soon.
//     let unsized_from = from.try_into().unwrap();
//
//     let out = unsafe { libc::lseek(file.as_raw_fd(), unsized_from, libc::SEEK_HOLE) };
//
//     out.try_into().unwrap()
// }
//
// fn seek_data(file: &mut File, from: u64) -> Option<u64> {
//     // NOTE: u64 does not fully fit in i64, but i64::MAX is 9_223_372_036_854_775_807
//     // (8 exbibytes) and we won't be seeing files this large any time soon.
//     let unsized_from = from.try_into().unwrap();
//
//     let out = unsafe { libc::lseek(file.as_raw_fd(), unsized_from, libc::SEEK_DATA) };
//
//     if out == -1 {
//         return None;
//     }
//
//     Some(out.try_into().unwrap())
// }
