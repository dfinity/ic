use anyhow::{bail, Context};
use blake3::{Hash, Hasher};
use nix::errno::Errno;
use nix::unistd::Whence;
use std::env;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::Path;

const BLOCK_LEN: usize = 1024 * 1024;
const BLOCK_LEN_U64: u64 = BLOCK_LEN as u64;

/// `icsum [filename]`
/// A tool for quickly calculating file checksums. This tool is much
/// faster than common checksum tools when run on sparse files.
fn main() -> anyhow::Result<()> {
    let args: Vec<_> = env::args().collect();
    // The first arg is the own executable path.
    if args.len() != 2 {
        bail!(
            "The program takes 1 argument, the file name, received {}",
            args.len() - 1
        );
    }
    let path = &args[1];

    let hash = calculate_digest(&mut File::open(Path::new(path)).context("Could not open file")?)
        .context("Hash calculation failed")?;

    println!("{}", hash.to_hex());

    Ok(())
}

fn calculate_digest(file: &mut File) -> std::io::Result<Hash> {
    const HASH_TAG: &[u8] = b"icsum-hash";
    // The algorithm works by chunking the input into blocks of [BLOCK_LEN].
    // Each such block's hash is calculated separately and combined by outer_hasher.
    // Since the hash of two equal blocks is the same, we can precalculate the hash of blocks of
    // holes (a block with zeros only). We then use the OS's file seek API to avoid actually having
    // to read the zeros from holes.
    //
    // Outer hash:
    //   hash = blake3(len(HASH_TAG) || HASH_TAG || len(file) || h_block_0 || .. || h_block_n)
    // Block hash:
    //   h_block_n = blake3(len(BLOCK_TAG) || BLOCK_TAG || block_n)
    //
    // Research paper: https://www.scitepress.org/Papers/2024/127645/127645.pdf
    let mut outer_hasher = Hasher::new();
    outer_hasher.update(&HASH_TAG.len().to_be_bytes());
    outer_hasher.update(HASH_TAG);
    outer_hasher.update(&file.metadata()?.len().to_be_bytes());
    let hole_hash = block_hash(vec![0; BLOCK_LEN].as_slice());
    iterate_blocks(file, |block| match block {
        Block::Hole => {
            outer_hasher.update(hole_hash.as_bytes());
        }
        Block::Data(bytes) => {
            outer_hasher.update(block_hash(bytes).as_bytes());
        }
    })?;

    Ok(outer_hasher.finalize())
}

fn block_hash(block: &[u8]) -> Hash {
    const BLOCK_TAG: &[u8] = b"icsum-block";
    let mut hasher = Hasher::new();
    hasher.update(&BLOCK_TAG.len().to_be_bytes());
    hasher.update(BLOCK_TAG);
    hasher.update(block);
    hasher.finalize()
}

#[derive(Eq, PartialEq)]
enum Block<'a> {
    /// A hole of [BLOCK_LEN] bytes. If the last block is a hole of less than [BLOCK_LEN], it will
    /// be represented by a [Block::Data] block containing zeros instead.
    Hole,
    /// Data block. This is always [BLOCK_LEN] long, except in the last block where it may be
    /// shorter.
    Data(&'a [u8]),
}

fn iterate_blocks(file: &mut File, mut callback: impl FnMut(Block)) -> std::io::Result<()> {
    let file_len = file.metadata()?.len();
    let mut buf = vec![0; BLOCK_LEN];
    let mut state = state_at(file, 0, file_len)?;

    for block in 0..file_len / BLOCK_LEN_U64 {
        let block_start_offset = block * BLOCK_LEN_U64;

        match state {
            // If we are in a hole but would pass `next_data` in this block, switch to data state.
            State::InHole { next_data } if block_start_offset + BLOCK_LEN_U64 > next_data => {
                state = State::InData {
                    next_hole: seek_hole(file, block_start_offset + BLOCK_LEN_U64)?
                        .unwrap_or(file_len),
                };
            }
            // If we are in data state but already passed `next_hole`, switch to hole state.
            State::InData { next_hole } if block_start_offset >= next_hole => {
                state = State::InHole {
                    next_data: seek_data(file, block_start_offset)?.unwrap_or(file_len),
                };
            }
            _ => {}
        }

        match state {
            State::InHole { .. } => callback(Block::Hole),
            State::InData { .. } => {
                file.read_exact_at(&mut buf, block_start_offset)?;
                callback(Block::Data(&buf));
            }
        }
    }

    // Handle remaining data at the end of file that may be shorter than a full block.
    buf.clear();
    file.seek(SeekFrom::Start(file_len / BLOCK_LEN_U64 * BLOCK_LEN_U64))?;
    file.read_to_end(&mut buf)?;
    callback(Block::Data(&buf));

    Ok(())
}

enum State {
    InHole { next_data: u64 },
    InData { next_hole: u64 },
}

fn state_at(file: &mut File, offset: u64, file_len: u64) -> std::io::Result<State> {
    let next_data = seek_data(file, offset)?.unwrap_or(file_len);
    let next_hole = seek_hole(file, offset)?.unwrap_or(file_len);
    file.seek(SeekFrom::Start(offset))?;
    let result = if next_data == offset {
        State::InData { next_hole }
    } else {
        State::InHole { next_data }
    };

    Ok(result)
}

/// Seek hole in `file` starting from offset `from`. If `from` is outside the file or if there
/// are no more holes in the file, the return value Ok(None) otherwise the return value is
/// Ok(start_of_hole) and the file is seeked to that position.
fn seek_hole(file: &mut File, from: u64) -> std::io::Result<Option<u64>> {
    // NOTE: u64 does not fully fit in i64, but i64::MAX is 9_223_372_036_854_775_807
    // (8 exbibytes) and we won't be seeing files this large any time soon.
    let unsized_from = from.try_into().unwrap();

    match nix::unistd::lseek(file.as_raw_fd(), unsized_from, Whence::SeekHole) {
        Ok(result) => Ok(Some(result as u64)),
        Err(Errno::ENXIO) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// See [seek_hole] for documentation.
fn seek_data(file: &mut File, from: u64) -> std::io::Result<Option<u64>> {
    // NOTE: u64 does not fully fit in i64, but i64::MAX is 9_223_372_036_854_775_807
    // (8 exbibytes) and we won't be seeing files this large any time soon.
    let unsized_from = from.try_into().unwrap();

    match nix::unistd::lseek(file.as_raw_fd(), unsized_from, Whence::SeekData) {
        Ok(result) => Ok(Some(result as u64)),
        Err(Errno::ENXIO) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};
    use std::io::Write;
    use std::path::PathBuf;

    fn create_tempfile() -> File {
        let tempdir = env::var_os("TEST_TMPDIR").map_or(env::temp_dir(), PathBuf::from);
        tempfile::tempfile_in(tempdir).expect("Could not create tempfile")
    }

    mod iterate_blocks {
        use super::*;

        #[test]
        /// This test ensures that the test environment supports sparse files.
        /// Otherwise, the rest of the test cases would be useless.
        fn file_system_supports_sparse_files() {
            let mut file = create_tempfile();
            file.seek(SeekFrom::Start(BLOCK_LEN_U64)).unwrap();
            writeln!(&mut file, "hello").unwrap();

            file.rewind().unwrap();

            let mut holes = 0;
            iterate_blocks(&mut file, |block| {
                if block == Block::Hole {
                    holes += 1;
                }
            })
            .unwrap();

            assert!(
                holes >= 1,
                "Expected at least 1 hole, filesystem likely doesn't support sparse files."
            );
        }

        #[test]
        fn no_holes_prime_bytes() {
            let mut file = create_tempfile();
            let mut rng = StdRng::seed_from_u64(0);
            let mut data = vec![0u8; 26205239];
            rng.fill_bytes(&mut data);

            file.write_all(&data).unwrap();

            verify_file(file);
        }

        #[test]
        fn no_holes_32mb() {
            let mut file = create_tempfile();
            let mut rng = StdRng::seed_from_u64(0);
            let mut data = vec![0u8; 32 * 1024 * 1024];
            rng.fill_bytes(&mut data);

            file.write_all(&data).unwrap();

            verify_file(file);
        }

        #[test]
        fn prime_holes_and_sizes() {
            let mut file = create_tempfile();
            let mut rng = StdRng::seed_from_u64(0);
            let mut data = vec![0u8; 26205239];
            rng.fill_bytes(&mut data);

            file.seek(SeekFrom::Current(9590653)).unwrap();
            file.write_all(&data).unwrap();

            file.seek(SeekFrom::Current(26205239)).unwrap();
            file.write_all(&data).unwrap();

            verify_file(file);
        }

        #[test]
        fn power_of_2_holes_and_sizes() {
            let eight_mb = (8 * 1024 * 1024) as i64;
            let mut file = create_tempfile();
            let mut rng = StdRng::seed_from_u64(0);
            let mut data = vec![0u8; eight_mb as usize];
            rng.fill_bytes(&mut data);

            file.seek(SeekFrom::Current(eight_mb)).unwrap();
            file.write_all(&data).unwrap();

            file.seek(SeekFrom::Current(eight_mb)).unwrap();
            file.write_all(&data).unwrap();

            verify_file(file);
        }

        #[test]
        fn power_of_2_mb_hole_at_end() {
            let eight_mb = (8 * 1024 * 1024) as i64;
            let mut file = create_tempfile();
            let mut rng = StdRng::seed_from_u64(0);
            let mut data = vec![0u8; eight_mb as usize];
            rng.fill_bytes(&mut data);

            file.write_all(&data).unwrap();

            file.seek(SeekFrom::Current(eight_mb)).unwrap();
            file.write_all(&data).unwrap();

            file.set_len(eight_mb as u64 * 8).unwrap();

            verify_file(file);
        }

        fn verify_file(mut file: File) {
            let mut contents_actual = vec![];
            file.rewind().unwrap();
            iterate_blocks(&mut file, |block| match block {
                Block::Hole => contents_actual.extend_from_slice(&[0; BLOCK_LEN]),
                Block::Data(data) => contents_actual.extend_from_slice(data),
            })
            .unwrap();

            file.rewind().unwrap();
            let mut contents_expected = vec![];
            file.read_to_end(&mut contents_expected).unwrap();

            // We don't use assert_eq because it would print the contents which is too long.
            assert!(contents_actual == contents_expected);
        }
    }

    #[test]
    fn zeros_have_same_digest_as_hole() {
        let mut file1 = create_tempfile();
        let mut file2 = create_tempfile();

        write!(&mut file1, "hello").unwrap();
        write!(&mut file2, "hello").unwrap();

        file1.write_all(&vec![0; 9590653]).unwrap();
        file2.seek(SeekFrom::Current(9590653)).unwrap();

        write!(&mut file1, "foo").unwrap();
        write!(&mut file2, "foo").unwrap();

        assert_eq!(
            calculate_digest(&mut file1).unwrap(),
            calculate_digest(&mut file2).unwrap()
        );
    }

    #[test]
    fn only_zeros_have_same_digest_as_hole() {
        let mut file1 = create_tempfile();
        let mut file2 = create_tempfile();

        file1.write_all(&vec![0; 9590653]).unwrap();
        file2.set_len(9590653).unwrap();

        assert_eq!(
            calculate_digest(&mut file1).unwrap(),
            calculate_digest(&mut file2).unwrap()
        );
    }
}
