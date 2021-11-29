use byteorder::ReadBytesExt;
use std::cmp::Ordering;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};

/// A helper to read information from stable memory and write to a writer, using
/// a buffer. Expects the input to be length-prefix encoded.
pub fn read(input: &mut impl Read, output: impl Write) -> std::io::Result<u32> {
    let prefix = input.read_u32::<byteorder::LittleEndian>()?;
    let mut piped_bytes = 0_u32;
    let trimmed = input.take(prefix as u64);
    let mut buffered_trimmed_reader = BufReader::new(trimmed);
    let mut buffered_writer = BufWriter::new(output);
    loop {
        let buf = buffered_trimmed_reader.fill_buf()?;
        let len = buf.len(); // Must be stored in variable to avoid borrow error
        if len == 0 {
            // no bytes read indicate EOF.
            break;
        }
        piped_bytes += len as u32;
        buffered_writer.write_all(buf)?;
        buffered_trimmed_reader.consume(len);
    }
    buffered_writer.flush()?;
    match prefix.cmp(&piped_bytes) {
        Ordering::Equal => Ok(prefix),
        Ordering::Less=>  Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "This program piped through {} bytes, more than the expected {}. That's a bug. ",
                piped_bytes, prefix
            ),
        )),
        Ordering::Greater=>Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!(
                "The length prefix instructed a payload of length {}, but we could only read {} bytes. \
                This could mean that input did not actual come from a stable memory file for \
                a canister using that stable memory library.",
                prefix, piped_bytes
            ),
        ))
    }
}
