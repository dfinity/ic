use std::io::{self, Write};

pub struct ChunkWriter {
    skip: usize,
    size: usize,
    data: Vec<u8>,
}

impl From<ChunkWriter> for Vec<u8> {
    fn from(c: ChunkWriter) -> Vec<u8> {
        c.data
    }
}

impl AsRef<Vec<u8>> for ChunkWriter {
    fn as_ref(&self) -> &Vec<u8> {
        &self.data
    }
}
impl AsMut<Vec<u8>> for ChunkWriter {
    fn as_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }
}

impl ChunkWriter {
    pub fn new(skip: usize, size: usize) -> Self {
        ChunkWriter {
            skip,
            size,
            data: Vec::new(),
        }
    }

    fn write_chunk(&mut self, buf: &[u8]) {
        if self.size == 0 {
            return;
        }

        if self.skip >= buf.len() {
            self.skip -= buf.len();
            return;
        }
        let mut buf = &buf[self.skip..];
        self.skip = 0;

        if self.size < buf.len() {
            buf = &buf[..self.size];
            self.size = 0;
        } else {
            self.size -= buf.len();
        }

        self.data.extend_from_slice(buf);
    }
}

impl Write for ChunkWriter {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_chunk(buf);
        Ok(buf.len())
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write_chunk(buf);
        Ok(())
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ChunkWriter;
    use std::io::Write;

    #[test]
    fn empty() {
        let source: Vec<_> = (0..=1002).into_iter().map(|v| v as u8).collect();
        for skip in [0, 10, 1000] {
            for bytes in [0, 1, 9, 10, 11, 999, 1000, 1001] {
                let mut buf = ChunkWriter::new(skip, 0);
                buf.write_all(&source[0..bytes]).unwrap();
                assert_eq!(buf.as_ref(), &Vec::<u8>::new())
            }
        }
    }

    #[test]
    fn non_empty() {
        let source: Vec<_> = (0..=2002).into_iter().map(|v| v as u8).collect();
        for skip in [0, 10, 1000] {
            for size in [1, 10, 1000] {
                for bytes in [
                    0, 1, 2, 9, 10, 11, 12, 19, 20, 21, 999, 1000, 1001, 1002, 1009, 1010, 1011,
                    1999, 2000, 2001,
                ] {
                    let mut buf = ChunkWriter::new(skip, size);
                    buf.write_all(&source[0..bytes]).unwrap();
                    assert_eq!(
                        buf.as_ref(),
                        &source[skip..(skip + std::cmp::min(size, bytes.saturating_sub(skip)))],
                        "{skip}|{size}|{bytes}",
                    )
                }
            }
        }
    }
}
