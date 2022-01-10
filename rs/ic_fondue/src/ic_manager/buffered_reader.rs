use nonblock::NonBlockingReader;
use std::io::Read;
use std::os::unix::io::AsRawFd;

/// Couples together an object implementing Read and some buffer type.
/// The real utility of this type is in [BufferedReader::process_read_event],
/// which is a very general eliminator for incrementally processing
/// input while its available. Internally, we use [NonBlockingReader] to
/// make sure that [BufferedReader::process_read_event] never blocks.
pub struct BufferedReader<Rd: AsRawFd + Read, Buffer> {
    pub rd: Option<NonBlockingReader<Rd>>,
    pub buf: Buffer,
}

impl<Rd: AsRawFd + Read, Buffer: Default> BufferedReader<Rd, Buffer> {
    pub fn new(rd: Rd) -> Self {
        BufferedReader {
            rd: Some(NonBlockingReader::from_fd(rd).expect("Couldn't initialize reader")),
            buf: Buffer::default(),
        }
    }

    /// If the associated reader is still open, we read bytes from said reader
    /// and mutate the underlying buffer acording to some function. Returns
    /// `None` iff `self.rd == None`.
    pub fn process_read_event<F, R>(&mut self, f: F) -> Option<R>
    where
        F: Fn(&[u8], &mut Buffer) -> R,
    {
        if let Some(ref mut innr) = self.rd {
            let mut avail = Vec::new();
            if let Ok(_n) = innr.read_available(&mut avail) {
                if innr.is_eof() {
                    self.close();
                }
                Some(f(&avail, &mut self.buf))
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn close(&mut self) {
        self.rd = None;
    }
}

/// Implements a trivial non-persistent line buffer. It is non-persistent
/// in the sense that as soon as a call to [LineBuffer::read_line] returns
/// `Some`, that data is removed from the buffer.
pub struct LineBuffer {
    buf: Vec<u8>,
}

impl Default for LineBuffer {
    fn default() -> Self {
        LineBuffer { buf: Vec::new() }
    }
}

impl LineBuffer {
    pub fn new() -> Self {
        LineBuffer::default()
    }

    /// Extends the internal buffer from a slice.
    pub fn extend_from_slice(&mut self, other: &[u8]) {
        self.buf.extend_from_slice(other);
    }

    /// If there is a line available on the buffer, we remove it from the buffer
    /// and return it wrapped in a `Some`; If this returns `None`, the buffer is
    /// left unaltered.
    pub fn read_line(&mut self) -> Option<String> {
        if let Some(next_nl) = self.buf.iter().position(|c| *c == b'\n') {
            // Because Vec::split_off returns the tail; we need to split and swap
            let mut line = self.buf.split_off(next_nl + 1);
            std::mem::swap(&mut line, &mut self.buf);

            //pops the newline and carriage return, if any
            line.pop();
            if let Some(b'\r') = line.last() {
                line.pop();
            }

            String::from_utf8(line).ok()
        } else {
            None
        }
    }

    /// Clears the internal buffer, returning its contents as a string
    pub fn clear(&mut self) -> String {
        let mut rest = Vec::new();
        std::mem::swap(&mut rest, &mut self.buf);

        if let Ok(s) = String::from_utf8(rest) {
            s
        } else {
            String::new()
        }
    }
}

mod test {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn line_buffer_works_as_expected() {
        //! This makes sure that [Linebuffer::extend_from_slice] and
        //! [LineBuffer::read_line] are working as expected.
        let mut lb = LineBuffer::new();

        lb.extend_from_slice(b"testing the");
        assert_eq!(lb.read_line(), None);
        lb.extend_from_slice(b" line\nbuffering\r\nmechanism");
        assert_eq!(lb.read_line(), Some("testing the line".to_string()));
        assert_eq!(lb.read_line(), Some("buffering".to_string()));
        assert_eq!(lb.read_line(), None);
        assert_eq!(lb.clear(), "mechanism");
    }
}
