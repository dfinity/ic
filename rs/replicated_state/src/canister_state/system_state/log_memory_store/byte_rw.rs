#![allow(dead_code)] // TODO: don't forget to cleanup.

pub(crate) struct ByteWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> ByteWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn write_u8(&mut self, val: u8) {
        self.buf[self.pos] = val;
        self.pos += 1;
    }

    pub fn write_u16(&mut self, val: u16) {
        self.buf[self.pos..self.pos + 2].copy_from_slice(&val.to_le_bytes());
        self.pos += 2;
    }

    pub fn write_u32(&mut self, val: u32) {
        self.buf[self.pos..self.pos + 4].copy_from_slice(&val.to_le_bytes());
        self.pos += 4;
    }

    pub fn write_u64(&mut self, val: u64) {
        self.buf[self.pos..self.pos + 8].copy_from_slice(&val.to_le_bytes());
        self.pos += 8;
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }
}

pub(crate) struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn read_u8(&mut self) -> u8 {
        let val = self.buf[self.pos];
        self.pos += 1;
        val
    }

    pub fn read_u16(&mut self) -> u16 {
        let val = u16::from_le_bytes(self.buf[self.pos..self.pos + 2].try_into().unwrap());
        self.pos += 2;
        val
    }

    pub fn read_u32(&mut self) -> u32 {
        let val = u32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        val
    }

    pub fn read_u64(&mut self) -> u64 {
        let val = u64::from_le_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        val
    }

    pub fn read_bytes<const N: usize>(&mut self) -> [u8; N] {
        let val = self.buf[self.pos..self.pos + N].try_into().unwrap();
        self.pos += N;
        val
    }
}
