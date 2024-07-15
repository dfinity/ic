/// For a given struct, extract references to locations where raw
/// file descriptors are stored within this struct, recursively.
pub trait EnumerateInnerFileDescriptors {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut std::os::unix::io::RawFd>);
}
