use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::{fs, io, io::Error, path::Path, path::PathBuf};

#[cfg(target_family = "unix")] // Otherwise, clippy complains about lack of use.
use std::io::ErrorKind::AlreadyExists;
#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;

#[cfg(target_os = "linux")]
use thiserror::Error;

/// Represents an action that should be run when this objects runs out of scope,
/// unless it's explicitly deactivated.
///
/// This helps with implementing functions that have transactional semantics:
///
/// ```text
/// do_x()?;
/// let mut guard_x = OnScopeExit::new(|| undo_x());
///
/// // If this fails, undo_x() is called
/// do_y()?;
/// let mut guard_y = OnScopeExit::new(|| undo_y());
///
/// // If this fails, both undo_x and undo_y are called.
/// let goods = get_goods()?;
///
/// // The transaction is complete, deactivate the undo actions.
/// guard_x.deactivate();
/// guard_y.deactivate();
///
/// return goods;
/// ```
struct OnScopeExit<F>
where
    F: FnOnce(),
{
    action: Option<F>,
}

#[cfg(target_family = "unix")] // Otherwise, clippy complains about lack of use.
impl<F> OnScopeExit<F>
where
    F: FnOnce(),
{
    fn new(action: F) -> Self {
        Self {
            action: Some(action),
        }
    }

    fn deactivate(&mut self) {
        self.action = None
    }
}

impl<F> Drop for OnScopeExit<F>
where
    F: FnOnce(),
{
    fn drop(&mut self) {
        if let Some(action) = self.action.take() {
            action()
        }
    }
}

/// Atomically writes to `dst` file, using `tmp` as a buffer.
///
/// Creates `tmp` if necessary and removes it if write fails with an error.
///
/// # Pre-conditions
///   * `dst` and `tmp` are not directories.
///   * `dst` and `tmp` are on the same file system.
///
/// # Panics
///
///   Doesn't panic unless `action` panics.
#[cfg(target_family = "unix")]
pub fn write_atomically_using_tmp_file<PDst, PTmp, F>(
    dst: PDst,
    tmp: PTmp,
    action: F,
) -> io::Result<()>
where
    F: FnOnce(&mut io::BufWriter<&std::fs::File>) -> io::Result<()>,
    PDst: AsRef<Path>,
    PTmp: AsRef<Path>,
{
    let mut cleanup = OnScopeExit::new(|| {
        let _ = fs::remove_file(tmp.as_ref());
    });

    let f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true) // Otherwise we'd overwrite existing content
        .open(tmp.as_ref())?;
    {
        let mut w = io::BufWriter::new(&f);
        action(&mut w)?;
        w.flush()?;
    }
    f.sync_all()?;
    fs::rename(tmp.as_ref(), dst.as_ref())?;
    sync_path(dst.as_ref().parent().unwrap_or_else(|| Path::new("/")))?;

    cleanup.deactivate();
    Ok(())
}

/// Invokes sync_all on the file or directory located at given path.
pub fn sync_path<P>(path: P) -> std::io::Result<()>
where
    P: AsRef<Path>,
{
    // There is no special API for syncing directories, so we do the same thing
    // for both files and directories. This works because directories are just
    // files treated in a special way by the kernel.
    let f = std::fs::File::open(path.as_ref())?;
    f.sync_all().map_err(|e| {
        Error::new(
            e.kind(),
            format!("failed to sync path {}: {}", path.as_ref().display(), e),
        )
    })
}

#[cfg(target_os = "linux")]
/// Copies only valid regions of file preserving the sparseness
/// of the file. Also utilizes copy_file_range which performs
/// in_kernel copy without the additional cost of transferring data
/// from the kernel to user space and then back into the kernel. Also
/// on certain file systems that support COW (btrfs/zfs), copy_file_range
/// is a metadata operation and is extremely efficient   
pub fn copy_file_sparse(from: &Path, to: &Path) -> io::Result<u64> {
    if *crate::IS_WSL {
        return copy_file_sparse_portable(from, to);
    }

    use cvt::*;
    use fs::OpenOptions;
    use io::{ErrorKind, Read};
    use libc::{ftruncate64, lseek64};
    use std::os::unix::{fs::OpenOptionsExt, fs::PermissionsExt, io::AsRawFd};

    unsafe fn copy_file_range(
        fd_in: libc::c_int,
        off_in: *mut libc::loff_t,
        fd_out: libc::c_int,
        off_out: *mut libc::loff_t,
        len: libc::size_t,
        flags: libc::c_uint,
    ) -> libc::c_long {
        libc::syscall(
            libc::SYS_copy_file_range,
            fd_in,
            off_in,
            fd_out,
            off_out,
            len,
            flags,
        )
    }

    let mut reader = std::fs::File::open(from)?;

    let (mode, len) = {
        let metadata = reader.metadata()?;
        if !metadata.is_file() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "the source path is not an existing regular file",
            ));
        }
        (metadata.permissions().mode(), metadata.len())
    };

    let bytes_to_copy: i64 = len as i64;

    let mut writer = OpenOptions::new()
        // prevent world readable/writeable file in case of empty umask
        .mode(0o000)
        .write(true)
        .create(true)
        .truncate(true)
        .open(to)?;

    let fd_in = reader.as_raw_fd();
    let fd_out = writer.as_raw_fd();

    cvt_r(|| unsafe { libc::fchmod(fd_out, mode) })?;
    match cvt_r(|| unsafe { ftruncate64(fd_out, bytes_to_copy) }) {
        Ok(_) => {}
        Err(err) => return Err(err),
    };

    let mut srcpos: i64 = 0;

    let (mut can_handle_sparse, mut next_beg) = {
        let ret = unsafe { lseek64(fd_in, srcpos, libc::SEEK_DATA) };
        if ret == -1 {
            (false, 0)
        } else {
            (true, ret)
        }
    };

    let mut next_end: libc::loff_t = bytes_to_copy;
    if can_handle_sparse {
        let ret = unsafe { lseek64(fd_in, next_beg, libc::SEEK_HOLE) };
        if ret == -1 {
            can_handle_sparse = false;
        } else {
            next_end = ret
        }
    }

    let mut next_len = next_end - next_beg;
    let mut use_copy_file_range = true;

    while srcpos < bytes_to_copy {
        if srcpos != 0 {
            if can_handle_sparse {
                next_beg = match cvt(unsafe { lseek64(fd_in, srcpos, libc::SEEK_DATA) }) {
                    Ok(beg) => beg,
                    Err(err) => match err.raw_os_error() {
                        Some(libc::ENXIO) => {
                            // Remaining portion is hole
                            return Ok(srcpos as u64);
                        }
                        _ => {
                            return Err(err);
                        }
                    },
                };

                next_end = cvt(unsafe { lseek64(fd_in, next_beg, libc::SEEK_HOLE) })?;
                next_len = next_end - next_beg;
            } else {
                next_beg = srcpos;
                next_end = bytes_to_copy - srcpos;
            }
        }

        if next_len <= 0 {
            srcpos = next_end;
            continue;
        }

        let num = if use_copy_file_range {
            match cvt(unsafe {
                copy_file_range(
                    fd_in,
                    &mut next_beg,
                    fd_out,
                    &mut next_beg,
                    next_len as usize,
                    0,
                )
            }) {
                Ok(n) => n as isize,
                Err(err) => match err.raw_os_error() {
                    // Try fallback if either:
                    // - Kernel version is < 4.5 (ENOSYS)
                    // - Files are mounted on different fs (EXDEV)
                    // - copy_file_range is disallowed, for example by seccomp (EPERM)
                    Some(libc::ENOSYS) | Some(libc::EPERM) => {
                        use_copy_file_range = false;
                        continue;
                    }
                    Some(libc::EXDEV) | Some(libc::EINVAL) => {
                        use_copy_file_range = false;
                        continue;
                    }
                    _ => {
                        return Err(err);
                    }
                },
            }
        } else {
            if can_handle_sparse {
                cvt(unsafe { lseek64(fd_in, next_beg, libc::SEEK_SET) })?;
                if next_beg != 0 {
                    cvt(unsafe { lseek64(fd_out, next_beg, libc::SEEK_SET) })?;
                }
            }
            const DEFAULT_BUF_SIZE: usize = 16 * 1024;
            let mut buf = unsafe {
                let buf: [u8; DEFAULT_BUF_SIZE] = std::mem::zeroed();
                buf
            };

            let mut written = 0;
            while next_len > 0 {
                let slice_len = next_len.min(DEFAULT_BUF_SIZE as i64) as usize;
                let len = match reader.read(&mut buf[..slice_len]) {
                    Ok(0) => {
                        // break early out of copy loop, because nothing is to be read anymore
                        srcpos += written;
                        break;
                    }
                    Ok(len) => len,
                    Err(ref err) if err.kind() == ErrorKind::Interrupted => continue,
                    Err(err) => return Err(err),
                };
                writer.write_all(&buf[..len])?;
                written += len as i64;
                next_len -= len as i64;
            }
            written as isize
        };
        srcpos += num as i64;
    }

    Ok(srcpos as u64)
}

#[cfg(not(target_os = "linux"))]
pub fn copy_file_sparse(from: &Path, to: &Path) -> io::Result<u64> {
    copy_file_sparse_portable(from, to)
}

fn copy_file_sparse_portable(from: &Path, to: &Path) -> io::Result<u64> {
    fs::copy(from, to)
}

/// Atomically write to `dst` file, using a random file in the parent directory
/// of `dst` as the temporary file.
///
/// # Pre-conditions
///   * `dst` is not a directory.
///   * The parent directory of `dst` must be writeable.
///
/// # Panics
///
///   Doesn't panic unless `action` panics.
#[cfg(target_family = "unix")]
pub fn write_atomically<PDst, F>(dst: PDst, action: F) -> io::Result<()>
where
    F: FnOnce(&mut io::BufWriter<&std::fs::File>) -> io::Result<()>,
    PDst: AsRef<Path>,
{
    // `.parent()` returns `None` for either `/` or a prefix (e.g. 'c:\\` on
    // windows). `write_atomically` is only available on UNIX, so we default to
    // `/` in case `.parent()` returns `None`.
    let tmp_path = dst
        .as_ref()
        .parent()
        .unwrap_or_else(|| Path::new("/"))
        .join(tmp_name());

    write_atomically_using_tmp_file(dst, tmp_path.as_path(), action)
}

/// Append .tmp to given file path
///
/// Examples:
/// bla.txt -> bla.txt.tmp
/// /tmp/bla.txt -> /tmp/bla.txt.tmp
/// /tmp/bla -> /tmp/bla.tmp
/// /tmp/ -> /tmp.tmp
pub fn get_tmp_for_path<P>(path: P) -> PathBuf
where
    P: AsRef<Path>,
{
    let extension = match path.as_ref().extension() {
        None => OsString::from("tmp"),
        Some(extension) => {
            let mut extension = OsString::from(extension);
            extension.push(OsStr::new(".tmp"));
            extension
        }
    };
    path.as_ref().with_extension(extension)
}

#[cfg(target_family = "unix")]
/// Write the given string to file `dest` in a crash-safe mannger
pub fn write_string_using_tmp_file<P>(dest: P, content: &str) -> io::Result<()>
where
    P: AsRef<Path>,
{
    write_using_tmp_file(dest, |f| f.write_all(content.as_bytes()))
}

#[cfg(target_family = "unix")]
/// Serialize given protobuf message to file `dest` in a crash-safe manner
pub fn write_protobuf_using_tmp_file<P>(dest: P, message: &impl prost::Message) -> io::Result<()>
where
    P: AsRef<Path>,
{
    write_using_tmp_file(dest, |writer| {
        let encoded_message = message.encode_to_vec();
        writer.write_all(&encoded_message)?;
        Ok(())
    })
}

#[cfg(target_family = "unix")]
/// Determines if two regular POSIX files reference the same data, i.e., both point to the same
/// inode number. Returns `true` if the files are hard links to the same inode, `false` if either
/// file is not a regular file. If either file does not exist, an error with
/// `err.kind() == NotFound` is returned.
pub fn are_hard_links_to_the_same_inode<P, Q>(p: &P, q: &Q) -> io::Result<bool>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    if !is_regular_file(p)? || !is_regular_file(q)? {
        return Ok(false);
    }
    let original_metadata = fs::metadata(p)?;
    let link_metadata = fs::metadata(q)?;
    Ok(original_metadata.ino() == link_metadata.ino())
}

#[cfg(target_family = "unix")]
/// Create a new hard link to an existing file. Returns an error if the original path is not a file
/// or doesn't exist, or if the link already exists.
pub fn create_hard_link_to_existing_file<P, Q>(original: &P, link: &Q) -> io::Result<()>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    fs::hard_link(original, link)
}

#[cfg(target_family = "unix")]
/// Checks if `file_name` points to an existing, POSIX regular file, which the current process can
/// access. In particular, this function returns true for regular files (and hard links), and false
/// for directories and symbolic links.
pub fn is_regular_file<P>(file_name: &P) -> io::Result<bool>
where
    P: AsRef<Path>,
{
    let symlink_metadata = std::fs::symlink_metadata(file_name)?;
    Ok(symlink_metadata.is_file())
}

#[cfg(target_family = "unix")]
/// Open an existing file for writing to it.
pub fn open_existing_file_for_write<P>(path: P) -> io::Result<std::fs::File>
where
    P: AsRef<Path>,
{
    std::fs::OpenOptions::new()
        .write(true)
        .read(true)
        .create(false)
        .open(&path)
}

#[cfg(target_family = "unix")]
/// Removes a file from the filesystem.
pub fn remove_file<P>(path: P) -> io::Result<()>
where
    P: AsRef<Path>,
{
    std::fs::remove_file(path)
}

#[cfg(target_family = "unix")]
/// Create and open a file exclusively with the given name.
///
/// If the file already exists, attempt to remove the file and retry.
fn create_file_exclusive_and_open<P>(f: P) -> io::Result<std::fs::File>
where
    P: AsRef<Path>,
{
    loop {
        // Important is to use create_new, which on Unix uses O_CREATE | O_EXCL
        // https://github.com/rust-lang/rust/blob/5ab502c6d308b0ccac8127c0464e432334755a60/library/std/src/sys/unix/fs.rs#L774
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(f.as_ref());

        match file {
            Err(ref e) if e.kind() == AlreadyExists => {
                std::fs::remove_file(f.as_ref())?;
            }
            Err(e) => {
                return Err(e);
            }
            Ok(f) => {
                return Ok(f);
            }
        }
    }
}

#[cfg(target_family = "unix")]
/// Write to file `dest` using `action` in a crash-safe manner
///
/// A new temporary file `dest.tmp` will be created. If it already exists,
/// it will be deleted first. The file will be opened in exclusive mode
/// and `action` executed with the BufWriter to that file.
///
/// The buffer and file will then be fsynced followed by renaming the
/// `dest.tmp` to `dest`. Target file `dest` will be overwritten in that
/// process if it already exists.
///
/// After renaming, the parent directory of `dest` will be fsynced.
///
/// The function will fail if `dest` exists but is a directory.
pub fn write_using_tmp_file<P, F>(dest: P, action: F) -> io::Result<()>
where
    P: AsRef<Path>,
    F: FnOnce(&mut io::BufWriter<&std::fs::File>) -> io::Result<()>,
{
    let dest_tmp = get_tmp_for_path(&dest);

    {
        let file = create_file_exclusive_and_open(&dest_tmp)?;
        let mut w = io::BufWriter::new(&file);
        action(&mut w)?;
        w.flush()?;
        file.sync_all()?;
    }

    let dest = dest.as_ref();
    fs::rename(dest_tmp.as_path(), dest)?;

    sync_path(dest.parent().unwrap_or_else(|| Path::new("/")))?;
    Ok(())
}

#[cfg(target_family = "unix")]
fn tmp_name() -> String {
    /// The character length of the random string used for temporary file names.
    const TMP_NAME_LEN: usize = 7;

    use rand::{distributions::Alphanumeric, Rng};

    let mut rng = rand::thread_rng();
    std::iter::repeat(())
        .map(|_| rng.sample(Alphanumeric))
        .map(char::from)
        .take(TMP_NAME_LEN)
        .collect()
}

#[cfg(target_os = "linux")]
#[derive(Clone, Eq, PartialEq, Debug, Error)]
pub enum CopyFileRangeAllError {
    #[error(transparent)]
    Nix(#[from] nix::Error),
    #[error("zero bytes copied")]
    WriteZero,
}

/// Copy a range of data from one file to another
///
/// As opposed to `nix::fcntl::copy_file_range` that it is based on, this
/// function either copies all bytes or returns an error
#[cfg(target_os = "linux")]
pub fn copy_file_range_all(
    src: &std::fs::File,
    mut src_offset: i64,
    dst: &std::fs::File,
    mut dst_offset: i64,
    len: usize,
) -> Result<(), CopyFileRangeAllError> {
    use std::os::unix::io::AsRawFd;
    let mut copied_total = 0;
    while copied_total < len {
        let copied = nix::fcntl::copy_file_range(
            src.as_raw_fd(),
            Some(&mut src_offset),
            dst.as_raw_fd(),
            Some(&mut dst_offset),
            len - copied_total,
        );
        match copied {
            Ok(0) => return Err(CopyFileRangeAllError::WriteZero),
            Ok(copied) => copied_total += copied,
            Err(nix::errno::Errno::EINTR) | Err(nix::errno::Errno::EAGAIN) => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

/// Reads and then writes a chunk of size `size` starting at `offset` in the file at `path`.
/// This defragments the file partially on some COW capable file systems
#[cfg(target_family = "unix")]
pub fn defrag_file_partially(path: &Path, offset: u64, size: usize) -> std::io::Result<()> {
    use std::os::unix::prelude::FileExt;

    let mut content = vec![0; size];
    let f = std::fs::OpenOptions::new()
        .write(true)
        .read(true)
        .create(false)
        .open(path)?;
    f.read_exact_at(&mut content[..], offset)?;
    f.write_all_at(&content, offset)?;
    Ok(())
}

/// Write a slice of slices to a file
/// Replacement for std::io::Write::write_all_vectored as long as it's nightly rust only
pub fn write_all_vectored(file: &mut fs::File, bufs: &[&[u8]]) -> std::io::Result<()> {
    use io::ErrorKind;
    use io::IoSlice;

    let mut slices: Vec<IoSlice> = bufs.iter().map(|s| IoSlice::new(s)).collect();
    let mut front = 0;
    // Guarantee that bufs is empty if it contains no data,
    // to avoid calling write_vectored if there is no data to be written.
    while front < slices.len() && slices[front].is_empty() {
        front += 1;
    }
    while front < slices.len() {
        match file.write_vectored(&slices[front..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "failed to write whole buffer",
                ));
            }
            Ok(n) => {
                // drop n bytes from the front of the data
                advance_slices(&mut slices, &mut front, n, bufs);
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Advance a slice of IoSlices by `drop`. Will increment `front` to
/// point past fully used slices, and modify slices if we point to the
/// middle of a slice
fn advance_slices<'a>(
    slices: &mut [io::IoSlice<'a>],
    front: &mut usize,
    drop: usize,
    bufs: &'a [&'a [u8]],
) {
    let mut written = drop;
    while written > 0 && *front < slices.len() {
        let first_len = slices[*front].len();
        if written >= first_len {
            // drop the first slice
            written -= first_len;
            *front += 1;
        } else {
            // drop only part of the first slice
            let new_data_len = first_len - written;
            let new_data: &[u8] = &bufs[*front][(bufs[*front].len() - new_data_len)..];
            let new_slice = io::IoSlice::new(new_data);
            slices[*front] = new_slice;
            written = 0;
        }
    }
}

/// Error indicating that a call to clone_file has failed.
#[derive(Debug)]
pub enum FileCloneError {
    /// The underlying file system doesn't support reflinks (file clones).
    OperationNotSupported,
    /// Source and destination are not on the same filesystem.
    DifferentFileSystems,
    /// Unexpected IO error happened when we called the syscall that clones a
    /// file.
    IoError(std::io::Error),
}

impl std::fmt::Display for FileCloneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OperationNotSupported => write!(f, "filesystem doesn't support reflinks"),
            Self::DifferentFileSystems => write!(f, "src and dst aren't on the same filesystem"),
            Self::IoError(err) => write!(f, "IO error: {}", err),
        }
    }
}

impl std::error::Error for FileCloneError {}

/// Makes a copy-on-write copy of file located at src into dst.  This is
/// typically a much faster operation than copying file contents, but it's
/// supported not by all file systems. Note that cloning is only supported
/// between paths located on the same filesystem.
///
/// # Errors
///
/// * Returns Err(OperationNotSupported) if the underlying filesystem doesn't
///   support clones.
///
/// * Returns low-level Err(IoError(e)) if one of files can't be open or the
///   corresponding syscall fails for some reason.
pub fn clone_file(src: &Path, dst: &Path) -> Result<(), FileCloneError> {
    if *crate::IS_WSL {
        Err(FileCloneError::OperationNotSupported)
    } else {
        clone_file_impl(src, dst)
    }
}

fn handle_last_os_error() -> FileCloneError {
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS) => FileCloneError::OperationNotSupported,
        // EOPNOTSUPP and ENOTSUP have the same value on Linux, but different
        // values on macOS.  So ENOTSUP is handled in a separate clause compiled
        // conditionally to avoid "unreachable-patterns" warning.
        #[cfg(target_os = "macos")]
        Some(libc::ENOTSUP) => FileCloneError::OperationNotSupported,
        Some(libc::EXDEV) => FileCloneError::DifferentFileSystems,
        _ => FileCloneError::IoError(err),
    }
}

#[cfg(target_os = "linux")]
fn clone_file_impl(src: &Path, dst: &Path) -> Result<(), FileCloneError> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    // This number is obtained by running the following C program:
    //
    // ```
    // #include <linux/fs.h>
    // #include <stdio.h>
    // int main() { printf("FICLONE = %d\n", FICLONE); }
    // ```
    //
    // The constant is fixed on all Linux kernels and isn't going to change as
    // this would break binary compatibility.
    //
    // NOTE: we use a macro here because the type of the second argument of
    // libc::ioctl is different on different platforms (can be either u_long or
    // u32).
    macro_rules! FICLONE_IO_REQ {
        () => {
            1074041865
        };
    }

    let src_f = OpenOptions::new()
        .read(true)
        .open(src)
        .map_err(FileCloneError::IoError)?;

    let dst_f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(dst)
        .map_err(FileCloneError::IoError)?;

    // See https://www.man7.org/linux/man-pages/man2/ioctl_ficlonerange.2.html
    //
    // int ioctl(int dest_fd, FICLONE, int src_fd);
    let ec = unsafe { libc::ioctl(dst_f.as_raw_fd(), FICLONE_IO_REQ!(), src_f.as_raw_fd()) };
    if ec < 0 {
        Err(handle_last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn clone_file_impl(src: &Path, dst: &Path) -> Result<(), FileCloneError> {
    use libc::{c_char, c_int};
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    extern "C" {
        fn clonefile(src: *const c_char, dst: *const c_char, flags: c_int) -> c_int;
    }

    // Arguments of clonefile must be null-terminated, Rust Paths aren't.
    fn cstring(p: &Path) -> Result<CString, FileCloneError> {
        CString::new(p.as_os_str().as_bytes()).map_err(|e| FileCloneError::IoError(e.into()))
    }

    let ec = unsafe { clonefile(cstring(src)?.as_ptr(), cstring(dst)?.as_ptr(), 0) };
    if ec < 0 {
        Err(handle_last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn clone_file_impl(_src: &Path, _dst: &Path) -> Result<(), FileCloneError> {
    Err(FileCloneError::OperationNotSupported)
}

#[cfg(test)]
mod tests {
    use super::advance_slices;
    use super::io::IoSlice;
    use super::write_atomically_using_tmp_file;

    #[test]
    fn test_write_success() {
        let tmp_dir = tempfile::TempDir::new().expect("failed to create a temporary directory");
        let dst = tmp_dir.path().join("target.txt");
        let tmp = tmp_dir.path().join("target_tmp.txt");

        write_atomically_using_tmp_file(&dst, &tmp, |buf| {
            use std::io::Write;

            buf.write_all(b"test")?;
            Ok(())
        })
        .expect("failed to write atomically");

        assert!(!tmp.exists());
        assert_eq!(
            std::fs::read(&dst).expect("failed to read destination file"),
            b"test".to_vec()
        );
    }

    #[test]
    fn test_write_failure() {
        let tmp_dir = tempfile::TempDir::new().expect("failed to create a temporary directory");
        let dst = tmp_dir.path().join("target.txt");
        let tmp = tmp_dir.path().join("target_tmp.txt");

        std::fs::write(&dst, b"original contents")
            .expect("failed to write to the destination file");

        let result = write_atomically_using_tmp_file(&dst, &tmp, |buf| {
            use std::io::Write;

            buf.write_all(b"new shiny contents")?;
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "something went wrong",
            ))
        });

        assert!(!tmp.exists());
        assert!(
            result.is_err(),
            "expected action result to be an error, got {:?}",
            result
        );
        assert_eq!(
            std::fs::read(&dst).expect("failed to read destination file"),
            b"original contents".to_vec()
        );
    }

    #[test]
    fn test_advance_slices() {
        let slice_size = 4096;
        let num_slices = 5;
        let data = vec![vec![1u8; slice_size]; num_slices];
        let bufs: &[&[u8]] = &data.iter().map(|v| v.as_slice()).collect::<Vec<&[u8]>>();
        let mut slices: Vec<IoSlice> = bufs.iter().map(|s| IoSlice::new(s)).collect();
        let mut front = 0;

        // advance two full slices
        advance_slices(&mut slices, &mut front, 2 * slice_size, bufs);
        assert_eq!(2, front);
        for i in front..num_slices {
            assert_eq!(*slices[i], *bufs[i]);
        }

        // advance 1.5 slices
        advance_slices(&mut slices, &mut front, slice_size + slice_size / 2, bufs);
        assert_eq!(3, front);
        assert_eq!(*slices[front], bufs[front][slice_size / 2..]);
        for i in (front + 1)..num_slices {
            assert_eq!(*slices[i], *bufs[i]);
        }

        // advance 1/4 slice
        advance_slices(&mut slices, &mut front, slice_size / 4, bufs);
        assert_eq!(3, front);
        assert_eq!(*slices[front], bufs[front][3 * slice_size / 4..]);
        for i in (front + 1)..num_slices {
            assert_eq!(*slices[i], *bufs[i]);
        }

        // advance the remaining 1.25 slices
        advance_slices(&mut slices, &mut front, slice_size + slice_size / 4, bufs);
        assert_eq!(5, front);
    }

    #[cfg(target_family = "unix")]
    mod are_hard_links_to_the_same_inode {
        use crate::fs::write_string_using_tmp_file;
        use crate::fs::{are_hard_links_to_the_same_inode, create_hard_link_to_existing_file};
        use assert_matches::assert_matches;
        use std::fs;
        use std::io::ErrorKind::NotFound;

        #[test]
        fn should_return_true_for_hard_linked_files() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let source = temp_dir.as_ref().join("source_file");
            write_string_using_tmp_file(&source, "test content").expect("error writing to file");
            let link = temp_dir.as_ref().join("link");
            create_hard_link_to_existing_file(&source, &link).expect("error creating hard link");
            assert_matches!(are_hard_links_to_the_same_inode(&source, &link), Ok(true));
        }

        #[test]
        fn should_return_false_for_symbolic_link() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let test_file = temp_dir.as_ref().join("source_file");
            write_string_using_tmp_file(&test_file, "test content").expect("error writing to file");
            let sym_link = temp_dir.as_ref().join("link");
            std::os::unix::fs::symlink(&test_file, &sym_link)
                .expect("error creating symbolic link");
            assert_matches!(
                are_hard_links_to_the_same_inode(&test_file, &sym_link),
                Ok(false)
            );
        }

        #[test]
        fn should_return_false_for_directory_and_file() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let test_file = temp_dir.as_ref().join("first");
            write_string_using_tmp_file(&test_file, "test content").expect("error writing to file");
            let test_dir = temp_dir.as_ref().join("second");
            fs::create_dir(&test_dir).expect("error creating directory");
            assert_matches!(
                are_hard_links_to_the_same_inode(&test_file, &test_dir),
                Ok(false)
            );
        }

        #[test]
        fn should_return_false_for_same_directory_twice() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let test_dir = temp_dir.as_ref().join("subdir");
            fs::create_dir(&test_dir).expect("error creating directory");
            assert_matches!(
                are_hard_links_to_the_same_inode(&test_dir, &test_dir),
                Ok(false)
            );
        }

        #[test]
        fn should_return_false_for_copied_files() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let source = temp_dir.as_ref().join("source_file");
            write_string_using_tmp_file(&source, "test content").expect("error writing to file");
            let copy = temp_dir.as_ref().join("copy");
            fs::copy(&source, &copy).expect("error copying files");
            assert_matches!(are_hard_links_to_the_same_inode(&source, &copy), Ok(false));
        }

        #[test]
        fn should_return_not_found_error_if_source_does_not_exist() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let original = temp_dir.as_ref().join("original");
            let link = temp_dir.as_ref().join("link");
            write_string_using_tmp_file(&link, "test content").expect("error writing to file");
            assert_matches!(
                are_hard_links_to_the_same_inode(&original, &link),
                Err(err) if err.kind() == NotFound);
        }

        #[test]
        fn should_return_not_found_error_if_destination_does_not_exist() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let original = temp_dir.as_ref().join("original");
            let link = temp_dir.as_ref().join("link");
            write_string_using_tmp_file(&original, "test content").expect("error writing to file");
            assert_matches!(
                are_hard_links_to_the_same_inode(&original, &link),
                Err(err) if err.kind() == NotFound);
        }

        #[test]
        fn should_return_not_found_error_if_neither_source_nor_destination_exists() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let original = temp_dir.as_ref().join("original");
            let link = temp_dir.as_ref().join("link");
            assert_matches!(
                are_hard_links_to_the_same_inode(&original, &link),
                Err(err) if err.kind() == NotFound);
        }
    }

    #[cfg(target_family = "unix")]
    mod create_hard_link_to_existing_file {
        use super::super::create_hard_link_to_existing_file;
        use super::super::write_string_using_tmp_file;
        use assert_matches::assert_matches;
        use std::fs;
        use std::io::ErrorKind;

        #[test]
        fn should_succeed_when_creating_a_hard_link_to_a_regular_file() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let source = temp_dir.as_ref().join("source_file");
            write_string_using_tmp_file(&source, "test content").expect("error writing to file");
            let destination = temp_dir.as_ref().join("destination");
            assert_matches!(
                create_hard_link_to_existing_file(&source, &destination),
                Ok(())
            );
        }

        #[test]
        fn should_return_an_error_when_creating_a_hard_link_to_a_directory() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let source = temp_dir.as_ref().join("source_file");
            fs::create_dir(&source).expect("error creating directory");
            let destination = temp_dir.as_ref().join("destination");
            assert_matches!(create_hard_link_to_existing_file(&source, &destination),
                Err(ref e) if e.kind() == ErrorKind::PermissionDenied
            );
        }

        #[test]
        fn should_return_an_error_when_creating_a_hard_link_to_a_file_that_does_not_exists() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let source = temp_dir.as_ref().join("source_file");
            let destination = temp_dir.as_ref().join("destination");
            assert_matches!(create_hard_link_to_existing_file(&source, &destination),
                Err(ref e) if e.kind() == ErrorKind::NotFound
            );
        }

        #[test]
        fn should_return_an_error_when_creating_a_hard_link_where_the_destination_already_exists() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let source = temp_dir.as_ref().join("source_file");
            write_string_using_tmp_file(&source, "test content").expect("error writing to file");
            let destination = temp_dir.as_ref().join("destination");
            fs::copy(&source, &destination).expect("error copying file");
            assert!(destination.exists());
            assert_matches!(create_hard_link_to_existing_file(&source, &destination),
                Err(ref e) if e.kind() == ErrorKind::AlreadyExists
            );
        }
    }

    #[cfg(target_family = "unix")]
    mod is_regular_file {
        use crate::fs::{
            create_hard_link_to_existing_file, is_regular_file, write_string_using_tmp_file,
        };
        use assert_matches::assert_matches;
        use std::fs;
        use std::io::ErrorKind::NotFound;

        #[test]
        fn should_return_true_if_file_is_a_regular_file() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let test_file = temp_dir.as_ref().join("test_file");
            write_string_using_tmp_file(&test_file, "test content").expect("error writing to file");
            assert!(
                is_regular_file(&test_file).expect("error determining if file is a regular file")
            );
        }

        #[test]
        fn should_return_true_if_file_is_a_hard_link_to_a_regular_file() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let test_file = temp_dir.as_ref().join("test_file");
            write_string_using_tmp_file(&test_file, "test content").expect("error writing to file");
            let test_hard_link = temp_dir.as_ref().join("test_link");
            create_hard_link_to_existing_file(&test_file, &test_hard_link)
                .expect("error creating hard link");
            assert!(
                is_regular_file(&test_file).expect("error determining if file is a regular file")
            );
        }

        #[test]
        fn should_return_false_if_file_is_a_directory() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let test_file = temp_dir.as_ref().join("test_file");
            fs::create_dir(&test_file).expect("error creating directory");
            assert!(
                !is_regular_file(&test_file).expect("error determining if file is a regular file")
            );
        }

        #[test]
        fn should_return_false_if_file_is_a_symbolic_link_to_a_file() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let test_file = temp_dir.as_ref().join("test_file");
            write_string_using_tmp_file(&test_file, "test content").expect("error writing to file");
            let test_sym_link = temp_dir.as_ref().join("test_sym_link");
            std::os::unix::fs::symlink(&test_file, &test_sym_link)
                .expect("error creating symbolic link");
            assert!(!is_regular_file(&test_sym_link)
                .expect("error determining if file is a regular file"));
        }

        #[test]
        fn should_return_false_if_file_is_a_hard_link_to_a_symbolic_link_to_a_file() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let test_file = temp_dir.as_ref().join("test_file");
            write_string_using_tmp_file(&test_file, "test content").expect("error writing to file");
            let test_sym_link = temp_dir.as_ref().join("test_sym_link");
            std::os::unix::fs::symlink(&test_file, &test_sym_link)
                .expect("error creating symbolic link");
            let test_hard_link = temp_dir.as_ref().join("test_hard_link");
            create_hard_link_to_existing_file(&test_sym_link, &test_hard_link)
                .expect("error creating hard link");
            assert!(!is_regular_file(&test_hard_link)
                .expect("error determining if file is a regular file"));
        }

        #[test]
        fn should_return_not_found_error_if_file_does_not_exist() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let test_file = temp_dir.as_ref().join("test_file");
            assert_matches!(
                is_regular_file(&test_file),
                Err(err) if err.kind() == NotFound
            );
        }
    }

    #[cfg(target_family = "unix")]
    mod open_existing_file_for_write {
        use crate::fs::{open_existing_file_for_write, write_string_using_tmp_file};
        use assert_matches::assert_matches;
        use std::fs::create_dir;
        use std::fs::Permissions;
        use std::io::ErrorKind::{NotFound, PermissionDenied};
        use std::os::unix::fs::PermissionsExt;

        #[test]
        fn should_succeed_if_file_exists() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let test_file = temp_dir.as_ref().join("test_file");
            write_string_using_tmp_file(&test_file, "test content").expect("error writing to file");
            open_existing_file_for_write(test_file).expect("error opening existing file for write");
        }

        #[test]
        fn should_return_error_if_file_does_not_exist() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let test_file = temp_dir.as_ref().join("test_file");
            assert_matches!(
                open_existing_file_for_write(test_file),
                Err(err) if err.kind() == NotFound
            );
        }

        #[test]
        fn should_return_error_if_file_is_a_directory() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let test_file = temp_dir.as_ref().join("test_file");
            create_dir(&test_file).expect("error creating directory");
            assert_matches!(
                open_existing_file_for_write(test_file),
                Err(err) if format!("{:?}", err).contains("Is a directory")  // ErrorKind::IsADirectory is unstable
            );
        }

        #[test]
        fn should_return_error_if_permission_is_denied() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let test_file = temp_dir.as_ref().join("test_file");
            write_string_using_tmp_file(&test_file, "test content").expect("error writing to file");
            std::fs::set_permissions(&test_file, Permissions::from_mode(0o400))
                .expect("Could not set the permissions of the test file.");
            assert_matches!(
                open_existing_file_for_write(&test_file),
                Err(err) if err.kind() == PermissionDenied
            );
            std::fs::set_permissions(&test_file, Permissions::from_mode(0o700)).expect(
                "failed to change permissions of test_file so that writing is possible \
                again, so that the directory can automatically be cleaned up",
            );
        }
    }

    #[cfg(target_family = "unix")]
    mod remove_file {
        use crate::fs::{remove_file, write_string_using_tmp_file};
        use assert_matches::assert_matches;
        use std::fs::create_dir;
        use std::fs::Permissions;
        use std::io::ErrorKind::{NotFound, PermissionDenied};
        use std::os::unix::fs::PermissionsExt;

        #[test]
        fn should_succeed_if_file_exists() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let test_file = temp_dir.as_ref().join("test_file");
            write_string_using_tmp_file(&test_file, "test content").expect("error writing to file");
            remove_file(&test_file).expect("error removing file");
        }

        #[test]
        fn should_return_error_if_file_does_not_exist() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let test_file = temp_dir.as_ref().join("test_file");
            assert_matches!(
                remove_file(test_file),
                Err(err) if err.kind() == NotFound
            );
        }

        #[test]
        fn should_return_error_if_file_is_a_directory() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let test_file = temp_dir.as_ref().join("test_file");
            create_dir(&test_file).expect("error creating directory");
            #[cfg(target_os = "linux")]
            assert_matches!(
                remove_file(test_file),
                Err(err) if format!("{:?}", err).contains("Is a directory")
            );
            #[cfg(target_os = "macos")]
            assert_matches!(
                remove_file(test_file),
                Err(err) if err.kind() == PermissionDenied
            );
        }

        #[test]
        fn should_return_error_if_permission_is_denied() {
            let temp_dir =
                tempfile::TempDir::new().expect("failed to create a temporary directory");
            let test_file = temp_dir.as_ref().join("test_file");
            write_string_using_tmp_file(&test_file, "test content").expect("error writing to file");
            std::fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o400))
                .expect("Could not set the permissions of the test file.");
            assert_matches!(
                remove_file(test_file),
                Err(err) if err.kind() == PermissionDenied
            );
            std::fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o700)).expect(
                "failed to change permissions of test_file so that writing is possible \
                again, so that the directory can automatically be cleaned up",
            );
        }
    }
}
