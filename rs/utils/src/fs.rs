use std::ffi::{OsStr, OsString};
use std::{fs, io, io::Error, path::Path, path::PathBuf};

#[cfg(target_family = "unix")] // Otherwise, clippy complains about lack of use.
use std::io::ErrorKind::AlreadyExists;

#[cfg(target_os = "linux")]
use thiserror::Error;

#[cfg(target_family = "unix")]
use std::io::Write;

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

/// Recursively set permissions to readonly for all files under the given
/// `path`.
pub fn sync_and_mark_files_readonly<P>(path: P) -> std::io::Result<()>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    let metadata = path.metadata()?;

    if metadata.is_dir() {
        let entries = path.read_dir()?;

        for entry_result in entries {
            let entry = entry_result?;
            sync_and_mark_files_readonly(&entry.path())?;
        }
    } else {
        // We keep directories writable to be able to rename them or delete the
        // files.
        let mut permissions = metadata.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions).map_err(|e| {
            Error::new(
                e.kind(),
                format!(
                    "failed to set readonly permissions for file {}: {}",
                    path.display(),
                    e
                ),
            )
        })?;
    }
    sync_path(path)
}

#[cfg(any(target_os = "linux"))]
/// Copies only valid regions of file preserving the sparseness
/// of the file. Also utilizes copy_file_range which performs
/// in_kernel copy without the additional cost of transferring data
/// from the kernel to user space and then back into the kernel. Also
/// on certain file systems that support COW (btrfs/zfs), copy_file_range
/// is a metadata operation and is extremely efficient   
pub fn copy_file_sparse(from: &Path, to: &Path) -> io::Result<u64> {
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

#[cfg(any(target_family = "unix"))]
/// Write the given string to file `dest` in a crash-safe mannger
pub fn write_string_using_tmp_file<P>(dest: P, content: &str) -> io::Result<()>
where
    P: AsRef<Path>,
{
    write_using_tmp_file(dest, |f| f.write_all(content.as_bytes()))
}

#[cfg(any(target_family = "unix"))]
/// Serialize given protobuf message to file `dest` in a crash-safe manner
pub fn write_protobuf_using_tmp_file<P>(dest: P, message: &impl prost::Message) -> io::Result<()>
where
    P: AsRef<Path>,
{
    write_using_tmp_file(dest, |writer| {
        let mut buf = Vec::<u8>::new();
        message
            .encode(&mut buf)
            .expect("Protobuf serialization failed in write_protobuf_using_tmp_file");
        writer.write_all(&buf)?;
        Ok(())
    })
}

#[cfg(any(target_family = "unix"))]
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

#[cfg(any(target_family = "unix"))]
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
#[derive(Error, Clone, Debug, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
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
}
