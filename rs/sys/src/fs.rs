use std::path::Path;

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
    };

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
