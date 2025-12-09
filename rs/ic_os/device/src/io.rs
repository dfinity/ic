use std::io;
use std::path::Path;
use std::time::Duration;

/// Retries a function, returning its result if it succeeds, or retrying if it fails with
/// the specified error.
pub fn retry_if_io_error<T>(
    error: nix::Error,
    mut f: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    const MAX_ATTEMPTS: i32 = 100;
    let mut attempts = 0;
    loop {
        match f() {
            Ok(res) => return Ok(res),
            Err(e) => {
                if e.raw_os_error() == Some(error as i32) {
                    attempts += 1;
                    if attempts >= MAX_ATTEMPTS {
                        return Err(e);
                    }
                    std::thread::sleep(Duration::from_millis((100 * attempts) as u64));
                } else {
                    return Err(e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_if_io_error_ebusy() {
        let mut attempts = 0;
        let result = retry_if_io_error(nix::Error::EBUSY, || {
            attempts += 1;
            if attempts < 3 {
                Err(io::Error::from_raw_os_error(nix::Error::EBUSY as i32))
            } else {
                Ok("success")
            }
        });

        assert_eq!(result.unwrap(), "success");
        assert_eq!(attempts, 3);
    }

    #[test]
    fn test_retry_if_io_error_different_error() {
        let result: Result<(), _> =
            retry_if_io_error(nix::Error::EBUSY, || Err(io::Error::other("fail")));
        assert!(result.is_err());
    }

    #[test]
    fn test_retry_if_io_error_enoent() {
        let mut attempts = 0;
        let result = retry_if_io_error(nix::Error::ENOENT, || {
            attempts += 1;
            if attempts < 3 {
                Err(io::Error::from_raw_os_error(nix::Error::ENOENT as i32))
            } else {
                Ok("success")
            }
        });

        assert_eq!(result.unwrap(), "success");
        assert_eq!(attempts, 3);
    }

    #[test]
    fn test_retry_if_io_error_wrong_error_no_retry() {
        let mut attempts = 0;
        let result = retry_if_io_error(nix::Error::EBUSY, || {
            attempts += 1;
            Err(io::Error::from_raw_os_error(nix::Error::ENOENT as i32))
        });

        assert!(result.is_err());
        assert_eq!(attempts, 1);
    }

    #[test]
    fn test_wait_for_path_exists() {
        use std::fs::File;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test_file");
        File::create(&file_path).unwrap();

        let result = wait_for_path(&file_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_wait_for_path_timeout() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("nonexistent_file");

        let result = wait_for_path(&file_path);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
    }
}
