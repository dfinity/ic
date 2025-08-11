use std::io;

/// Retries a function, returning its result if it succeeds, or retrying if it fails with
/// ResourceBusy.
pub fn retry_if_busy<T>(mut f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    const MAX_ATTEMPTS: i32 = 10;
    let mut attempts = MAX_ATTEMPTS;
    loop {
        match f() {
            Ok(res) => return Ok(res),
            Err(e) => {
                if e.kind() == io::ErrorKind::ResourceBusy && attempts > 0 {
                    attempts -= 1;
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
    fn test_retry_if_busy() {
        let mut attempts = 0;
        let result = retry_if_busy(|| {
            attempts += 1;
            if attempts < 3 {
                Err(io::Error::new(io::ErrorKind::ResourceBusy, "busy"))
            } else {
                Ok("success")
            }
        });

        assert_eq!(result.unwrap(), "success");
        assert_eq!(attempts, 3);
    }

    #[test]
    fn test_retry_if_busy_failure() {
        let result: Result<(), _> = retry_if_busy(|| Err(io::Error::other("fail")));
        assert!(result.is_err());
    }
}
