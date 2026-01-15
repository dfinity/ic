use std::net::Ipv6Addr;
use std::process::Command;

use anyhow::{Result, bail};

/// Systemd requires IP addresses to be specified with the prefix length
pub fn to_cidr(ipv6_address: Ipv6Addr, prefix_length: u8) -> String {
    format!("{ipv6_address}/{prefix_length}")
}

/// Run a command with args and get the stdout if success, stderr if failure.
pub fn get_command_stdout(command: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(command).args(args).output()?;
    if !output.status.success() {
        bail!(
            "Error running command: '{} {}': {}",
            command,
            args.join(" "),
            String::from_utf8(output.stderr)?
        );
    }
    Ok(String::from_utf8(output.stdout)?)
}

/// Retry the given function `f` until either:
/// * f has been called `attempts` times
/// * `stop_pred` returns true when passed the result of `f()`
///
/// The result returned is either the one held after `stop_pred` returns true or the one held after `attempts` has been breached.
pub fn retry_pred<F, P, T, W>(attempts: usize, f: F, stop_pred: P, wait_func: W) -> Result<T>
where
    F: Fn() -> Result<T>,
    P: Fn(&Result<T>) -> bool,
    W: Fn(usize),
{
    for attempt in 1..attempts {
        let result = f();
        if stop_pred(&result) {
            return result;
        }
        wait_func(attempt);
    }
    f()
}

/// Retry until `f` returns ok() or has been called `attempts` times
pub fn retry<F, T>(attempts: usize, f: F, wait: std::time::Duration) -> Result<T>
where
    F: Fn() -> Result<T>,
{
    retry_pred(
        attempts,
        f,
        |result| result.is_ok(),
        |_| std::thread::sleep(wait),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_to_cidr() {
        let addr = "2800:2801:2802:2803:2804:2805:2806:2807"
            .parse::<Ipv6Addr>()
            .unwrap();
        assert_eq!(
            to_cidr(addr, 64),
            "2800:2801:2802:2803:2804:2805:2806:2807/64"
        );
    }
}
