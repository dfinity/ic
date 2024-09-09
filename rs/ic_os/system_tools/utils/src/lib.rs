use std::iter::IntoIterator;
use std::net::Ipv6Addr;
use std::process::Command;

use anyhow::{bail, Result};

pub mod deployment;

/// Systemd requires ip addresses to be specified with the prefix length
pub fn to_cidr(ipv6_address: Ipv6Addr, prefix_length: u8) -> String {
    format!("{}/{}", ipv6_address, prefix_length)
}

/// Run a command with args and get the stdout if success, stderr if failure.
pub fn get_command_stdout<'a, StringIter: IntoIterator<Item = &'a str>>(
    command: &str,
    args: StringIter,
) -> Result<String> {
    let mut cmd = Command::new(command);
    let mut arg_string: String = String::new();
    // TODO - replace loop with single chain call pipeline.
    for arg in args {
        cmd.arg(arg);
        arg_string.push_str(arg);
        arg_string.push(' ');
    }
    let output = cmd.output()?;
    if !output.status.success() {
        bail!(
            "Error running command: '{} {}': {:?}",
            command,
            arg_string,
            output.stderr
        );
    }
    Ok(String::from_utf8(output.stdout)?)
}

/// Inject `to_inject` into a copy of `source` every `spacing` chars
/// Will not inject at the end of the string.
/// If spacing is 0, return source string
/// TODO - use chunks for a more functional approach
pub fn intersperse(source: &str, to_inject: char, spacing: usize) -> String {
    if spacing == 0 {
        return source.to_string();
    }
    let mut result = String::new();
    for (i, c) in source.to_string().chars().enumerate() {
        result.push(c);
        if i % spacing == (spacing - 1) && i != (source.len() - 1) {
            result.push(to_inject);
        }
    }
    result
}

// Retry the given function `f` until either:
// * f has been called `attempts` times
// * `stop_pred` returns true when passed the result of `f()`
// `wait_func` is called before each attempt.
// The result returned is either the one held after `stop_pred` returns true or the one held after `attempts` has been breached.
pub fn retry_pred<F, P, T, W>(attempts: usize, f: F, stop_pred: P, wait_func: W) -> Result<T>
where
    F: Fn() -> Result<T, anyhow::Error>,
    P: Fn(&Result<T>) -> bool,
    W: Fn(usize),
{
    for attempt in 1..attempts - 1 {
        // Final attempt is last line of function
        wait_func(attempt);
        let result = f();
        if stop_pred(&result) {
            return result;
        }
    }
    f()
}

// Retry until `f` returns ok() or has been called `attempts` times
pub fn retry<F, T>(attempts: usize, f: F, wait: std::time::Duration) -> Result<T>
where
    F: Fn() -> Result<T, anyhow::Error>,
{
    retry_pred(
        attempts,
        f,
        |result| result.is_ok(),
        |_| std::thread::sleep(wait),
    )
}

#[cfg(test)]
pub mod tests {
    use super::*;
    #[test]
    fn test_intersperse() {
        assert_eq!(intersperse("aabbccddeeff", ':', 2), "aa:bb:cc:dd:ee:ff");
        assert_eq!(intersperse("something", ':', 0), "something");
        assert_eq!(
            intersperse("11112222333344445555666677778888", ':', 4),
            "1111:2222:3333:4444:5555:6666:7777:8888"
        );
    }
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
