//! In-process CPU profiling support.

use lazy_static::lazy_static;
use pprof::{ProfilerGuard, Report};
use prost::Message;
use regex::Regex;
use std::time::Duration;
use thiserror::Error;
use tokio::time::sleep;

/// Errors returned by `profile()` and `flamegraph()`.
#[derive(Error, Debug)]
pub enum Error {
    /// Error encountered while collecting the CPU profile (e.g. profile already
    /// in progress).
    #[error(transparent)]
    Pprof {
        #[from]
        source: pprof::Error,
    },

    /// Error encoding pprof protobuf.
    #[error(transparent)]
    Encode {
        #[from]
        source: prost::EncodeError,
    },
}

/// Drops the thread number, if any, from the thread name and replaces all
/// underscores and spaces with dashes.
fn extract_thread_name(thread_name: &str) -> String {
    lazy_static! {
        static ref THREAD_NAME_RE: Regex =
            Regex::new(r"^(?P<thread_name>[a-z-_ :]+?)(-?\d)*$").unwrap();
        static ref THREAD_NAME_REPLACE_SEPARATOR_RE: Regex = Regex::new(r"[_ ]").unwrap();
    }

    THREAD_NAME_RE
        .captures(thread_name)
        .and_then(|cap| {
            cap.name("thread_name").map(|thread_name| {
                THREAD_NAME_REPLACE_SEPARATOR_RE
                    .replace_all(thread_name.as_str(), "-")
                    .into_owned()
            })
        })
        .unwrap_or_else(|| thread_name.to_owned())
}

/// Collects a CPU profile for the given `duration` by sampling at the given
/// `frequency`.
pub async fn collect(duration: Duration, frequency: i32) -> Result<Report, pprof::Error> {
    let guard = ProfilerGuard::new(frequency)?;
    sleep(duration).await;

    guard
        .report()
        .frames_post_processor(move |frames| {
            frames.thread_name = extract_thread_name(&frames.thread_name);
        })
        .build()
}

/// Collects a protobuf-encoded `pprof` CPU profile for the given `duration` by
/// sampling at the given `frequency`.
pub async fn profile(duration: Duration, frequency: i32) -> Result<Vec<u8>, Error> {
    let mut body: Vec<u8> = Vec::new();
    collect(duration, frequency)
        .await?
        .pprof()?
        .encode(&mut body)?;

    Ok(body)
}

/// Collects a CPU profile as SVG flamegraph for the given `duration` by
/// sampling at the given `frequency`.
pub async fn flamegraph(duration: Duration, frequency: i32) -> Result<Vec<u8>, Error> {
    let mut body: Vec<u8> = Vec::new();
    collect(duration, frequency).await?.flamegraph(&mut body)?;

    Ok(body)
}
