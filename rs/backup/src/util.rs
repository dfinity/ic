use ic_types::ReplicaVersion;
use serde::{Deserialize, Deserializer, Serializer, de::Error};
use std::future::Future;
use tokio::runtime::Runtime;

pub(crate) fn block_on<F: Future>(f: F) -> F::Output {
    let rt = Runtime::new().unwrap_or_else(|err| panic!("Could not create tokio runtime: {err}"));
    rt.block_on(f)
}

pub(crate) fn sleep_secs(secs: u64) {
    let sleep_duration = std::time::Duration::from_secs(secs);
    std::thread::sleep(sleep_duration);
}

pub(crate) fn replica_from_string<'de, D>(deserializer: D) -> Result<ReplicaVersion, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    ReplicaVersion::try_from(s).map_err(D::Error::custom)
}

pub(crate) fn replica_to_string<S>(ver: &ReplicaVersion, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = ver.to_string();
    serializer.serialize_str(&s)
}
