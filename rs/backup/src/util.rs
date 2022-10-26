use ic_types::{PrincipalId, SubnetId};
use std::{future::Future, str::FromStr};
use tokio::runtime::Runtime;

pub fn block_on<F: Future>(f: F) -> F::Output {
    let rt = Runtime::new().unwrap_or_else(|err| panic!("Could not create tokio runtime: {}", err));
    rt.block_on(f)
}

pub fn sleep_secs(secs: u64) {
    let sleep_duration = std::time::Duration::from_secs(secs);
    std::thread::sleep(sleep_duration);
}

pub fn subnet_id_from_str(s: &str) -> Result<SubnetId, String> {
    PrincipalId::from_str(s)
        .map_err(|e| format!("Unable to parse subnet_id {:?}", e))
        .map(SubnetId::from)
}
