use rate_limits_api::{GetConfigResponse, Version};
use storage::VERSION;
use types::{ConfigResponse, OutputConfig};
mod storage;
mod types;

#[ic_cdk_macros::update]
fn get_config(version: Option<Version>) -> GetConfigResponse {
    let test_version_inc = VERSION.with(|v| {
        let mut ver = v.borrow_mut();
        let current_version = ver.get(&()).unwrap_or(0);
        ver.insert((), current_version + 1);
        current_version
    });

    let response = ConfigResponse {
        version: version.unwrap_or(test_version_inc),
        active_since: 1,
        config: OutputConfig { rules: vec![] },
    };

    Ok(response.into())
}
