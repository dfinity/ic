use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_tests::qualification_setup::IC_CONFIG;
use serde_cbor::Value;
use std::time::Duration;

// 2 Hours
const OVERALL_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);

pub fn main() -> anyhow::Result<()> {
    // setup env variable for config
    let initial_version = std::env::var("INITIAL_VERSION")?;

    let network_layout = format!(
        r#"{{
        "subnets": [
            {{
                "subnet_type": "system",
                "num_nodes": 4
            }},
            {{
                "subnet_type": "application",
                "num_nodes": 4
            }},
            {{
                "subnet_type": "application",
                "num_nodes": 4
            }}
        ],
        "num_unassigned_nodes": 4,
        "num_nodes": 4,
        "initial_version": "{}"
        }}"#,
        initial_version
    );
    // Validate that the string is valid json
    let validated = serde_json::to_string(&serde_json::from_str::<Value>(&network_layout)?)?;

    std::env::set_var(IC_CONFIG, validated);

    SystemTestGroup::new()
        .with_overall_timeout(OVERALL_TIMEOUT)
        .with_setup(ic_tests::qualification_setup::setup)
        .execute_from_args()
}
