use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

// Build reproducibility. askama adds a include_bytes! call when it's generating
// a template impl so that rustc will recompile the module when the file changes
// on disk. See https://github.com/djc/askama/blob/180696053833147a61b3348646a953e7d92ae582/askama_shared/src/generator.rs#L141
// The stringified output of every proc-macro is added to the metadata hash for
// a crate. That output includes the full filepath to include_bytes!. It may be
// different on two machines, if they use different tempdir paths for the build.
// However, if we include the html source directly in the output, no
// inconsistency is introduced.
fn main() {
    println!("cargo:rerun-if-changed=templates/ic.json5.template");
    let mut f = File::create(
        PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("ic_config_template.rs"),
    )
    .unwrap();
    f.write_all(
        format!(
            r#"
#[derive(Template)]
#[template(escape = "none", source = {:?}, ext = "json5")]
pub struct IcConfigTemplate {{
    pub ipv6_address: String,
    pub ipv6_prefix: String,
    pub ipv4_address: String,
    pub ipv4_gateway: String,
    pub nns_urls: String,
    pub backup_retention_time_secs: String,
    pub backup_purging_interval_secs: String,
    pub query_stats_epoch_length: String,
    pub jaeger_addr: String,
    pub domain_name: String,
    pub node_reward_type: String,
    pub malicious_behavior: String,
    pub enable_beta_registration_feature: bool,
}}
    "#,
            std::fs::read_to_string("templates/ic.json5.template").unwrap()
        )
        .as_bytes(),
    )
    .unwrap();
}
