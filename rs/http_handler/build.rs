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
    println!("cargo:rerun-if-changed=templates/dashboard.html");
    let mut f = File::create(PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("dashboard.rs"))
        .unwrap();
    f.write_all(
        format!(
            r#"
#[derive(Template)]
#[template(escape = "html", source = {:?}, ext = "html")]
struct Dashboard<'a> {{
    subnet_type: ic_registry_subnet_type::SubnetType,
    http_config: &'a ic_config::http_handler::Config,

    height: Height,
    replicated_state: &'a ic_replicated_state::replicated_state::ReplicatedState,
    canisters: &'a Vec<&'a ic_replicated_state::CanisterState>,
    cow_memory_manager_enabled: bool,
    replica_version: ic_types::ReplicaVersion,
}}
    "#,
            std::fs::read_to_string("templates/dashboard.html").unwrap()
        )
        .as_bytes(),
    )
    .unwrap();
}
