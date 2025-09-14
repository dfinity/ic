use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

// TODO: Remove this workaround when the issue is fixed in askama.
// https://github.com/askama-rs/askama/issues/461
//
// Build reproducibility. askama adds a include_bytes! call when it's generating
// a template impl so that rustc will recompile the module when the file changes
// on disk. See https://github.com/djc/askama/blob/180696053833147a61b3348646a953e7d92ae582/askama_shared/src/generator.rs#L141
// The stringified output of every proc-macro is added to the metadata hash for
// a crate. That output includes the full filepath to include_bytes!. It may be
// different on two machines, if they use different tempdir paths for the build.
// However, if we include the html source directly in the output, no
// inconsistency is introduced.
fn main() {
    println!("cargo:rerun-if-changed=templates/guestos_vm_template.xml");
    let mut f = File::create(
        PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("guestos_vm_template.rs"),
    )
    .unwrap();
    f.write_all(
        format!(
            r#"
#[derive(Template)]
#[template(escape = "xml", source = {:?}, ext = "xml")]
pub struct GuestOSTemplateProps {{
    pub domain_name: String,
    pub domain_uuid: String,
    pub cpu_domain: String,
    pub console_log_path: String,
    pub vm_memory: u32,
    pub nr_of_vcpus: u32,
    pub mac_address: macaddr::MacAddr6,
    pub disk_device: PathBuf,
    pub config_media_path: PathBuf,
    pub enable_sev: bool,
    pub direct_boot: Option<DirectBootConfig>
}}
    "#,
            std::fs::read_to_string("templates/guestos_vm_template.xml").unwrap()
        )
        .as_bytes(),
    )
    .unwrap();
}
