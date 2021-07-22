use ic_base_types::CanisterId;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::result::Result;
use std::str::FromStr;

enum BuildError {
    /// IO error happened
    IO(io::Error),
    /// moc returned non-zero
    MocFailure(Output),
}

impl From<io::Error> for BuildError {
    fn from(err: io::Error) -> Self {
        BuildError::IO(err)
    }
}

impl BuildError {
    fn print_stderr(&self) {
        match self {
            BuildError::IO(io_err) => {
                eprintln!("IO error: {:?}", io_err);
            }
            BuildError::MocFailure(output) => {
                eprintln!("moc returned {:?}", output.status.code());
                eprintln!("--- moc stdout ----------------------");
                eprint!("{}", String::from_utf8_lossy(&output.stdout));
                eprintln!("--- moc stderr ----------------------");
                eprint!("{}", String::from_utf8_lossy(&output.stderr));
                eprintln!("-------------------------------------");
            }
        }
    }
}

/// Create a gen/<canister_id>.did file pointing at the .did file for a canister
/// that the lifeline interacts with.
///
/// - `relative_path`: path to the .did file, relative to this directory. Used
///   for local dev.
/// - `name`: name of the canister.
/// - `id`: the CanisterId of that canister.
/// - `modify_did`: callback to modify the .did file before copying it to
///   `gen/`.
///
/// Returns args to be passed to `moc`
fn create_did_alias<F>(
    relative_path: &str,
    name: &str,
    id: CanisterId,
    modify_did: F,
) -> Result<Vec<String>, io::Error>
where
    F: FnOnce(&mut String),
{
    println!("cargo:rerun-if-changed={}", relative_path);
    let target_file_path = format!("gen/{}.did", id);
    // Delete the old if it's already there
    let _ = std::fs::remove_file(&target_file_path);
    // On CI, we use environment variables to know where the .did files are.
    // For local development, we use paths relative to gen/.
    let env_var = format!("{}_DID", name.to_ascii_uppercase());
    let did_file_path = env::var(env_var).unwrap_or_else(|_| relative_path.to_string());

    println!("did_file_path={:?}", did_file_path);

    let mut did_contents = fs::read_to_string(did_file_path).unwrap();

    modify_did(&mut did_contents);

    fs::write(target_file_path, did_contents.as_bytes()).unwrap();

    // The `--actor-alias` options teach `moc` of the `PrincipalId`-s of
    // `lifeline`'s communication partners.
    Ok(vec![
        "--actor-alias".to_string(),
        name.to_string(),
        id.to_string(),
    ])
}

/// This is a hack to work around a moc/Motoko limitation. Service definition
/// for the governance canister takes an argument (for initialization), but moc
/// can't handle services with function types.
///
/// We don't want to initialize the service in lifeline canister anyway, so we
/// remove the argument here to make this build.
fn remove_governance_service_args(did: &mut String) {
    *did = did.replace("service : (Governance) ->", "service :");
}

const GOVERNANCE_DID: &str = "../../governance/canister/governance.did";
const ROOT_DID: &str = "../root/canister/root.did";

fn compile_lifeline() -> Result<(), BuildError> {
    // Add symlinks to the .did files for foreign canisters
    let governance_args = create_did_alias(
        GOVERNANCE_DID,
        "governance",
        GOVERNANCE_CANISTER_ID,
        remove_governance_service_args,
    )?;

    let root_args = create_did_alias(ROOT_DID, "root", ROOT_CANISTER_ID, |_| {})?;

    // Compile the lifeline to Wasm
    let output = Command::new("moc")
        .arg("lifeline.mo")
        .args(governance_args)
        .args(root_args)
        // `--actor-idl` teaches `moc` to where to look for the `.did` files.
        .arg("--actor-idl")
        .arg("gen")
        // Put the output file in a location that:
        // - is ignored by git
        // - is easily findable for manual inspection
        // - is easy to embed in rust using `include_bytes!`
        .arg("-o")
        .arg("gen/lifeline.wasm")
        .output()?;

    if output.status.success() {
        Ok(())
    } else {
        Err(BuildError::MocFailure(output))
    }
}

fn main() {
    println!("cargo:rerun-if-changed=lifeline.mo");
    println!("cargo:rerun-if-changed=lifeline.did");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", ROOT_DID);
    println!("cargo:rerun-if-changed={}", GOVERNANCE_DID);

    compile_lifeline().unwrap_or_else(|e| {
        eprintln!("Could not build the Wasm for the lifeline canister. Error:");
        e.print_stderr();

        eprintln!(
            "The current directory is {:?}.\n\
            `moc --version` output: {:?}.\n\
            IN_NIX_SHELL={:?}.\n\
            NIX_BUILD_TOP={:?}.\n\
            lifeline.mo exists? {:?}.\n\
            gen/rrkah-fqaaa-aaaaa-aaaaq-cai.did exists? {:?}.\n\
            PATH={:?}.\n\
            `ls` output: {:?}.",
            env::current_dir().map(|pb| pb.as_path().display().to_string()),
            Command::new("moc").arg("--version").output(),
            env::var("IN_NIX_SHELL"),
            env::var("NIX_BUILD_TOP"),
            PathBuf::from_str("lifeline.mo").map(|pb| pb.as_path().is_file()),
            PathBuf::from_str("gen/rrkah-fqaaa-aaaaa-aaaaq-cai.did")
                .map(|pb| pb.as_path().is_file()),
            env::var("PATH"),
            Command::new("ls").output()
        );

        panic!()
    });
}
