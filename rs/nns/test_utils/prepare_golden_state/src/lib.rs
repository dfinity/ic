use std::{
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};
use tempfile::TempDir;

#[derive(Debug, Clone, Copy)]
pub enum StateSource {
    Fiduciary,
    Nns,
    Sns,
}

const STATE_SOURCE_USER: &str = "dev";
const STATE_SOURCE_HOST: &str = "zh1-pyr07.zh1.dfinity.network";

impl StateSource {
    pub fn state_dir_name(&self) -> &'static str {
        match self {
            StateSource::Fiduciary => "fiduciary_state",
            StateSource::Nns => "nns_state",
            StateSource::Sns => "sns_state",
        }
    }

    fn to_argument(self) -> String {
        format!(
            "{}@{}:/home/dev/{}.tar.zst",
            STATE_SOURCE_USER,
            STATE_SOURCE_HOST,
            self.state_dir_name()
        )
    }
}

impl FromStr for StateSource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "fiduciary" => Ok(StateSource::Fiduciary),
            "nns" => Ok(StateSource::Nns),
            "sns" => Ok(StateSource::Sns),
            _ => Err(format!("Unknown state source: {s}")),
        }
    }
}

/// If available, uses the `TEST_TMPDIR` environment variable, which is set by
/// `bazel test`, and points to where you are allowed to write to disk.
/// Otherwise, this just falls back on vanilla TempDir::new.
fn bazel_test_compatible_temp_dir_or_panic() -> TempDir {
    match std::env::var("TEST_TMPDIR") {
        Ok(dir) => TempDir::new_in(dir).unwrap(),
        Err(_err) => TempDir::new().unwrap(),
    }
}

pub fn maybe_download_and_untar_golden_state_or_panic(state_source: StateSource) -> TempDir {
    match std::env::var_os("USE_EXISTING_STATE_DIR") {
        Some(existing_state_dir_name) => {
            let existing_state_dir = PathBuf::from(existing_state_dir_name.clone());
            let existing_state = existing_state_dir.join(state_source.state_dir_name());
            let destination_dir = TempDir::new_in(&existing_state_dir).unwrap();
            if !existing_state.exists() {
                panic!(
                    "USE_EXISTING_STATE_DIR is set to {existing_state_dir_name:?}, but {existing_state:?} does not exist"
                );
            }
            std::fs::rename(&existing_state, &destination_dir).unwrap();
            destination_dir
        }
        None => download_and_untar_golden_state_or_panic(state_source),
    }
}

fn download_and_untar_golden_state_or_panic(state_source: StateSource) -> TempDir {
    let download_destination = bazel_test_compatible_temp_dir_or_panic();
    let download_destination = download_destination
        .path()
        .join(format!("{}.tar.zst", state_source.state_dir_name()));
    download_golden_state_or_panic(state_source, &download_destination);

    let state_dir = bazel_test_compatible_temp_dir_or_panic();
    untar_state_archive_or_panic(
        &download_destination,
        state_dir.path(),
        state_source.state_dir_name(),
        bazel_test_compatible_temp_dir_or_panic,
    );
    state_dir
}

pub fn download_golden_state_or_panic(state_source: StateSource, destination: &Path) {
    let source = state_source.to_argument();
    println!("Downloading {source} to {destination:?} ...");

    // Actually download.
    let scp_out = Command::new("scp")
        .arg("-oUserKnownHostsFile=/dev/null")
        .arg("-oStrictHostKeyChecking=no")
        .arg("-v")
        .arg(source.clone())
        .arg(destination)
        .output()
        .unwrap_or_else(|err| panic!("Could not scp from {source:?} because: {err:?}!"));

    // Inspect result.
    if !scp_out.status.success() {
        panic!("Could not scp from {source}\n{scp_out:#?}");
    }

    let size = std::fs::metadata(destination)
        .map(|metadata| {
            let len = metadata.len() as f64;
            let len = len / (1 << 30) as f64;
            format!("{len:.2} GiB")
        })
        .unwrap_or_else(|_err| "???".to_string());

    let destination = destination.to_string_lossy();
    println!("Downloaded {source} to {destination}. size = {size}");
}

pub fn untar_state_archive_or_panic(
    source: &Path,
    destination: &Path,
    state_dir: &str,
    create_temp_dir: impl Fn() -> TempDir,
) {
    println!("Unpacking {state_dir} from {source:?} to {destination:?}...");

    // TODO: Mathias reports having problems with this (or something similar) on Mac.
    let unpack_destination = create_temp_dir();
    let unpack_destination = unpack_destination
        .path()
        .to_str()
        .expect("Was trying to convert a Path to a string.");
    let tar_out = Command::new("tar")
        .arg("--extract")
        .arg("--file")
        .arg(source)
        .arg("--directory")
        .arg(unpack_destination)
        .output()
        .unwrap_or_else(|err| panic!("Could not unpack {source:?}: {err}"));

    if !tar_out.status.success() {
        panic!("Could not unpack {source:?}\n{tar_out:#?}");
    }

    // Move $UNTAR_DESTINATION/nns_state/ic_state to final output dir path, StateMachine's so-called
    // state_dir.
    println!("Renaming {unpack_destination:?}/{state_dir}/ic_state to {destination:?}...");
    std::fs::rename(
        format!("{unpack_destination}/{state_dir}/ic_state"),
        destination,
    )
    .unwrap();

    println!("Unpacked {source:?} to {destination:?}");
}
