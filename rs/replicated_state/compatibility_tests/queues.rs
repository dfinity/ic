use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn data_dependency_file(dependency_path: &str) -> PathBuf {
    let runfiles_path: PathBuf = env::var("RUNFILES_DIR")
        .expect("RUNFILES_DIR not set; are you running this from Bazel?")
        .into();
    println!("runfiles_path: {:?}", runfiles_path);
    runfiles_path.join(dependency_path) // Path to the specific dependency
}

fn run_unit_test(binary: &Path, test_name: &str, current_dir: &Path) -> std::process::Output {
    let mut cmd = Command::new(binary);
    cmd.arg(test_name)
        .arg("--include-ignored")
        .arg("--nocapture")
        .current_dir(current_dir);
    let output = cmd
        .output()
        .unwrap_or_else(|e| panic!("Could not execute unit test binary {binary:?}: {e:?}"));
    println!("Command output: {:?}", output);
    assert!(
        output.status.success(),
        "Command failed: with status {:?}",
        output.status
    );
    assert!(
        std::str::from_utf8(&output.stdout).unwrap().contains("1 passed"),
        "Trying to execute {} from {:?}, but no test with such name was found.\nCheck that you don't have a typo in the name of the target module or test?",
        test_name, 
        binary.file_name().unwrap(),
    );
    output
}

const TESTS: [(&str, &str); 1] = [(
    "ic/rs/replicated_state/replicated_state_test_binary/replicated_state_test",
    "canister_state::queues::tests::mainnet_compatibility_tests::basic_test::",
)];

#[test]
fn compatibility_test() {
    for (binary_name, test_fqn_prefix) in TESTS {
        let binary = data_dependency_file(binary_name);
        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp_dir_path = tmp_dir.path();
        run_unit_test(
            &binary,
            &format!("{}serialize", test_fqn_prefix),
            &tmp_dir_path,
        );
        let nr_files = fs::read_dir(&tmp_dir_path).unwrap().count();
        assert_eq!(nr_files, 1);
        run_unit_test(
            &binary,
            &format!("{}deserialize", test_fqn_prefix),
            &tmp_dir_path,
        );
    }
}
