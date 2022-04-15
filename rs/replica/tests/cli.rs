use assert_cmd::Command;
use ic_config::SAMPLE_CONFIG;
use predicates::prelude::*;

#[test]
fn nonexistent_config_causes_failure() {
    Command::cargo_bin("replica")
        .unwrap()
        .arg("does_not_exist.toml")
        .assert()
        .stderr(predicate::str::contains("No such file or directory"))
        .failure();
}

#[test]
fn too_many_arguments_causes_exit_code_1() {
    Command::cargo_bin("replica")
        .unwrap()
        .args(&["arg1", "arg2"])
        .assert()
        .stderr(predicate::str::starts_with(
            "error: Found argument 'arg1' which wasn't expected",
        ))
        .failure();
}

#[test]
fn help_arg_prints_help() {
    Command::cargo_bin("replica")
        .unwrap()
        .arg("--help")
        .assert()
        .stdout(predicate::str::contains(
            "Arguments for the Internet Computer Replica.",
        ))
        .failure();
}

#[test]
fn can_read_config_from_stdin() {
    Command::cargo_bin("replica")
        .unwrap()
        .arg("-")
        .write_stdin("garbage garbage")
        .assert()
        .stderr(predicate::str::contains("<stdin>"))
        .failure();
}

#[test]
fn can_read_config_from_arg() {
    Command::cargo_bin("replica")
        .unwrap()
        .arg("-")
        .write_stdin("--config=garbage garbage")
        .assert()
        .stderr(predicate::str::contains("Failed to parse"))
        .failure();
}

#[test]
fn can_print_sample_config() {
    Command::cargo_bin("replica")
        .unwrap()
        .arg("--sample-config")
        .assert()
        .stdout(predicate::str::contains(SAMPLE_CONFIG))
        .success();
}
