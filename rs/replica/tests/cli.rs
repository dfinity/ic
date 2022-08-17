use assert_cmd::Command;
use ic_config::SAMPLE_CONFIG;
use predicates::prelude::*;

fn new_replica_command() -> Command {
    match Command::cargo_bin("replica") {
        // When in Cargo environment. This should be removed after Bazel the migration is complete.
        Ok(v) => v,
        // When in Bazel environment
        Err(_) => Command::new("rs/replica/replica"),
    }
}

#[test]
fn nonexistent_config_causes_failure() {
    new_replica_command()
        .arg("does_not_exist.toml")
        .assert()
        .stderr(predicate::str::contains("No such file or directory"))
        .failure();
}

#[test]
fn too_many_arguments_causes_exit_code_1() {
    new_replica_command()
        .args(&["arg1", "arg2"])
        .assert()
        .stderr(predicate::str::starts_with(
            "error: Found argument 'arg1' which wasn't expected",
        ))
        .failure();
}

#[test]
fn help_arg_prints_help() {
    new_replica_command()
        .arg("--help")
        .assert()
        .stdout(predicate::str::contains(
            "Arguments for the Internet Computer Replica.",
        ))
        .failure();
}

#[test]
fn can_read_config_from_stdin() {
    new_replica_command()
        .arg("-")
        .write_stdin("garbage garbage")
        .assert()
        .stderr(predicate::str::contains("<stdin>"))
        .failure();
}

#[test]
fn can_read_config_from_arg() {
    new_replica_command()
        .arg("-")
        .write_stdin("--config=garbage garbage")
        .assert()
        .stderr(predicate::str::contains("Failed to parse"))
        .failure();
}

#[test]
fn can_print_sample_config() {
    new_replica_command()
        .arg("--sample-config")
        .assert()
        .stdout(predicate::str::contains(SAMPLE_CONFIG))
        .success();
}
