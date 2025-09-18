use std::io::Write;
use std::path::PathBuf;

use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{SshSession, get_dependency_path, scp_send_to};
use ic_system_test_driver::driver::universal_vm::UniversalVms;
use ic_system_test_driver::driver::{group::SystemTestGroup, universal_vm::UniversalVm};
use ic_system_test_driver::systest;

use anyhow::Result;
use slog::info;

fn setup(env: TestEnv) {
    UniversalVm::new(String::from("my_uvm"))
        .start(&env)
        .expect("failed to setup universal VM");
}

fn test(env: TestEnv) {
    let expected_size: usize = 1457471;

    let path = get_dependency_path("test.txt");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(
        (1..=expected_size)
            .map(|i| i as u8)
            .collect::<Vec<_>>()
            .as_slice(),
    )
    .unwrap();

    let actual = path.metadata().unwrap().len() as usize;
    assert_eq!(
        actual, expected_size,
        "Unexpected local file size: {actual} vs {expected_size}"
    );

    let uvm = env.get_deployed_universal_vm("my_uvm").unwrap();
    for i in 0..50 {
        info!(
            env.logger(),
            "Phase 1 - Copying file iteration {}/100 to /tmp/test-{i}.txt",
            i + 1
        );

        let session = uvm.block_on_ssh_session().unwrap();
        scp_send_to(
            env.logger(),
            &session,
            &path,
            PathBuf::from(format!("/tmp/test-{i}.txt")).as_path(),
            0o644,
        );

        let actual = uvm
            .block_on_bash_script(&format!("wc -c /tmp/test-{i}.txt | awk '{{print $1}}'"))
            .unwrap()
            .trim()
            .parse::<usize>()
            .unwrap();
        assert_eq!(
            actual, expected_size,
            "Unexpected remote file size: {actual} vs {expected_size}"
        );
    }

    for i in 0..50 {
        info!(
            env.logger(),
            "Phase 2 - Copying file iteration {}/100 to /tmp/test-{i}.txt",
            i + 1
        );

        let session = uvm.block_on_ssh_session().unwrap();

        uvm.block_on_bash_script_from_session(&session, &format!("mkdir -p /tmp/testdir-{i}"))
            .unwrap();

        scp_send_to(
            env.logger(),
            &session,
            &path,
            PathBuf::from(format!("/tmp/testdir-{i}/test-{i}.txt")).as_path(),
            0o644,
        );

        let actual = uvm
            .block_on_bash_script(&format!(
                "wc -c /tmp/testdir-{i}/test-{i}.txt | awk '{{print $1}}'"
            ))
            .unwrap()
            .trim()
            .parse::<usize>()
            .unwrap();
        assert_eq!(
            actual, expected_size,
            "Unexpected remote file size: {actual} vs {expected_size}"
        );
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
