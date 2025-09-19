use std::io::Write;
use std::path::PathBuf;

use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{SshSession, get_dependency_path, scp_send_to};
use ic_system_test_driver::driver::universal_vm::UniversalVms;
use ic_system_test_driver::driver::{group::SystemTestGroup, universal_vm::UniversalVm};
use ic_system_test_driver::systest;

use anyhow::Result;
use rand::Rng;
use sha2::{Sha256, Digest};
use slog::info;

fn setup(env: TestEnv) {
    UniversalVm::new(String::from("my_uvm"))
        .start(&env)
        .expect("failed to setup universal VM");
}

fn test(env: TestEnv) {
    let expected_size: usize = 1457471;
    let mut buffer = vec![0u8; expected_size];
    let mut rng = rand::thread_rng();

    for i in 0..100 {
        info!(env.logger(), "Copying file iteration {}/100", i + 1);

        let path = get_dependency_path(format!("test-{i}.txt"));
        let mut file = std::fs::File::create(&path).unwrap();
        rng.fill(&mut buffer[..]);
        file.write_all(&buffer).unwrap();

        let actual = path.metadata().unwrap().len() as usize;
        assert_eq!(
            actual, expected_size,
            "Unexpected local file size: {actual} vs {expected_size}"
        );

        let actual_sha256 = Sha256::digest(&buffer)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        let uvm = env.get_deployed_universal_vm("my_uvm").unwrap();
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

        let remote_sha256 = uvm
            .block_on_bash_script(&format!(
                "sha256sum /tmp/testdir-{i}/test-{i}.txt | awk '{{print $1}}'"
            ))
            .unwrap()
            .trim()
            .to_string();
        assert_eq!(
            actual_sha256, remote_sha256,
            "Unexpected remote file sha256: {remote_sha256} vs {actual_sha256}"
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
