use ic_state_machine_tests::StateMachine;
use std::process::{Command, Stdio};

#[test]
fn poc() {
    let pid = std::process::id().to_string();
    println!("before creating SM");
    Command::new("ps")
        .args(["-o", "nlwp", &pid])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("failed to execute process");
    let env = StateMachine::new();
    println!("after creating SM");
    Command::new("ps")
        .args(["-o", "nlwp", &pid])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("failed to execute process");
    drop(env);
    println!("after dropping SM");
    Command::new("ps")
        .args(["-o", "nlwp", &pid])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("failed to execute process");
}
