use ic_state_machine_tests::StateMachine;
use std::process::{Command, Stdio};

#[test]
fn poc() {
    let pid = std::process::id().to_string();
    println!("before creating SM");
    Command::new("sh")
        .args(["-c", format!("ps -M {pid} | wc -l").as_str()])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("failed to execute process");
    let env = StateMachine::new();
    println!("after creating SM");
    Command::new("sh")
        .args(["-c", format!("ps -M {pid} | wc -l").as_str()])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("failed to execute process");
    drop(env);
    println!("after dropping SM");
    Command::new("sh")
        .args(["-c", format!("ps -M {pid} | wc -l").as_str()])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("failed to execute process");
}
