use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

pub struct PocketIC {
    process: Child,
}

impl PocketIC {
    /// Launch binary which will listen on port
    pub fn new(bin_path: &str) -> Self {
        let bin_path = PathBuf::from(bin_path);
        let mut command = Command::new(bin_path);
        let process = command
            .spawn()
            .expect("Failed to launch pocketIC backend process.");
        retry(|| reqwest::blocking::get("http://0.0.0.0:3000/"), 10, 500);
        println!(
            "Launched pocketIC backend process with pid {}",
            process.id()
        );
        Self { process }
    }

    pub fn test_call(&self) {
        let url = "http://0.0.0.0:3000/test?first=2&second=3";
        let response = reqwest::blocking::get(url)
            .expect("Failed to get response.")
            .text()
            .expect("Failed to get text");
        println!("Response:\n{}", response);
    }
}

impl Drop for PocketIC {
    fn drop(&mut self) {
        let msg = format!("Failed to kill process with pid {}.", self.process.id());
        self.process.kill().expect(&msg);
    }
}

fn retry<T, S>(func: impl Fn() -> Result<T, S>, backoff_step_milis: u64, max_milis: u64) {
    let start = std::time::SystemTime::now();
    let mut cur_step = backoff_step_milis;
    while start.elapsed().expect("Failed to get systime") < Duration::from_millis(max_milis) {
        match func() {
            Ok(..) => return,
            Err(..) => {
                std::thread::sleep(Duration::from_millis(cur_step));
                cur_step += backoff_step_milis;
            }
        }
    }
    panic!("Retrying took too much time.");
}
