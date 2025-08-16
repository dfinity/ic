use ic_sev::guest::is_sev_active;
use std::process::ExitCode;

fn main() -> ExitCode {
    match is_sev_active() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(err) => {
            eprintln!("Error checking SEV status: {err:?}");
            ExitCode::from(2)
        }
    }
}
