use std::{
    env,
    fs::File,
    io::Write,
    path::PathBuf,
    process::{Command, Output},
};
use tempfile::tempdir;

#[macro_export]
macro_rules! assert_err {
    ($output:expr, $err_str:expr) => {
        assert_eq!($output.status.code(), Some(1), "output: {:?}", $output);

        // Stderr can contain cargo specific output like compilation time, which isn't
        // deterministic. To ensure our tests are deterministic, we only verify that the
        // given error message is a substring of `stderr`
        let stderr = String::from_utf8($output.stderr).unwrap();
        assert!(
            stderr.contains($err_str),
            "Cannot find the given error message in the error stream.
Error message given: {}
Actual error stream:
-----------
{}
-----------",
            $err_str,
            stderr
        );
    };
}

#[macro_export]
macro_rules! assert_success {
    ($output:expr, $out_str:expr) => {
        assert_eq!($output.status.code(), Some(0), "output: {:?}", $output);
        pretty_assertions::assert_eq!(&String::from_utf8($output.stdout).unwrap(), $out_str);
    };
}

pub struct BenchTest {
    config: Option<String>,
    bench_name: Option<String>,
    base_dir: BaseDir,
    runtime_path: Option<PathBuf>,
    no_runtime_integrity_check: bool,
    canister_output: bool,
    noise_threshold: Option<f64>,
    instruction_tracing: bool,
    hide_results: bool,
}

impl BenchTest {
    pub fn no_config() -> Self {
        Self {
            config: None,
            bench_name: None,
            base_dir: BaseDir::Temp,
            runtime_path: None,
            no_runtime_integrity_check: false,
            canister_output: false,
            noise_threshold: None,
            instruction_tracing: false,
            hide_results: false,
        }
    }

    pub fn with_config(config: &str) -> Self {
        Self {
            config: Some(config.into()),
            bench_name: None,
            base_dir: BaseDir::Temp,
            runtime_path: None,
            no_runtime_integrity_check: false,
            canister_output: false,
            noise_threshold: None,
            instruction_tracing: false,
            hide_results: false,
        }
    }

    /// Creates a test that executes the benchmarks of a canister in the `tests` dir.
    pub fn canister(canister_name: &str) -> Self {
        Self {
            config: None,
            bench_name: None,
            base_dir: BaseDir::Path(
                PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("..")
                    .join("tests")
                    .join(canister_name),
            ),
            runtime_path: None,
            no_runtime_integrity_check: false,
            canister_output: false,
            noise_threshold: None,
            instruction_tracing: false,
            hide_results: false,
        }
    }

    pub fn with_bench(self, bench_name: &str) -> Self {
        Self {
            bench_name: Some(bench_name.to_string()),
            ..self
        }
    }

    pub fn with_runtime_path(self, path: PathBuf) -> Self {
        Self {
            runtime_path: Some(path),
            ..self
        }
    }

    pub fn with_no_runtime_integrity_check(self) -> Self {
        Self {
            no_runtime_integrity_check: true,
            ..self
        }
    }

    pub fn with_canister_output(self) -> Self {
        Self {
            canister_output: true,
            ..self
        }
    }

    pub fn with_noise_threshold(self, noise_threshold: f64) -> Self {
        Self {
            noise_threshold: Some(noise_threshold),
            ..self
        }
    }

    pub fn with_instruction_tracing(self) -> Self {
        Self {
            instruction_tracing: true,
            ..self
        }
    }

    pub fn with_hide_results(self) -> Self {
        Self {
            hide_results: true,
            ..self
        }
    }

    pub fn run<R>(self, f: impl FnOnce(Output) -> R) {
        let canbench: &'static str = env!("CARGO_BIN_EXE_canbench");

        // Create a temporary directory in case no specific directory is specified.
        let dir = tempdir().unwrap();

        let dir_path = match &self.base_dir {
            BaseDir::Temp => dir.path(),
            BaseDir::Path(path) => path,
        };

        if let Some(config) = self.config {
            // Write the canbench.yml file with the config provided.
            let config_path = dir_path.join("canbench.yml");
            let mut config_file = File::create(config_path).unwrap();
            config_file.write_all(config.as_bytes()).unwrap()
        }

        // Show only benchmark results and summary, skip unrelated output like downloads.
        let mut cmd_args = vec!["--less-verbose".to_string(), "--show-summary".to_string()];
        if let Some(bench_name) = self.bench_name {
            cmd_args.push(bench_name.clone());
        }

        if let Some(runtime_path) = self.runtime_path {
            cmd_args.push("--runtime-path".to_string());
            cmd_args.push(runtime_path.to_str().unwrap().to_string());
        }

        if self.no_runtime_integrity_check {
            cmd_args.push("--no-runtime-integrity-check".to_string());
        }

        if self.canister_output {
            cmd_args.push("--show-canister-output".to_string());
        }

        if let Some(noise_threshold) = self.noise_threshold {
            cmd_args.push("--noise-threshold".to_string());
            cmd_args.push(noise_threshold.to_string());
        }

        if self.instruction_tracing {
            cmd_args.push("--instruction-tracing".to_string());
        }

        if self.hide_results {
            cmd_args.push("--hide-results".to_string());
        }

        let output = Command::new(canbench)
            .current_dir(dir_path)
            .args(cmd_args)
            .output()
            .unwrap();

        f(output);
    }
}

// The base directory to use for running canbench.
enum BaseDir {
    // A temporary directory is created.
    Temp,

    // A specific path is specified.
    Path(PathBuf),
}
