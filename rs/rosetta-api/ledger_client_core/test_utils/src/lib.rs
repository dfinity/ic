pub mod sample_data;

pub fn init_test_logger() {
    // Unfortunately cargo test doesn't capture stdout properly
    // so we set the level to warn (so we don't spam).
    // I tried to use env logger here, which is supposed to work,
    // and sure, cargo test captures it's output on MacOS, but it
    // doesn't on linux.
    log4rs::init_file("log_config_tests.yml", Default::default()).ok();
}

pub fn create_tmp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("test_tmp_")
        .tempdir_in(".")
        .unwrap()
}
