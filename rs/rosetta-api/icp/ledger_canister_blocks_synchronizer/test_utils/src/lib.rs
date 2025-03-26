pub mod sample_data;

pub fn create_tmp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("test_tmp_")
        .tempdir_in(".")
        .unwrap()
}
