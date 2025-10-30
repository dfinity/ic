/// Constructs a temporary directory in a location appropriate for tests.
pub fn tmpdir(prefix: &str) -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix);
    // Bazel defines TEST_TMPDIR unique for each test.
    // https://bazel.build/reference/test-encyclopedia#test-interaction-filesystem
    match std::env::var_os("TEST_TMPDIR") {
        Some(path) => builder
            .tempdir_in(&path)
            .unwrap_or_else(|e| panic!("failed to create a temporary directory in {path:?}: {e}")),
        None => builder
            .tempdir()
            .expect("failed to create a temporary directory"),
    }
}
