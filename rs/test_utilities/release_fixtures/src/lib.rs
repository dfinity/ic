use std::env;
use std::fs::File;
use std::io::{self, Read};

fn open_fixture_file(fixture_name: &str) -> File {
    let mut runfiles_path = env::current_exe().unwrap();
    runfiles_path.pop(); // Pop the executable name
    runfiles_path.pop(); // Additional pop to get to the base directory for runfiles
    runfiles_path.push(format!(
        "external/release_fixture_{}/file/downloaded",
        fixture_name
    )); // Path to the data file
    File::open(runfiles_path.clone()).expect(
        format!(
            "Unable to open the data file {} for fixture {}",
            runfiles_path.to_str().unwrap(),
            fixture_name
        )
        .as_str(),
    )
}
