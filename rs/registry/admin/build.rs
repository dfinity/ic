fn main() {
    let full_version = if let (Ok(commit_date_iso_8601_txt_path), Ok(version_txt_path)) = (
        std::env::var("COMMIT_DATE_ISO_8601_TXT_PATH"),
        std::env::var("VERSION_TXT_PATH"),
    ) {
        // Bazel way
        let commit_date_iso_8601 = std::fs::read_to_string(&commit_date_iso_8601_txt_path).unwrap();
        let commit_date_iso_8601 = commit_date_iso_8601.trim();
        let version = std::fs::read_to_string(&version_txt_path).unwrap();
        let version = version.trim();
        format!("{commit_date_iso_8601} {version}")
    } else {
        // Cargo way
        let mut cmd = std::process::Command::new("git");
        cmd.args(["show", "-s", "--format=%cI %H"]);
        let output = cmd.output().expect("failed to execute `{cmd:?}`");
        if !output.status.success() {
            panic!("`{cmd:?}` exited with non-zero status: {:?}", output.status);
        }
        let s = String::from_utf8(output.stdout)
            .unwrap_or_else(|e| panic!("`{cmd:?}` output is not valid UTF-8 because: {e:?}"));
        s.trim().to_string()
    };
    println!("cargo:rustc-env=VERSION={full_version}");
}
