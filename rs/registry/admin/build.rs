fn main() {
    if let (Ok(commit_date_iso_8601_txt_path), Ok(version_txt_path)) = (
        std::env::var("COMMIT_DATE_ISO_8601_TXT_PATH"),
        std::env::var("VERSION_TXT_PATH"),
    ) {
        let commit_date_iso_8601 = std::fs::read_to_string(&commit_date_iso_8601_txt_path).unwrap();
        let commit_date_iso_8601 = commit_date_iso_8601.trim();
        let version = std::fs::read_to_string(&version_txt_path).unwrap();
        let version = version.trim();
        let full_version = format!("{commit_date_iso_8601} {version}");
        println!("cargo:rustc-env=VERSION={full_version}");
    }
}
