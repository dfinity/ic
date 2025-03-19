use std::{path::PathBuf, str::FromStr};

use ic_http_utils::file_downloader::{FileDownloadError, FileDownloader};
use ic_system_test_driver::{driver::group::SystemTestGroup, driver::test_env::TestEnv, systest};

fn test(_env: TestEnv) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let url = "https://download.dfinity.systems/ic/64060e6a91446ed41be3e1fdfc0abae997d83d86/guest-os/update-img/update-img.tar.zst";
    let downloader = FileDownloader::new_with_timeout(None, std::time::Duration::from_secs(2));

    let output = PathBuf::from_str("/tmp/replica").unwrap();
    let mut last_iteration_size = 0;
    loop {
        let response = runtime.block_on(downloader.download_file(
            url,
            output.as_path(),
            Some("9125fa5fccf580a6796e6fcd0ad3efe8026d689af4f4e0feab1d8421aad31e66".to_string()),
        ));
        if response.is_ok() {
            break;
        }

        if let Err(FileDownloadError::ReqwestError(e)) = response {
            if !e.is_timeout() {
                panic!("Unexpected error: {:?}", e);
            }
        } else {
            panic!("Unexpected error: {:?}", response);
        }

        let metadata = std::fs::metadata(&output).unwrap();
        assert_ne!(
            metadata.len(),
            last_iteration_size,
            "Sizes are the same in two iterations meaning there is a bug in the implementation"
        );
        last_iteration_size = metadata.len();
    }
}

fn main() {
    SystemTestGroup::new()
        .with_setup(|_| ())
        .add_test(systest!(test))
        .execute_from_args()
        .unwrap();
}
