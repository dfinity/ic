use crate::files::mk_temp_dir_with_permissions;
use std::path::PathBuf;
use tokio::net::UnixListener;

/// Creates a temporary file; it is the caller's responsibility to delete it
/// after use.
pub fn get_temp_file_path() -> PathBuf {
    // So, tempfile has no method for creating just the temporary file NAME,
    // instead, it suggests you create the file and then close it, to make sure
    // it gets deleted; but keep the path around.
    // (https://docs.rs/tempfile/3.2.0/tempfile/struct.TempPath.html#method.close)
    let tmp_file = tempfile::NamedTempFile::new().expect("Could not create temp file");
    let tmp_file = tmp_file.into_temp_path();
    let file_path = tmp_file.to_path_buf();
    tmp_file
        .close()
        .expect("Could not close temp file in order to make temp file name");
    file_path
}

/// Starts a fresh CSP Vault server instance for testing, and returns
/// a socket path at which the server is listening.
pub fn start_new_remote_csp_vault_server_for_test() -> PathBuf {
    let socket_path = get_temp_file_path();
    let return_socket_path = socket_path.clone();
    let _ignore_if_file_does_not_exist = std::fs::remove_file(&socket_path);
    let sks_dir = mk_temp_dir_with_permissions(0o700);
    let listener = UnixListener::bind(&socket_path).unwrap_or_else(|e| {
        panic!(
            "Error binding to socket at {}: {}",
            socket_path.display(),
            e
        )
    });
    let server = ic_crypto_internal_csp::vault::remote_csp_vault::TarpcCspVaultServerImpl::new(
        sks_dir.path(),
        listener,
    );
    tokio::spawn(async move {
        let _move_temp_dir_here_to_ensure_it_is_not_cleaned_up = sks_dir;
        server.run().await;
    });
    return_socket_path
}
