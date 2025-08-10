use crate::files::mk_temp_dir_with_permissions;
use ic_crypto_internal_csp::vault::remote_csp_vault::TarpcCspVaultServerImpl;
use std::path::PathBuf;
use tempfile::TempDir;
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
pub fn start_new_remote_csp_vault_server_for_test(rt_handle: &tokio::runtime::Handle) -> PathBuf {
    let (socket_path, sks_dir, listener) = setup_listener(rt_handle);
    let server = TarpcCspVaultServerImpl::builder(sks_dir.path()).build(listener);
    rt_handle.spawn(async move {
        let _move_temp_dir_here_to_ensure_it_is_not_cleaned_up = sks_dir;
        server.run().await;
    });
    socket_path
}
pub fn start_new_remote_csp_vault_server_in_temp_dir(
    rt_handle: &tokio::runtime::Handle,
) -> (TempDir, PathBuf) {
    let (socket_path, sks_dir, listener) = setup_listener(rt_handle);
    let server = TarpcCspVaultServerImpl::builder(sks_dir.path()).build(listener);
    rt_handle.spawn(async move {
        server.run().await;
    });
    (sks_dir, socket_path)
}

pub fn setup_listener(rt_handle: &tokio::runtime::Handle) -> (PathBuf, TempDir, UnixListener) {
    let socket_path = get_temp_file_path();
    let _ignore_if_file_does_not_exist = std::fs::remove_file(&socket_path);
    let sks_dir = mk_temp_dir_with_permissions(0o700);
    let listener = {
        let _enter_guard = rt_handle.enter();
        UnixListener::bind(&socket_path).unwrap_or_else(|e| {
            panic!(
                "Error binding to socket at {}: {}",
                socket_path.display(),
                e
            )
        })
    };
    (socket_path, sks_dir, listener)
}
