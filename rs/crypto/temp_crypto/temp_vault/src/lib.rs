use ic_crypto_internal_csp::vault::api::CspVault;
use ic_crypto_internal_csp::vault::remote_csp_vault::{RemoteCspVault, TarpcCspVaultServerImpl};
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_logger::replica_logger::no_op_logger;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::UnixListener;

pub struct RemoteVaultEnvironment {
    pub vault_server: Arc<TempCspVaultServer>,
    pub vault_client_runtime: TokioRuntimeOrHandle,
}

impl RemoteVaultEnvironment {
    pub fn start_server_with_local_csp_vault<C: CspVault + 'static>(
        local_csp_vault: Arc<C>,
    ) -> Self {
        RemoteVaultEnvironment {
            vault_server: Arc::new(TempCspVaultServer::start_with_local_csp_vault(
                local_csp_vault,
            )),
            vault_client_runtime: TokioRuntimeOrHandle::new(None),
        }
    }

    pub fn new_vault_client(&self) -> Arc<dyn CspVault> {
        Arc::new(
            RemoteCspVault::new(
                self.vault_server.vault_socket_path().as_path(),
                self.vault_client_runtime.handle().clone(),
                no_op_logger(),
                Arc::new(CryptoMetrics::none()),
            )
            .expect("Could not create RemoteCspVault"),
        )
    }
}

pub enum TokioRuntimeOrHandle {
    Runtime(tokio::runtime::Runtime),
    Handle(tokio::runtime::Handle),
}

impl TokioRuntimeOrHandle {
    pub fn new(option_handle: Option<tokio::runtime::Handle>) -> Self {
        if let Some(handle) = option_handle {
            Self::Handle(handle)
        } else {
            let multi_thread_rt = tokio::runtime::Runtime::new().expect("failed to create runtime");
            Self::Runtime(multi_thread_rt)
        }
    }

    pub fn handle(&self) -> &tokio::runtime::Handle {
        match &self {
            TokioRuntimeOrHandle::Runtime(runtime) => runtime.handle(),
            TokioRuntimeOrHandle::Handle(handle) => handle,
        }
    }
}
/// A unix socket living in a temporary directory that will be automatically deleted
/// when struct goes out of scope.
pub struct TempSocket {
    _temp_dir: TempDir,
    socket_path: PathBuf,
}

impl TempSocket {
    pub fn new_in_temp_dir() -> Self {
        let temp_dir = tempfile::Builder::new()
            .prefix("ic_crypto_csp_vault_")
            .tempdir()
            .expect("failed to create temporary directory");
        let socket_path = {
            let mut path = temp_dir.path().to_path_buf();
            path.push("ic-crypto-csp.socket");
            path
        };

        Self {
            _temp_dir: temp_dir,
            socket_path,
        }
    }

    pub fn bind_unix_listener(&self, tokio_rt: &tokio::runtime::Handle) -> UnixListener {
        let _enter_guard = tokio_rt.enter();
        UnixListener::bind(&self.socket_path).expect("failed to bind")
    }

    pub fn socket_path(&self) -> PathBuf {
        self.socket_path.clone()
    }
}

/// A CSP vault server listening to a temporary unix socket.
pub struct TempCspVaultServer {
    _tokio_runtime: TokioRuntimeOrHandle,
    join_handle: tokio::task::JoinHandle<()>,
    temp_socket: TempSocket,
}

impl Drop for TempCspVaultServer {
    fn drop(&mut self) {
        // Aborts the tokio task that runs the vault server. This drops
        // the server and thus the temporary socket and thus the server-side
        // handle to the file acting as unix domain socket used for
        // communication with the server.
        // If also all client-side handles to the temporary socket are dropped,
        // then nothing should prevent the deletion (=cleanup) of the
        // directory behind the temporary socket when the latter is dropped.
        // Note that [the fields of a struct are dropped in declaration order]
        // (https://doc.rust-lang.org/reference/destructors.html#destructors).
        self.join_handle.abort();
    }
}

impl TempCspVaultServer {
    pub fn start_from_crypto_root(
        crypto_root: PathBuf,
        opt_tokio_rt_handle: Option<tokio::runtime::Handle>,
    ) -> Self {
        Self::start_server(
            Box::new(move |listener| {
                TarpcCspVaultServerImpl::new(
                    crypto_root.as_path(),
                    listener,
                    no_op_logger(),
                    Arc::new(CryptoMetrics::none()),
                )
            }),
            opt_tokio_rt_handle,
        )
    }

    pub fn start_with_local_csp_vault<C: CspVault + 'static>(local_csp_vault: Arc<C>) -> Self {
        Self::start_server(
            |listener| TarpcCspVaultServerImpl::new_for_test(local_csp_vault, listener),
            None,
        )
    }

    fn start_server<C: CspVault + 'static>(
        server_factory: impl FnOnce(UnixListener) -> TarpcCspVaultServerImpl<C>,
        opt_tokio_rt_handle: Option<tokio::runtime::Handle>,
    ) -> Self {
        let temp_socket = TempSocket::new_in_temp_dir();
        let tokio_runtime = TokioRuntimeOrHandle::new(opt_tokio_rt_handle);
        let listener = temp_socket.bind_unix_listener(tokio_runtime.handle());
        let server = server_factory(listener);
        let join_handle = tokio_runtime.handle().spawn(server.run());

        Self {
            _tokio_runtime: tokio_runtime,
            join_handle,
            temp_socket,
        }
    }

    pub fn vault_socket_path(&self) -> PathBuf {
        self.temp_socket.socket_path()
    }
}
