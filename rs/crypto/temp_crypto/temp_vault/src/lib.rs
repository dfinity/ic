use ic_crypto_internal_csp::vault::api::CspVault;
use ic_crypto_internal_csp::vault::local_csp_vault::ProdLocalCspVault;
use ic_crypto_internal_csp::vault::remote_csp_vault::{
    RemoteCspVault, RemoteCspVaultBuilder, TarpcCspVaultServerImpl, TarpcCspVaultServerImplBuilder,
};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::UnixListener;

pub struct RemoteVaultEnvironment<C> {
    pub vault_server: TempCspVaultServer<C>,
    pub vault_client_runtime: TokioRuntimeOrHandle,
}

impl<C: CspVault + 'static> RemoteVaultEnvironment<C> {
    pub fn start_server_with_local_csp_vault(local_csp_vault: Arc<C>) -> Self {
        RemoteVaultEnvironment {
            vault_server: TempCspVaultServer::start_with_local_csp_vault(local_csp_vault),
            vault_client_runtime: TokioRuntimeOrHandle::new(None),
        }
    }
}

impl<Builder> RemoteVaultEnvironment<Builder> {
    pub fn new_vault_client(&self) -> Arc<dyn CspVault> {
        Arc::new(
            self.new_vault_client_builder()
                .build()
                .expect("Could not create RemoteCspVault"),
        )
    }

    pub fn new_vault_client_builder(&self) -> RemoteCspVaultBuilder {
        RemoteCspVault::builder(
            self.vault_server.vault_socket_path(),
            self.vault_client_runtime.handle().clone(),
        )
    }

    pub fn shutdown_server_now(&mut self) {
        self.vault_server.shutdown_now();
    }
}

impl<C: CspVault + 'static> RemoteVaultEnvironment<C> {
    pub fn start_server(server_builder: TarpcCspVaultServerImplBuilder<C>) -> Self {
        RemoteVaultEnvironment {
            vault_server: TempCspVaultServer::start_server(server_builder),
            vault_client_runtime: TokioRuntimeOrHandle::new(None),
        }
    }

    pub fn restart_server(&mut self) {
        self.vault_server.restart();
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
    listener: Option<UnixListener>,
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
            listener: None,
        }
    }

    pub fn bind_unix_listener(&mut self, tokio_rt: &tokio::runtime::Handle) -> UnixListener {
        let _enter_guard = tokio_rt.enter();
        let listener = UnixListener::bind(&self.socket_path).expect("failed to bind");
        let (listener1, listener2) = duplicate(listener);
        self.listener = Some(listener1);
        listener2
    }

    pub fn recreate_unix_listener(&mut self, tokio_rt: &tokio::runtime::Handle) -> UnixListener {
        let _enter_guard = tokio_rt.enter();
        let listener = self
            .listener
            .take()
            .expect("missing UnixListener. Was the socket bound before?");
        let (listener1, listener2) = duplicate(listener);
        self.listener = Some(listener1);
        listener2
    }

    pub fn socket_path(&self) -> PathBuf {
        self.socket_path.clone()
    }
}

/// A CSP vault server listening to a temporary unix socket.
pub struct TempCspVaultServer<C> {
    server_builder: TarpcCspVaultServerImplBuilder<C>,
    status: ServerStatus,
    temp_socket: TempSocket,
}

enum ServerStatus {
    Up {
        _runtime: tokio::runtime::Runtime,
        _join_handle: tokio::task::JoinHandle<()>,
    },
    Down,
}

impl<C> Drop for TempCspVaultServer<C> {
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
        self.shutdown_now()
    }
}

impl TempCspVaultServer<ProdLocalCspVault> {
    pub fn start_from_crypto_root(crypto_root: PathBuf) -> Self {
        let server_builder = TarpcCspVaultServerImpl::builder(crypto_root.as_path());
        Self::start_server(server_builder)
    }
}

impl<C: CspVault + 'static> TempCspVaultServer<C> {
    pub fn start_with_local_csp_vault(local_csp_vault: Arc<C>) -> Self {
        let server_builder = TarpcCspVaultServerImpl::builder_for_test(local_csp_vault);
        Self::start_server(server_builder)
    }
}

impl<C: CspVault + 'static> TempCspVaultServer<C> {
    fn start_server(server_builder: TarpcCspVaultServerImplBuilder<C>) -> Self {
        let mut temp_socket = TempSocket::new_in_temp_dir();
        let tokio_runtime = tokio::runtime::Runtime::new().expect("failed to create runtime");
        let listener = temp_socket.bind_unix_listener(tokio_runtime.handle());
        let join_handle = tokio_runtime
            .handle()
            .spawn(server_builder.build(listener).run());

        Self {
            server_builder,
            status: ServerStatus::Up {
                _runtime: tokio_runtime,
                _join_handle: join_handle,
            },
            temp_socket,
        }
    }

    pub fn restart(&mut self) {
        let tokio_runtime = tokio::runtime::Runtime::new().expect("failed to create runtime");
        let listener = self
            .temp_socket
            .recreate_unix_listener(tokio_runtime.handle());
        let join_handle = tokio_runtime
            .handle()
            .spawn(self.server_builder.build(listener).run());
        self.status = ServerStatus::Up {
            _runtime: tokio_runtime,
            _join_handle: join_handle,
        };
    }
}

impl<Builder> TempCspVaultServer<Builder> {
    pub fn shutdown_now(&mut self) {
        self.status = ServerStatus::Down; //drops tokio::task::JoinHandle<()> and tokio::runtime::Runtime
    }

    pub fn vault_socket_path(&self) -> PathBuf {
        self.temp_socket.socket_path()
    }
}

fn duplicate(listener: UnixListener) -> (UnixListener, UnixListener) {
    //tokio::net::UnixListener does not have a try_clone() method but std::os::unix::net::UnixListener does.
    //Since we can convert between the two types back and forth, we will use std::os::unix::net::UnixListener::try_clone
    //to duplicate the socket.
    let std_listener = listener
        .into_std()
        .expect("could not convert tokio UnixListener to std::os::unix::net::UnixListener");
    let copy = std_listener
        .try_clone()
        .expect("could not clone original std::os::unix::net::UnixListener");
    (
        UnixListener::from_std(std_listener)
            .expect("could not convert std::os::unix::net::UnixListener to tokio UnixListener"),
        UnixListener::from_std(copy)
            .expect("could not convert std::os::unix::net::UnixListener to tokio UnixListener"),
    )
}
