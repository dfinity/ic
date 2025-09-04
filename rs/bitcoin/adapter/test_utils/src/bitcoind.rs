use std::{
    collections::{HashMap, VecDeque},
    fmt::Debug,
    fs,
    io::{self, Read},
    net,
    path::PathBuf,
    process,
    sync::Arc,
};

use bitcoin::p2p::{Magic, ServiceFlags};

use bitcoin::{
    block::Header as BlockHeader,
    consensus::{deserialize_partial, encode, serialize},
    p2p::{
        message::{NetworkMessage, RawNetworkMessage},
        message_blockdata::{GetHeadersMessage, Inventory},
        message_network::VersionMessage,
    },
    BlockHash,
};
use ic_btc_adapter::BlockLike;

use bitcoin::io as bitcoin_io;

use tempfile::{tempdir, TempDir};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::rpc_client::{Auth, RpcClient, RpcClientType, RpcError};

// TODO(XC-471): Fix this for Dogecoin.
const MINIMUM_PROTOCOL_VERSION: u32 = 70001;

async fn write_network_message<Block: BlockLike>(
    socket: &mut TcpStream,
    magic: Magic,
    payload: NetworkMessage<Block>,
) -> io::Result<()> {
    let res = RawNetworkMessage::new(magic, payload);
    let serialized = serialize(&res);
    socket.write_all(&serialized).await?;
    socket.flush().await?;
    Ok(())
}

async fn handle_getdata<Block: BlockLike>(
    socket: &mut TcpStream,
    msg: &[Inventory],
    magic: Magic,
    blocks: Arc<HashMap<BlockHash, Block>>,
) -> io::Result<()> {
    for inv in msg.iter() {
        match inv {
            Inventory::Block(hash) => {
                if !blocks.contains_key(hash) {
                    continue;
                }
                let block = blocks.get(hash).unwrap();
                write_network_message(socket, magic, NetworkMessage::Block(block.clone())).await?;
            }
            _ => {
                unimplemented!();
            }
        }
    }
    Ok(())
}

async fn handle_ping<Block: BlockLike>(
    socket: &mut TcpStream,
    val: u64,
    magic: Magic,
) -> io::Result<()> {
    write_network_message(socket, magic, <NetworkMessage<Block>>::Pong(val)).await
}

async fn handle_version<Block: BlockLike>(
    socket: &mut TcpStream,
    v: &VersionMessage,
    magic: Magic,
) -> io::Result<()> {
    if v.version < MINIMUM_PROTOCOL_VERSION {
        let err = io::Error::other("Protocol version too low");
        return Err(err);
    }
    let mut version = v.clone();
    version.services.add(ServiceFlags::NETWORK);
    write_network_message(socket, magic, <NetworkMessage<Block>>::Version(version)).await?;
    write_network_message(socket, magic, <NetworkMessage<Block>>::Verack).await?;
    Ok(())
}

async fn handle_getaddr<Block: BlockLike>(socket: &mut TcpStream, magic: Magic) -> io::Result<()> {
    write_network_message(socket, magic, <NetworkMessage<Block>>::Addr(vec![])).await
}

async fn handle_getheaders<Block: BlockLike>(
    socket: &mut TcpStream,
    msg: &GetHeadersMessage,
    magic: Magic,
    cached_headers: Arc<HashMap<BlockHash, BlockHeader>>,
    children: Arc<HashMap<BlockHash, Vec<BlockHash>>>,
) -> io::Result<()> {
    let mut block_headers: Vec<BlockHeader> = vec![];

    let locator = {
        let mut found = None;

        for locator in &msg.locator_hashes {
            if cached_headers.contains_key(locator) {
                found = Some(*locator);
                break;
            }
        }
        found.unwrap_or_else(|| {
            // If no locators are found, use the genesis hash.
            // TODO(XC-471): fix this for Dogecoin.
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
                .parse()
                .unwrap()
        })
    };

    let mut queue = VecDeque::new();
    queue.extend(children.get(&locator).unwrap_or(&vec![]).iter().copied());
    while let Some(next) = queue.pop_front() {
        if block_headers.len() >= 2000 {
            break;
        }
        block_headers.push(cached_headers[&next]);
        queue.extend(children.get(&next).unwrap_or(&vec![]));
    }
    write_network_message(
        socket,
        magic,
        <NetworkMessage<Block>>::Headers(block_headers),
    )
    .await
}

fn decompress(location: String) -> Vec<u8> {
    let bytes = std::fs::read(location).unwrap();
    let mut dec = flate2::read::GzDecoder::new(bytes.as_slice());
    let mut decompressed = Vec::new();
    dec.read_to_end(&mut decompressed)
        .expect("failed to decode gzip");
    decompressed
}

#[derive(Clone)]
struct FakeBitcoind<Block> {
    cached_headers: Arc<HashMap<BlockHash, BlockHeader>>,
    blocks: Arc<HashMap<BlockHash, Block>>,
    children: Arc<HashMap<BlockHash, Vec<BlockHash>>>,
}

impl<Block> FakeBitcoind<Block>
where
    Block: BlockLike + for<'de> serde::Deserialize<'de> + Clone + Debug + Send + Sync + 'static,
{
    pub fn new(headers_location: String, blocks_location: String) -> Self {
        let decompressed_headers = decompress(headers_location);
        let headers: Vec<BlockHeader> = serde_json::from_slice(&decompressed_headers).unwrap();
        let cached_headers = Arc::new(
            headers
                .iter()
                .map(|header| (header.block_hash(), *header))
                .collect(),
        );
        let decompressed_blocks = decompress(blocks_location);
        let blocks: Vec<Block> = serde_json::from_slice(&decompressed_blocks).unwrap();
        let blocks: Arc<HashMap<BlockHash, Block>> = Arc::new(
            blocks
                .iter()
                .map(|block| (block.block_hash(), block.clone()))
                .collect(),
        );
        let mut children: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();
        headers.iter().for_each(|header| {
            let entry = children.entry(header.prev_blockhash);
            entry
                .and_modify(|children_vec| children_vec.push(header.block_hash()))
                .or_insert(vec![header.block_hash()]);
        });
        Self {
            cached_headers,
            blocks,
            children: Arc::new(children),
        }
    }

    async fn start_mock(&self, listener: TcpListener) {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let FakeBitcoind {
                cached_headers,
                blocks,
                children,
            } = self.clone();
            tokio::spawn(async move {
                let mut unparsed = vec![];
                loop {
                    let mut buf = vec![0; 1024];
                    let bytes_read = socket.read(&mut buf).await.unwrap();
                    buf.truncate(bytes_read);
                    unparsed.extend(buf.iter());

                    while !unparsed.is_empty() {
                        match deserialize_partial::<RawNetworkMessage<Block>>(&unparsed) {
                            Ok((raw, cnt)) => {
                                let handler_result =
                                match raw.payload() {
                                    NetworkMessage::Version(v) => {
                                        handle_version::<Block>(&mut socket, v, *raw.magic()).await
                                    }
                                    NetworkMessage::Verack => Ok(()),
                                    NetworkMessage::GetAddr => {
                                        handle_getaddr::<Block>(&mut socket, *raw.magic()).await
                                    }
                                    NetworkMessage::GetHeaders(msg) => {
                                        handle_getheaders::<Block>(&mut socket, msg, *raw.magic(), cached_headers.clone(), children.clone()).await
                                    }
                                    NetworkMessage::GetData(msg) => {
                                        handle_getdata(&mut socket, msg, *raw.magic(), blocks.clone()).await
                                    }
                                    NetworkMessage::Ping(val) => {
                                        handle_ping::<Block>(&mut socket, *val, *raw.magic()).await
                                    }
                                    smth => panic!("Unexpected NetworkMessage: {:?}", smth),
                                };
                                if let Err(err) = handler_result {
                                    eprintln!("Mock bitcoind handler error: {}", err);
                                }
                                unparsed.drain(..cnt);
                            }
                            Err(encode::Error::Io(ref err)) // Received incomplete message
                                if err.kind() == bitcoin_io::ErrorKind::UnexpectedEof =>
                            {
                                break
                            }
                            Err(err) => panic!("{}", err),
                        }
                    }
                }
            });
        }
    }
}

pub fn mock_bitcoin<Block>(
    rt: &tokio::runtime::Handle,
    test_data_path: String,
    block_data_path: String,
) -> net::SocketAddr
where
    Block: BlockLike + for<'de> serde::Deserialize<'de> + Clone + Debug + Send + Sync + 'static,
{
    let listener = rt.block_on(async { TcpListener::bind("127.0.0.1:0").await.unwrap() });
    let addr = listener.local_addr().unwrap();
    rt.spawn(async {
        let p2p_mock = <FakeBitcoind<Block>>::new(test_data_path, block_data_path);
        p2p_mock.start_mock(listener).await;
    });
    addr
}

const LOCAL_IP: net::Ipv4Addr = net::Ipv4Addr::new(127, 0, 0, 1);

/// Bitcoin or Dogecoin daemon.
pub struct Daemon<T: RpcClientType> {
    /// RPC client that connects to this Bitcoin daemon.
    pub rpc_client: RpcClient<T>,
    _work_dir: WorkDir,
    p2p_socket: Option<net::SocketAddrV4>,
    process: process::Child,
}

impl<T: RpcClientType> Drop for Daemon<T> {
    fn drop(&mut self) {
        let _ = self.stop();
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

enum WorkDir {
    Persisted(PathBuf),
    Temporary(TempDir),
}

impl WorkDir {
    fn path(&self) -> PathBuf {
        match self {
            Self::Persisted(path) => path.to_owned(),
            Self::Temporary(tmp_dir) => tmp_dir.path().into(),
        }
    }
}

/// Configuration for [Daemon].
pub struct Conf<'a> {
    /// [Auth] setting of the daemon. If not specified, an auto-generated cookie file will be used.
    pub auth: Option<Auth>,
    /// Whether p2p port should be enabled.
    pub p2p: bool,
    /// Whether output of the daemon should be duplicated to stdout.
    pub view_stdout: bool,
    /// Work directory. If not specified, a randomly generated temporary directory will be used.
    pub work_dir: Option<PathBuf>,
    /// Additional args to pass to the daemon command line. If not specified, the default args
    /// are `["-regtest", "-fallbackfee=0.0001"]`.
    pub args: Vec<&'a str>,
}

impl<'a> Default for Conf<'a> {
    fn default() -> Self {
        Self {
            auth: None,
            p2p: false,
            view_stdout: false,
            work_dir: None,
            args: vec!["-regtest", "-fallbackfee=0.0001"],
        }
    }
}

impl<T: RpcClientType> Daemon<T> {
    /// Create a new daemon by running the executable at the given path, network and
    /// configration.
    pub fn new(daemon_path: &str, network: T, conf: Conf) -> Result<Daemon<T>, RpcError> {
        let work_dir = match conf.work_dir {
            Some(dir) => {
                fs::create_dir_all(dir.clone())?;
                WorkDir::Persisted(dir)
            }
            None => WorkDir::Temporary(tempdir()?),
        };

        let conf_path = work_dir.path().join("bitcoin.conf");
        let auth = match conf.auth {
            None => {
                let cookie_file = work_dir.path().join(network.to_string()).join(".cookie");
                Auth::CookieFile(cookie_file)
            }
            Some(Auth::UserPass(_, _)) => panic!("Auth::UserPass is not supported"),
            Some(auth) => auth,
        };
        fs::write(conf_path.clone(), "")?;
        let rpc_port = get_available_port()?;
        let rpc_socket = net::SocketAddrV4::new(LOCAL_IP, rpc_port);
        let rpc_url = format!("http://{}", rpc_socket);
        let (p2p_args, p2p_socket) = if conf.p2p {
            let p2p_port = get_available_port()?;
            let p2p_socket = net::SocketAddrV4::new(LOCAL_IP, p2p_port);
            let p2p_arg = format!("-port={}", p2p_port);
            let args = vec![p2p_arg];
            (args, Some(p2p_socket))
        } else {
            (vec!["-listen=0".to_string()], None)
        };

        let stdout = if conf.view_stdout {
            process::Stdio::inherit()
        } else {
            process::Stdio::null()
        };

        let mut process = process::Command::new(daemon_path)
            .arg("-printtoconsole")
            .arg(format!("-conf={}", conf_path.display()))
            .arg(format!("-datadir={}", work_dir.path().display()))
            .arg(format!("-rpcport={}", rpc_port))
            .args(&p2p_args)
            .args(&conf.args)
            .stdout(stdout)
            .spawn()?;

        if let Some(status) = process.try_wait()? {
            panic!("early exit with: {:?}", status);
        }
        assert!(process.stderr.is_none());

        let mut i = 0;
        let rpc_client = loop {
            std::thread::sleep(std::time::Duration::from_millis(100));
            match RpcClient::new(network, &rpc_url, auth.clone()) {
                Ok(client) => break client.ensure_wallet()?,
                Err(err) if i > 50 => return Err(err),
                Err(_) => {
                    i += 1;
                }
            }
        };

        Ok(Self {
            _work_dir: work_dir,
            p2p_socket,
            rpc_client,
            process,
        })
    }

    /// Stop the daemon process and return its [ExitStatus].
    pub fn stop(&mut self) -> Result<process::ExitStatus, RpcError> {
        self.rpc_client.stop()?;
        Ok(self.process.wait()?)
    }

    /// Return the p2p socket the daemon listens on if `p2p` was specified.
    pub fn p2p_socket(&self) -> Option<net::SocketAddrV4> {
        self.p2p_socket
    }
}

fn get_available_port() -> Result<u16, std::io::Error> {
    // using 0 as port let the system assign a port available
    let t = net::TcpListener::bind(("127.0.0.1", 0))?; // 0 means the OS choose a free port
    t.local_addr().map(|s| s.port())
}
