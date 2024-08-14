use std::{
    collections::{HashMap, VecDeque},
    io::{self, ErrorKind, Read},
    net::SocketAddr,
    sync::Arc,
};

use bitcoin::{
    consensus::{deserialize_partial, encode, serialize},
    network::{
        constants::ServiceFlags,
        message::{NetworkMessage, RawNetworkMessage},
        message_blockdata::{GetHeadersMessage, Inventory},
        message_network::VersionMessage,
    },
    Block, BlockHash, BlockHeader,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const MINIMUM_PROTOCOL_VERSION: u32 = 70001;

async fn write_network_message(
    socket: &mut TcpStream,
    magic: u32,
    payload: NetworkMessage,
) -> io::Result<()> {
    let res = RawNetworkMessage { magic, payload };
    let serialized = serialize(&res);
    socket.write_all(&serialized).await?;
    socket.flush().await?;
    Ok(())
}

async fn handle_getdata(
    socket: &mut TcpStream,
    msg: Vec<Inventory>,
    magic: u32,
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

async fn handle_ping(socket: &mut TcpStream, val: u64, magic: u32) -> io::Result<()> {
    write_network_message(socket, magic, NetworkMessage::Pong(val)).await
}

async fn handle_version(socket: &mut TcpStream, v: VersionMessage, magic: u32) -> io::Result<()> {
    if v.version < MINIMUM_PROTOCOL_VERSION {
        let err = io::Error::new(ErrorKind::Other, "Protocol version too low");
        return Err(err);
    }
    let mut version = v.clone();
    version.services.add(ServiceFlags::NETWORK);
    write_network_message(socket, magic, NetworkMessage::Version(version)).await?;
    write_network_message(socket, magic, NetworkMessage::Verack).await?;
    Ok(())
}

async fn handle_getaddr(socket: &mut TcpStream, magic: u32) -> io::Result<()> {
    write_network_message(socket, magic, NetworkMessage::Addr(vec![])).await
}

async fn handle_getheaders(
    socket: &mut TcpStream,
    msg: GetHeadersMessage,
    magic: u32,
    cached_headers: Arc<HashMap<BlockHash, BlockHeader>>,
    children: Arc<HashMap<BlockHash, Vec<BlockHash>>>,
) -> io::Result<()> {
    let mut block_headers: Vec<BlockHeader> = vec![];

    let locator = {
        let mut found = None;

        for locator in msg.locator_hashes {
            if cached_headers.contains_key(&locator) {
                found = Some(locator);
                break;
            }
        }
        found.unwrap_or(
            // If no locators are found, use the genesis hash.
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
                .parse()
                .unwrap(),
        )
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
    write_network_message(socket, magic, NetworkMessage::Headers(block_headers)).await
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
struct FakeBitcoind {
    cached_headers: Arc<HashMap<BlockHash, BlockHeader>>,
    blocks: Arc<HashMap<BlockHash, Block>>,
    children: Arc<HashMap<BlockHash, Vec<BlockHash>>>,
}

impl FakeBitcoind {
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
                        match deserialize_partial::<RawNetworkMessage>(&unparsed) {
                            Ok((raw, cnt)) => {
                                let handler_result =
                                match raw.payload {
                                    NetworkMessage::Version(v) => {
                                        handle_version(&mut socket, v, raw.magic).await
                                    }
                                    NetworkMessage::Verack => Ok(()),
                                    NetworkMessage::GetAddr => {
                                        handle_getaddr(&mut socket, raw.magic).await
                                    }
                                    NetworkMessage::GetHeaders(msg) => {
                                        handle_getheaders(&mut socket, msg, raw.magic, cached_headers.clone(), children.clone()).await
                                    }
                                    NetworkMessage::GetData(msg) => {
                                        handle_getdata(&mut socket, msg, raw.magic, blocks.clone()).await
                                    }
                                    NetworkMessage::Ping(val) => {
                                        handle_ping(&mut socket, val, raw.magic).await
                                    }
                                    smth => panic!("Unexpected NetworkMessage: {:?}", smth),
                                };
                                if let Err(err) = handler_result {
                                    eprintln!("Mock bitcoind handler error: {}", err);
                                }
                                unparsed.drain(..cnt);
                            }
                            Err(encode::Error::Io(ref err)) // Received incomplete message
                                if err.kind() == std::io::ErrorKind::UnexpectedEof =>
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

pub fn mock_bitcoin(
    rt: &tokio::runtime::Handle,
    test_data_path: String,
    block_data_path: String,
) -> SocketAddr {
    let listener = rt.block_on(async { TcpListener::bind("127.0.0.1:0").await.unwrap() });
    let addr = listener.local_addr().unwrap();
    rt.spawn(async {
        let p2p_mock = FakeBitcoind::new(test_data_path, block_data_path);
        p2p_mock.start_mock(listener).await;
    });
    addr
}
