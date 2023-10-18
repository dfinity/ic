use std::collections::{HashMap, VecDeque};

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

struct FakeBitcoind {
    listener: TcpListener,
    cached_headers: HashMap<BlockHash, BlockHeader>,
    blocks: HashMap<BlockHash, Block>,
    children: HashMap<BlockHash, Vec<BlockHash>>,
}

impl FakeBitcoind {
    pub fn new(listener: TcpListener, headers_location: String, blocks_location: String) -> Self {
        let headers_json = std::fs::read_to_string(headers_location).unwrap();
        let headers: Vec<BlockHeader> = serde_json::from_str(&headers_json).unwrap();
        let cached_headers = headers
            .iter()
            .map(|header| (header.block_hash(), *header))
            .collect();
        let blocks_json = std::fs::read_to_string(blocks_location).unwrap();
        let blocks: Vec<Block> = serde_json::from_str(&blocks_json).unwrap();
        let blocks: HashMap<BlockHash, Block> = blocks
            .iter()
            .map(|block| (block.block_hash(), block.clone()))
            .collect();
        let mut children: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();
        headers.iter().for_each(|header| {
            let entry = children.entry(header.prev_blockhash);
            entry
                .and_modify(|children_vec| children_vec.push(header.block_hash()))
                .or_insert(vec![header.block_hash()]);
        });
        Self {
            listener,
            cached_headers,
            blocks,
            children,
        }
    }

    async fn start_mock(&mut self) {
        let (mut socket, _) = self.listener.accept().await.unwrap();
        let mut unparsed = vec![];
        loop {
            let mut buf = vec![0; 1024];
            let bytes_read = socket.read(&mut buf).await.unwrap();
            buf.truncate(bytes_read);
            unparsed.extend(buf.iter());

            while !unparsed.is_empty() {
                match deserialize_partial::<RawNetworkMessage>(&unparsed) {
                    Ok((raw, cnt)) => {
                        match raw.payload {
                            NetworkMessage::Version(v) => {
                                self.handle_version(&mut socket, v, raw.magic).await
                            }
                            NetworkMessage::Verack => (),
                            NetworkMessage::GetAddr => {
                                self.handle_getaddr(&mut socket, raw.magic).await
                            }
                            NetworkMessage::GetHeaders(msg) => {
                                self.handle_getheaders(&mut socket, msg, raw.magic).await
                            }
                            NetworkMessage::GetData(msg) => {
                                self.handle_getdata(&mut socket, msg, raw.magic).await
                            }
                            NetworkMessage::Ping(val) => {
                                self.handle_ping(&mut socket, val, raw.magic).await
                            }
                            smth => panic!("Unexpected NetworkMessage: {:?}", smth),
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
    }

    async fn handle_getdata(&self, socket: &mut TcpStream, msg: Vec<Inventory>, magic: u32) {
        for inv in msg.iter() {
            match inv {
                Inventory::Block(hash) => {
                    if !self.blocks.contains_key(hash) {
                        continue;
                    }
                    let block = self.blocks.get(hash).unwrap();
                    let res = RawNetworkMessage {
                        magic,
                        payload: NetworkMessage::Block(block.clone()),
                    };
                    let serialized = serialize(&res);
                    socket.write_all(&serialized).await.unwrap();
                }
                _ => {
                    unimplemented!();
                }
            }
        }
    }

    async fn handle_ping(&self, socket: &mut TcpStream, val: u64, magic: u32) {
        let pong = RawNetworkMessage {
            magic,
            payload: NetworkMessage::Pong(val),
        };

        let serialized = serialize(&pong);
        socket.write_all(&serialized).await.unwrap();
    }

    async fn handle_version(&self, socket: &mut TcpStream, v: VersionMessage, magic: u32) {
        if v.version < MINIMUM_PROTOCOL_VERSION {
            return;
        }
        let verack = RawNetworkMessage {
            magic,
            payload: NetworkMessage::Verack,
        };

        let mut version = v.clone();
        version.services.add(ServiceFlags::NETWORK);
        let version = RawNetworkMessage {
            magic,
            payload: NetworkMessage::Version(version),
        };

        let serialized = serialize(&version);
        socket.write_all(&serialized).await.unwrap();

        let serialized = serialize(&verack);
        socket.write_all(&serialized).await.unwrap();
    }

    async fn handle_getaddr(&self, socket: &mut TcpStream, magic: u32) {
        let addr = RawNetworkMessage {
            magic,
            payload: NetworkMessage::Addr(vec![]),
        };
        let serialized = serialize(&addr);
        socket.write_all(&serialized).await.unwrap();
    }

    async fn handle_getheaders(&self, socket: &mut TcpStream, msg: GetHeadersMessage, magic: u32) {
        let mut block_headers: Vec<BlockHeader> = vec![];

        let locator = {
            let mut found = None;

            for locator in msg.locator_hashes {
                if self.cached_headers.contains_key(&locator) {
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
        queue.extend(
            self.children
                .get(&locator)
                .unwrap_or(&vec![])
                .iter()
                .copied(),
        );
        while let Some(next) = queue.pop_front() {
            if block_headers.len() >= 2000 {
                break;
            }
            block_headers.push(self.cached_headers[&next]);
            queue.extend(self.children.get(&next).unwrap_or(&vec![]));
        }

        let response = RawNetworkMessage {
            magic,
            payload: NetworkMessage::Headers(block_headers),
        };
        socket.write_all(&serialize(&response)).await.unwrap();
    }
}

pub fn mock_bitcoin(rt: &tokio::runtime::Handle, test_data_path: String, block_data_path: String) {
    rt.spawn(async {
        let listener = TcpListener::bind("127.0.0.1:8333").await.unwrap();
        let mut p2p_mock = FakeBitcoind::new(listener, test_data_path, block_data_path);
        p2p_mock.start_mock().await;
    });
}
