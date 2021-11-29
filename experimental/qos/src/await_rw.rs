//! async/await based implementation of the reader/writer traits

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::{channel, error::TryRecvError, error::TrySendError, Receiver, Sender};
use tokio::task::JoinHandle;

use crate::interface::{ErrorCode, Payload, ReadStub, StreamReader, StreamWriter, WriteStub};

pub struct AwaitWriter {
    write_request_sender: Sender<Payload>,
    _write_task: JoinHandle<()>,
}

impl AwaitWriter {
    pub fn new(writer: WriteStub) -> Self {
        let (sender, receiver): (Sender<Payload>, Receiver<Payload>) = channel(1);
        let _write_task = tokio::spawn(async move {
            Self::process_write_requests(receiver, writer).await;
        });
        Self {
            write_request_sender: sender,
            _write_task,
        }
    }

    async fn process_write_requests(
        mut write_request_receiver: Receiver<Payload>,
        mut writer: WriteStub,
    ) {
        // TODO: make the awaits cancelable
        loop {
            let payload = match write_request_receiver.recv().await {
                Some(payload) => payload,
                None => return,
            };

            if let Err(e) = writer.write_all(&payload).await {
                println!("Failed to write({:?}): {:?}", payload[0], e);
            }
        }
    }
}

#[async_trait]
impl StreamWriter for AwaitWriter {
    async fn send(&mut self, payload: Payload) -> Result<(), ErrorCode> {
        self.write_request_sender
            .try_send(payload)
            .map_err(|e| match e {
                TrySendError::Full(t) => ErrorCode::SendFull(t),
                _ => ErrorCode::Failed,
            })
    }
}

pub struct AwaitReader {
    payload_receiver: Receiver<Payload>,
    _read_task: JoinHandle<()>,
}

impl AwaitReader {
    pub fn new(reader: ReadStub) -> Self {
        let (sender, receiver): (Sender<Payload>, Receiver<Payload>) = channel(1);
        let _read_task = tokio::spawn(async move {
            Self::process_read(sender, reader).await;
        });
        Self {
            payload_receiver: receiver,
            _read_task,
        }
    }

    async fn process_read(mut payload_sender: Sender<Payload>, mut reader: ReadStub) {
        // TODO: make the awaits cancelable
        loop {
            let mut payload = vec![0; 1024 * 192]; // TODO: ...
            if let Err(e) = reader.read_exact(payload.as_mut_slice()).await {
                println!("process_read(): Failed to read: {:?}", e);
                continue;
            }

            if let Err(e) = payload_sender.send(payload).await {
                println!("process_read(): failed to send: {:?}", e);
            }
        }
    }
}

#[async_trait]
impl StreamReader for AwaitReader {
    async fn receive(&mut self) -> Result<Payload, ErrorCode> {
        self.payload_receiver.try_recv().map_err(|e| match e {
            TryRecvError::Empty => ErrorCode::ReadEmpty,
            _ => ErrorCode::Failed,
        })
    }
}
