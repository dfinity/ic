//! Polling based implementation of the reader/writer traits

use async_trait::async_trait;
use futures::poll;
use futures::task::Poll;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::interface::{ErrorCode, Payload, ReadStub, StreamReader, StreamWriter, WriteStub};

pub struct PollWriter {
    writer: WriteStub,
    pending: Option<Payload>,
    last_op: String,
}

impl PollWriter {
    pub fn new(writer: WriteStub) -> Self {
        Self {
            writer,
            pending: None,
            last_op: "".to_string(),
        }
    }

    async fn process_write(&mut self) -> Result<(), ErrorCode> {
        let mut payload = self.pending.take().unwrap();
        let ret = poll!(self.writer.write(&payload));
        self.last_op = format!("process_write({}): {:?}", payload[0], ret);
        match ret {
            Poll::Ready(result) => match result {
                Ok(sent) => {
                    if sent < payload.len() {
                        self.pending = Some(payload.split_off(sent));
                    }
                    Ok(())
                }
                Err(e) => {
                    println!("process_write(): failed to write: {:?}", e);
                    Err(ErrorCode::Failed)
                }
            },
            Poll::Pending => {
                self.pending = Some(payload);
                Ok(())
            }
        }
    }

    fn get_state(&self) -> String {
        match &self.pending {
            None => "None pending".to_string(),
            Some(payload) => format!("Pending: pat = {}, len = {}", payload[0], payload.len()),
        }
    }
}

#[async_trait]
impl StreamWriter for PollWriter {
    async fn send(&mut self, payload: Payload) -> Result<(), ErrorCode> {
        let ret = match &self.pending {
            None => {
                // Case 1: previous write not pending
                self.pending = Some(payload);
                self.process_write().await
            }
            Some(_) => {
                // Case 2: previous write needs to be sent out
                let _ = self.process_write().await;
                if self.pending.is_none() {
                    self.pending = Some(payload);
                    self.process_write().await
                } else {
                    Err(ErrorCode::SendFull(payload))
                }
            }
        };

        println!(
            "poll::send(): last_op: [{}], state: [{}]",
            self.last_op,
            self.get_state()
        );
        ret
    }
}

pub struct PollReader {
    reader: ReadStub,
    pending: Option<(Payload, usize)>, // Read buffer, cur offset
    last_op: String,
}

impl PollReader {
    pub fn new(reader: ReadStub) -> Self {
        Self {
            reader,
            pending: None,
            last_op: "".to_string(),
        }
    }

    async fn process_read(&mut self) -> Result<Payload, ErrorCode> {
        let (mut buf, offset) = self.pending.take().unwrap();
        let ret = poll!(self.reader.read(&mut buf[offset..]));
        self.last_op = format!("process_read({}): {:?}", buf[0], ret);
        match ret {
            Poll::Ready(result) => match result {
                Ok(read) => {
                    if (offset + read) < buf.len() {
                        self.pending = Some((buf, offset + read));
                        Err(ErrorCode::ReadEmpty)
                    } else {
                        Ok(buf)
                    }
                }
                Err(e) => {
                    println!("process_read(): failed to read: {:?}", e);
                    Err(ErrorCode::Failed)
                }
            },
            Poll::Pending => {
                self.pending = Some((buf, offset));
                Err(ErrorCode::ReadEmpty)
            }
        }
    }

    fn get_state(&self) -> String {
        match &self.pending {
            None => "None pending".to_string(),
            Some((buf, offset)) => {
                format!("Pending: pat = {}, len = {}", buf[0], buf.len() - offset)
            }
        }
    }
}

#[async_trait]
impl StreamReader for PollReader {
    async fn receive(&mut self) -> Result<Payload, ErrorCode> {
        if self.pending.is_none() {
            self.pending = Some((vec![0; 1024 * 192], 0));
        }
        let ret = self.process_read().await;
        println!(
            "poll::receive(): last_op: [{}], state: [{}]",
            self.last_op,
            self.get_state()
        );
        ret
    }
}
