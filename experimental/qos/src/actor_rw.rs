//! Actor based implementation of the reader/writer traits

use actix::prelude::*;
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use crate::interface::{ErrorCode, Payload, StreamWriter, WriteStub};

type WriteResult = Result<(), ErrorCode>;
struct WriteActor {
    writer: Option<WriteStub>,
}

#[derive(Message)]
#[rtype(result = "WriteResult")]
pub struct WriteRequest(pub Payload);

impl WriteActor {
    pub fn new(writer: WriteStub) -> Self {
        Self {
            writer: Some(writer),
        }
    }
}

impl Actor for WriteActor {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(1);
    }
}

impl Handler<WriteRequest> for WriteActor {
    type Result = AtomicResponse<Self, WriteResult>;

    fn handle(&mut self, message: WriteRequest, _: &mut Self::Context) -> Self::Result {
        let mut writer = self.writer.take().unwrap();
        AtomicResponse::new(Box::pin(
            async move {
                let result = writer.write_all(&message.0).await.map_err(|e| {
                    println!("WriteActor::handle(): failed: {:?}", e);
                    ErrorCode::Failed
                });
                (writer, result)
            }
            .into_actor(self)
            .map(|(writer, result), this, _| {
                this.writer = Some(writer);
                result
            }),
        ))
    }
}

pub struct WriteActorFE {
    backend: Addr<WriteActor>,
}

impl WriteActorFE {
    pub fn new(writer: WriteStub) -> Self {
        let backend = WriteActor::new(writer).start();
        Self { backend }
    }
}

#[async_trait]
impl StreamWriter for WriteActorFE {
    async fn send(&mut self, payload: Payload) -> Result<(), ErrorCode> {
        self.backend.try_send(WriteRequest(payload)).map_err(|e| {
            println!("WriteActorFE::try_send(): failed: {:?}", e);
            match e {
                SendError::Full(p) => ErrorCode::SendFull(p.0),
                SendError::Closed(_) => ErrorCode::Failed,
            }
        })
    }
}
