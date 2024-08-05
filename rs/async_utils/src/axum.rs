use axum::body::{Body, HttpBody};
use bytes::Bytes;
use futures_util::Stream;
use std::{
    pin::{pin, Pin},
    task::Poll,
};
use sync_wrapper::SyncWrapper;

/// Wrapper used for conversion from an Axum Body to a Reqwest one
pub struct BodyDataStream {
    inner: SyncWrapper<Body>,
}

impl BodyDataStream {
    pub const fn new(body: Body) -> Self {
        Self {
            inner: SyncWrapper::new(body),
        }
    }
}

impl Stream for BodyDataStream {
    type Item = Result<Bytes, anyhow::Error>;

    #[inline]
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        loop {
            let mut pinned = pin!(self.inner.get_mut());
            match futures_util::ready!(pinned.as_mut().poll_frame(cx)?) {
                Some(frame) => match frame.into_data() {
                    Ok(data) => return Poll::Ready(Some(Ok(data))),
                    Err(_frame) => {}
                },
                None => return Poll::Ready(None),
            }
        }
    }
}
