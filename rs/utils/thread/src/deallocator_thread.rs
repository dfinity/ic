use crate::JoinOnDrop;
use crossbeam_channel::{bounded, unbounded, Sender};

/// An object to be deallocated in the background.
type Deallocation = Box<dyn std::any::Any + Send + 'static>;

/// A helper struct that notifies when it's deallocated.
struct NotifyWhenDeallocated {
    channel: Sender<()>,
}

impl Drop for NotifyWhenDeallocated {
    fn drop(&mut self) {
        self.channel
            .send(())
            .expect("Failed to notify deallocation");
    }
}

// We will not use the deallocation thread when the number of pending
// deallocation objects goes above the threshold.
const DEALLOCATION_BACKLOG_THRESHOLD: usize = 500;

/// A thread that deallocates complex objects in the background. It spreads the
/// cost of deallocation over a longer period of time, to avoid long pauses.
pub struct DeallocatorThread {
    deallocation_sender: DeallocationSender,
    _deallocation_handle: JoinOnDrop<()>,
}

impl DeallocatorThread {
    pub fn new(name: &str, sleep_between_drops: u32) -> Self {
        #[allow(clippy::disallowed_methods)]
        let (sender, receiver) = unbounded();
        let deallocation_sender = DeallocationSender { sender };
        let _deallocation_handle = JoinOnDrop::new(
            std::thread::Builder::new()
                .name(name.to_string())
                .spawn({
                    move || {
                        while let Ok(object) = receiver.recv() {
                            std::mem::drop(object);
                            // Sleep, to spread out the load on the memory allocator.
                            std::thread::sleep(sleep_between_drops);
                        }
                    }
                })
                .expect("failed to spawn background deallocation thread"),
        );

        Self {
            deallocation_sender,
            _deallocation_handle,
        }
    }

    /// Returns a reference to the sender to the deallocation thread.
    pub fn sender(&self) -> &DeallocationSender {
        &self.deallocation_sender
    }

    /// Sends an object to be deallocated in the background, iff the backlog is
    /// under the threshold; else, drops the object directly.
    pub fn send(&self, obj: Deallocation) {
        self.deallocation_sender.send(obj);
    }

    /// Wait until deallocation queue is empty.
    ///
    /// Used in tests to wait for all deallocations to complete.
    #[doc(hidden)]
    pub fn flush_deallocation_channel(&self) {
        let (send, recv) = bounded(1);
        self.deallocation_sender
            .send(Box::new(NotifyWhenDeallocated { channel: send }));
        recv.recv()
            .expect("Failed to receive deallocation notification");
    }
}

/// A cheaply cloneable sender to a `DeallocatorThread`.
#[derive(Clone)]
pub struct DeallocationSender {
    sender: Sender<Deallocation>,
}

impl DeallocationSender {
    /// Sends an object to be deallocated in the background, iff the backlog is
    /// under the threshold; else, drops the object directly.
    pub fn send(&self, obj: Deallocation) {
        if self.sender.len() < DEALLOCATION_BACKLOG_THRESHOLD {
            self.sender
                .send(obj)
                .expect("failed to send object to deallocation thread");
        } else {
            std::mem::drop(obj);
        }
    }
}
