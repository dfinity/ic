use std::thread;

/// An object that joins a thread when it's dropped. Mostly helpful to implement
/// graceful shutdowns.
///
/// Note that Rust destroys fields in the order of their declaration:
///
/// > The fields of a struct, tuple or enum variant are dropped in declaration
/// order.
///
/// See:
/// * https://doc.rust-lang.org/stable/reference/destructors.html
/// * https://github.com/rust-lang/rfcs/blob/master/text/1857-stabilize-drop-order.md
///
/// That means that if you have a send/receive channel to talk to the thread in
/// your struct as well, you should make JoinOnDrop the last field in your
/// struct.
pub struct JoinOnDrop<T>(Option<thread::JoinHandle<T>>);

impl<T> JoinOnDrop<T> {
    pub fn new(h: thread::JoinHandle<T>) -> Self {
        Self(Some(h))
    }

    /// Explicitly joins the thread.
    pub fn join(mut self) -> thread::Result<T> {
        // It's OK to unwrap here because the wrapped object can only become
        // None when it's out of scope.
        self.0.take().unwrap().join()
    }
}

impl<T> Drop for JoinOnDrop<T> {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            let _ = h.join();
        }
    }
}
