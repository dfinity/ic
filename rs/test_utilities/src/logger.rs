use ic_logger::ReplicaLogger;
use std::io;
use std::sync::{Arc, Mutex};

struct SyncBuf(Arc<Mutex<Vec<u8>>>);

impl io::Write for SyncBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct PrintOnDrop(Arc<Mutex<Vec<u8>>>);

impl Drop for PrintOnDrop {
    fn drop(&mut self) {
        let buf = self.0.lock().unwrap();
        print!("{}", String::from_utf8_lossy(&buf))
    }
}

pub fn with_test_logger<F, R>(f: F) -> R
where
    F: FnOnce(&slog::Logger) -> R,
{
    use slog::Drain;

    let buf = Arc::new(Mutex::new(vec![]));
    let writer = SyncBuf(Arc::clone(&buf));
    let _print = PrintOnDrop(buf);

    let plain = slog_term::PlainDecorator::new(writer);
    let drain = slog_term::FullFormat::new(plain).build();
    let drain = Mutex::new(drain).fuse();
    let log = slog::Logger::root(drain, slog::o!());
    slog_scope::scope(&log, || f(&log))
}

pub fn get_test_replica_logger() -> ReplicaLogger {
    use slog::Drain;

    let buf = Arc::new(Mutex::new(vec![]));
    let writer = SyncBuf(Arc::clone(&buf));
    let _print = PrintOnDrop(buf);

    let plain = slog_term::PlainDecorator::new(writer);
    let drain = slog_term::FullFormat::new(plain)
        .build()
        .filter_level(slog::Level::Info)
        .ignore_res();
    let drain = Mutex::new(drain).fuse();
    slog::Logger::root(drain, slog::o!()).into()
}

pub fn with_test_replica_logger<F, R>(f: F) -> R
where
    F: FnOnce(ReplicaLogger) -> R,
{
    f(get_test_replica_logger())
}
