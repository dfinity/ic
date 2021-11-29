use slog::slog_o;
use slog_scope::info;

// Return the page number of the page that `base_address[count]` falls on
pub fn page_num<T>(base_address: *mut T, count: usize) -> u64 {
    let address = unsafe { base_address.offset(count as isize) };
    let address_page_boundary = address as u64 & !(*memory_area::PAGE_SIZE as u64 - 1);
    (address_page_boundary - base_address as u64) / *memory_area::PAGE_SIZE as u64
}

// Helper function to perform a memory read `base_address[count]` and print additional information.
pub fn memory_read<T>(base_address: *mut T, count: usize) -> T
where
    T: std::fmt::Display + std::cmp::PartialEq,
{
    let page_num = page_num(base_address, count);
    let address = unsafe { base_address.offset(count as isize) };
    let value = unsafe { std::ptr::read(address) };
    info!(
        "READ  0x{:x} page({}) memory[{}] = {}",
        address as u64, page_num, count, value
    );
    value
}

// Helper function to perform a memory write `base_address[count] = val` followed by memory read
// `base_address[count]` and print additional information.
pub fn memory_write_read<T>(memory: *mut T, count: usize, val: T)
where
    T: std::fmt::Display + std::fmt::Debug + PartialEq + Copy,
{
    let page_num = page_num(memory, count);
    let address = unsafe { memory.offset(count as isize) };
    info!(
        "WRITE 0x{:x} page({}) memory[{}] <- {}",
        address as u64, page_num, count, val
    );
    unsafe {
        std::ptr::write(address as *mut T, val);
    }
    let read_val = memory_read(memory, count);
    assert_eq!(val, read_val);
}

pub fn init_logger() -> (slog_scope::GlobalLoggerGuard, slog_async::AsyncGuard) {
    use slog::Drain; // for .fuse()
    let drain = slog_term::CompactFormat::new(slog_term::PlainSyncDecorator::new(
        slog_term::TestStdoutWriter,
    ))
    .build();
    // use async_guard to guarantee the log is flushed before exiting
    let (async_log, async_guard) = slog_async::Async::new(drain.fuse())
        .chan_size(100)
        .overflow_strategy(slog_async::OverflowStrategy::Block)
        .build_with_guard();
    let root_logger = slog::Logger::root(
        async_log.fuse(),
        slog_o!("version" => env!("CARGO_PKG_VERSION")),
    );
    let log_guard = slog_scope::set_global_logger(root_logger);
    (log_guard, async_guard)
}
