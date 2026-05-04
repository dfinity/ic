use ic_canister_log::declare_log_buffer;

// Info log messages
declare_log_buffer!(name = INFO, capacity = 1000);

// Error log messages.
declare_log_buffer!(name = ERROR, capacity = 1000);
