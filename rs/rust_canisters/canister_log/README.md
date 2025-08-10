# IC Canister Log

This package provides a basic logging library for smart contracts running on the [Internet Computer](https://internetcomputer.org/) (also known as [canisters](https://internetcomputer.org/docs/current/references/glossary/#canister)).

## Usage

Macros `declare_log_buffer` and `log` are the core library interface.
The `declare_log_buffer` macros creates a circular buffer of messages with the specified capacity.
The `log` macro formats and appends messages to a buffer.

You can extract messages from the log buffer using the `export` function.

```rust
use ic_canister_log::{declare_log_buffer, export, log};

// Keep up to 100 last messages.
declare_log_buffer!(name = LOG, capacity = 100);

fn sum_and_log(x: u64, y: u64) -> u64 {
   let result = x.saturating_add(y);
   log!(LOG, "{} + {} = {}", x, y, result);
   result
}

fn print_log_entries() {
  for entry in export(&LOG) {
    println!("{}:{} {}", entry.file, entry.line, entry.message);
  }
}
```
