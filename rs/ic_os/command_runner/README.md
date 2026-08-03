# command_runner

Tiny abstraction crate for code that shells out to external commands.

## How it works
- `CommandRunner` wraps synchronous `std::process::Command` execution.
- `AsyncCommandRunner` wraps asynchronous `tokio::process::Command` execution.
- `RealCommandRunner` and `RealAsyncCommandRunner` are the production
  implementations.
- Both traits are `mockall`-mockable, so crates that depend on command output
  can test failure paths without spawning real processes.

Use this crate whenever command execution is part of the logic and you want that
logic to stay unit-testable.
