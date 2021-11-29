
export PATH := ../../../rs/.cargo-home/bin:$(PATH)

all:
	cd ../../../rs && cargo build --release
	cd -
	cargo build --release
	flamegraph /usr/bin/time ../../../rs/target/release/drun --config ic.toml messages.txt
