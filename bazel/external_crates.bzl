"""
This module declares all direct rust dependencies.

Run `./bin/bazel-pin.sh` from the top-level directory of the working tree after changing this file to regenerate Cargo Bazel lockfiles.
"""

load("@rules_rust//crate_universe:defs.bzl", "crate", "crates_repository", "splicing_config")

def external_crates_repository(name, static_openssl, cargo_lockfile, lockfile):
    crates_repository(
        name = name,
        isolated = True,
        cargo_lockfile = cargo_lockfile,
        lockfile = lockfile,
        cargo_config = "//:bazel/cargo.config",
        generator_urls = {
            "aarch64-apple-darwin": "https://github.com/bazelbuild/rules_rust/releases/download/0.15.0/cargo-bazel-aarch64-apple-darwin",
            "x86_64-pc-windows-gnu": "https://github.com/bazelbuild/rules_rust/releases/download/0.15.0/cargo-bazel-x86_64-pc-windows-gnu.exe",
            "x86_64-unknown-linux-gnu": "https://github.com/bazelbuild/rules_rust/releases/download/0.15.0/cargo-bazel-x86_64-unknown-linux-gnu",
            "x86_64-pc-windows-msvc": "https://github.com/bazelbuild/rules_rust/releases/download/0.15.0/cargo-bazel-x86_64-pc-windows-msvc.exe",
            "x86_64-apple-darwin": "https://github.com/bazelbuild/rules_rust/releases/download/0.15.0/cargo-bazel-x86_64-apple-darwin",
            "x86_64-unknown-linux-musl": "https://github.com/bazelbuild/rules_rust/releases/download/0.15.0/cargo-bazel-x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-gnu": "https://github.com/bazelbuild/rules_rust/releases/download/0.15.0/cargo-bazel-aarch64-unknown-linux-gnu",
        },
        annotations = {
            "ic_bls12_381": [crate.annotation(
                rustc_flags = [
                    "-C",
                    "opt-level=3",
                ],
            )],
            "ring": [crate.annotation(
                build_script_env = {
                    "CFLAGS": "-fdebug-prefix-map=$${pwd}=/source",
                },
            )],
            "openssl-sys": [] if not static_openssl else [crate.annotation(
                build_script_data = [
                    "@openssl//:gen_dir",
                    "@openssl//:openssl",
                ],
                # https://github.com/sfackler/rust-openssl/tree/master/openssl-sys/build
                build_script_data_glob = ["build/**/*.c"],
                build_script_env = {
                    "OPENSSL_DIR": "$(execpath @openssl//:gen_dir)",
                    "OPENSSL_STATIC": "true",
                },
                data = ["@openssl"],
                deps = ["@openssl"],
            )],
            "librocksdb-sys": [crate.annotation(
                build_script_env = {
                    # Bazel executors assign only one core when executing
                    # the build script, making rocksdb compilation
                    # extremely slow. Bazel doesn't provide any way to
                    # override this settings so we cheat by starting more
                    # processes in parallel.
                    #
                    # See IDX-2406.
                    "NUM_JOBS": "8",
                },
            )],
            "pprof": [crate.annotation(
                build_script_data = [
                    "@com_google_protobuf//:protoc",
                ],
                build_script_env = {
                    "PROTOC": "$(execpath @com_google_protobuf//:protoc)",
                },
            )],
            "prost-build": [crate.annotation(
                build_script_env = {
                    "PROTOC_NO_VENDOR": "1",
                },
            )],
        },
        packages = {
            "actix-rt": crate.spec(
                version = "^2.2.0",
            ),
            "actix-web": crate.spec(
                version = "^4.0.0-beta.6",
            ),
            "addr": crate.spec(
                version = "=0.15.6",
                default_features = False,
                features = [
                    "idna",
                ],
            ),
            "arbitrary": crate.spec(
                version = "=1.3.0",
            ),
            "arc-swap": crate.spec(
                version = "^1",
            ),
            "assert_approx_eq": crate.spec(
                version = "^1.1.0",
            ),
            "by_address": crate.spec(
                version = "^1.1.0",
            ),
            "chacha20poly1305": crate.spec(
                version = "^0.10.0",
            ),
            "anyhow": crate.spec(
                version = "^1",
            ),
            "arrayvec": crate.spec(
                version = "^0.5.1",
            ),
            "askama": crate.spec(
                version = "^0.11.1",
                features = [
                    "serde-json",
                ],
            ),
            "assert-json-diff": crate.spec(
                version = "^2.0.1",
            ),
            "assert_cmd": crate.spec(
                version = "^0.12",
            ),
            "assert_matches": crate.spec(
                version = "^1.5.0",
            ),
            "async-recursion": crate.spec(
                version = "^0.3.2",
            ),
            "async-scoped": crate.spec(
                version = "^0.7.1",
                features = [
                    "use-tokio",
                ],
            ),
            "async-socks5": crate.spec(
                version = "^0.5.1",
            ),
            "async-stream": crate.spec(
                version = "^0.3.2",
            ),
            "async-trait": crate.spec(
                version = "^0.1.31",
            ),
            "axum": crate.spec(
                version = "^0.6.1",
            ),
            "axum-server": crate.spec(
                version = "^0.5.1",
                features = [
                    "tls-openssl",
                    "tls-rustls",
                ],
            ),
            "backoff": crate.spec(
                version = "^0.3.0",
            ),
            "base32": crate.spec(
                version = "^0.4.0",
            ),
            "base64": crate.spec(
                version = "^0.11.0",
            ),
            "bech32": crate.spec(
                version = "^0.9.0",
            ),
            "bincode": crate.spec(
                version = "^1.2.1",
            ),
            "bindgen": crate.spec(
                version = "^0.59.0",
                default_features = False,
                features = ["runtime"],
            ),
            "bip32": crate.spec(
                version = "^0.4.0",
                features = [
                    "secp256k1",
                ],
            ),
            "bit-vec": crate.spec(
                version = "^0.6.3",
            ),
            "bitcoin": crate.spec(
                version = "^0.28.1",
                features = [
                    "default",
                    "rand",
                    "use-serde",
                ],
            ),
            "bitcoincore-rpc": crate.spec(
                version = "^0.15.0",
            ),
            "bitcoind": crate.spec(
                version = "^0.32.0",
            ),
            "bitflags": crate.spec(
                version = "^1.2.1",
            ),
            "bs58": crate.spec(
                version = "0.4.0",
            ),
            "ic_bls12_381": crate.spec(
                version = "^0.8.0",
                features = [
                    "alloc",
                    "experimental",
                    "groups",
                    "pairings",
                    "zeroize",
                ],
                default_features = False,
            ),
            "build-info": crate.spec(
                git = "https://github.com/dfinity-lab/build-info",
                rev = "abb2971c5d07a9b40d41a0c84b63a3156f2ff764",
            ),
            "build-info-build": crate.spec(
                git = "https://github.com/dfinity-lab/build-info",
                rev = "abb2971c5d07a9b40d41a0c84b63a3156f2ff764",
                default_features = False,
            ),
            "byte-unit": crate.spec(
                version = "^4.0.14",
            ),
            "byteorder": crate.spec(
                version = "^1.3.4",
            ),
            "bytes": crate.spec(
                version = "^1.0.1",
            ),
            "cached": crate.spec(
                version = "^0.41",
                default_features = False,
            ),
            "candid": crate.spec(
                version = "^0.8.1",
            ),
            "cargo_metadata": crate.spec(
                version = "^0.14.2",
            ),
            "candid_derive": crate.spec(version = "^0.5.0"),
            "cc": crate.spec(
                version = "^1.0",
            ),
            "cddl": crate.spec(
                version = "^0.9.0-beta.1",
            ),
            "cfg-if": crate.spec(version = "^0.1.10"),
            "chrono": crate.spec(
                version = "=0.4.19",
            ),
            "ciborium": crate.spec(
                git = "https://github.com/enarx/ciborium",
                rev = "7d8f6e499db51fe52f5d3c2ce1d0e0be61c7eaa2",
            ),
            "clap": crate.spec(
                version = "^3.1.6",
                features = [
                    "derive",
                ],
            ),
            "clap_4_0_0": crate.spec(
                package = "clap",
                version = "^4.0.0",
                features = [
                    "derive",
                ],
            ),
            "cloudflare": crate.spec(
                version = "^0.9.1",
            ),
            "colored": crate.spec(
                version = "^2.0.0",
            ),
            "comparable": crate.spec(
                version = "^0.5",
                features = [
                    "derive",
                ],
            ),
            "console": crate.spec(
                version = "^0.11",
            ),
            "convert_case": crate.spec(
                version = "^0.6.0",
            ),
            "crc32fast": crate.spec(
                version = "^1.2.0",
            ),
            "criterion": crate.spec(
                version = "^0.3",
                features = [
                    "html_reports",
                    "async_tokio",
                ],
            ),
            "crossbeam": crate.spec(
                version = "^0.8.0",
            ),
            "crossbeam-channel": crate.spec(
                version = "^0.5.5",
            ),
            "crossbeam-utils": crate.spec(
                version = "^0.8.11",
            ),
            "csv": crate.spec(
                version = "^1.1",
            ),
            "curve25519-dalek": crate.spec(
                version = "^3.0.2",
            ),
            "cvt": crate.spec(
                version = "^0.1.1",
            ),
            "dashmap": crate.spec(
                version = "^5.3.4",
            ),
            "debug_stub_derive": crate.spec(
                version = "^0.3.0",
            ),
            "derive_more": crate.spec(
                git = "https://github.com/dfinity-lab/derive_more",
                rev = "9f1b894e6fde640da4e9ea71a8fc0e4dd98d01da",
            ),
            "digest": crate.spec(
                version = "^0.9.0",
            ),
            "ed25519-consensus": crate.spec(
                version = "^2.0.1",
            ),
            "either": crate.spec(
                version = "^1.6",
            ),
            "erased-serde": crate.spec(
                version = "^0.3.11",
            ),
            "escargot": crate.spec(
                version = "^0.5.7",
                features = ["print"],
            ),
            "ethnum": crate.spec(
                version = "^1.3.2",
            ),
            "exec": crate.spec(
                version = "^0.3.1",
            ),
            "eyre": crate.spec(
                version = "^0.6.8",
            ),
            "features": crate.spec(
                version = "^0.10.0",
            ),
            "ff": crate.spec(
                version = "^0.12.0",
                features = [
                    "std",
                ],
                default_features = False,
            ),
            "fix-hidden-lifetime-bug": crate.spec(
                version = "^0.2.4",
            ),
            "flate2": crate.spec(
                version = "^1.0.22",
            ),
            "float-cmp": crate.spec(
                version = "^0.9.0",
            ),
            "form_urlencoded": crate.spec(
                version = "^1.0.0",
            ),
            "fs_extra": crate.spec(
                version = "^1.2.0",
            ),
            "futures": crate.spec(
                version = "^0.3.6",
            ),
            "futures-util": crate.spec(
                version = "^0.3.8",
            ),
            "futures-core": crate.spec(
                version = "^0.3.21",
            ),
            "getrandom": crate.spec(
                version = "^0.2",
                features = [
                    "custom",
                ],
            ),
            "gflags": crate.spec(
                version = "^0.3.7",
            ),
            "gflags-derive": crate.spec(
                version = "^0.1",
            ),
            "glob": crate.spec(
                version = "^0.3.0",
            ),
            "h2": crate.spec(
                version = "^0.3.14",
            ),
            "hashlink": crate.spec(
                version = "^0.8.0",
            ),
            "hex": crate.spec(
                version = "^0.4.3",
                features = [
                    "serde",
                ],
            ),
            "hex-literal": crate.spec(
                version = "^0.2.1",
            ),
            "http": crate.spec(
                version = "^0.2.6",
            ),
            "http-body": crate.spec(
                version = "^0.4",
            ),
            "http-serde": crate.spec(
                version = "^1.1.2",
            ),
            "httparse": crate.spec(
                version = "^1.5.1",
            ),
            "httptest": crate.spec(
                version = "^0.15.4",
            ),
            "humantime": crate.spec(
                version = "^2.1.0",
            ),
            "humantime-serde": crate.spec(
                version = "^1.0",
            ),
            "hyper": crate.spec(
                version = "^0.14.18",
                features = [
                    "client",
                    "full",
                    "http1",
                    "http2",
                    "server",
                    "tcp",
                ],
            ),
            "hyper-rustls": crate.spec(
                version = "^0.24.0",
                features = [
                    "http2",
                ],
            ),
            "hyper-socks2": crate.spec(
                version = "^0.6.0",
            ),
            "hyper-tls": crate.spec(
                version = "^0.5.0",
            ),
            "iai": crate.spec(
                version = "^0.1",
            ),
            "ic0": crate.spec(
                version = "0.18.9",
            ),
            "ic-agent": crate.spec(
                version = "^0.24.1",
                features = [
                    "hyper",
                ],
            ),
            "ic-btc-interface": crate.spec(
                git = "https://github.com/dfinity/bitcoin-canister",
                rev = "b1693619e3d4dbc00d8c79e9b6886e1db48b21f7",
            ),
            "ic-btc-validation": crate.spec(
                git = "https://github.com/dfinity/bitcoin-canister",
                rev = "0e996988693f2d55fc9533c44dc20ae5310a1894",
            ),
            "ic-btc-test-utils": crate.spec(
                git = "https://github.com/dfinity/bitcoin-canister",
                rev = "b1693619e3d4dbc00d8c79e9b6886e1db48b21f7",
            ),
            "ic-cdk": crate.spec(
                version = "0.7.0",
            ),
            "ic-cdk-timers": crate.spec(
                version = "0.1.0",
            ),
            "ic-cdk-macros": crate.spec(
                version = "^0.6.8",
            ),
            "ic-certified-map": crate.spec(
                version = "^0.3.1",
            ),
            "ic-metrics-encoder": crate.spec(
                version = "^1.1.0",
            ),
            "ic-stable-structures": crate.spec(
                version = "^0.5.0",
            ),
            "ic-response-verification": crate.spec(
                version = "^0.2.1",
            ),
            "ic-test-state-machine-client": crate.spec(
                version = "^2.2.0",
            ),
            "ic-utils": crate.spec(
                version = "^0.24.1",
                features = [
                    "raw",
                ],
            ),
            "ic-wasm": crate.spec(
                version = "^0.1.3",
            ),
            "ic-xrc-types": crate.spec(
                version = "^1.0.0",
            ),
            "idna": crate.spec(
                version = "^0.3.0",
            ),
            "indicatif": crate.spec(
                version = "^0.15",
                features = [
                    "improved_unicode",
                ],
            ),
            "indicatif_0_17_3": crate.spec(
                package = "indicatif",
                version = "^0.17.3",
            ),
            "indoc": crate.spec(
                version = "^1.0.6",
            ),
            "insta": crate.spec(
                version = "=1.8.0",
            ),
            "instant-acme": crate.spec(
                version = "^0.3.2",
            ),
            "intmap": crate.spec(
                version = "^1.1.0",
                features = ["serde"],
            ),
            "ipnet": crate.spec(
                version = "^2.5.0",
            ),
            "isocountry": crate.spec(
                version = "0.3.2",
            ),
            "itertools": crate.spec(
                version = "^0.10.0",
            ),
            "jemalloc-ctl": crate.spec(
                version = "^0.3.3",
            ),
            "jemallocator": crate.spec(
                version = "^0.3.2",
            ),
            "json-patch": crate.spec(
                version = "^0.2.6",
            ),
            "json5": crate.spec(
                version = "^0.4.1",
            ),
            "k256": crate.spec(
                version = "^0.13.1",
                features = [
                    "arithmetic",
                    "ecdsa",
                    "pem",
                    "pkcs8",
                ],
                default_features = False,
            ),
            "lazy_static": crate.spec(
                version = "^1.4.0",
            ),
            "lazy-regex": crate.spec(
                version = "^2",
            ),
            "leaky-bucket": crate.spec(
                version = "^0.11.0",
            ),
            "leb128": crate.spec(
                version = "^0.2.5",
            ),
            "libc": crate.spec(
                version = "^0.2.91",
            ),
            "libflate": crate.spec(
                version = "^1.1.2",
            ),
            "libfuzzer-sys": crate.spec(
                version = "^0.4",
            ),
            "libsecp256k1": crate.spec(
                version = "^0.7.0",
            ),
            "libusb": crate.spec(
                version = "^0.3.0",
            ),
            "linked-hash-map": crate.spec(
                version = "^0.5.3",
            ),
            "log": crate.spec(
                version = "^0.4.14",
            ),
            "log4rs": crate.spec(
                version = "^1.1.1",
            ),
            "lru": crate.spec(
                version = "^0.7.8",
                default_features = False,
            ),
            "maplit": crate.spec(
                version = "^1.0.2",
            ),
            "minicbor": crate.spec(
                version = "^0.19.1",
                features = ["alloc", "derive"],
            ),
            "minicbor-derive": crate.spec(
                version = "^0.13.0",
            ),
            "mio": crate.spec(
                version = "^0.7",
                features = [
                    "os-ext",
                    "os-poll",
                    "pipe",
                ],
            ),
            "mockall": crate.spec(
                version = "^0.11.1",
            ),
            "mockall-0_7_2": crate.spec(
                package = "mockall",
                version = "^0.7.2",
            ),
            "mockall-0_8_3": crate.spec(
                package = "mockall",
                version = "^0.8.3",
            ),
            "native-tls": crate.spec(
                version = "^0.2.7",
                features = [
                    "alpn",
                ],
            ),
            "nix": crate.spec(
                version = "^0.23.0",
            ),
            "nonblock": crate.spec(
                version = "^0.1.0",
            ),
            "notify": crate.spec(
                version = "^4.0.12",
            ),
            "num": crate.spec(
                version = "^0.4.0",
            ),
            "num-bigint": crate.spec(
                version = "^0.4.0",
            ),
            "num-bigint-dig": crate.spec(
                version = "0.8",
                features = ["prime"],
            ),
            "num-derive": crate.spec(
                version = "^0.3",
            ),
            "num-integer": crate.spec(
                version = "^0.1.41",
            ),
            "num-rational": crate.spec(
                version = "^0.2.2",
            ),
            "num-traits": crate.spec(
                version = "^0.2.12",
                features = [
                    "libm",
                ],
                default_features = False,
            ),
            "num_cpus": crate.spec(
                version = "^1.13.1",
            ),
            "once_cell": crate.spec(
                version = "^1.8",
            ),
            "openssh-keys": crate.spec(
                version = "^0.5.0",
            ),
            "openssl": crate.spec(
                version = "^0.10.55",
            ),
            "openssl-sys": crate.spec(
                version = "0.9",
            ),
            "opentelemetry": crate.spec(
                version = "^0.17.0",
            ),
            "opentelemetry_0_18_0": crate.spec(
                package = "opentelemetry",
                version = "^0.18.0",
            ),
            "opentelemetry-prometheus": crate.spec(
                version = "^0.10.0",
            ),
            "opentelemetry_prometheus_0_11_0": crate.spec(
                package = "opentelemetry-prometheus",
                version = "^0.11.0",
            ),
            "p256": crate.spec(
                version = "^0.13.2",
                features = [
                    "arithmetic",
                    "ecdsa",
                    "pem",
                    "pkcs8",
                ],
                default_features = False,
            ),
            "pairing": crate.spec(
                version = "^0.22",
            ),
            "parking_lot": crate.spec(
                version = "^0.12.1",
            ),
            "parse_int": crate.spec(
                version = "^0.4.0",
            ),
            "paste": crate.spec(
                version = "^1.0.0",
            ),
            "pathdiff": crate.spec(
                version = "^0.2.1",
            ),
            "pem": crate.spec(
                version = "^1.0.1",
            ),
            "pico-args": crate.spec(
                version = "^0.3",
            ),
            "pkg-config": crate.spec(
                version = "^0.3",
            ),
            "pprof": crate.spec(
                version = "^0.10.1",
                features = [
                    "flamegraph",
                    "prost-codec",
                ],
                default_features = False,
            ),
            "predicates": crate.spec(
                version = "^1.0.1",
            ),
            "pretty-bytes": crate.spec(
                version = "^0.2.2",
            ),
            "pretty_assertions": crate.spec(
                version = "^0.6.1",
            ),
            "priority-queue": crate.spec(
                version = "^1.3.1",
                features = [
                    "serde",
                ],
            ),
            "proc-macro2": crate.spec(
                version = "^1.0",
            ),
            "procfs": crate.spec(
                version = "^0.9",
                default_features = False,
            ),
            "prometheus": crate.spec(
                version = "^0.13.0",
                features = [
                    "process",
                ],
            ),
            "prometheus-parse": crate.spec(
                version = "^0.2.3",
            ),
            "proptest": crate.spec(
                version = "^1.0.0",
            ),
            "test-strategy": crate.spec(
                version = "^0.2",
            ),
            "proptest-derive": crate.spec(
                version = "^0.3.0",
            ),
            "prost": crate.spec(
                version = "=0.11.0",
            ),
            "prost-build": crate.spec(
                version = "=0.11.1",
            ),
            "prost-derive": crate.spec(
                version = "=0.11.0",
            ),
            "protobuf": crate.spec(
                version = "^2.27.1",
            ),
            "quickcheck": crate.spec(
                version = "^1.0.3",
            ),
            "quinn": crate.spec(
                version = "^0.10.0",
                features = [
                    "ring",
                ],
            ),
            "quote": crate.spec(
                version = "^1.0",
            ),
            "rand-0_8_4": crate.spec(
                package = "rand",
                version = "^0.8.4",
                features = [
                    "small_rng",
                ],
            ),
            "rand_chacha-0_3_1": crate.spec(
                package = "rand_chacha",
                version = "^0.3.1",
            ),
            "rand_distr-0_4": crate.spec(
                package = "rand_distr",
                version = "^0.4",
            ),
            "rand_pcg": crate.spec(
                version = "^0.3.1",
            ),
            "randomkit": crate.spec(
                version = "^0.1.1",
            ),
            "rayon": crate.spec(
                version = "^1.5.1",
            ),
            "rcgen": crate.spec(
                version = "^0.10.0",
            ),
            "redis": crate.spec(
                version = "^0.22.1",
                features = [
                    "tokio-comp",
                    "connection-manager",
                ],
            ),
            "regex": crate.spec(
                version = "^1.3.9",
            ),
            "reqwest": crate.spec(
                version = "^0.11.1",
                features = [
                    "blocking",
                    "json",
                    "multipart",
                    "native-tls",
                    "rustls-tls",
                    "stream",
                ],
            ),
            "retain_mut": crate.spec(
                version = "^0.1",
            ),
            "ring": crate.spec(
                version = "^0.16.11",
                features = [
                    "std",
                ],
            ),
            "ripemd": crate.spec(
                version = "^0.1.1",
            ),
            "rocksdb": crate.spec(
                version = "^0.15.0",
                default_features = False,
            ),
            "rsa": crate.spec(
                version = "^0.6.1",
            ),
            "rsa-0_4_0": crate.spec(
                package = "rsa",
                version = "^0.4.0",
            ),
            "rstack-self": crate.spec(
                version = "^0.3",
            ),
            "rusqlite": crate.spec(
                version = "^0.28.0",
                features = ["bundled"],
            ),
            "rust_decimal": crate.spec(
                version = "^1.25.0",
            ),
            "rust_decimal_macros": crate.spec(
                version = "^1.25.0",
            ),
            "rustc-hash": crate.spec(
                version = "^1.1.0",
            ),
            "rustls": crate.spec(
                version = "^0.21.0",
                features = [
                    "dangerous_configuration",
                ],
            ),
            "rustls-native-certs": crate.spec(
                version = "^0.6.2",
            ),
            "rustls-pemfile": crate.spec(
                version = "^1",
            ),
            "rustversion": crate.spec(
                version = "^1.0",
            ),
            "rusty-fork": crate.spec(
                version = "^0.3.0",
            ),
            "scoped_threadpool": crate.spec(
                version = "0.1.*",
            ),
            "scopeguard": crate.spec(
                version = "^1.1.0",
            ),
            "semver": crate.spec(
                version = "^1.0.9",
                features = [
                    "serde",
                ],
            ),
            "serde": crate.spec(
                version = "^1.0.99",
                features = [
                    "derive",
                ],
                default_features = False,
            ),
            "serde-bytes-repr": crate.spec(
                version = "^0.1.5",
            ),
            "serde_bytes": crate.spec(
                version = "^0.11",
            ),
            "serde_cbor": crate.spec(
                version = "^0.11.2",
            ),
            "serde_derive": crate.spec(
                version = "^1.0",
            ),
            "serde_json": crate.spec(
                version = "^1.0.40",
            ),
            "serde_millis": crate.spec(
                version = "^0.1",
            ),
            "serde_with": crate.spec(
                version = "^1.6.2",
            ),
            "serde_yaml": crate.spec(
                version = "^0.8.24",
            ),
            "serial_test": crate.spec(
                version = "^0.8.0",
            ),
            "sev": crate.spec(
                version = "=1.1.0",  # Pinned to 1.1.0. The crate broke semantic verisioning with breaking changes in 1.2.0 (https://github.com/virtee/sev/issues/81).
                features = [
                    "openssl",
                ],
            ),
            "sha2": crate.spec(
                version = "^0.10.2",
            ),
            "sha2-0_9_1": crate.spec(
                package = "sha2",
                version = "^0.9.1",
            ),
            "sha3": crate.spec(
                version = "^0.9.1",
            ),
            "signal-hook": crate.spec(
                version = "^0.3.6",
                features = [
                    "iterator",
                ],
            ),
            "signal-hook-mio": crate.spec(
                version = "^0.2.0",
                features = [
                    "support-v0_7",
                ],
            ),
            "simple_asn1": crate.spec(
                version = "^0.5.4",
            ),
            "slog": crate.spec(
                version = "^2.5.2",
                features = [
                    "max_level_trace",
                    "nested-values",
                    "release_max_level_debug",
                    "release_max_level_trace",
                ],
            ),
            "slog-async": crate.spec(
                version = "^2.5",
                features = [
                    "nested-values",
                ],
            ),
            "slog-envlogger": crate.spec(
                version = "^2.2.0",
            ),
            "slog-json": crate.spec(
                version = "^2.3",
                features = [
                    "nested-values",
                ],
            ),
            "slog-scope": crate.spec(
                version = "^4.1.2",
            ),
            "slog-term": crate.spec(
                version = "^2.6.0",
            ),
            "slog_derive": crate.spec(
                version = "^0.2.0",
            ),
            "socket2": crate.spec(
                version = "^0.3.19",
                features = [
                    "reuseport",
                ],
            ),
            "ssh2": crate.spec(
                git = "https://github.com/dfinity-lab/ssh2-rs",
                rev = "f842906afaa2443206b8365d51950ed3ef85c940",
            ),
            "static_assertions": crate.spec(
                version = "^0.3.4",
            ),
            "strum": crate.spec(
                version = "^0.24.1",
                features = [
                    "derive",
                ],
            ),
            "strum_macros": crate.spec(
                version = "^0.24.1",
            ),
            "stubborn-io": crate.spec(
                version = "^0.3.2",
            ),
            "substring": crate.spec(
                version = "^1.4.5",
            ),
            "subtle": crate.spec(
                version = "^2.4",
            ),
            "syn": crate.spec(
                version = "^1.0",
                features = [
                    "fold",
                    "full",
                ],
            ),
            "tar": crate.spec(
                version = "^0.4.38",
            ),
            "tarpc": crate.spec(
                version = "^0.32",
                features = [
                    "full",
                ],
            ),
            "tempfile": crate.spec(
                version = "^3.1.0",
            ),
            "tester": crate.spec(
                version = "^0.7.0",
            ),
            "thiserror": crate.spec(
                version = "^1.0",
            ),
            "thousands": crate.spec(
                version = "^0.2.0",
            ),
            "thread_profiler": crate.spec(
                version = "^0.3",
            ),
            "threadpool": crate.spec(
                version = "^1.8.1",
            ),
            "tiny_http": crate.spec(
                version = "^0.10.0",
            ),
            "time": crate.spec(
                version = "^0.3.20",
            ),
            "tokio": crate.spec(
                version = "^1.15.0",
                features = [
                    "full",
                    "io-util",
                    "macros",
                    "net",
                    "rt",
                    "sync",
                    "time",
                ],
            ),
            "tokio-io-timeout": crate.spec(
                version = "^1.2.0",
            ),
            "tokio-metrics": crate.spec(
                version = "^0.2.2",
            ),
            "tokio-openssl": crate.spec(
                version = "^0.6.1",
            ),
            "tokio-rustls": crate.spec(
                version = "^0.24.0",
                features = [
                    "dangerous_configuration",
                ],
            ),
            "tokio-serde": crate.spec(
                version = "^0.8",
                features = [
                    "bincode",
                    "json",
                ],
            ),
            "tokio-socks": crate.spec(
                version = "^0.5.1",
            ),
            "tokio-test": crate.spec(
                version = "^0.4.2",
            ),
            "tokio-util": crate.spec(
                version = "^0.7.4",
                features = [
                    "codec",
                    "time",
                ],
            ),
            "toml": crate.spec(
                version = "^0.5.9",
            ),
            "tonic": crate.spec(
                version = "^0.8.2",
            ),
            "tonic-build": crate.spec(
                version = "^0.8.2",
            ),
            "tower": crate.spec(
                version = "^0.4.11",
                features = [
                    "buffer",
                    "limit",
                    "load-shed",
                    "steer",
                    "timeout",
                    "util",
                ],
            ),
            "tower-http": crate.spec(
                version = "^0.3",
                features = [
                    "trace",
                ],
            ),
            "tower-request-id": crate.spec(
                version = "^0.2.1",
            ),
            "tower-test": crate.spec(
                version = "^0.4.0",
            ),
            "tracing": crate.spec(
                version = "^0.1.34",
            ),
            "tracing-appender": crate.spec(
                version = "^0.2.2",
            ),
            "tracing-subscriber": crate.spec(
                version = "^0.3.11",
                features = [
                    "json",
                ],
            ),
            "trust-dns-resolver": crate.spec(
                version = "^0.22.0",
            ),
            "url": crate.spec(
                version = "^2.1.1",
                features = [
                    "serde",
                ],
            ),
            "uuid": crate.spec(
                version = "^1.3.0",
                features = [
                    "v4",
                    "serde",
                ],
            ),
            "vsock": crate.spec(
                version = "^0.3",
            ),
            "walrus": crate.spec(
                version = "^0.19.0",
            ),
            "wait-timeout": crate.spec(
                version = "^0.2.0",
            ),
            "walkdir": crate.spec(
                version = "^2.3.1",
            ),
            "warp": crate.spec(
                version = "^0.3.2",
                features = [
                    "tls",
                ],
            ),
            "wasm-bindgen": crate.spec(
                version = "^0.2",
            ),
            "wasm-encoder": crate.spec(
                version = "^0.23.0",
            ),
            "wasm-smith": crate.spec(
                version = "^0.12.4",
            ),
            "wasmparser": crate.spec(
                version = "^0.100.0",
            ),
            "wasmprinter": crate.spec(
                version = "^0.2.50",
            ),
            "wasmtime": crate.spec(
                version = "^9.0.3",
                default_features = False,
                features = [
                    "cranelift",
                    "parallel-compilation",
                    "posix-signals-on-macos",
                ],
            ),
            "wasmtime-environ": crate.spec(
                version = "^9.0.3",
            ),
            "wasmtime-runtime": crate.spec(
                version = "^9.0.3",
            ),
            "wast": crate.spec(
                version = "^53.0.0",
            ),
            "wat": crate.spec(
                version = "^1.0.57",
            ),
            "wee_alloc": crate.spec(
                version = "^0.4.3",
            ),
            "which": crate.spec(
                version = "^4.2.2",
            ),
            "wsl": crate.spec(
                version = "^0.1.0",
            ),
            "wycheproof": crate.spec(
                version = "^0.5",
            ),
            "wiremock": crate.spec(
                # Pinning to 0.5.18 because we are pinned to Rust 1.66
                # where pin_macro is unstable.
                version = "=0.5.18",
            ),
            "x509-parser": crate.spec(
                version = "^0.12.0",
            ),
            "x509-parser_0_15": crate.spec(
                package = "x509-parser",
                version = "^0.15.0",
                features = ["verify"],
            ),
            "yansi": crate.spec(
                version = "^0.5.0",
            ),
            "zeroize": crate.spec(
                version = "^1.4.3",
                features = [
                    "zeroize_derive",
                ],
            ),
        },
        splicing_config = splicing_config(
            resolver_version = "2",
        ),
    )
