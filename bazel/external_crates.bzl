"""
This module declares all direct rust dependencies.

Run `./bin/bazel-pin.sh` from the top-level directory of the working tree after changing this file
to regenerate Cargo Bazel lockfiles.
"""

load("@rules_rust//crate_universe:defs.bzl", "crate", "crates_repository", "splicing_config")
load("//bazel:fuzz_testing.bzl", "DEFAULT_RUSTC_FLAGS_FOR_FUZZING")

def sanitize_external_crates(sanitizers_enabled):
    FUZZING_ANNOTATION = [crate.annotation(rustc_flags = DEFAULT_RUSTC_FLAGS_FOR_FUZZING)] if sanitizers_enabled else []
    return {
        "candid": FUZZING_ANNOTATION,
        "wasmtime": FUZZING_ANNOTATION,
        "bitcoin": FUZZING_ANNOTATION,
        "bincode": FUZZING_ANNOTATION,
    }

ICRC_1_REV = "26a80d777e079644cd69e883e18dad1a201f5b1a"

BUILD_INFO_REV = "701a696844fba5c87df162fbbc1ccef96f27c9d7"

def external_crates_repository(name, cargo_lockfile, lockfile, sanitizers_enabled):
    CRATE_ANNOTATIONS = {
        "ic_bls12_381": [crate.annotation(
            rustc_flags = [
                "-C",
                "opt-level=3",
            ],
        )],
        "k256": [crate.annotation(
            rustc_flags = [
                "-C",
                "opt-level=3",
            ],
        )],
        "p256": [crate.annotation(
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
        "ic-wasm": [crate.annotation(
            gen_binaries = True,
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
        "metrics-proxy": [crate.annotation(
            gen_binaries = True,
        )],
    }
    CRATE_ANNOTATIONS.update(sanitize_external_crates(sanitizers_enabled = sanitizers_enabled))
    crates_repository(
        name = name,
        isolated = True,
        cargo_lockfile = cargo_lockfile,
        lockfile = lockfile,
        cargo_config = "//:bazel/cargo.config",
        annotations = CRATE_ANNOTATIONS,
        packages = {
            "actix-rt": crate.spec(
                version = "^2.2.0",
            ),
            "actix-web": crate.spec(
                version = "^4.3.0",
            ),
            "addr": crate.spec(
                version = "^0.15.6",
                default_features = False,
                features = [
                    "idna",
                ],
            ),
            "aide": crate.spec(
                version = "^0.13.0",
                features = [
                    "axum",
                ],
            ),
            "arbitrary": crate.spec(
                version = "^1.3.0",
            ),
            "arc-swap": crate.spec(
                version = "^1",
            ),
            "anyhow": crate.spec(
                version = "^1",
            ),
            "arrayvec": crate.spec(
                version = "^0.7.4",
            ),
            "askama": crate.spec(
                version = "^0.12.1",
                features = [
                    "serde-json",
                ],
            ),
            "assert-json-diff": crate.spec(
                version = "^2.0.1",
            ),
            "assert_cmd": crate.spec(
                version = "^2.0.12",
            ),
            "assert_matches": crate.spec(
                version = "^1.5.0",
            ),
            "async-recursion": crate.spec(
                version = "^1.0.5",
            ),
            "async-scoped": crate.spec(
                version = "^0.8.0",
                features = [
                    "use-tokio",
                ],
            ),
            "async-socks5": crate.spec(
                version = "^0.5.1",
            ),
            "async-stream": crate.spec(
                version = "^0.3.5",
            ),
            "async-trait": crate.spec(
                version = "^0.1.73",
            ),
            "axum_0_6_1": crate.spec(
                package = "axum",
                version = "^0.6.1",
                features = [
                    "headers",
                ],
            ),
            "axum": crate.spec(
                version = "^0.7.4",
            ),
            "axum-server_0_6_0": crate.spec(
                package = "axum-server",
                version = "^0.6.0",
                features = [
                    "tls-rustls",
                ],
            ),
            "axum-extra": crate.spec(
                version = "^0.9.0",
                features = ["typed-header"],
            ),
            "axum-server": crate.spec(
                version = "^0.5.1",
                features = [
                    "tls-rustls",
                ],
            ),
            "backoff": crate.spec(
                version = "^0.4.0",
            ),
            "backon": crate.spec(
                version = "^0.4.1",
            ),
            "base32": crate.spec(
                version = "^0.4.0",
            ),
            "base64": crate.spec(
                version = "^0.13.1",
            ),
            "bech32": crate.spec(
                version = "^0.9.0",
            ),
            "bincode": crate.spec(
                version = "^1.2.1",
            ),
            "bindgen": crate.spec(
                version = "^0.65.1",
                default_features = False,
                features = ["runtime"],
            ),
            "bip32": crate.spec(
                version = "^0.5.0",
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
                version = "^0.5.0",
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
                rev = BUILD_INFO_REV,
            ),
            "build-info-build": crate.spec(
                git = "https://github.com/dfinity-lab/build-info",
                rev = BUILD_INFO_REV,
                default_features = False,
            ),
            "by_address": crate.spec(
                version = "^1.1.0",
            ),
            "byte-unit": crate.spec(
                version = "^4.0.14",
            ),
            "byteorder": crate.spec(
                version = "^1.3.4",
            ),
            "bytes": crate.spec(
                version = "^1.5.0",
            ),
            "cached": crate.spec(
                version = "^0.49",
                default_features = False,
            ),
            "candid": crate.spec(
                version = "^0.10.6",
            ),
            "cargo_metadata": crate.spec(
                version = "^0.14.2",
            ),
            "candid_parser": crate.spec(
                version = "^0.1.2",
            ),
            "cc": crate.spec(
                version = "^1.0",
            ),
            "cddl": crate.spec(
                version = "^0.9.4",
            ),
            "cfg-if": crate.spec(version = "^1.0.0"),
            "chacha20poly1305": crate.spec(
                version = "^0.10.0",
            ),
            "chrono": crate.spec(
                version = "^0.4.31",
                default_features = False,
                features = [
                    "alloc",
                    "clock",
                    "serde",
                ],
            ),
            "ciborium": crate.spec(
                version = "^0.2.1",
            ),
            "cidr": crate.spec(
                version = "^0.2.2",
            ),
            "clap_3_2_25": crate.spec(
                package = "clap",
                version = "^3.2.25",
                features = [
                    "derive",
                ],
            ),
            "clap": crate.spec(
                version = "^4.0.0",
                features = [
                    "derive",
                    "string",
                ],
            ),
            "cloudflare": crate.spec(
                version = "^0.9.1",
                default_features = False,
                features = [
                    "rustls-tls",
                ],
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
                version = "^0.5",
                features = [
                    "html_reports",
                    "async_tokio",
                ],
            ),
            "crossbeam": crate.spec(
                version = "^0.8.4",
            ),
            "crossbeam-channel": crate.spec(
                version = "^0.5.11",
            ),
            "csv": crate.spec(
                version = "^1.1",
            ),
            "curve25519-dalek": crate.spec(
                version = "^4.1.2",
                features = ["group", "precomputed-tables"],
            ),
            "cvt": crate.spec(
                version = "^0.1.1",
            ),
            "dashmap": crate.spec(
                version = "^5.3.4",
            ),
            "derive_more": crate.spec(
                git = "https://github.com/dfinity-lab/derive_more",
                rev = "9f1b894e6fde640da4e9ea71a8fc0e4dd98d01da",
            ),
            "digest": crate.spec(
                version = "^0.9.0",
            ),
            "dyn-clone": crate.spec(
                version = "^1.0.14",
            ),
            "ed25519-consensus": crate.spec(
                version = "^2.0.1",
            ),
            "ed25519-dalek": crate.spec(
                version = "^2.1.1",
                features = ["std", "zeroize", "digest", "batch", "pkcs8", "pem"],
            ),
            "educe": crate.spec(
                version = "^0.4",
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
            "ethabi": crate.spec(
                version = "^18.0.0",
            ),
            "ethers-core": crate.spec(
                version = "^2.0.7",
            ),
            "ethnum": crate.spec(
                version = "^1.3.2",
                features = ["serde"],
            ),
            "exec": crate.spec(
                version = "^0.3.1",
            ),
            "eyre": crate.spec(
                version = "^0.6.8",
            ),
            "ff": crate.spec(
                version = "^0.12.0",
                features = [
                    "std",
                ],
                default_features = False,
            ),
            "flate2": crate.spec(
                version = "^1.0.22",
            ),
            "form_urlencoded": crate.spec(
                version = "^1.0.0",
            ),
            "fs_extra": crate.spec(
                version = "^1.2.0",
            ),
            "futures": crate.spec(
                version = "^0.3.30",
            ),
            "futures-util": crate.spec(
                version = "^0.3.30",
            ),
            "get_if_addrs": crate.spec(
                version = "^0.5.3",
            ),
            "getrandom": crate.spec(
                version = "^0.2",
                features = [
                    "custom",
                ],
            ),
            "glob": crate.spec(
                version = "^0.3.0",
            ),
            "group": crate.spec(
                version = "^0.13",
            ),
            "h2": crate.spec(
                version = "^0.3.26",
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
                version = "^0.4.1",
            ),
            "http": crate.spec(
                version = "^0.2.9",
            ),
            "http_1_0_0": crate.spec(
                package = "http",
                version = "^1.0.0",
            ),
            "http-body": crate.spec(
                version = "^0.4",
            ),
            "http-body_1_0_0": crate.spec(
                package = "http-body",
                version = "^1.0.0",
            ),
            "http-body-util": crate.spec(
                version = "^0.1.0",
            ),
            "http-serde": crate.spec(
                version = "^2.0.0",
            ),
            "httptest": crate.spec(
                version = "^0.15.4",
            ),
            "humantime": crate.spec(
                version = "^2.1.0",
            ),
            "hyper_0_14_27": crate.spec(
                package = "hyper",
                version = "^0.14.27",
                features = [
                    "client",
                    "full",
                    "http1",
                    "http2",
                    "server",
                    "tcp",
                ],
            ),
            "hyper": crate.spec(
                version = "^1.2.0",
                features = [
                    "full",
                ],
            ),
            "hyper-util": crate.spec(
                version = "^0.1.3",
                features = [
                    "full",
                ],
            ),
            "hyper-rustls": crate.spec(
                version = "^0.24.2",
                features = [
                    "http2",
                ],
            ),
            "hyper-rustls_0_26_0": crate.spec(
                package = "hyper-rustls",
                version = "^0.26.0",
                features = [
                    "http2",
                ],
            ),
            "hyper-socks2": crate.spec(
                version = "^0.8.0",
                default_features = False,
                features = [
                    "rustls",
                ],
            ),
            "hyperlocal-next": crate.spec(
                version = "^0.9.0",
            ),
            "ic0": crate.spec(
                version = "^0.18.11",
            ),
            "icrc1-test-env": crate.spec(
                git = "https://github.com/dfinity/ICRC-1",
                rev = ICRC_1_REV,
            ),
            "icrc1-test-suite": crate.spec(
                git = "https://github.com/dfinity/ICRC-1",
                rev = ICRC_1_REV,
            ),
            "ic-agent": crate.spec(
                version = "^0.34.0",
                features = [
                    "hyper",
                    "reqwest",
                    "pem",
                ],
            ),
            "ic-btc-interface": crate.spec(
                version = "^0.2.0",
            ),
            "ic-btc-validation": crate.spec(
                version = "^0.1.0",
            ),
            "ic-btc-test-utils": crate.spec(
                version = "^0.1.0",
            ),
            "ic-canister-log": crate.spec(
                version = "^0.2.0",
            ),
            "ic-cbor": crate.spec(
                version = "2.3.0",
            ),
            "ic-cdk": crate.spec(
                version = "^0.13.1",
            ),
            "ic-cdk-timers": crate.spec(
                version = "^0.7.0",
            ),
            "ic-cdk-macros": crate.spec(
                version = "^0.9.0",
            ),
            "ic-certified-map": crate.spec(
                version = "^0.3.1",
            ),
            "ic-certification": crate.spec(
                version = "2.3.0",
            ),
            "ic-http-certification": crate.spec(
                version = "2.3.0",
            ),
            "ic-metrics-encoder": crate.spec(
                version = "^1.1.1",
            ),
            "ic_principal": crate.spec(
                version = "^0.1.1",
                default_features = False,
            ),
            "ic-stable-structures": crate.spec(
                version = "^0.6.0",
            ),
            "ic-response-verification": crate.spec(
                version = "2.3.0",
            ),
            "ic-test-state-machine-client": crate.spec(
                version = "^3.0.0",
            ),
            "ic-utils": crate.spec(
                version = "^0.34.0",
                features = ["raw"],
            ),
            "ic-wasm": crate.spec(
                version = "^0.7.1",
                features = [
                    "exe",
                ],
                default_features = False,
            ),
            "ic-xrc-types": crate.spec(
                version = "^1.2.0",
            ),
            "idna": crate.spec(
                version = "^0.3.0",
            ),
            "indexmap": crate.spec(
                version = "^2.1.0",
            ),
            "indicatif": crate.spec(
                version = "^0.17.3",
            ),
            "indoc": crate.spec(
                version = "^1.0.9",
            ),
            "inferno": crate.spec(
                version = "^0.11.19",
            ),
            "insta": crate.spec(
                version = "^1.31.0",
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
                version = "^0.3.2",
            ),
            "itertools": crate.spec(
                version = "^0.12.0",
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
                version = "^0.13.3",
                features = [
                    "arithmetic",
                    "ecdsa",
                    "pem",
                    "pkcs8",
                    "precomputed-tables",
                    "schnorr",
                    "std",
                ],
                default_features = False,
            ),
            "k8s-openapi": crate.spec(
                version = "^0.20.0",
                features = [
                    "v1_22",
                ],
            ),
            "kube": crate.spec(
                version = "^0.87.2",
                features = [
                    "runtime",
                    "derive",
                    "ws",
                ],
            ),
            "lazy_static": crate.spec(
                version = "^1.4.0",
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
                version = "^0.4.7",
                default_features = False,
            ),
            "libsecp256k1": crate.spec(
                version = "^0.7.0",
            ),
            "libnss": crate.spec(
                version = "^0.5.0",
            ),
            "linked-hash-map": crate.spec(
                version = "^0.5.3",
            ),
            "little-loadshedder": crate.spec(
                version = "^0.1.0",
            ),
            "local-ip-address": crate.spec(
                version = "^0.5.6",
            ),
            "log": crate.spec(
                version = "^0.4.14",
            ),
            "lru": crate.spec(
                version = "^0.7.8",
                default_features = False,
            ),
            "maplit": crate.spec(
                version = "^1.0.2",
            ),
            "maxminddb": crate.spec(
                version = "^0.24",
            ),
            "metrics-proxy": crate.spec(
                git = "https://github.com/dfinity/metrics-proxy.git",
                rev = "b6933ed79ac07baee7f3fbc0793bed95e614d27c",
                # When updating this, please make sure that the built
                # binary exports metrics http_cache_* after one
                # successful request to the proxy.  The OpenTelemetry
                # package version pinned by this software must equal
                # the OpenTelemetry version pinned by the
                # axum-otel-metrics version pinned by this software,
                # due to technical idiosyncrasies of the OpenTelemetry
                # crate.  When these do not match, custom metrics are
                # not exported.
                default_features = False,
                features = [
                    "rustls-tls-webpki-roots",
                ],
            ),
            "minicbor": crate.spec(
                version = "^0.19.1",
                features = ["alloc", "derive"],
            ),
            "minicbor-derive": crate.spec(
                version = "^0.13.0",
            ),
            "mockall": crate.spec(
                version = "^0.11.4",
            ),
            "mockito": crate.spec(
                version = "^1.2.0",
            ),
            "moka": crate.spec(
                version = "^0.12",
                features = [
                    "future",
                ],
            ),
            "nix": crate.spec(
                version = "^0.24.3",
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
                version = "^0.8",
                features = ["prime"],
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
            "opentelemetry": crate.spec(
                version = "^0.20.0",
                features = [
                    "metrics",
                ],
            ),
            "opentelemetry-prometheus": crate.spec(
                version = "^0.13.0",
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
            "paste": crate.spec(
                version = "^1.0.0",
            ),
            "pathdiff": crate.spec(
                version = "^0.2.1",
            ),
            "pem": crate.spec(
                version = "^1.0.1",
            ),
            "pin-project-lite": crate.spec(
                version = "^0.2",
            ),
            "ping": crate.spec(
                version = "^0.5.0",
            ),
            "pkcs8": crate.spec(
                version = "^0.10.2",
            ),
            "pkg-config": crate.spec(
                version = "^0.3",
            ),
            "pprof": crate.spec(
                version = "^0.13.0",
                features = [
                    "flamegraph",
                    "prost-codec",
                ],
                default_features = False,
            ),
            "predicates": crate.spec(
                version = "^3.0.4",
            ),
            "pretty-bytes": crate.spec(
                version = "^0.2.2",
            ),
            "pretty_assertions": crate.spec(
                version = "^1.4.0",
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
                version = "^0.13.3",
                features = [
                    "process",
                ],
            ),
            "proptest": crate.spec(
                version = "^1.0.0",
            ),
            "test-strategy": crate.spec(
                version = "^0.3.1",
            ),
            "prometheus-parse": crate.spec(
                version = "^0.2.4",
            ),
            "proptest-derive": crate.spec(
                version = "^0.3.0",
            ),
            "prost": crate.spec(
                version = "^0.12",
            ),
            "prost-build": crate.spec(
                version = "^0.12",
            ),
            "prost-derive": crate.spec(
                version = "^0.12",
            ),
            "protobuf": crate.spec(
                version = "^2.27.1",
            ),
            "publicsuffix": crate.spec(
                version = "^2.2.3",
            ),
            "quickcheck": crate.spec(
                version = "^1.0.3",
            ),
            "quinn": crate.spec(
                version = "^0.10.2",
                features = [
                    "ring",
                ],
            ),
            "quote": crate.spec(
                version = "^1.0",
            ),
            "rand": crate.spec(
                version = "^0.8.5",
                features = [
                    "small_rng",
                ],
            ),
            "rand_chacha": crate.spec(
                version = "^0.3.1",
            ),
            "rand_distr": crate.spec(
                version = "^0.4",
            ),
            "rand_pcg": crate.spec(
                version = "^0.3.1",
            ),
            "randomkit": crate.spec(
                version = "^0.1.1",
            ),
            "ratelimit": crate.spec(
                version = "^0.7.1",
            ),
            "rayon": crate.spec(
                version = "^1.5.1",
            ),
            "rcgen": crate.spec(
                version = "^0.11.1",
                features = [
                    "zeroize",
                ],
            ),
            "rgb": crate.spec(
                version = "^0.8.37",
            ),
            "regex": crate.spec(
                version = "^1.3.9",
            ),
            "reqwest_0_11_27": crate.spec(
                package = "reqwest",
                version = "^0.11.27",
                default_features = False,
                features = [
                    "blocking",
                    "json",
                    "multipart",
                    "rustls-tls-webpki-roots",
                    "stream",
                ],
            ),
            "reqwest": crate.spec(
                version = "^0.12.3",
                default_features = False,
                features = [
                    "blocking",
                    "http2",
                    "json",
                    "rustls-tls",
                    "rustls-tls-native-roots",
                    "socks",
                    "stream",
                ],
            ),
            "ring": crate.spec(
                version = "^0.17.7",
                features = [
                    "std",
                ],
            ),
            "ripemd": crate.spec(
                version = "^0.1.1",
            ),
            "rlp": crate.spec(
                version = "^0.5.2",
            ),
            "rocksdb": crate.spec(
                version = "^0.21.0",
                default_features = False,
            ),
            "rolling-file": crate.spec(
                version = "^0.2.0",
            ),
            "rsa": crate.spec(
                version = "^0.9.2",
                features = ["sha2"],
            ),
            "rstack-self": crate.spec(
                version = "^0.3",
            ),
            "rusb": crate.spec(
                version = "0.9",
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
                version = "^0.21.10",
                features = [
                    "dangerous_configuration",
                ],
            ),
            "rustls_0_22_2": crate.spec(
                package = "rustls",
                version = "^0.22.2",
            ),
            "rustls-native-certs": crate.spec(
                version = "^0.7.0",
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
            "schemars": crate.spec(
                version = "^0.8.16",
            ),
            "scoped_threadpool": crate.spec(
                version = "^0.1.9",
            ),
            "scopeguard": crate.spec(
                version = "^1.1.0",
            ),
            "scraper": crate.spec(
                version = "^0.17.1",
            ),
            "semver": crate.spec(
                version = "^1.0.9",
                features = [
                    "serde",
                ],
            ),
            "serde": crate.spec(
                version = "^1.0",
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
                version = "^1.0.107",
            ),
            "serde_with": crate.spec(
                version = "^1.14.0",
            ),
            "serde_yaml": crate.spec(
                version = "^0.9.29",
            ),
            "sha2": crate.spec(
                version = "^0.10.8",
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
            "signature": crate.spec(
                version = "^2.1.0",
            ),
            "simple_asn1": crate.spec(
                version = "^0.6.2",
            ),
            "slog": crate.spec(
                version = "^2.7.0",
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
            "socket2": crate.spec(
                version = "^0.5.6",
                features = [
                    "all",
                ],
            ),
            "ssh2": crate.spec(
                version = "0.9.4",
            ),
            "strum": crate.spec(
                version = "^0.26.2",
                features = [
                    "derive",
                ],
            ),
            "strum_macros": crate.spec(
                version = "^0.26.2",
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
                version = "^1.0.109",
                features = [
                    "fold",
                    "full",
                ],
            ),
            "tar": crate.spec(
                version = "^0.4.38",
            ),
            "tarpc": crate.spec(
                version = "^0.34",
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
            "textplots": crate.spec(
                version = "^0.8",
            ),
            "thiserror": crate.spec(
                version = "^1.0.57",
            ),
            "thousands": crate.spec(
                version = "^0.2.0",
            ),
            "threadpool": crate.spec(
                version = "^1.8.1",
            ),
            "time": crate.spec(
                version = "^0.3.31",
            ),
            "tokio": crate.spec(
                version = "^1.36.0",
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
                version = "^0.3.0",
            ),
            "tokio-rustls": crate.spec(
                version = "^0.24.1",
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
                version = "^0.7.10",
                features = [
                    "codec",
                    "time",
                    "rt",
                ],
            ),
            "toml": crate.spec(
                version = "^0.5.9",
            ),
            "tonic": crate.spec(
                version = "^0.11.0",
            ),
            "tonic-build": crate.spec(
                version = "^0.11.0",
            ),
            "tower": crate.spec(
                version = "^0.4.13",
                features = ["full"],
            ),
            "tower-http": crate.spec(
                version = "^0.4.4",
                features = [
                    "trace",
                    "request-id",
                    "util",
                    "compression-full",
                ],
            ),
            "tower_http_0_5_1": crate.spec(
                package = "tower-http",
                version = "^0.5.1",
                features = [
                    "cors",
                    "limit",
                    "trace",
                    "request-id",
                    "util",
                    "compression-full",
                ],
            ),
            "tower_governor": crate.spec(
                version = "^0.1",
            ),
            "tower-request-id": crate.spec(
                version = "^0.3.0",
            ),
            "tower-test": crate.spec(
                version = "^0.4.0",
            ),
            "tracing": crate.spec(
                version = "^0.1.40",
            ),
            "tracing-appender": crate.spec(
                version = "^0.2.3",
            ),
            "tracing-flame": crate.spec(
                version = "^0.2.0",
            ),
            "tracing-core": crate.spec(
                version = "^0.1.32",
            ),
            "tracing-serde": crate.spec(
                version = "^0.1.3",
            ),
            "tracing-slog": crate.spec(
                version = "^0.2",
            ),
            "tracing-subscriber": crate.spec(
                version = "^0.3.18",
                features = [
                    "env-filter",
                    "fmt",
                    "json",
                ],
            ),
            "trust-dns-resolver": crate.spec(
                version = "^0.22.0",
            ),
            "turmoil": crate.spec(
                version = "^0.6",
            ),
            "url": crate.spec(
                version = "^2.4.1",
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
                version = "^0.4",
            ),
            "walrus": crate.spec(
                version = "^0.19.0",
            ),
            "walkdir": crate.spec(
                version = "^2.3.1",
            ),
            "warp": crate.spec(
                version = "^0.3.6",
                features = [
                    "tls",
                ],
            ),
            "wasm-bindgen": crate.spec(
                version = "^0.2",
            ),
            "wasm-encoder": crate.spec(
                version = "^0.38.1",
                features = [
                    "wasmparser",
                ],
            ),
            "wasm-smith": crate.spec(
                version = "^0.201.0",
                default_features = False,
                features = [
                    "wasmparser",
                ],
            ),
            "wasmparser": crate.spec(
                version = "^0.118.1",
            ),
            "wasmprinter": crate.spec(
                version = "^0.2.50",
            ),
            "wasmtime": crate.spec(
                version = "^18.0.2",
                default_features = False,
                features = [
                    "cranelift",
                    "parallel-compilation",
                    "runtime",
                ],
            ),
            "wasmtime-environ": crate.spec(
                version = "^18.0.2",
            ),
            "wasmtime-runtime": crate.spec(
                version = "^18.0.2",
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
                version = "^0.5.19",
            ),
            "x509-cert": crate.spec(
                version = "^0.2.4",
                features = [
                    "builder",
                    "hazmat",
                ],
            ),
            "x509-parser": crate.spec(
                version = "^0.15.1",
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
            "zstd": crate.spec(
                version = "^0.13.0",
            ),
            "pcre2": crate.spec(
                version = "^0.2.6",
            ),
        },
        splicing_config = splicing_config(
            resolver_version = "2",
        ),
    )
