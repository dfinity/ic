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
        "ic-stable-structures": FUZZING_ANNOTATION,
    }

ICRC_1_REV = "26a80d777e079644cd69e883e18dad1a201f5b1a"

BUILD_INFO_REV = "701a696844fba5c87df162fbbc1ccef96f27c9d7"

def external_crates_repository(name, cargo_lockfile, lockfile, sanitizers_enabled):
    CRATE_ANNOTATIONS = {
        "canbench": [crate.annotation(
            gen_binaries = True,
        )],
        "cc": [crate.annotation(
            # Patch for determinism issues
            # https://github.com/rust-lang/cc-rs/issues/1271
            patch_args = ["-p1"],
            patches = ["@@//bazel:cc_rs.patch"],
        )],
        "curve25519-dalek": [crate.annotation(
            rustc_flags = [
                "-C",
                "opt-level=3",
            ],
        )],
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
        "lmdb-rkv-sys": [crate.annotation(
            build_script_data = [
                "@lmdb//:lmdb.h",
            ],
            build_script_env = {
                "LMDB_NO_BUILD": "1",
                "LMDB_H_PATH": "$(location @lmdb//:lmdb.h)",
            },
            # ensure LMDB lib is available at runtime
            deps = ["@lmdb"],
        )],
        "p256": [crate.annotation(
            rustc_flags = [
                "-C",
                "opt-level=3",
            ],
        )],
        "rustix": [crate.annotation(
            # Patch for determinism issues
            # https://github.com/bytecodealliance/rustix/issues/1199
            patch_args = ["-p1"],
            patches = ["@rustix-patch//file:downloaded"],
        )],
        "tikv-jemalloc-sys": [crate.annotation(
            # Avoid building jemalloc from rust (in part bc it creates builder-specific config files)
            build_script_data = crate.select([], {
                "x86_64-unknown-linux-gnu": [
                    "@jemalloc//:libjemalloc",
                ],
            }),
            build_script_env = crate.select(
                {},
                {
                    "x86_64-unknown-linux-gnu": {"JEMALLOC_OVERRIDE": "$(location @jemalloc//:libjemalloc)"},
                },
            ),
        )],
        "cranelift-isle": [crate.annotation(
            # Patch for determinism issues
            patch_args = ["-p4"],
            patches = ["@@//bazel:cranelift-isle.patch"],
        )],
        "cranelift-codegen-meta": [crate.annotation(
            # Patch for determinism issues
            patch_args = ["-p4"],
            patches = ["@@//bazel:cranelift-codegen-meta.patch"],
        )],
        "secp256k1-sys": [crate.annotation(
            # This specific version is used by ic-btc-kyt canister, which
            # requires an extra cfg flag to avoid linking issues.
            # Applying the same cfg to other versions of secp256k1-sys
            # may break other programs or tests.
            version = "0.10.0",
            rustc_flags = ["--cfg=rust_secp_no_symbol_renaming"],
        )],
        "sha2": [crate.annotation(
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
                version = "^2.10.0",
            ),
            "actix-web": crate.spec(
                version = "^4.9.0",
            ),
            "addr": crate.spec(
                version = "^0.15.6",
                default_features = False,
                features = [
                    "idna",
                ],
            ),
            "aide": crate.spec(
                version = "^0.13.4",
                features = [
                    "axum",
                ],
            ),
            "arbitrary": crate.spec(
                version = "^1.3.2",
            ),
            "arc-swap": crate.spec(
                version = "^1.7.1",
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
                version = "^2.0.16",
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
            "async-stream": crate.spec(
                version = "^0.3.6",
            ),
            "async-trait": crate.spec(
                version = "^0.1.83",
            ),
            "axum": crate.spec(
                version = "^0.7.7",
            ),
            "axum-extra": crate.spec(
                version = "^0.9.0",
                features = ["typed-header"],
            ),
            "axum-server": crate.spec(
                version = "^0.6.0",
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
                version = "^1.3.3",
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
            "bitcoin-0-32": crate.spec(
                package = "bitcoin",
                version = "^0.32.2",
                default_features = False,
            ),
            "bitcoin": crate.spec(
                version = "^0.28.2",
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
                version = "0.10.0",
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
                version = "^1.7.2",
            ),
            "cached": crate.spec(
                version = "^0.49",
                default_features = False,
            ),
            "canbench": crate.spec(
                version = "^0.1.7",
            ),
            "canbench-rs": crate.spec(
                version = "^0.1.7",
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
                version = "^0.4.38",
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
            "clap": crate.spec(
                version = "^4.5.20",
                features = [
                    "derive",
                    "string",
                ],
            ),
            "cloudflare": crate.spec(
                git = "https://github.com/dfinity/cloudflare-rs.git",
                rev = "a6538a036926bd756986c9c0a5de356daef48881",
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
                version = "^0.5.1",
                features = [
                    "html_reports",
                    "async_tokio",
                ],
            ),
            "crossbeam": crate.spec(
                version = "^0.8.4",
            ),
            "crossbeam-channel": crate.spec(
                version = "^0.5.13",
            ),
            "csv": crate.spec(
                version = "^1.1",
            ),
            "ctrlc": crate.spec(
                version = "3.4.5",
                features = ["termination"],
            ),
            "curve25519-dalek": crate.spec(
                version = "^4.1.3",
                features = ["group", "precomputed-tables"],
            ),
            "cvt": crate.spec(
                version = "^0.1.1",
            ),
            "dashmap": crate.spec(
                version = "^5.3.4",
            ),
            "dyn-clone": crate.spec(
                version = "^1.0.14",
            ),
            "ed25519-dalek": crate.spec(
                version = "^2.1.1",
                features = ["std", "zeroize", "digest", "batch", "pkcs8", "pem", "hazmat"],
            ),
            "educe": crate.spec(
                version = "^0.4",
            ),
            "erased-serde": crate.spec(
                version = "^0.3.11",
            ),
            "escargot": crate.spec(
                version = "^0.5.7",
                features = ["print"],
            ),
            "ethers-core": crate.spec(
                version = "^2.0.7",
            ),
            "ethnum": crate.spec(
                version = "^1.3.2",
                features = ["serde"],
            ),
            "evm_rpc_types": crate.spec(
                version = "^1.2.0",
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
                version = "^1.0.31",
            ),
            "form_urlencoded": crate.spec(
                version = "^1.0.0",
            ),
            "fqdn": crate.spec(
                version = "0.3.11",
            ),
            "fs_extra": crate.spec(
                version = "^1.2.0",
            ),
            "futures": crate.spec(
                version = "^0.3.31",
            ),
            "futures-util": crate.spec(
                version = "^0.3.31",
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
            "group": crate.spec(
                version = "^0.13",
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
            "hkdf": crate.spec(
                version = "^0.12",
            ),
            "http": crate.spec(
                version = "^1.1.0",
            ),
            "http-body": crate.spec(
                version = "^1.0.1",
            ),
            "http-body-util": crate.spec(
                version = "^0.1.2",
            ),
            "hmac": crate.spec(
                version = "^0.12",
            ),
            "humantime": crate.spec(
                version = "^2.1.0",
            ),
            "humantime-serde": crate.spec(
                version = "^1.1.1",
            ),
            "hyper": crate.spec(
                version = "^1.5.0",
                features = ["full"],
            ),
            "hyper-socks2": crate.spec(
                version = "^0.9.1",
                default_features = False,
            ),
            "hyper-util": crate.spec(
                version = "^0.1.10",
                features = ["full"],
            ),
            "hyper-rustls": crate.spec(
                default_features = False,
                version = "^0.27.3",
                features = [
                    "http1",
                    "http2",
                    "native-tokio",
                    "ring",
                    "tls12",
                ],
            ),
            "ic0": crate.spec(
                version = "^0.18.11",
            ),
            "ic-agent": crate.spec(
                version = "^0.37.1",
                features = [
                    "experimental_sync_call",
                    "hyper",
                    "reqwest",
                    "pem",
                ],
            ),
            "ic-bn-lib": crate.spec(
                git = "https://github.com/dfinity/ic-bn-lib",
                rev = "526d34d15cfbf369d8baf2dae9932aa18d570a1d",
            ),
            "ic-btc-interface": crate.spec(
                version = "^0.2.2",
            ),
            "ic-btc-test-utils": crate.spec(
                version = "^0.1.0",
            ),
            "ic-canister-log": crate.spec(
                version = "^0.2.0",
            ),
            "ic-canister-sig-creation": crate.spec(
                version = "^1.0.1",
            ),
            "ic-cbor": crate.spec(
                version = "2.6.0",
            ),
            "ic-cdk": crate.spec(
                version = "^0.16.0",
            ),
            "ic-cdk-timers": crate.spec(
                version = "^0.11.0",
            ),
            "ic-cdk-macros": crate.spec(
                version = "^0.9.0",
            ),
            "ic-certified-map": crate.spec(
                version = "^0.3.1",
            ),
            "ic-certification": crate.spec(
                version = "2.6.0",
            ),
            "ic-certificate-verification": crate.spec(
                version = "2.6.0",
            ),
            "ic-http-certification": crate.spec(
                version = "2.6.0",
            ),
            "ic-http-gateway": crate.spec(
                git = "https://github.com/dfinity/http-gateway",
                tag = "0.1.0-b0",
            ),
            "ic-metrics-encoder": crate.spec(
                version = "^1.1.1",
            ),
            "ic_principal": crate.spec(
                version = "^0.1.1",
                default_features = False,
            ),
            "ic-response-verification": crate.spec(
                version = "2.6.0",
            ),
            "ic-sha3": crate.spec(
                version = "^1.0.0",
            ),
            "ic-stable-structures": crate.spec(
                version = "^0.6.5",
            ),
            "icrc1-test-env": crate.spec(
                git = "https://github.com/dfinity/ICRC-1",
                rev = ICRC_1_REV,
            ),
            "icrc1-test-suite": crate.spec(
                git = "https://github.com/dfinity/ICRC-1",
                rev = ICRC_1_REV,
            ),
            "ic-test-state-machine-client": crate.spec(
                version = "^3.0.0",
            ),
            "ic-transport-types": crate.spec(
                version = "^0.37.1",
            ),
            "ic-utils": crate.spec(
                version = "^0.37.0",
                features = ["raw"],
            ),
            "ic-verify-bls-signature": crate.spec(
                version = "^0.6.0",
                features = [
                    "alloc",
                ],
                default_features = False,
            ),
            "ic-wasm": crate.spec(
                version = "^0.8.4",
                features = [
                    "exe",
                ],
                default_features = False,
            ),
            "ic-xrc-types": crate.spec(
                version = "^1.2.0",
            ),
            "idna": crate.spec(
                version = "^1.0.2",
            ),
            "indexmap": crate.spec(
                version = "^2.2.6",
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
                version = "^0.7.2",
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
            "json-patch": crate.spec(
                version = "^0.2.6",
            ),
            "json5": crate.spec(
                version = "^0.4.1",
            ),
            "k256": crate.spec(
                version = "^0.13.4",
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
                version = "^0.22.0",
                features = [
                    "v1_24",
                ],
            ),
            "kube": crate.spec(
                version = "^0.93.1",
            ),
            "lazy_static": crate.spec(
                version = "^1.4.0",
            ),
            "leb128": crate.spec(
                version = "^0.2.5",
            ),
            "libc": crate.spec(
                version = "^0.2.158",
            ),
            "libflate": crate.spec(
                version = "^2.1.0",
            ),
            "libfuzzer-sys": crate.spec(
                version = "^0.4.7",
                default_features = False,
            ),
            "libnss": crate.spec(
                version = "^0.5.0",
            ),
            "little-loadshedder": crate.spec(
                version = "^0.2.0",
            ),
            "lmdb-rkv": crate.spec(
                git = "https://github.com/dfinity-lab/lmdb-rs",
                rev = "4d952c8f1dca79de855af892b444d7112567b58d",
            ),
            "lmdb-rkv-sys": crate.spec(
                git = "https://github.com/dfinity-lab/lmdb-rs",
                rev = "4d952c8f1dca79de855af892b444d7112567b58d",
                default_features = False,
            ),
            "local-ip-address": crate.spec(
                version = "^0.5.6",
            ),
            "lru": crate.spec(
                version = "^0.7.8",
                default_features = False,
            ),
            "mach2": crate.spec(
                # Wasmtime depends on 0.4.2 but specifies 0.4.1.
                # Enforce 0.4.2 using a dummy dependency until
                # the upstream issue is fixed.
                version = "^0.4.2",
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
                version = "^0.13.0",
            ),
            "mockito": crate.spec(
                version = "^1.2.0",
            ),
            "moka": crate.spec(
                version = "^0.12.8",
                features = [
                    "future",
                    "sync",
                ],
            ),
            "more-asserts": crate.spec(
                version = "^0.3.1",
            ),
            "nftables": crate.spec(
                version = "^0.4.1",
            ),
            "nix": crate.spec(
                version = "^0.24.3",
            ),
            "num-bigint": crate.spec(
                version = "^0.4.6",
            ),
            "num-bigint-dig": crate.spec(
                version = "^0.8",
                features = ["prime"],
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
                version = "^1.16.0",
            ),
            "once_cell": crate.spec(
                version = "^1.8",
            ),
            "openssh-keys": crate.spec(
                version = "^0.5.0",
            ),
            "opentelemetry": crate.spec(
                version = "^0.27.0",
                features = [
                    "metrics",
                    "trace",
                ],
            ),
            "opentelemetry_0_20_0": crate.spec(
                package = "opentelemetry",
                version = "^0.20.0",
                features = [
                    "metrics",
                    "trace",
                ],
            ),
            "opentelemetry-otlp": crate.spec(
                version = "^0.27.0",
                features = [
                    "grpc-tonic",
                ],
            ),
            "opentelemetry_sdk": crate.spec(
                version = "^0.27.0",
                features = [
                    "trace",
                    "rt-tokio",
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
                version = "^0.23",
            ),
            "parking_lot": crate.spec(
                version = "^0.12.1",
            ),
            "paste": crate.spec(
                version = "^1.0.15",
            ),
            "pcre2": crate.spec(
                version = "^0.2.6",
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
                    "criterion",
                    "flamegraph",
                    "prost-codec",
                ],
                default_features = False,
            ),
            "predicates": crate.spec(
                version = "^3.1.2",
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
                version = "^1.0.89",
            ),
            "procfs": crate.spec(
                version = "^0.9",
                default_features = False,
            ),
            "prometheus": crate.spec(
                version = "^0.13.4",
                features = [
                    "process",
                ],
            ),
            "proptest": crate.spec(
                version = "^1.5.0",
            ),
            "prometheus-parse": crate.spec(
                version = "^0.2.4",
            ),
            "proptest-derive": crate.spec(
                version = "^0.5.0",
            ),
            "prost_0_12_0": crate.spec(
                package = "prost",
                version = "^0.12",
            ),
            "prost": crate.spec(
                version = "^0.13.3",
            ),
            "prost-build": crate.spec(
                version = "^0.13.3",
            ),
            "protobuf": crate.spec(
                version = "^2.28.0",
            ),
            "publicsuffix": crate.spec(
                version = "^2.2.3",
            ),
            "quickcheck": crate.spec(
                version = "^1.0.3",
            ),
            "quinn": crate.spec(
                version = "^0.11.5",
                default_features = False,
                features = ["ring", "log", "runtime-tokio", "rustls"],
            ),
            "quinn-udp": crate.spec(
                version = "^0.5.5",
            ),
            "quote": crate.spec(
                version = "^1.0.37",
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
            "ratelimit": crate.spec(
                version = "^0.9.1",
            ),
            "rayon": crate.spec(
                version = "^1.10.0",
            ),
            "rcgen": crate.spec(
                version = "^0.13.1",
                features = [
                    "zeroize",
                ],
            ),
            "rgb": crate.spec(
                version = "^0.8.37",
            ),
            "regex": crate.spec(
                version = "^1.11.0",
            ),
            "reqwest": crate.spec(
                version = "^0.12.8",
                default_features = False,
                features = [
                    "blocking",
                    "http2",
                    "json",
                    "multipart",
                    "rustls-tls",
                    "rustls-tls-native-roots",
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
                version = "^0.22.0",
                default_features = False,
            ),
            "rolling-file": crate.spec(
                version = "^0.2.0",
            ),
            "rsa": crate.spec(
                version = "^0.9.6",
                features = ["sha2"],
            ),
            "rstest": crate.spec(
                version = "^0.19.0",
            ),
            "rusb": crate.spec(
                version = "0.9",
            ),
            "rusqlite": crate.spec(
                version = "^0.28.0",
                features = ["bundled"],
            ),
            "rust_decimal": crate.spec(
                version = "^1.36.0",
            ),
            "rust_decimal_macros": crate.spec(
                version = "^1.36.0",
            ),
            "rustc-demangle": crate.spec(
                version = "^0.1.16",
            ),
            "rustc-hash": crate.spec(
                version = "^1.1.0",
            ),
            "rustls": crate.spec(
                version = "^0.23.16",
                default_features = False,
                features = [
                    "ring",
                    "std",
                    "brotli",
                ],
            ),
            "rustls-pemfile": crate.spec(
                version = "^2.1.2",
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
            "secp256k1": crate.spec(
                version = "^0.22",
                features = [
                    "global-context",
                    "rand-std",
                ],
            ),
            "semver": crate.spec(
                version = "^1.0.9",
                features = [
                    "serde",
                ],
            ),
            "serde": crate.spec(
                version = "^1.0.203",
                features = [
                    "derive",
                ],
                default_features = False,
            ),
            "serde-bytes-repr": crate.spec(
                version = "^0.1.5",
            ),
            "serde_bytes": crate.spec(
                version = "^0.11.15",
            ),
            "serde_cbor": crate.spec(
                version = "^0.11.2",
            ),
            "serde_json": crate.spec(
                version = "^1.0.107",
            ),
            "serde_regex": crate.spec(
                version = "^1.1.0",
            ),
            "serde_with": crate.spec(
                version = "^1.14.0",
            ),
            "serde_yaml": crate.spec(
                version = "^0.9.33",
            ),
            "sha2": crate.spec(
                version = "^0.10.8",
            ),
            "sha3": crate.spec(
                version = "^0.10.8",
            ),
            "signal-hook": crate.spec(
                version = "^0.3.6",
                features = [
                    "iterator",
                ],
            ),
            "signature": crate.spec(
                version = "^2.2.0",
            ),
            "simple_asn1": crate.spec(
                version = "^0.6.2",
            ),
            "simple_moving_average": crate.spec(
                version = "^1.0.2",
            ),
            "slog": crate.spec(
                version = "^2.7.0",
                features = [
                    "max_level_trace",
                    "nested-values",
                    "release_max_level_trace",
                ],
            ),
            "slog-async": crate.spec(
                version = "^2.8.0",
                features = [
                    "nested-values",
                ],
            ),
            "slog-envlogger": crate.spec(
                version = "^2.2.0",
            ),
            "slog-json": crate.spec(
                version = "^2.6.1",
                features = [
                    "nested-values",
                ],
            ),
            "slog-scope": crate.spec(
                version = "^4.4.0",
            ),
            "slog-term": crate.spec(
                version = "^2.9.1",
            ),
            "socket2": crate.spec(
                version = "^0.5.7",
                features = [
                    "all",
                ],
            ),
            "ssh2": crate.spec(
                version = "0.9.4",
            ),
            "static_assertions": crate.spec(
                version = "1.1.0",
            ),
            "strum": crate.spec(
                version = "^0.26.3",
                default_features = False,
            ),
            "strum_macros": crate.spec(
                version = "^0.26.4",
            ),
            "stubborn-io": crate.spec(
                version = "^0.3.2",
            ),
            "subtle": crate.spec(
                version = "^2.6.1",
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
                version = "^3.12.0",
            ),
            "tester": crate.spec(
                version = "^0.7.0",
            ),
            "test-strategy": crate.spec(
                version = "^0.3.1",
            ),
            "textplots": crate.spec(
                version = "^0.8",
            ),
            "thiserror": crate.spec(
                version = "^1.0.65",
            ),
            "thousands": crate.spec(
                version = "^0.2.0",
            ),
            "threadpool": crate.spec(
                version = "^1.8.1",
            ),
            "tikv-jemalloc-ctl": crate.spec(
                version = "^0.5",
            ),
            "tikv-jemallocator": crate.spec(
                version = "^0.5",
            ),
            "time": crate.spec(
                version = "^0.3.36",
            ),
            "tokio": crate.spec(
                version = "^1.41.1",
                features = ["full"],
            ),
            "tokio-io-timeout": crate.spec(
                version = "^1.2.0",
            ),
            "tokio-metrics": crate.spec(
                version = "^0.3.1",
            ),
            "tokio-rustls": crate.spec(
                version = "^0.26.0",
                default_features = False,
                features = [
                    "ring",
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
                version = "^0.4.4",
            ),
            "tokio-util": crate.spec(
                version = "^0.7.12",
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
                version = "^0.12.3",
            ),
            "tonic-build": crate.spec(
                version = "^0.12.3",
            ),
            "tower": crate.spec(
                version = "^0.5.1",
                features = ["full"],
            ),
            "tower-http": crate.spec(
                version = "^0.6.1",
                features = [
                    "cors",
                    "limit",
                    "trace",
                    "request-id",
                    "util",
                    "compression-full",
                    "tracing",
                ],
            ),
            "tower_governor": crate.spec(
                version = "^0.4.2",
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
            "tracing-opentelemetry": crate.spec(
                version = "^0.28.0",
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
                version = "^0.6.4",
            ),
            "url": crate.spec(
                version = "^2.5.3",
                features = [
                    "serde",
                ],
            ),
            "uuid": crate.spec(
                version = "^1.11.0",
                features = [
                    "v4",
                    "serde",
                ],
            ),
            "vsock": crate.spec(
                version = "^0.4",
            ),
            "walkdir": crate.spec(
                version = "^2.3.1",
            ),
            "warp": crate.spec(
                version = "^0.3.7",
                features = ["tls"],
            ),
            "wasm-bindgen": crate.spec(
                version = "^0.2",
            ),
            "wasm-encoder": crate.spec(
                version = "^0.217.0",
                features = [
                    "wasmparser",
                ],
            ),
            "wasm-smith": crate.spec(
                version = "^0.212.0",
                default_features = False,
                features = [
                    "wasmparser",
                ],
            ),
            "wasmparser": crate.spec(
                version = "^0.217.0",
            ),
            "wasmprinter": crate.spec(
                version = "^0.217.0",
            ),
            "wasmtime": crate.spec(
                version = "^26.0.0",
                default_features = False,
                features = [
                    "cranelift",
                    "gc",
                    "parallel-compilation",
                    "runtime",
                ],
            ),
            "wasmtime-environ": crate.spec(
                version = "^26.0.0",
            ),
            "wast": crate.spec(
                version = "^212.0.0",
            ),
            "wat": crate.spec(
                version = "1.212.0",
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
                version = "^0.6",
                default_features = False,
                features = [
                    "ecdsa",
                    "eddsa",
                    "hkdf",
                    "mac",
                    "rsa_sig",
                ],
            ),
            "x509-cert": crate.spec(
                version = "^0.2.5",
                features = [
                    "builder",
                    "hazmat",
                ],
            ),
            "x509-parser": crate.spec(
                version = "^0.16.0",
            ),
            "yansi": crate.spec(
                version = "^0.5.0",
            ),
            "zeroize": crate.spec(
                version = "^1.8.1",
                features = [
                    "zeroize_derive",
                ],
            ),
            "zstd": crate.spec(
                version = "^0.13.2",
            ),
        },
        splicing_config = splicing_config(
            resolver_version = "2",
        ),
    )
