"""
This module declares all direct rust dependencies.

Run `./bin/bazel-pin.sh` from the top-level directory of the working tree after changing this file
to regenerate Cargo Bazel lockfiles.
"""

load("@rules_rust//crate_universe:defs.bzl", "crate", "crates_repository", "splicing_config", "render_config")
load("//bazel:fuzz_testing.bzl", "DEFAULT_RUSTC_FLAGS_FOR_FUZZING")

load("@manifests//:defs.bzl", MANIFESTS_TMP = "MANIFESTS")

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

# TODO: create ticket for automatically loading manifests
MANIFESTS = [ "//:Cargo.toml" ] + MANIFESTS_TMP #+ [

ALIASES = {
    "axum-0.6.20": "axum_0_6_1", # sigh
    "axum-0.7.4": "axum",
    "bs50-0.5.0": "bs58",
    "clap-3.2.25": "clap_3_2_25",
    "clap-4.4.8": "clap",
    "http-0.2.12": "http_0_2_12",
    "http-1.1.0": "http",

    "http-body-0.4.6": "http_body_0_4_6",
    "http-body-1.0.0": "http-body",
    "hyper-0.14.27": "hyper_0_14_27",
    "hyper-1.3.1": "hyper",
    "hyper-rustls-0.24.2": "hyper-rustls",
    "hyper-rustls-0.27.1": "hyper_rustls_0_27_x",
    "ic0-0.21.1": "ic0",
    "opentelemetry-0.20.0": "opentelemetry_0_20_0",
    "opentelemetry-0.23.0": "opentelemetry",
    "opentelemetry-prometheus-0.13.0": "opentelemetry_prometheus_0_13_0",
    "opentelemetry-prometheus-0.16.0": "opentelemetry-prometheus",
    "rand_chacha-0.4.19": "rand_chacha_0_4_19",
    "reqwest-0.11.27": "reqwest_0_11_27",
    "reqwest-0.12.4": "reqwest",
    "ring-0.17.7": "ring",
    "rustls-0.21.12": "rustls_0_21_12",
    "rustls-0.23.8": "rustls",
    "sha2-0.9.9": "sha2_0_9_1", # sigh
    "sha2-0.10.8": "sha2",
    "tokio-rustls-0.24.1": "tokio_rustls_0_24_1",
    "tokio-rustls-0.26.0": "tokio-rustls",
    "tower-http-0.4.4": "tower_http_0_4_4",
    "tower-http-0.5.2": "tower-http",
    "wasmparser-0.201.0": "wasmparser",
}


def foo(name, actual, tags):

    alias = ALIASES.get(name)
    if not (alias == None):
        return native.alias(name = alias, actual = actual, tags = tags)


    return native.alias(name = name, actual = actual, tags = tags)


# TODO: for each crate here (axum, bs58, clap) add an alias_rule
# TODO: dedup this from the above, this is stupid
# TODO: figure out how to find duplicates even if they're not defined here (but
#   only defined in manifests)
def external_crates_repository(name, cargo_lockfile, lockfile, sanitizers_enabled):
    CRATE_ANNOTATIONS = {
        "canbench": [crate.annotation(
            gen_binaries = True,
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
        manifests = MANIFESTS,
        packages = {
            #"actix-rt": crate.spec(
            #    version = "^2.2.0",
            #),
            # TODO: actix-web: different features from toml
            #"actix-web": crate.spec(
            #    version = "^4.3.0",
            #),
            #"addr": crate.spec(
            #    version = "^0.15.6",
            #    default_features = False,
            #    features = [
            #        "idna",
            #    ],
            #),
            #"aide": crate.spec(
            #    version = "^0.13.0",
            #    features = [
            #        "axum",
            #    ],
            #),
            # TODO: marked as optional
            "arbitrary": crate.spec(
                version = "^1.3.0",
            ),
            #"arc-swap": crate.spec(
            #    version = "^1",
            #),
            #"anyhow": crate.spec(
            #    version = "^1",
            #),
            #"arrayvec": crate.spec(
            #    version = "^0.7.4",
            #),
            #"askama": crate.spec(
            #    version = "^0.12.1",
            #    features = [
            #        "serde-json",
            #    ],
            #),
            #"assert-json-diff": crate.spec(
            #    version = "^2.0.1",
            #),
            #"assert_cmd": crate.spec(
            #    version = "^2.0.12",
            #),
            #"assert_matches": crate.spec(
            #    version = "^1.5.0",
            #),
            #"async-recursion": crate.spec(
            #    version = "^1.0.5",
            #),
            #"async-scoped": crate.spec(
            #    version = "^0.8.0",
            #    features = [
            #        "use-tokio",
            #    ],
            #),
            # TODO: not used in Cargo.tomls
            #"async-socks5": crate.spec(
            #    version = "^0.5.1",
            #),
            #"async-stream": crate.spec(
            #    version = "^0.3.5",
            #),
            #"async-trait": crate.spec(
            #    version = "^0.1.73",
            #),
            # TODO: difference: boundary_node: does not have feature "headers"
            #"axum_0_6_1": crate.spec(
            #    package = "axum",
            #    version = "^0.6.1",
            #    features = [
            #        "headers",
            #    ],
            #),
            # TODO: difference: Cargo.toml has features = ["json"]
            #"axum": crate.spec(
            #    version = "^0.7.4",
            #),
            #"axum-extra": crate.spec(
            #    version = "^0.9.0",
            #    features = ["typed-header"],
            #),
            #"axum-server": crate.spec(
            #    version = "^0.5.1",
            #    features = [
            #        "tls-rustls",
            #    ],
            #),
            #"backoff": crate.spec(
            #    version = "^0.4.0",
            #),
            #"backon": crate.spec(
            #    version = "^0.4.1",
            #),
            #"base32": crate.spec(
            #    version = "^0.4.0",
            #),
            #"base64": crate.spec(
            #    version = "^0.13.1",
            #),
            #"bech32": crate.spec(
            #    version = "^0.9.0",
            #),
            #"bincode": crate.spec(
            #    version = "^1.3.3",
            #),
            # TODO: not in cargo, but in lmdb
            "bindgen": crate.spec(
                version = "^0.65.1",
                default_features = False,
                features = ["runtime"],
            ),
            #"bip32": crate.spec(
            #    version = "^0.5.0",
            #    features = [
            #        "secp256k1",
            #    ],
            #),
            #"bit-vec": crate.spec(
            #    version = "^0.6.3",
            #),
            #"bitcoin": crate.spec(
            #    version = "^0.28.1",
            #    features = [
            #        "default",
            #        "rand",
            #        "use-serde",
            #    ],
            #),
            #"bitcoincore-rpc": crate.spec(
            #    version = "^0.15.0",
            #),
            #"bitcoind": crate.spec(
            #    version = "^0.32.0",
            #),
            # TODO: only used by lmdb build
            "bitflags": crate.spec(
                version = "^1.2.1",
            ),
            #"bs58": crate.spec(
            #    version = "^0.5.0",
            #),
            #"ic_bls12_381": crate.spec(
            #    version = "^0.8.0",
            #    features = [
            #        "alloc",
            #        "experimental",
            #        "groups",
            #        "pairings",
            #        "zeroize",
            #    ],
            #    default_features = False,
            #),
            #"build-info": crate.spec(
            #    git = "https://github.com/dfinity-lab/build-info",
            #    rev = BUILD_INFO_REV,
            #),
            "build-info-build": crate.spec(
                git = "https://github.com/dfinity-lab/build-info",
                rev = BUILD_INFO_REV,
                default_features = False,
            ),
            #"by_address": crate.spec(
            #    version = "^1.1.0",
            #),
            #"byte-unit": crate.spec(
            #    version = "^4.0.14",
            #),
            #"byteorder": crate.spec(
            #    version = "^1.3.4",
            #),
            #"bytes": crate.spec(
            #    version = "^1.6.0",
            #),
            #"cached": crate.spec(
            #    version = "^0.49",
            #    default_features = False,
            #),
            "canbench": crate.spec(
                version = "^0.1.4",
            ),
            "canbench-rs": crate.spec(
                version = "^0.1.4",
            ),
            #"candid": crate.spec(
            #    version = "^0.10.6",
            #),
            #"cargo_metadata": crate.spec(
            #    version = "^0.14.2",
            #),
            #"candid_parser": crate.spec(
            #    version = "^0.1.2",
            #),
            "cc": crate.spec( # build dep
                version = "^1.0",
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
            #"minicbor": crate.spec(
            #    version = "^0.19.1",
            #    features = ["alloc", "derive"],
            #),
            #"minicbor-derive": crate.spec(
            #    version = "^0.13.0",
            #),
            #"mockall": crate.spec(
            #    version = "^0.12.1",
            #),
            #"mockito": crate.spec(
            #    version = "^1.2.0",
            #),
            #"moka": crate.spec(
            #    version = "^0.12",
            #    features = [
            #        "future",
            #        "sync",
            #    ],
            #),
            #"more-asserts": crate.spec(
            #    version = "^0.3.1",
            #),
            #"nftables": crate.spec(
            #    version = "^0.4",
            #),
            #"nix": crate.spec(
            #    version = "^0.24.3",
            #),
            #"num": crate.spec(
            #    version = "^0.4.0",
            #),
            #"num-bigint": crate.spec(
            #    version = "^0.4.0",
            #),
            #"num-bigint-dig": crate.spec(
            #    version = "^0.8",
            #    features = ["prime"],
            #),
            #"num-rational": crate.spec(
            #    version = "^0.2.2",
            #),
            #"num-traits": crate.spec(
            #    version = "^0.2.12",
            #    features = [
            #        "libm",
            #    ],
            #    default_features = False,
            #),
            #"num_cpus": crate.spec(
            #    version = "^1.13.1",
            #),
            #"once_cell": crate.spec(
            #    version = "^1.8",
            #),
            #"openssh-keys": crate.spec(
            #    version = "^0.5.0",
            #),
            #"opentelemetry": crate.spec(
            #    version = "^0.23.0",
            #    features = [
            #        "metrics",
            #        "trace",
            #    ],
            #),
            #"opentelemetry_0_20_0": crate.spec(
            #    package = "opentelemetry",
            #    version = "^0.20.0",
            #    features = [
            #        "metrics",
            #        "trace",
            #    ],
            #),
            #"opentelemetry-otlp": crate.spec(
            #    version = "^0.16.0",
            #    features = [
            #        "grpc-tonic",
            #    ],
            #),
            #"opentelemetry_sdk": crate.spec(
            #    version = "^0.23.0",
            #    features = [
            #        "trace",
            #        "rt-tokio",
            #    ],
            #),
            #"opentelemetry-prometheus": crate.spec(
            #    version = "^0.16.0",
            #),
            #"opentelemetry-prometheus_0_13_0": crate.spec(
            #    package = "opentelemetry-prometheus",
            #    version = "^0.13.0",
            #),
            #"p256": crate.spec(
            #    version = "^0.13.2",
            #    features = [
            #        "arithmetic",
            #        "ecdsa",
            #        "pem",
            #        "pkcs8",
            #    ],
            #    default_features = False,
            #),
            #"pairing": crate.spec(
            #    version = "^0.22",
            #),
            #"parking_lot": crate.spec(
            #    version = "^0.12.1",
            #),
            #"paste": crate.spec(
            #    version = "^1.0.0",
            #),
            #"pathdiff": crate.spec(
            #    version = "^0.2.1",
            #),
            #"pcre2": crate.spec(
            #    version = "^0.2.6",
            #),
            #"pem": crate.spec(
            #    version = "^1.0.1",
            #),
            #"pin-project-lite": crate.spec(
            #    version = "^0.2",
            #),
            #"ping": crate.spec(
            #    version = "^0.5.0",
            #),
            #"pkcs8": crate.spec(
            #    version = "^0.10.2",
            #),
            # TODO: lmdb
            "pkg-config": crate.spec(
                version = "^0.3",
            ),
            #"pprof": crate.spec(
            #    version = "^0.13.0",
            #    features = [
            #        "flamegraph",
            #        "prost-codec",
            #    ],
            #    default_features = False,
            #),
            #"predicates": crate.spec(
            #    version = "^3.0.4",
            #),
            #"pretty-bytes": crate.spec(
            #    version = "^0.2.2",
            #),
            #"pretty_assertions": crate.spec(
            #    version = "^1.4.0",
            #),
            #"priority-queue": crate.spec(
            #    version = "^1.3.1",
            #    features = [
            #        "serde",
            #    ],
            #),
            #"proc-macro2": crate.spec(
            #    version = "^1.0",
            #),
            #"procfs": crate.spec(
            #    version = "^0.9",
            #    default_features = False,
            #),
            #"prometheus": crate.spec(
            #    version = "^0.13.4",
            #    features = [
            #        "process",
            #    ],
            #),
            #"proptest": crate.spec(
            #    version = "^1.0.0",
            #),
            #"prometheus-parse": crate.spec(
            #    version = "^0.2.4",
            #),
            #"proptest-derive": crate.spec(
            #    version = "^0.3.0",
            #),
            #"prost": crate.spec(
            #    version = "^0.12",
            #),
            #"prost-build": crate.spec(
            #    version = "^0.12",
            #),
            #"prost-derive": crate.spec(
            #    version = "^0.12",
            #),
            #"protobuf": crate.spec(
            #    version = "^2.28.0",
            #),
            #"publicsuffix": crate.spec(
            #    version = "^2.2.3",
            #),
            #"quickcheck": crate.spec(
            #    version = "^1.0.3",
            #),
            #"quinn": crate.spec(
            #    version = "^0.10.2",
            #    features = [
            #        "ring",
            #    ],
            #),
            #"quinn-udp": crate.spec(
            #    version = "^0.5.1",
            #),
            #"quote": crate.spec(
            #    version = "^1.0",
            #),
            #"rand": crate.spec(
            #    version = "^0.8.5",
            #    features = [
            #        "small_rng",
            #    ],
            #),
            "rand_chacha": crate.spec(
                version = "^0.3.1",
            ),
            #"rand_distr": crate.spec(
            #    version = "^0.4",
            #),
            #"rand_pcg": crate.spec(
            #    version = "^0.3.1",
            #),
            #"randomkit": crate.spec(
            #    version = "^0.1.1",
            #),
            #"ratelimit": crate.spec(
            #    version = "^0.9.1",
            #),
            #"rayon": crate.spec(
            #    version = "^1.10.0",
            #),
            #"rcgen": crate.spec(
            #    version = "^0.13.1",
            #    features = [
            #        "zeroize",
            #    ],
            #),
            #"rgb": crate.spec(
            #    version = "^0.8.37",
            #),
            #"regex": crate.spec(
            #    version = "^1.10.4",
            #),
            #"reqwest_0_11_27": crate.spec(
            #    package = "reqwest",
            #    version = "^0.11.27",
            #    default_features = False,
            #    features = [
            #        "blocking",
            #        "json",
            #        "multipart",
            #        "rustls-tls-webpki-roots",
            #        "socks",
            #        "stream",
            #    ],
            #),
            #"reqwest": crate.spec(
            #    package = "reqwest",
            #    version = "^0.12.3",
            #    default_features = False,
            #    features = [
            #        "blocking",
            #        "http2",
            #        "json",
            #        "multipart",
            #        "rustls-tls",
            #        "rustls-tls-native-roots",
            #        "stream",
            #    ],
            #),
            #"ring": crate.spec(
            #    version = "^0.17.7",
            #    features = [
            #        "std",
            #    ],
            #),
            #"ripemd": crate.spec(
            #    version = "^0.1.1",
            #),
            #"rlp": crate.spec(
            #    version = "^0.5.2",
            #),
            #"rocksdb": crate.spec(
            #    version = "^0.22.0",
            #    default_features = False,
            #),
            #"rolling-file": crate.spec(
            #    version = "^0.2.0",
            #),
            #"rsa": crate.spec(
            #    version = "^0.9.2",
            #    features = ["sha2"],
            #),
            #"rstack-self": crate.spec(
            #    version = "^0.3",
            #),
            #"rstest": crate.spec(
            #    version = "^0.19",
            #),
            #"rusb": crate.spec(
            #    version = "0.9",
            #),
            #"rusqlite": crate.spec(
            #    version = "^0.28.0",
            #    features = ["bundled"],
            #),
            #"rust_decimal": crate.spec(
            #    version = "^1.25.0",
            #),
            #"rust_decimal_macros": crate.spec(
            #    version = "^1.25.0",
            #),
            #"rustc-hash": crate.spec(
            #    version = "^1.1.0",
            #),
            #"rustls_0_21_12": crate.spec(
            #    package = "rustls",
            #    version = "^0.21.12",
            #    features = [
            #        "dangerous_configuration",
            #    ],
            #),
            #"rustls": crate.spec(
            #    package = "rustls",
            #    default_features = False,
            #    version = "^0.23.8",
            #    features = [
            #        "ring",
            #    ],
            #),
            #"rustls-native-certs": crate.spec(
            #    version = "^0.7.0",
            #),
            #"rustls-pemfile": crate.spec(
            #    version = "^2.1.2",
            #),
            #"rustls-pki-types": crate.spec(
            #    version = "^1.7.0",
            #    features = [
            #        "alloc",
            #    ],
            #),
            # proc macro dep (rust_canister/dfn_macro)
            "rustversion": crate.spec(
                version = "^1.0",
            ),
            #"rusty-fork": crate.spec(
            #    version = "^0.3.0",
            #),
            # TODO: used in pocket-ic but not picked up?
            "schemars": crate.spec(
                version = "^0.8.16",
            ),
            #"schnorr_fun": crate.spec(
            #    version = "^0.10",
            #),
            #"scoped_threadpool": crate.spec(
            #    version = "^0.1.9",
            #),
            #"scopeguard": crate.spec(
            #    version = "^1.1.0",
            #),
            #"scraper": crate.spec(
            #    version = "^0.17.1",
            #),
            #"semver": crate.spec(
            #    version = "^1.0.9",
            #    features = [
            #        "serde",
            #    ],
            #),
            #"serde": crate.spec(
            #    version = "^1.0.203",
            #    features = [
            #        "derive",
            #    ],
            #    default_features = False,
            #),
            #"serde-bytes-repr": crate.spec(
            #    version = "^0.1.5",
            #),
            #"serde_bytes": crate.spec(
            #    version = "^0.11.14",
            #),
            #"serde_cbor": crate.spec(
            #    version = "^0.11.2",
            #),
            #"serde_json": crate.spec(
            #    version = "^1.0.107",
            #),
            #"serde_regex": crate.spec(
            #    version = "^1.1.0",
            #),
            #"serde_with": crate.spec(
            #    version = "^1.14.0",
            #),
            #"serde_yaml": crate.spec(
            #    version = "^0.9.33",
            #),
            #"sha2-0_9_1": crate.spec(
            #    package = "sha2",
            #    version = "^0.9.1",
            #),
            #"sha3": crate.spec(
            #    version = "^0.9.1",
            #),
            #"signal-hook": crate.spec(
            #    version = "^0.3.6",
            #    features = [
            #        "iterator",
            #    ],
            #),
            #"signature": crate.spec(
            #    version = "^2.2.0",
            #),
            #"simple_asn1": crate.spec(
            #    version = "^0.6.2",
            #),
            #"simple_moving_average": crate.spec(
            #    version = "^1.0.2",
            #),
            #"slog": crate.spec(
            #    version = "^2.7.0",
            #    features = [
            #        "max_level_trace",
            #        "nested-values",
            #        "release_max_level_debug",
            #        "release_max_level_trace",
            #    ],
            #),
            #"slog-async": crate.spec(
            #    version = "^2.8.0",
            #    features = [
            #        "nested-values",
            #    ],
            #),
            #"slog-envlogger": crate.spec(
            #    version = "^2.2.0",
            #),
            #"slog-json": crate.spec(
            #    version = "^2.6.1",
            #    features = [
            #        "nested-values",
            #    ],
            #),
            #"slog-scope": crate.spec(
            #    version = "^4.4.0",
            #),
            #"slog-term": crate.spec(
            #    version = "^2.9.1",
            #),
            #"socket2": crate.spec(
            #    version = "^0.5.7",
            #    features = [
            #        "all",
            #    ],
            #),
            #"ssh2": crate.spec(
            #    version = "0.9.4",
            #),
            #"strum": crate.spec(
            #    version = "^0.26.2",
            #    features = [
            #        "derive",
            #    ],
            #),
            #"strum_macros": crate.spec(
            #    version = "^0.26.2",
            #),
            #"stubborn-io": crate.spec(
            #    version = "^0.3.2",
            #),
            #"substring": crate.spec(
            #    version = "^1.4.5",
            #),
            #"subtle": crate.spec(
            #    version = "^2.4",
            #),
            #"syn": crate.spec(
            #    version = "^1.0.109",
            #    features = [
            #        "fold",
            #        "full",
            #    ],
            #),
            #"sync_wrapper": crate.spec(
            #    version = "^1.0.1",
            #),
            #"tar": crate.spec(
            #    version = "^0.4.38",
            #),
            #"tarpc": crate.spec(
            #    version = "^0.34",
            #    features = [
            #        "full",
            #    ],
            #),
            #"tempfile": crate.spec(
            #    version = "^3.10.1",
            #),
            #"tester": crate.spec(
            #    version = "^0.7.0",
            #),
            #"test-strategy": crate.spec(
            #    version = "^0.3.1",
            #),
            #"textplots": crate.spec(
            #    version = "^0.8",
            #),
            #"thiserror": crate.spec(
            #    version = "^1.0.57",
            #),
            #"thousands": crate.spec(
            #    version = "^0.2.0",
            #),
            #"threadpool": crate.spec(
            #    version = "^1.8.1",
            #),
            #"time": crate.spec(
            #    version = "^0.3.36",
            #),
            #"tokio": crate.spec(
            #    version = "^1.38.0",
            #    features = [
            #        "full",
            #    ],
            #),
            #"tokio-io-timeout": crate.spec(
            #    version = "^1.2.0",
            #),
            #"tokio-metrics": crate.spec(
            #    version = "^0.3.1",
            #),
            #"tokio_rustls_0_24_1": crate.spec(
            #    package = "tokio-rustls",
            #    version = "^0.24.1",
            #    features = [
            #        "dangerous_configuration",
            #    ],
            #),
            #"tokio-rustls": crate.spec(
            #    version = "^0.26.0",
            #    default_features = False,
            #    features = [
            #        "logging",
            #        "tls12",
            #        "ring",
            #    ],
            #),
            #"tokio-serde": crate.spec(
            #    version = "^0.8",
            #    features = [
            #        "bincode",
            #        "json",
            #    ],
            #),
            #"tokio-socks": crate.spec(
            #    version = "^0.5.1",
            #),
            #"tokio-test": crate.spec(
            #    version = "^0.4.2",
            #),
            #"tokio-util": crate.spec(
            #    version = "^0.7.11",
            #    features = [
            #        "codec",
            #        "time",
            #        "rt",
            #    ],
            #),
            #"toml": crate.spec(
            #    version = "^0.5.9",
            #),
            #"tonic": crate.spec(
            #    version = "^0.11.0",
            #),
            "tonic-build": crate.spec( # XXX: in cargo tomls: build-dependencies (not reflected here)
                version = "^0.11.0",
            ),
            #"tower": crate.spec(
            #    version = "^0.4.13",
            #    features = ["full"],
            #),
            #"tower_http_0_4_4": crate.spec(
            #    version = "^0.4.4",
            #    package = "tower-http",
            #    features = [
            #        "trace",
            #        "request-id",
            #        "util",
            #        "compression-full",
            #    ],
            #),
            #"tower-http": crate.spec(
            #    version = "^0.5.2",
            #    features = [
            #        "cors",
            #        "limit",
            #        "trace",
            #        "request-id",
            #        "util",
            #        "compression-full",
            #        "tracing",
            #    ],
            #),
            #"tower_governor": crate.spec(
            #    version = "^0.1",
            #),
            #"tower-request-id": crate.spec(
            #    version = "^0.3.0",
            #),
            #"tower-test": crate.spec(
            #    version = "^0.4.0",
            #),
            #"tracing": crate.spec(
            #    version = "^0.1.40",
            #),
            #"tracing-appender": crate.spec(
            #    version = "^0.2.3",
            #),
            #"tracing-flame": crate.spec(
            #    version = "^0.2.0",
            #),
            #"tracing-core": crate.spec(
            #    version = "^0.1.32",
            #),
            #"tracing-opentelemetry": crate.spec(
            #    version = "^0.24.0",
            #),
            #"tracing-serde": crate.spec(
            #    version = "^0.1.3",
            #),
            #"tracing-slog": crate.spec(
            #    version = "^0.2",
            #),
            #"tracing-subscriber": crate.spec(
            #    version = "^0.3.18",
            #    features = [
            #        "env-filter",
            #        "fmt",
            #        "json",
            #    ],
            #),
            #"trust-dns-resolver": crate.spec(
            #    version = "^0.22.0",
            #),
            #"turmoil": crate.spec(
            #    version = "^0.6.2",
            #),
            #"url": crate.spec(
            #    version = "^2.4.1",
            #    features = [
            #        "serde",
            #    ],
            #),
            #"uuid": crate.spec(
            #    version = "^1.3.0",
            #    features = [
            #        "v4",
            #        "serde",
            #    ],
            #),
            #"vsock": crate.spec(
            #    version = "^0.4",
            #),
            #"walrus": crate.spec(
            #    version = "^0.19.0",
            #),
            #"walkdir": crate.spec(
            #    version = "^2.3.1",
            #),
            #"warp": crate.spec(
            #    version = "^0.3.6",
            #    features = [
            #        "tls",
            #    ],
            #),
            #"wasm-bindgen": crate.spec(
            #    version = "^0.2",
            #),
            #"wasm-encoder": crate.spec(
            #    version = "^0.201.0",
            #    features = [
            #        "wasmparser",
            #    ],
            #),
            #"wasm-smith": crate.spec(
            #    version = "^0.201.0",
            #    default_features = False,
            #    features = [
            #        "wasmparser",
            #    ],
            #),
            #"wasmparser": crate.spec(
            #    version = "^0.201.0",
            #),
            #"wasmprinter": crate.spec(
            #    version = "^0.2.50",
            #),
            #"wasmtime": crate.spec(
            #    version = "^21.0.1",
            #    default_features = False,
            #    features = [
            #        "cranelift",
            #        "gc",
            #        "parallel-compilation",
            #        "runtime",
            #    ],
            #),
            #"wasmtime-environ": crate.spec(
            #    version = "^21.0.1",
            #),
            #"wast": crate.spec(
            #    version = "^53.0.0",
            #),
            #"wat": crate.spec(
            #    version = "^1.0.57",
            #),
            #"wee_alloc": crate.spec(
            #    version = "^0.4.3",
            #),
            #"which": crate.spec(
            #    version = "^4.2.2",
            #),
            #"wsl": crate.spec(
            #    version = "^0.1.0",
            #),
            #"wycheproof": crate.spec(
            #    version = "^0.5",
            #),
            #"wiremock": crate.spec(
            #    version = "^0.5.19",
            #),
            #"x509-cert": crate.spec(
            #    version = "^0.2.5",
            #    features = [
            #        "builder",
            #        "hazmat",
            #    ],
            #),
            #"x509-parser": crate.spec(
            #    version = "^0.16.0",
            #),
            #"yansi": crate.spec(
            #    version = "^0.5.0",
            #),
            #"zeroize": crate.spec(
            #    version = "^1.8.1",
            #    features = [
            #        "zeroize_derive",
            #    ],
            #),
            #"zstd": crate.spec(
            #    version = "^0.13.1",
            #),
        },
        splicing_config = splicing_config(
            resolver_version = "2",
        ),
        render_config = render_config(
            default_alias_rule = "@@ic//bazel:external_crates.bzl:foo",

        ),
    )
