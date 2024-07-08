"""
This module declares all direct rust dependencies.

Run `./bin/bazel-pin.sh` from the top-level directory of the working tree after changing this file
to regenerate Cargo Bazel lockfiles.
"""

load("@manifests//:defs.bzl", "MANIFESTS")
load("@rules_rust//crate_universe:defs.bzl", "crate", "crates_repository", "render_config", "splicing_config")
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

# Some legacy aliases from when crates were defined in Bazel
# { "actual": "alias" }
ALIASES = {
    # rules_rust appends the version to the name as soon as there is more than
    # one version of that crate.
    "axum-0.7.5": "axum",
    "bs50-0.5.0": "bs58",
    "clap-4.4.8": "clap",
    "http-1.1.0": "http",
    "http-body-1.0.0": "http-body",
    "hyper-1.4.0": "hyper",
    "hyper-rustls-0.24.2": "hyper-rustls",
    "ic0-0.21.1": "ic0",
    "opentelemetry-0.23.0": "opentelemetry",
    "opentelemetry-prometheus-0.16.0": "opentelemetry-prometheus",
    "reqwest-0.12.4": "reqwest",
    "ring-0.17.7": "ring",
    "rustls-0.23.10": "rustls",
    "sha2-0.10.8": "sha2",
    "sha3-0.10.8": "sha3",
    "tower-http-0.5.2": "tower-http",
    "wasmparser-0.201.0": "wasmparser",

    # Some aliases used by crates that have not been ported to all_crate_deps.
    # The versions might not match exactly for historical reasons.
    "axum-0.6.20": "axum_0_6_1",
    "axum-server-0.5.1": "axum-server",
    "axum-server-0.6.0": "axum_server_0_6_0",
    "clap-3.2.25": "clap_3_2_25",
    "http-0.2.12": "http_0_2_12",
    "http-body-0.4.6": "http_body_0_4_6",
    "hyper-0.14.27": "hyper_0_14_27",
    "hyper-rustls-0.27.1": "hyper_rustls_0_27_x",
    "opentelemetry-0.20.0": "opentelemetry_0_20_0",
    "opentelemetry-prometheus-0.13.0": "opentelemetry_prometheus_0_13_0",
    "rand_chacha-0.4.19": "rand_chacha_0_4_19",
    "reqwest-0.11.27": "reqwest_0_11_27",
    "rustls-0.21.12": "rustls_0_21_12",
    "sha2-0.9.9": "sha2_0_9_1",
    "tokio-rustls-0.24.1": "tokio_rustls_0_24_1",
    "tokio-rustls-0.26.0": "tokio-rustls",
    "tower-http-0.4.4": "tower_http_0_4_4",
}

# Some packages (crates) not picked up automatically by rules_rust
PACKAGES = {

    # marked as optional in Cargo.toml
    "arbitrary": crate.spec(
        version = "^1.3.0",
    ),

    # Couple LDMB deps for our custom crate build (deps not
    # specified in any Cargo.tomls)
    "bindgen": crate.spec(
        version = "^0.65.1",
        default_features = False,
        features = ["runtime"],
    ),
    "pkg-config": crate.spec(
        version = "^0.3",
    ),
    "bitflags": crate.spec(
        version = "^1.2.1",
    ),

    # build deps not picked up by rules_rust
    "build-info-build": crate.spec(
        git = "https://github.com/dfinity-lab/build-info",
        rev = BUILD_INFO_REV,
        default_features = False,
    ),
    "cc": crate.spec(
        version = "^1.0",
    ),
    "canbench": crate.spec(
        version = "^0.1.4",
    ),
    "canbench-rs": crate.spec(
        version = "^0.1.4",
    ),
    "tonic-build": crate.spec(
        version = "^0.11.0",
    ),

    # Crate that we build & export but do not actually depend on
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

    # proc macro dep not picked up by rules_rust
    "rustversion": crate.spec(
        version = "^1.0",
    ),

    # some deps which for reasons unclear are not picked up by rules_rust
    "rand_chacha": crate.spec(
        version = "^0.3.1",
    ),
    "schemars": crate.spec(
        version = "^0.8.16",
    ),

    # needed by fuzzing (no corresponding Cargo.tomls)
    "libfuzzer-sys": crate.spec(
        version = "^0.4.7",
        default_features = False,
    ),
    "wasm-smith": crate.spec(
        version = "^0.201.0",
        default_features = False,
        features = [
            "wasmparser",
        ],
    ),
}

# A custom alias rule (used by crates_repository) to enable our legacy aliases
def ic_alias(name, actual, tags):
    alias = ALIASES.get(name)
    if not (alias == None):
        return native.alias(name = alias, actual = actual, tags = tags)

    return native.alias(name = name, actual = actual, tags = tags)

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
        manifests = ["//:Cargo.toml"] + MANIFESTS,
        packages = PACKAGES,
        splicing_config = splicing_config(
            resolver_version = "2",
        ),
        render_config = render_config(
            default_alias_rule = "@@ic//bazel:external_crates.bzl:ic_alias",
        ),
    )
