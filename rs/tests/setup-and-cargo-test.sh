#! /usr/bin/env bash
set -eu

if [[ ${TMPDIR-/tmp} == /run/* ]]; then
    echo "Running in nix-shell on Linux, unsetting TMPDIR"
    export TMPDIR=
fi

show_help() {
    echo "Usage: ./setup-and-cargo-test.sh [OPTIONS] [-- FONDUE_OPTIONS]"
    echo ""
    echo "Compiles the replica and orchestrator, sets the binaries up then"
    echo "runs system-tests"
    echo ""
    echo "This script must be ran from 'rs/tests'. "
    echo ""
    echo "For information on the fondue options run this script with '-- -h'."
    echo ""
    echo "Options:"
    echo "   --no-build    Does not build the replica nor the orchestrator"
    echo ""
    echo "   --debug       Build the binaries in debug mode (ignored if --no-build is specified)"
    echo ""
    echo "   --jobs NUM    Passes '--jobs NUM' to all cargo build commands issued by this script."
    echo ""
    echo "   --no-cleanup  Do not delete temp. directories (./.tmp*)."
    echo ""
}

cleanup=true
no_build=false
debug=false
jobs_str=""

while [[ $# -ge 1 ]]; do
    case $1 in
        --no-build)
            no_build=true
            shift
            ;;
        --debug)
            debug=true
            shift
            ;;
        --jobs)
            shift
            jobs_str="--jobs $1"
            shift
            ;;
        --no-cleanup)
            cleanup=false
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Unknown option $1"
            show_help
            exit 1
            ;;
    esac
done

if [[ "$debug" == true ]]; then
    release_string=""
    BUILD_DIR="debug"
else
    release_string="--release"
    BUILD_DIR="release"
fi

currdir=$(basename "$PWD")
if [[ "$currdir" != "tests" ]]; then
    echo "You must run this from the tests directory."
    exit 1
fi

# Call cleanup() when the user presses Ctrl+C
trap "on_sigterm" 2

remove_tmp_dirs() {
    if [[ "$cleanup" == true ]]; then
        echo "Removing any temporary directories (./.tmp* and ./ic_config*)!"
        rm -rf ./.tmp*
        rm -rf ./ic_config*
    fi
}

# The shell kills the process group. However, the orchestrator sets the pgid to
# its own pid. As a result, the orchestrators and the replicas started by this
# script will not get killed when the user presses Ctrl+C. As a mitigation, ...
# we simply kill all orchestrator and system-tests.
on_sigterm() {
    echo "Received SIGINT ..."
    echo "Sending SIGTERM to 'orchestrator' processes started by this session!"
    for pid in $(pgrep orchestrator); do kill -s SIGTERM "$pid"; done
    echo "Sending SIGTERM to 'system-tests' processes started by this session!"
    for pid in $(pgrep system-tests); do kill -s SIGTERM "$pid"; done
    echo "Sending SIGTERM to 'ic-rosetta-api' processes started by this session!"
    for pid in $(pgrep ic-rosetta-api); do kill -s SIGTERM "$pid"; done
    echo "Sending SIGTERM to 'rosetta-cli' processes started by this session!"
    # I don't think this one is necessary, but just in case...
    for pid in $(pgrep rosetta-cli); do kill -s SIGTERM "$pid"; done
    echo "You can remove rosetta_workspace/rosetta_api_tmp_* dirs after you confirmed rosetta_api finished"
    remove_tmp_dirs
}

if [[ "$no_build" != true ]]; then
    ## Go build the replica and the orchestrator
    pushd ..
    st_build=$(date)
    pushd replica
    cargo build ${jobs_str} --bin replica ${release_string} --features malicious_code
    popd
    cargo build ${jobs_str} --bin orchestrator --bin ic-rosetta-api ${release_string}
    popd
    cargo build ${jobs_str}
    e_build=$(date)

    echo "Building times:"
    echo "  + $st_build"
    echo "  - $e_build"
fi

## Determine where the target lives
case $(uname) in
    Darwin) RUST_TRIPLE=x86_64-apple-darwin ;;
    Linux) RUST_TRIPLE=x86_64-unknown-linux-gnu ;;
esac

## Sets target to the BUILD_DIR subdir of $CARGO_TARGET_DIR if this variable is set.
## If CARGO_TEST_DIR is not set, we use the default $(pwd)/../target instead.
target=${CARGO_TARGET_DIR:-$(pwd)/../target}/${RUST_TRIPLE}/${BUILD_DIR}

if [[ ! -f "${target}/replica" ]] || [[ ! -f "${target}/orchestrator" ]]; then
    echo "Make sure that the following files exist:"
    echo "    - ${target}/replica"
    echo "    - ${target}/orchestrator"
    echo "    - ${target}/ic-rosetta-api"
    exit 1
fi

## Make a local-bin directory and link the replica and orchestrator here
mkdir -p local-bin
ln -fs "${target}/replica" local-bin/
ln -fs "${target}/orchestrator" local-bin/
ln -fs "${target}/ic-rosetta-api" local-bin/

## Update path; because we must run this script from the tests directory,
## we know local bin is in here.
PATH="$PWD/../../ic-os/guestos/scripts:$PWD/local-bin:$PATH"
SUMMARY_SCRIPT="$PWD/../../gitlab-ci/src/test_results/summary.py"
TEST_RESULTS="$(mktemp -d)/test-results.json"

## Run tests
st_test=$(date)
cargo run --bin system-tests -- --result-file "${TEST_RESULTS}" "$@"
e_test=$(date)

## Print summary
python3 "${SUMMARY_SCRIPT}" --test_results "${TEST_RESULTS}" --verbose

## Summary
echo "Testing times:"
echo "  + $st_test"
echo "  - $e_test"

remove_tmp_dirs
