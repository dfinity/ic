#!/usr/bin/env bash

set -eEuo pipefail

forbidden_testnets="mercury"
for item in $forbidden_testnets; do
    # shellcheck disable=SC2154
    if [[ "$testnet" == "$item" ]]; then
        echo >&2 "This script is not intended to run against the '${item}' testnet. Aborting."
        exit 1
    fi
done

if [[ -z "$testnet" ]]; then
    echo >&2 "ERROR: <testnet> argument is not set."
    exit_usage
fi

# Results will be stored in $results_dir/$experiment_dir -- this will allow us to collect all runs
# if ever needed.
# shellcheck disable=SC2154
echo "Creating '$experiment_dir' to store all the data for this run."
mkdir -p "$experiment_dir"

echo "$@" >"$experiment_dir/params"

REPO_ROOT="$(git rev-parse --show-toplevel)"
PROD_SRC=${PROD_SRC:-$REPO_ROOT/testnet}

if [[ -z "${GIT_REVISION:-}" ]]; then
    echo >&2 "ERROR: Environment variable GIT_REVISION is not set. Please set it before invoking this script."
    echo >&2 -e "\nExample (for the current git HEAD revision):"
    echo >&2 -e "\n     export GIT_REVISION=\$(git rev-parse --verify HEAD)"
    echo >&2 -e "\nor (for the latest available master):"
    echo >&2 -e "\n     export GIT_REVISION=\$($REPO_ROOT/gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh origin/master)"
    echo >&2 -e "\n"
    exit 1
fi
function disk_image_exists() {
    curl --output /dev/null --silent --head --fail \
        "https://download.dfinity.systems/ic/$GIT_REVISION/guest-os/disk-img/disk-img.tar.gz" \
        || curl --output /dev/null --silent --head --fail \
            "https://download.dfinity.systems/ic/$GIT_REVISION/guest-os/disk-img.tar.gz"
}

for i in {1..60}; do
    if disk_image_exists; then
        echo "Disk image found for $GIT_REVISION"
        break
    fi
    echo "Disk image not available for $GIT_REVISION, waiting 30s for it to built by the CI ($i/60)"
    sleep 30
done
if [[ $i -ge 60 ]]; then
    echo "Disk image not found for $GIT_SHA, giving up"
    exit 1
fi

# Create the artifacts/bin directory and add it to the path
MEDIA_BIN_PATH="${REPO_ROOT}/artifacts/guestos/${testnet}/${GIT_REVISION}/bin"
export MEDIA_CANISTERS_PATH="${REPO_ROOT}/artifacts/guestos/${testnet}/${GIT_REVISION}/canisters"
if [[ -n "${IN_NIX_SHELL:-}" ]] && type "ic-workload-generator" >/dev/null; then
    echo "ATTENTION: Running in Nix shell with ic-workload-generator in path. Will re-use the binaries from the Nix shell."
else
    export PATH=$PATH:$MEDIA_BIN_PATH
fi

# Store git information
git rev-parse HEAD >"$experiment_dir/git-SHA"
git describe HEAD --always >"$experiment_dir/git-describe"
git status -s >"$experiment_dir/git-status"
git diff >"$experiment_dir/git-diff"

if [[ "$testnet" != "none" ]] && [[ ! -d "$PROD_SRC/env/$testnet" ]]; then
    echo >&2 "'$testnet' doesn't exist (checked at '$PROD_SRC/env/$testnet'), aborting."
    exit 1
fi

# Helper function to exit deployment script if it takes more than 30min
deploy_with_timeout() {
    echo "1000" >"${experiment_dir}/deploy_exit_code.txt" # write dummy value to file (to be overwritten later)
    echo "0" >"${experiment_dir}/sleep_timeout.txt"
    (
        "${REPO_ROOT}/testnet/tools/icos_deploy.sh" "$@"
        echo $? >"${experiment_dir}/deploy_exit_code.txt"
    ) &
    pid=$!
    # Interrupt deployment if it takes more than 30min (note that we don't use timeout because we want to print out
    # the reason why the test was interrupted)
    timeout=1800
    (sleep "${timeout}" && kill -HUP $pid && echo "${timeout}" >"${experiment_dir}/sleep_timeout.txt") 2>/dev/null &
    watcher=$! # Even though watcher is not used anywhere later, omitting it will lead to different behavior..
    if wait $pid 2>/dev/null; then
        echo "Deployment process finished"
    fi
    typeset -i SLEEP_TIMEOUT=$(cat "${experiment_dir}/sleep_timeout.txt")
    typeset -i DEPLOY_EXIT_CODE=$(cat "${experiment_dir}/deploy_exit_code.txt")
    if ((DEPLOY_EXIT_CODE == 0 && SLEEP_TIMEOUT == 0)); then
        success "Deployment processes finished gracefully"
    elif ((SLEEP_TIMEOUT != 0)); then
        failure "Deployment process timed out"
        exit 124
    elif ((DEPLOY_EXIT_CODE == 1000)); then
        failure "Deployment process exited prematurely"
        exit 1
    else
        failure "Deployment process finished with exit code ${DEPLOY_EXIT_CODE}"
        exit "${DEPLOY_EXIT_CODE}"
    fi
}

# Helper function to convert times
dateFromEpoch() {
    date --date="@$1"
}

# Download icx binary from agent-rs repo
function download_agent_rs_binaries() {
    local BIN_DIR="$1"
    local RELEASE_TAG=${2:-20162d2}
    curl -L "https://github.com/dfinity/agent-rs/releases/download/$RELEASE_TAG/binaries-linux.tar.gz" | tar -C "$BIN_DIR" -zxf -
}

# Wait until proposal is both accepted and executed. This
# is useful for subnet creation proposal where the actual
# change to subnet record only happens after DKG finishes
# running.
wait_for_proposal_execution() {
    (
        local network="$1"
        local proposal="$2"
        local status_file=${3:-$(mktemp proposal-status-XXXXXX.did)}
        local nns_url_http="${NNS_URL//https/http}"
        local DID_FILE="$REPO_ROOT/rs/nns/governance/canister/governance.did"
        local NNS_CANISTER_ID=rrkah-fqaaa-aaaaa-aaaaq-cai
        local expected=4
        printf "\nWaiting for the proposal to be approved\nStatus in: %s\n\n" "$status_file"
        for ((retries = 100; ; retries--)); do
            # Wait until time has been spent on execution.
            local state=$(cd "$results_dir" && icx "$nns_url_http" query "$NNS_CANISTER_ID" get_proposal_info --candid="$DID_FILE" "(${proposal}:nat64)" | tee "${status_file}" | idl2json | jq '.[0].status|tonumber')
            printf '\r Expected state: %12s  Actual state: %12s  with %3d tries left' "$expected" "$state" "$retries"
            if [[ "$state" == "$expected" ]]; then
                printf '\n\nOK\n\n'
                break
            elif [[ "$state" == "2" ]]; then
                echo "ERROR: proposal is rejected"
                exit 1
            elif [[ "$state" == "5" ]]; then
                printf "ERROR: proposal failed"
                exit 1
            elif ((retries > 0)); then
                sleep 10
            else
                echo
                printf "ERROR: %s\n" \
                    "Proposal has not been accepted." \
                    "Expected state: $expected" \
                    "Actual state:   $state"
                exit 1
            fi
        done
        rm -f "$status_file"
    )
}

# Escape IPv6 HTTP URLs for prometheus queries
escapebracket() {
    sed "s/\\[/\\\\\\\\[/g" - | sed "s/\\]/\\\\\\\\]/g"
}

# The function 'jq_hostvars' replaces the templates (e.g. '{{p2p_listen_port}}')
# with their values defined in the same input file (e.g. '4100')
# If one argument is provided, it must be further jq filters.
# If two arguments are provided, the first is filters to feed into the template
# expansion, while the second is further jq filters. (passing `._meta.hostvars`
# for the first argument is the same as omitting the first argument altogether).
# Example usage:
# jq_hostvars 'map(select(.subnet_index==1) | .api_listen_url)[1:] | join(",")'
function jq_hostvars() {
    if [ -z ${1+x} ]; then
        local prefilter='._meta.hostvars'
        local postfilter='.'
    elif [ -z ${2+x} ]; then
        local prefilter='._meta.hostvars'
        local postfilter=$1
    else
        local prefilter=$1
        local postfilter=$2
    fi

    cd "$PROD_SRC"
    ansible-inventory -i "env/$testnet/hosts" --list \
        | jq -L"${PROD_SRC}/jq" --sort-keys \
            -r "import \"ansible\" as ansible;
                 $prefilter | map_values(ansible::interpolate) | $postfilter"
}

# Join array $2 with a separator provided in $1. For instance:
# data=(a b c)
# join_array , "${data[@]}"
# ==> "a,b,c"
# https://stackoverflow.com/questions/53839253/how-can-i-convert-an-array-into-a-comma-separated-string
join_array() {
    local IFS="$1"
    shift
    echo "$*"
}

function collect_metrics() {
    # take subnet_index from argument 1, or default to subnet 1.
    subnet_index=${1:-1}
    echo "Collecting metrics from the subnet with index=${subnet_index}"
    # If endtime is not set or null, set it to now.
    endtime="${endtime:=$(date '+%s')}"
    # If duration is not set or null, set it to endtime - starttime.
    duration="${duration:=$((endtime - starttime))}"
    # Get the report
    # Produce the list of all nodes in the testnet, suitable for passing to the Prometheus query
    metricshosts="$(jq_subnet_load_urls_for_metrics $subnet_index)"

    # Extract the IC name from the testnet name (p2p_15_28 -> p2p)
    ic="${testnet%%_*}"

    # Get these metrics. We will go from the start time to the endtime, with 60s step.
    # In each of the time windows (steps) we calculate the min, max, avg for the metric.
    mkdir -p "$experiment_dir/metrics"
    common_labels="ic=\"$ic\",job=\"replica\",instance=~\"$metricshosts\""
    for selector in "consensus_ingress_message_bytes_delivered_sum{$common_labels}" "artifact_pool_consensus_height_stat{$common_labels,type=\"finalization\",pool_type=\"validated\",stat=\"max\"}"; do
        metric="${selector%%\{*}"
        # Calculate the averages over the large interval.
        # We split into smaller buckets, then apply avg_over_time. The outer avg it
        # to get an aggregate, instead of having values per replica.
        curl -G "http://prometheus.dfinity.systems:9090/api/v1/query" \
            -o "$experiment_dir/metrics/${metric}_avg_total.json" \
            -fsSL -m 30 --retry 10 --retry-connrefused \
            -H "Accept: application/json" \
            --data-urlencode "time=$endtime" \
            --data-urlencode "query=avg(rate(${selector}[${duration}s]))"
    done

    echo "Results stored in '$experiment_dir/metrics'"
}

function wait_for_subnet_to_stop() {
    while true; do
        endtime="$(date '+%s')"
        duration=60
        collect_metrics
        finalization_rate="$(jq -r '.data.result[0].value[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_avg_total.json")"
        echo "Finalization rate = $finalization_rate"
        test "$finalization_rate" = "0" && break
        sleep 5
    done
}

function wait_for_subnet_to_resume() {
    subnet=${1:-1}
    while true; do
        endtime="$(date '+%s')"
        export endtime
        export duration=60
        collect_metrics "$subnet"
        local finalization_rate
        finalization_rate="$(jq -r '.data.result[0].value[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_avg_total.json")"
        echo "Finalization rate = $finalization_rate"
        threshold=$(finalization_rate_threshold $subnet)
        test "$(echo "$finalization_rate > threshold && $finalization_rate < 10.0" | bc -l)" = 1 && break
        sleep 5
    done
}

small_subnet_size=13
XL_subnet_size=55
small_subnet_finalization_threshold=0.9
large_subnet_finalization_threshold=0.3
XL_subnet_finalization_threshold=0.24
#return treshold value depending on size and index of subnet
function finalization_rate_threshold() {
    local subnet_id=$1
    local nns_url=$(jq_hostvars '[._meta.hostvars[.nns.hosts[0]]]' 'map(.api_listen_url)[0]')
    local num_nodes=$(ic-admin --nns-url "$nns_url" get-topology | jq -r ".topology.subnets | to_entries[$subnet_id].value.records[0].value.membership | length")
    if ((num_nodes > XL_subnet_size)); then
        threshold=$XL_subnet_finalization_threshold
    elif ((num_nodes > small_subnet_size)); then
        threshold=$large_subnet_finalization_threshold
    elif ((subnet_id == 0)); then
        threshold=$large_subnet_finalization_threshold
    else
        threshold=$small_subnet_finalization_threshold
    fi
    echo "$threshold"
}

emoji_red_mark='\342\235\214'
emoji_green_mark='\342\234\205'
emoji_tada='\360\237\216\211'
emoji_cry='\360\237\230\255'

# set the exit code to 1 in case of a failure, but don't exit just yet, other conditions might be
# checked which may carry useful information for debugging
failure() {
    printf "${emoji_red_mark} %s ${emoji_cry}${emoji_cry}${emoji_cry}\n" "$*"
    exit_code=1
}
# print success message but don't change exit code, as other parts of the script may have failed
success() {
    printf "${emoji_green_mark} %s ${emoji_tada}${emoji_tada}${emoji_tada}\n" "$*"
}

# Return the nth node from the subnet, as an ansible host so that we can e.g.
# `--limit $(jq_nth_subnet_node 1 3)`
# This is why we don't call `jq_hostvars "map` -- jq map swallows the keys
function jq_nth_subnet_node() {
    local subnet_number=$1
    local nth=$2
    jq_hostvars "with_entries(select(.value.subnet_index==$subnet_number)) | keys[$nth] "
}
# Split nodes list from the provided subnet_number into 3 groups, and return the nodes from Nth group
# This is used to split the subnet into 3 groups:
# 1. group (1/3 of the nodes) are the hosts that the workload generator will target
# 2. group (1/3 of the nodes) unused
# 3. group (1/3 of the nodes) are the ones being stress-tested (e.g. replica service stopped)
# If subnet has nodes:
# [ "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12" ]
# then _nwise(3) splits into chunks *of up to 3 entries each* (i.e does NOT split into 3 groups!):
# [ "1", "2", "3" ] [ "4", "5", "6" ] [ "7", "8", "9" ] [ "10", "11", "12" ]
# and then we take the first entry from each group, and join with commas, i.e.:
# echo '[ "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12" ]' | jq '[_nwise(3)[0]] | join(",")'
# "1,4,7,10"
function jq_subnet_nodes_nth_third() {
    local subnet_number=$1
    local which_third=$2
    jq_hostvars "with_entries(select(.value.subnet_index==$subnet_number)) | keys | [_nwise(3)[$which_third]] | join(\",\")"
}

function jq_subnet_nodes_urls_nth_third() {
    # same as jq_subnet_nodes_nth_third, only return comma separated listen URL addresses of the hosts, e.g.
    # http://[2a00:fb01:400:42:5000:5eff:fed1:30ec]:8080,http://[2a00:fb01:400:42:5000:98ff:feae:e4f3]:8080
    local subnet_number=$1
    local which_third=$2
    jq_hostvars "map(select(.subnet_index==$subnet_number) | .api_listen_url) | [_nwise(3)[$which_third]] | join(\",\")"
}

function jq_load_filtered_urls_for_metrics() {
    # return '|' separated load nodes from the requested subnet, filtering before and after as requested
    local prefilter=$1
    local postfilter=${2:-.}
    jq_hostvars "map(select($prefilter) | .metrics_listen_addr) | $postfilter | join(\"|\")" | escapebracket
}

function jq_subnet_load_urls_for_metrics() {
    # return '|' separated load nodes from the requested subnet, filtering after as requested
    jq_load_filtered_urls_for_metrics ".subnet_index==$1" "${2:-.}"
}

function jq_subnet_load_third_nodes_urls_for_metrics() {
    # return '|' separated load nodes from the requested subnet, after splitting the subnet to 3 groups.
    # the load nodes are the nodes in the 1st and 2nd third of the nodes.
    jq_subnet_load_urls_for_metrics $1 "[_nwise(3)[:2]] | flatten"
}

NUM_STEPS_MATCHED=0
function step() {
    # Runs a named step if the name matches the env var STEPS.
    # Optional steps are skipped unless STEPS matches the step name exactly.
    # Requirements:
    # - Make it clear which commands have a side-effect in the shell
    #   - Done by running side-effect free commands in a subshell () vs {}.
    # - Run just some commands

    STEPS_PATTERN="^(${STEPS:-.*})([.].*|$)"
    ENV_FILE="${results_dir}/env_vars"
    echo "ENV_FILE=$ENV_FILE"

    if [[ "$1" == "--optional" ]]; then
        local optional="1"
        shift 1
    else
        local optional=""
    fi
    STEP="$1"
    if [[ "$STEP" =~ $STEPS_PATTERN ]]; then
        ((NUM_STEPS_MATCHED++))
        test -n "${DRY_RUN:-}" || printf "\n\n"
        echo "#$(echo "$1" | tr -cd '.' | tr . '#')${optional:+ (Optional)} $*"
        test -e "$ENV_FILE" || touch "$ENV_FILE"
        # shellcheck disable=SC1090
        source "$ENV_FILE"
        # Nothing more to do if:
        #    this is a dry run
        # OR the step is optional and doesn't match the filter exactly.
        if test -n "${DRY_RUN:-}" || { test -n "${optional:-}" && [[ "$STEP" != "${STEPS:-}" ]]; }; then
            : Skipping step "$STEP"
        else
            echo "Start: $(date -u)"
            echo "$STEP	$(date -u)" >>"$results_dir/step_log"

            false
        fi
    else
        true
    fi
}

# Function to preserve vars to be used over multiple steps, so that they are still there if the shell is killed.
setvar() {
    printf 'export %s="%s"\n' "$1" "$2" >>"$ENV_FILE"
}

set_verbosity() {
    test -z "${VERBOSE:-}" || set -x
}

if [[ -n "${GITLAB_CI:-}" ]]; then
    echo "Set the trap for collecting the deployment logs on exit with error"
    trap 'if [[ $? -ne 0 ]]; then echo -e "\e[0Ksection_start:$(date +%s):error_trap[collapsed=true]\r\e[0KClick here to see details from the test error handler."; timeout 120 $REPO_ROOT/testnet/tools/icos_collect_debug_info.py --deployment-name=$testnet --out-dir=$experiment_dir/debug_info; echo "Destroying the testnet"; timeout 120 "$REPO_ROOT/testnet/tools/icos_destroy.sh" "$testnet"; echo -e "\e[0Ksection_end:$(date +%s):error_trap\r\e[0K"; fi' EXIT
fi

echo "Starting $(basename "$0") on testnet '$testnet'."

cd "$PROD_SRC"
