repo_root() {
    git rev-parse --show-toplevel
}

LIGHT_GRAY_TEXT='\033[0;37m'
RED_TEXT='\033[0;31m'
GREEN_TEXT='\033[0;32m'
YELLOW_TEXT='\033[0;33m'
BLUE_TEXT='\033[0;34m'
PURPLE_TEXT='\033[0;35m'
CYAN_TEXT='\033[0;36m'
NO_COLOR='\033[0m'

print_light_gray() {
    echo -e "${LIGHT_GRAY_TEXT}$*${NO_COLOR}"
}

print_red() {
    echo -e "${RED_TEXT}$*${NO_COLOR}" 1>&2
}

print_green() {
    echo -e "${GREEN_TEXT}$*${NO_COLOR}"
}

print_yellow() {
    echo -e "${YELLOW_TEXT}$*${NO_COLOR}" 1>&2
}

print_blue() {
    echo -e "${BLUE_TEXT}$*${NO_COLOR}"
}

print_purple() {
    echo -e "${PURPLE_TEXT}$*${NO_COLOR}"
}

print_cyan() {
    echo -e "${CYAN_TEXT}$*${NO_COLOR}"
}

info() {
    print_green "***** $*"
}

log() {
    echo "   $*"
}

log_stderr() {
    echo "   $*" >&2
}

debug_log() {
    if [ ! -z ${DEBUG_BASH+x} ]; then
        log_stderr "$*"
    fi
}

error() {
    print_red "ERROR: $1"
    exit 1
}

# Works from inside/outside of the repo to return the root of this repository
repo_root() {
    local SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
    # Execute in subshell to not change directory of caller
    (cd "$SCRIPT_DIR" && git rev-parse --show-toplevel)
}

STEPS_PATTERN="^(${STEPS:-.*})([.].*|$)"
NUM_STEPS_MATCHED=0
step() {
    # Runs a named step if the name matches the env var STEPS.
    # Optional steps are skipped unless STEPS matches the step name exactly.
    if [[ "$1" == "--optional" ]]; then
        local optional="1"
        shift 1
    else
        local optional=""
    fi
    STEP="$1"
    shift 1
    if [[ "$STEP" =~ $STEPS_PATTERN ]]; then
        ((NUM_STEPS_MATCHED++))
        test -n "${DRY_RUN:-}" || printf "\n\n"
        print_blue "--------------- $(echo "$1" | tr -cd '.' | tr . '#')${optional:+ (Optional)} $STEP. $*"
        # test -e "$ENV_FILE" || touch "$ENV_FILE"
        # shellcheck disable=SC1090
        # source "$ENV_FILE"
        # Nothing more to do if:
        #    this is a dry run
        # OR the step is optional and doesn't match the filter exactly.
        if test -n "${DRY_RUN:-}" || { test -n "${optional:-}" && [[ "$STEP" != "${STEPS:-}" ]]; }; then
            echo "Skipping step $STEP"
        else
            echo "Step $STEP start: $(date -u --rfc-3339=seconds)"
            false
        fi
    else
        true
    fi
}

move_node_to_new_nns() {
    local NNS_NODE_IP=$1
    local UNASSIGNED_NODE_IP=$2

    local SSH_ARGS="-A -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
    # Stop the unassigned node
    ssh $SSH_ARGS "admin@$UNASSIGNED_NODE_IP" "sudo systemctl stop ic-replica"
    LOCAL_TMP=$(mktemp -d /tmp/ic_registry_local_store.XXXX)

    # Replace the local store on the node
    while ! rsync -r -e "ssh $SSH_ARGS" "admin@[$NNS_NODE_IP]:/var/lib/ic/data/ic_registry_local_store" "$LOCAL_TMP/"; do
        echo "rsync failed with status code $?"
        sleep 1
    done
    while ! rsync -r -e "ssh $SSH_ARGS" --rsync-path="sudo rsync" "$LOCAL_TMP/ic_registry_local_store" "admin@[$UNASSIGNED_NODE_IP]:/var/lib/ic/data/"; do
        echo "rsync failed with status code $?"
        sleep 1
    done

    # Fix permissions
    ssh $SSH_ARGS "admin@$UNASSIGNED_NODE_IP" "sudo chown -R ic-replica:ic-registry-local-store /var/lib/ic/data/ic_registry_local_store"

    # Start the unassigned node
    ssh $SSH_ARGS "admin@$UNASSIGNED_NODE_IP" "sudo systemctl start ic-replica"
}

install_binary() {
    local DOWNLOAD_NAME=$1
    local GIT_HASH=$2
    local DEST_FOLDER=$3

    log "Downloading $DOWNLOAD_NAME..."

    local DEST=$DEST_FOLDER/$DOWNLOAD_NAME

    PLATFORM=$(uname | tr '[[:upper:]]' '[[:lower:]]')
    local TEMP_GZ=$(mktemp)
    curl "https://download.dfinity.systems/ic/${GIT_HASH}/binaries/x86_64-${PLATFORM}/${DOWNLOAD_NAME}.gz" -o "$TEMP_GZ"
    gunzip -c "$TEMP_GZ" >"$DEST"
    rm "$TEMP_GZ"

    chmod +x "$DEST"
}
