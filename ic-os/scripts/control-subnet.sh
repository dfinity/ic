#!/usr/bin/env bash

set -o errexit
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"
BASE_DIR="$(dirname "${BASH_SOURCE[0]}")/.."

TMP_DIR="$(mktemp -d)"

# Set argument defaults
CREATE=0

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        c | cr | cre | crea | creat | create)
            CREATE=1
            ;;
        d=* | de=* | des=* | dest=* | destr=* | destro=* | destroy=*)
            DESTROY="${argument#*=}"
            shift
            ;;
        sta=* | star=* | start=*)
            START="${argument#*=}"
            shift
            ;;
        sto=* | stop=*)
            STOP="${argument#*=}"
            shift
            ;;
        -h | --help)
            echo 'Usage:

   ____  _____ ___ _   _ ___ _______   __
  |  _ \|  ___|_ _| \ | |_ _|_   _\ \ / /
  | | | | |_   | ||  \| || |  | |  \ V /
  | |_| |  _|  | || |\  || |  | |   | |
  |____/|_|   |___|_| \_|___| |_|   |_|

    Internet Computer Operating System
        Control Subnet Deployment

Commands:
  create, cre           create node
  start=, sta=          start node   (Example: start=all|nns|app|"0,2,5,7,8")
  stop=, sto=           stop node    (Example: stop=all|nns|app|"0,2,5,7,8")
  destroy=, des=        destroy node (Example: destroy=all|nns|app|"0,2,5,7,8")

Arguments:
  -d=, --disk=          specify source of disk image (Default: ./build-out/disk.img)
  -h, --help            show this help message and exit
  -i=, --input=         JSON formatted input file (Default: ./subnet.json)
  -m=, --media=         specify source of removable media (Default: ./build-out/*.img)
  -x,  --debug          enable verbose console output
'
            exit 1
            ;;
        -i=* | --input=*)
            INPUT="${argument#*=}"
            shift
            ;;
        -x | --debug)
            DEBUG=1
            ;;
        *)
            echo 'Error: Argument is not supported.'
            exit 1
            ;;
    esac
done

# Set arguments if undefined
DISK="${DISK:=${BASE_DIR}/disk.img}"
INPUT="${INPUT:=${BASE_DIR}/subnet.json}"
DESTROY="${DESTROY:=none}"
START="${START:=none}"
STOP="${STOP:=none}"

# Load INPUT
CONFIG="$(cat ${INPUT})"

DEPLOYMENT=$(echo ${CONFIG} | jq -r -c '.deployment')
MEDIA="${MEDIA:=${BASE_DIR}/build-out/${DEPLOYMENT}-*.img}"

CORES=$(echo ${CONFIG} | jq -r -c '.resources.cores')
MEMORY_GB=$(echo ${CONFIG} | jq -r -c '.resources.memory_gb')
DISK_GB=$(echo ${CONFIG} | jq -r -c '.resources.disk_gb')
IPV4_BRIDGE=$(echo ${CONFIG} | jq -r -c '.resources.ipv4_bridge')

all_nodes() {
    # Query all nodes in subnet
    echo ${CONFIG} | jq -c '.datacenters[]' | while read datacenters; do
        echo ${datacenters} | jq -c '.hosts[]' | while read hosts; do
            echo ${hosts} | jq -c '.nodes[]' | while read nodes; do
                ALL_DC=$(echo ${nodes} | jq -r '.id' | while read node; do
                    echo "${node}"
                done)
                echo ${ALL_DC} >>"${TMP_DIR}/ALL"
            done
        done
    done
    ALL="$(cat ${TMP_DIR}/ALL)"
    rm -f "${TMP_DIR}/ALL)"
    echo "$(echo ${ALL[@]})"
}

nns_nodes() {
    # Query all NNS nodes in subnet
    echo ${CONFIG} | jq -c '.datacenters[]' | while read datacenters; do
        echo ${datacenters} | jq -c '.hosts[]' | while read hosts; do
            echo ${hosts} | jq -c '.nodes[]' | while read nodes; do
                NNS_DC=$(echo ${nodes} | jq -c 'select(.type|test("nns"))' | while read node; do
                    echo "$(echo ${node} | jq -r '.id')"
                done)
                echo "${NNS_DC}" >>"${TMP_DIR}/NNS"
            done
        done
    done
    NNS="$(cat ${TMP_DIR}/NNS)"
    rm -f "${TMP_DIR}/NNS)"
    echo "$(echo ${NNS[@]})"
}

app_nodes() {
    # Query all APP nodes in subnet
    echo ${CONFIG} | jq -c '.datacenters[]' | while read datacenters; do
        echo ${datacenters} | jq -c '.hosts[]' | while read hosts; do
            echo ${hosts} | jq -c '.nodes[]' | while read nodes; do
                APP_DC=$(echo ${nodes} | jq -c 'select(.type|test("app"))' | while read node; do
                    echo "$(echo ${node} | jq -r '.id')"
                done)
                echo "${APP_DC}" >>"${TMP_DIR}/APP"
            done
        done
    done
    APP="$(cat ${TMP_DIR}/APP)"
    rm -f "${TMP_DIR}/APP)"
    echo "$(echo ${APP[@]})"
}

custom_nodes() {
    nodes=${1}

    echo "$(echo ${nodes})"
}

get_host() {
    node=${1}

    echo ${CONFIG} | jq -c '.datacenters[]' | while read datacenters; do
        echo ${datacenters} | jq -c '.hosts[]' | while read hosts; do
            echo ${hosts} | jq -c "{host: .serial, id: .nodes[].id} | select(.id == \"${node}\")" | while read nodes; do
                echo ${nodes} | jq -r '.host'
            done
        done
    done
}

get_all_hosts() {
    echo ${CONFIG} | jq -c '.datacenters[]' | while read datacenters; do
        echo ${datacenters} | jq -c '.hosts[]' | while read hosts; do
            echo ${hosts} | jq -r '.serial'
        done
    done
}

validate_input() {
    input=${1}

    if [ "${input}" == "all" ]; then
        VALIDATED_INPUT="$(all_nodes)"
    elif [ "${input}" == "nns" ]; then
        VALIDATED_INPUT="$(nns_nodes)"
    elif [ "${input}" == "app" ]; then
        VALIDATED_INPUT="$(app_nodes)"
    else
        VALIDATED_INPUT="$(custom_nodes ${input})"
    fi
}

create_node() {
    for host in $(get_all_hosts); do
        rsync --archive --compress --verbose --rsh="ssh -o StrictHostKeyChecking=no" --rsync-path='sudo rsync' ${DISK} ${host}:/home/ic/
        rsync --archive --compress --verbose --rsh="ssh -o StrictHostKeyChecking=no" --rsync-path='sudo rsync' ${MEDIA} ${host}:/home/ic/
        ssh -o StrictHostKeyChecking=no -t ${host} "sudo -i -u ic sh -c \"export 'ANSIBLE_CONFIG=~/ansible/testnet.cfg' ; ansible-playbook ~/ansible/testnet.yml -e ic_deployment='testnet' --tags=ic_guest -e ic_cores=${CORES} -e ic_memory_gb=${MEMORY_GB} -e ic_disk_gb=${DISK_GB} -e ic_ipv4_bridge=${IPV4_BRIDGE} -e ic_state='create'\""
    done
}

destroy_node() {
    for node in ${VALIDATED_INPUT//,/ }; do
        ssh -o StrictHostKeyChecking=no -t $(get_host ${node}) "sudo -i sh -c \"virsh destroy ${DEPLOYMENT}-$(get_host ${node})-${node} ; true\""
        ssh -o StrictHostKeyChecking=no -t $(get_host ${node}) "sudo -i sh -c \"virsh undefine ${DEPLOYMENT}-$(get_host ${node})-${node} --nvram ; true\""
        ssh -o StrictHostKeyChecking=no -t $(get_host ${node}) "sudo -i sh -c \"virsh vol-delete /var/lib/libvirt/images/${DEPLOYMENT}-$(get_host ${node})-${node}.img\" ; true"
        ssh -o StrictHostKeyChecking=no -t $(get_host ${node}) "sudo -i sh -c \"rm -f /var/lib/libvirt/media/${DEPLOYMENT}-$(get_host ${node})-${node}.img\""
    done
}

start_node() {
    for node in ${VALIDATED_INPUT//,/ }; do
        ssh -o StrictHostKeyChecking=no -t $(get_host ${node}) "sudo -i sh -c \"virsh start ${DEPLOYMENT}-$(get_host ${node})-${node} ; true\""
    done
}

stop_node() {
    for node in ${VALIDATED_INPUT//,/ }; do
        ssh -o StrictHostKeyChecking=no -t $(get_host ${node}) "sudo -i sh -c \"virsh destroy ${DEPLOYMENT}-$(get_host ${node})-${node} ; true\""
    done
}

function remove_temporary_directory() {
    rm -rf ${TMP_DIR}
}

# See how we were called
if [ "${DESTROY}" != "none" ]; then
    validate_input "${DESTROY}"
    destroy_node "${VALIDATED_INPUT}"
    remove_temporary_directory
elif [ "${START}" != "none" ]; then
    validate_input "${START}"
    start_node "${VALIDATED_INPUT}"
    remove_temporary_directory
elif [ "${STOP}" != "none" ]; then
    validate_input "${STOP}"
    stop_node "${VALIDATED_INPUT}"
    remove_temporary_directory
elif [ "${CREATE}" -eq 1 ]; then
    validate_input "${CREATE}"
    create_node "${VALIDATED_INPUT}"
    remove_temporary_directory
else
    echo 'Please specify at least one node. Example:
  command=all|nns|app|"0,2,6,7,8"'
fi
