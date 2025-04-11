#!/bin/bash

set -e

# Generate the GuestOS configuration.

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh
source /opt/ic/bin/config.sh

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -h | --help)
            echo 'Usage:
Generate GuestOS Configuration

Arguments:
  -h, --help            show this help message and exit
  -i=, --input=         specify the input template file (Default: /opt/ic/share/guestos.xml.template)
  -m=, --media=         specify the config media image file (Default: /run/ic-node/config.img)
  -o=, --output=        specify the output configuration file (Default: /var/lib/libvirt/guestos.xml)
'
            exit 1
            ;;
        -i=* | --input=*)
            INPUT="${argument#*=}"
            shift
            ;;
        -m=* | --media=*)
            MEDIA="${argument#*=}"
            shift
            ;;
        -o=* | --output=*)
            OUTPUT="${argument#*=}"
            shift
            ;;
        *)
            echo "Error: Argument is not supported."
            exit 1
            ;;
    esac
done

function validate_arguments() {
    if [ "${INPUT}" == "" -o "${OUTPUT}" == "" ]; then
        $0 --help
    fi
}

# Set arguments if undefined
INPUT="${INPUT:=/opt/ic/share/guestos.xml.template}"
MEDIA="${MEDIA:=/run/ic-node/config.img}"
OUTPUT="${OUTPUT:=/var/lib/libvirt/guestos.xml}"

function read_config_variables() {
    ipv6_gateway=$(get_config_value '.network_settings.ipv6_config.Deterministic.gateway')
    ipv4_address=$(get_config_value '.network_settings.ipv4_config.address')
    ipv4_prefix_length=$(get_config_value '.network_settings.ipv4_config.prefix_length')
    ipv4_gateway=$(get_config_value '.network_settings.ipv4_config.gateway')
    domain_name=$(get_config_value '.network_settings.domain_name')
    node_reward_type=$(get_config_value '.icos_settings.node_reward_type')
    nns_urls=$(get_config_value '.icos_settings.nns_urls | join(",")')
    mgmt_mac=$(get_config_value '.icos_settings.mgmt_mac')

    use_nns_public_key=$(get_config_value '.icos_settings.use_nns_public_key')
    use_node_operator_private_key=$(get_config_value '.icos_settings.use_node_operator_private_key')

    vm_memory=$(get_config_value '.hostos_settings.vm_memory')
    vm_cpu=$(get_config_value '.hostos_settings.vm_cpu')
    vm_nr_of_vcpus=$(get_config_value '.hostos_settings.vm_nr_of_vcpus')

}

function assemble_config_media() {
    ipv6_address="$(/opt/ic/bin/hostos_tool generate-ipv6-address --node-type GuestOS)"
    /opt/ic/bin/config generate-guestos-config --guestos-ipv6-address "$ipv6_address"

    cmd=(/opt/ic/bin/build-bootstrap-config-image.sh ${MEDIA})
    cmd+=(--guestos_config "/boot/config/config-guestos.json")
    if [[ "${use_nns_public_key,,}" == "true" ]]; then
        cmd+=(--nns_public_key "/boot/config/nns_public_key.pem")
    fi
    if [[ "${use_node_operator_private_key,,}" == "true" ]]; then
        cmd+=(--node_operator_private_key "/boot/config/node_operator_private_key.pem")
    fi
    cmd+=(--ipv6_address "$(/opt/ic/bin/hostos_tool generate-ipv6-address --node-type GuestOS)")
    cmd+=(--ipv6_gateway "${ipv6_gateway}")
    if [[ -n "$ipv4_address" && -n "$ipv4_prefix_length" && -n "$ipv4_gateway" ]]; then
        cmd+=(--ipv4_address "${ipv4_address}/${ipv4_prefix_length}")
        cmd+=(--ipv4_gateway "${ipv4_gateway}")
    fi
    if [[ -n "$domain_name" ]]; then
        cmd+=(--domain "${domain_name}")
    fi
    if [[ -n "$node_reward_type" ]]; then
        cmd+=(--node_reward_type "${node_reward_type}")
    fi
    cmd+=(--hostname "guest-${mgmt_mac//:/}")
    cmd+=(--nns_urls "${nns_urls}")

    # Run the above command
    "${cmd[@]}"
    write_log "Assembling config media for GuestOS: ${MEDIA}"
}

function generate_guestos_config() {
    MAC_ADDRESS=$(/opt/ic/bin/hostos_tool generate-mac-address --node-type GuestOS)

    # Generate inline CPU spec based on mode
    CPU_SPEC=$(mktemp)
    if [ "${vm_cpu}" == "qemu" ]; then
        CPU_DOMAIN="qemu"
        cat >"${CPU_SPEC}" <<EOF
<cpu mode='host-model'/>
EOF
    else
        CPU_DOMAIN="kvm"
        CORE_COUNT=$((vm_nr_of_vcpus / 4))
        cat >"${CPU_SPEC}" <<EOF
<cpu mode='host-passthrough' migratable='off'>
  <cache mode='passthrough'/>
  <topology sockets='2' cores='${CORE_COUNT}' threads='2'/>
  <feature policy="require" name="topoext"/>
</cpu>
EOF
    fi

    if [ ! -f "${OUTPUT}" ]; then
        mkdir -p "$(dirname "$OUTPUT")"
        sed -e "s@{{ resources_memory }}@${vm_memory}@" \
            -e "s@{{ nr_of_vcpus }}@${vm_nr_of_vcpus:-64}@" \
            -e "s@{{ mac_address }}@${MAC_ADDRESS}@" \
            -e "s@{{ cpu_domain }}@${CPU_DOMAIN}@" \
            -e "/{{ cpu_spec }}/{r ${CPU_SPEC}" -e "d" -e "}" \
            "${INPUT}" >"${OUTPUT}"
        restorecon -R "$(dirname "$OUTPUT")"
        write_log "Generating GuestOS configuration file: ${OUTPUT}"
        write_metric "hostos_generate_guestos_config" \
            "1" \
            "HostOS generate GuestOS config" \
            "gauge"
    else
        write_log "GuestOS configuration file already exists: ${OUTPUT}"
        write_metric "hostos_generate_guestos_config" \
            "0" \
            "HostOS generate GuestOS config" \
            "gauge"
    fi

    rm -f "${CPU_SPEC}"
}

function main() {
    validate_arguments
    read_config_variables
    assemble_config_media
    generate_guestos_config
}

main
