# Tools for dealing with the partition table (defined in partitions.csv)
# and disk image building.

# Prepare properly sized disk image with partitions set up as specified.
#
# Arguments:
#   $1: The file where to generate the disk image in.
function prepare_disk_image() {
    local DISK_IMAGE="$1"
    truncate --size 0 "$DISK_IMAGE"
    truncate --size 43310M "$DISK_IMAGE"
    generate_sfdisk_script | sfdisk "$DISK_IMAGE"
}

# Write a single partition image into a specific partition of the
# disk image.
#
# Arguments:
#   $1: The disk image to write into.
#   $2: The name of the partition that should be written.
#   $3: The file with the contents of the partition to be written.
function write_single_partition() {
    local DISK_IMAGE="$1"
    local PART_NAME="$2"
    local PART_IMAGE="$3"

    local FILE_SIZE=$(stat -c "%s" "$PART_IMAGE")

    local PART_START=${PARTITION_START_BY_NAME["$PART_NAME"]}
    local PART_SIZE=${PARTITION_SIZE_BY_NAME["$PART_NAME"]}
    local PART_SIZE_BYTES=$(("$PART_SIZE" * 512))

    if [ "$FILE_SIZE" -gt "$PART_SIZE_BYTES" ]; then exit 1; fi

    dd if="$PART_IMAGE" of="$DISK_IMAGE" bs=512 seek="$PART_START" conv=sparse,notrunc
}

# Extracts a single partition image from a disk image to a file.
#
# Arguments:
#   $1: The disk image to be read from.
#   $2: The name of the partition that should be read.
#   $3: The file to which the partition contents should be.
function extract_single_partition() {
    local DISK_IMAGE="$1"
    local PART_NAME="$2"
    local PART_IMAGE="$3"

    local FILE_SIZE=$(stat -c "%s" "$PART_IMAGE")

    local PART_START=$((${PARTITION_START_BY_NAME["$PART_NAME"]} / 8))
    local PART_SIZE=$((${PARTITION_SIZE_BY_NAME["$PART_NAME"]} / 8))

    dd if="$DISK_IMAGE" of="$PART_IMAGE" bs=4096 skip="$PART_START" count="$PART_SIZE" conv=sparse
}

# All of the below are helper functions -- should not be used directly.

# Read partitions.csv in "canonical form" (i.e. remove all comments,
# strip whitespace from fields).
# Internal utility function.
function read_canonical_partitions_csv() {
    local BASE_DIR=$(dirname "${BASH_SOURCE[0]}")
    sed -e '/^#/d' -e 's/ *, */,/g' <"${BASE_DIR}"/partitions.csv
}

# Produce an sfdisk script as output to set up the partition table
function generate_sfdisk_script() {
    echo "label: gpt"
    echo "label-id: 2B110BB7-CDEC-7D41-B97E-893EDCBE5428"
    read_canonical_partitions_csv \
        | while IFS=, read -r name start size type uuid comment; do
            if [ "$type" == "L" ]; then
                type=0FC63DAF-8483-4772-8E79-3D69D8477DE4
            elif [ "$type" == "U" ]; then
                type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
            fi
            echo start=$start,size=$size,type=$type,uuid=$uuid
        done
}

function read_partition_sizes_by_name() {
    read_canonical_partitions_csv \
        | while IFS=, read -r name start size type uuid comment; do
            echo "[$name]=$size"
        done
}

function read_partition_starts_by_name() {
    read_canonical_partitions_csv \
        | while IFS=, read -r name start size type uuid comment; do
            echo "[$name]=$start"
        done
}

eval "declare -A PARTITION_SIZE_BY_NAME=( $(read_partition_sizes_by_name) )"
eval "declare -A PARTITION_START_BY_NAME=( $(read_partition_starts_by_name) )"
