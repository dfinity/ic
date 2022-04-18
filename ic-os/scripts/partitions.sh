# Tools for dealing with the partition table (defined in partitions.csv)
# and disk image building.
#
# NOTE: When sourcing, be sure to specify CSV dir, or "", otherwise, arguments
# to the parent script will be passed.
#
# Arguments:
#   $1: The folder containing layout CSVs.

if [ "$1" != "" ]; then
    CSV_DIR="$1"
else
    BASE_DIR=$(dirname "${BASH_SOURCE[0]}")/..
    CSV_DIR="${BASE_DIR}"/build
fi

function prepare_disk_image() {
    local DISK_IMAGE="$1"
    local IMAGE_SIZE_BYTES="$2"

    truncate --size 0 "$DISK_IMAGE"
    truncate --size "$IMAGE_SIZE_BYTES" "$DISK_IMAGE"

    generate_sfdisk_script | sfdisk "$DISK_IMAGE"
}

# Clear any existing LVM mounts.
function clear_lvm_mounts() {
    local OPEN_LVM=$(losetup -O BACK-FILE,NAME | grep lvm.img | tr -s ' ' | cut -d ' ' -f 2)
    for LOOP in $OPEN_LVM; do
        losetup -d $LOOP
    done
}

# Prepare an LVM PV with LVs set up as specified.
#
# Arguments:
#   $1: The file where to generate the LVM PV in.
#   $2: The size of the target file.
#   $3: The name of the VG to create.
#   $4: The UUID of the desired VG.
#   $5: The UUID of the desired PV.
function prepare_lvm_image() {
    local DISK_IMAGE="$1"
    local IMAGE_SIZE_BYTES="$2"
    local VOLUME_GROUP="$3"
    local VG_UUID="$4"
    local PV_UUID="$5"

    truncate --size 0 "$DISK_IMAGE"
    truncate --size "$IMAGE_SIZE_BYTES" "$DISK_IMAGE"

    LOOP_NAME=$(losetup -P -f --show "$DISK_IMAGE")
    trap "losetup -d $LOOP_NAME" EXIT

    pvcreate -f "$LOOP_NAME" -u "$PV_UUID" --norestorefile

    create_lvm_volumes "$VOLUME_GROUP" "$VG_UUID" "$PV_UUID" "$IMAGE_SIZE_BYTES"
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

# Write a single partition image into a specific volume of the
# lvm vg.
#
# Arguments:
#   $1: The disk image to be read from.
#   $2: The volume group to be read from.
#   $3: The name of the volume that should be read.
#   $4: The file to which the volume contents should be.
function write_single_lvm_volume() {
    local DISK_IMAGE="$1"
    local VOLUME_GROUP="$2"
    local PART_NAME="$3"
    local PART_IMAGE="$4"

    local FILE_SIZE=$(stat -c "%s" "$PART_IMAGE")

    local PART_SIZE=${VOLUME_SIZE_BY_NAME["$PART_NAME"]}
    local PART_SIZE_BYTES=$(("$PART_SIZE" * 4194304))

    local PART_OFFSET=$((${PARTITION_START_BY_NAME["$VOLUME_GROUP"]} * 512))
    local LVM_OFFSET=$((2048 * 512))
    local VOLUME_OFFSET=$((${VOLUME_START_BY_NAME["$PART_NAME"]} * 4194304))

    local OFFSET=$((${PART_OFFSET} + ${LVM_OFFSET} + ${VOLUME_OFFSET}))
    local OFFSET_BLOCKS=$((${OFFSET} / 4096))

    if [ "$FILE_SIZE" -gt "$PART_SIZE_BYTES" ]; then exit 1; fi

    dd if="$PART_IMAGE" of="$DISK_IMAGE" bs=4096 seek="$OFFSET_BLOCKS" conv=sparse,notrunc
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

    local PART_START=$((${PARTITION_START_BY_NAME["$PART_NAME"]} / 8))
    local PART_SIZE=$((${PARTITION_SIZE_BY_NAME["$PART_NAME"]} / 8))

    dd if="$DISK_IMAGE" of="$PART_IMAGE" bs=4096 skip="$PART_START" count="$PART_SIZE" conv=sparse
}

# Extracts a single volume from a disk image to a file.
#
# Arguments:
#   $1: The disk image to be read from.
#   $2: The volume group to be read from.
#   $3: The name of the volume that should be read.
#   $4: The file to which the volume contents should be.
function extract_single_volume() {
    local DISK_IMAGE="$1"
    local VOLUME_GROUP="$2"
    local PART_NAME="$3"
    local PART_IMAGE="$4"

    local PART_SIZE=$((${VOLUME_SIZE_BY_NAME["$PART_NAME"]} * 1024))

    local PART_OFFSET=$((${PARTITION_START_BY_NAME["$VOLUME_GROUP"]} * 512))
    local LVM_OFFSET=$((2048 * 512))
    local VOLUME_OFFSET=$((${VOLUME_START_BY_NAME["$PART_NAME"]} * 4194304))

    local OFFSET=$((${PART_OFFSET} + ${LVM_OFFSET} + ${VOLUME_OFFSET}))
    local OFFSET_BLOCKS=$((${OFFSET} / 4096))

    dd if="$DISK_IMAGE" of="$PART_IMAGE" bs=4096 skip="$OFFSET_BLOCKS" count="$PART_SIZE" conv=sparse
}

# All of the below are helper functions -- should not be used directly.

# Read partitions.csv in "canonical form" (i.e. remove all comments,
# strip whitespace from fields).
# Internal utility function.
function read_canonical_partitions_csv() {
    sed -e '/^#/d' -e 's/ *, */,/g' <"${CSV_DIR}"/partitions.csv
}

# Read volumes.csv in "canonical form" (i.e. remove all comments,
# strip whitespace from fields).
# Internal utility function.
function read_canonical_volumes_csv() {
    sed -e '/^#/d' -e 's/ *, */,/g' <"${CSV_DIR}"/volumes.csv
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

# Build out LVM volumes for each partition defined in partitions CSV
function create_lvm_volumes() {
    local VOLUME_GROUP="$1"
    local VG_UUID="$2"
    local PV_UUID="$3"
    local SIZE="$4"

    local DEV_SIZE=$(("$SIZE" / 512))
    local PE_COUNT=$((("$DEV_SIZE" / 8192) - 1))

    local out=backup

    # Create the header
    cat >>$out <<EOF
contents = "Text Format Volume Group"
version = 1

$VOLUME_GROUP {
	id = "$VG_UUID"
	seqno = 1
	format = "lvm2"			# informational
	status = ["RESIZEABLE", "READ", "WRITE"]
	flags = []
	extent_size = 8192		# 4 Megabytes
	max_lv = 0
	max_pv = 0
	metadata_copies = 0
EOF

    # Add section for PVs
    cat >>$out <<EOF
	physical_volumes {
		pv0 {
			id = "$PV_UUID"

			status = ["ALLOCATABLE"]
			flags = []
			dev_size = $DEV_SIZE
			pe_start = 2048
			pe_count = $PE_COUNT
		}
	}
EOF

    # Add section for LVs
    #
    # ----------
    # Example:
    # ----------
    # logical_volumes {
    #   esp {
    #     id = "qxkWcA-0XF7-scev-KJ2F-T4hY-c9xH-6tuqZ7"
    #     status = ["READ", "WRITE", "VISIBLE"]
    #     flags = []
    #     creation_time = 1620345600
    #     creation_host = "builder"
    #     segment_count = 1
    #
    #     segment1 {
    #       start_extent = 0
    #       extent_count = 25
    #
    #       type = "striped"
    #       stripe_count = 1        # linear
    #
    #       stripes = [
    #         "pv0", 0
    #       ]
    #     }
    #   }
    # }
    cat >>$out <<EOF
	logical_volumes {
EOF
    read_canonical_volumes_csv \
        | while IFS=, read -r name start size uuid comment; do
            cat >>$out <<EOF
		$name {
			id = "$uuid"
			status = ["READ", "WRITE", "VISIBLE"]
			flags = []
			creation_time = 1620345600
			creation_host = "builder"
			segment_count = 1

			segment1 {
				start_extent = 0
				extent_count = $size

				type = "striped"
				stripe_count = 1	# linear

				stripes = [
					"pv0", $start
				]
			}
		}
EOF
        done
    cat >>$out <<EOF
	}
EOF

    # Close out the main structure
    cat >>$out <<EOF
}
EOF

    faketime "2021-5-7 0" vgcfgrestore -f $out "$VOLUME_GROUP"
    rm $out

    vgscan --mknodes
}

function read_partition_sizes_by_name() {
    read_canonical_partitions_csv \
        | while IFS=, read -r name start size type uuid comment; do
            echo "[$name]=$size"
        done
}

function read_volume_sizes_by_name() {
    read_canonical_volumes_csv \
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

function read_volume_starts_by_name() {
    read_canonical_volumes_csv \
        | while IFS=, read -r name start size type uuid comment; do
            echo "[$name]=$start"
        done
}

eval "declare -A PARTITION_SIZE_BY_NAME=( $(read_partition_sizes_by_name) )"
eval "declare -A VOLUME_SIZE_BY_NAME=( $(read_volume_sizes_by_name) )"
eval "declare -A PARTITION_START_BY_NAME=( $(read_partition_starts_by_name) )"
eval "declare -A VOLUME_START_BY_NAME=( $(read_volume_starts_by_name) )"
