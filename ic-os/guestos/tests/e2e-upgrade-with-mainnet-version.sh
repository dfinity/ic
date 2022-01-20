#!/usr/bin/env bash
#
# Runs a Guest OS upgrade from base version to new version
#
: <<'DOC'
tag::catalog[]

Title:: GuestOS upgrade test

Parameters::
. ci_project_dir - the directory of the IC repository being checked out at.
. subnet - the subnet to perform mainnet version query, and to perform upgrade operation. Possible values: "nns", "app".
. downgrade - whether this is a downgrade from remote version to local new version. Possible values: true, false.
. request_type - the request type to be used in the workload generator. Possible values: "update", "query".

Success::
. Testnet upgraded successfully and performs healthy after the upgrade.

end::catalog[]
DOC

if (($# < 4)); then
    echo >&2 "Usage: guest-os-e2e-upgrade.sh <ci_project_dir> <subnet> <downgrade> <request_type>\n
    Example #1: guest-os-e2e-upgrade.sh \"/builds/git/JgGsR4vA/4/dfinity-lab/public/ic\" nns false query
    Example #2: guest-ose-e2e-upgrade.sh \"/builds/git/JgGsR4vA/4/dfinity-lab/public/ic\" app true update"
    exit 1
fi

ci_project_dir="$1"
subnet="$2"
downgrade="$3"
request_type="$4"

# Make sure the host has mounted necessary devices into the docker container.
# And check dependencies.
ls -lah /dev/kvm /dev/net/tun "${ci_project_dir}/artifacts/release" "${ci_project_dir}/ic-os/guestos/build-out"/{disk-img,update-img}

mkdir -p gitlab-runner-tmp
cd gitlab-runner-tmp

ls "${ci_project_dir}/artifacts/canisters"
for canister in "${ci_project_dir}"/artifacts/canisters/*.gz; do
    gzip -d "${canister}"
done
ls "${ci_project_dir}/artifacts/canisters"

for f in ic-prep ic-admin ic-nns-init ic-workload-generator; do
    gzip -d "${ci_project_dir}/artifacts/release/$f.gz"
    chmod u+x "${ci_project_dir}/artifacts/release/$f"
    ln -sf "${ci_project_dir}/artifacts/release/$f" "$f"
done

if [[ $downgrade = "true" ]]; then
    local_image_name="disk-img"
    remote_image_name="update-img"
else
    local_image_name="update-img"
    remote_image_name="disk-img"
fi

# Find replica revision of the subnet from mainnet
mainnet_nns="https://ic0.app/"
nns_subnet_id="tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
if [[ $subnet == "app" ]]; then
    # Find oldest app subnet revision
    max_distance=-1
    revision=""
    subnets=$(
        "$(pwd)"/ic-admin --nns-url "$mainnet_nns" get-subnet-list | jq -r '.[]'
    )
    for sn in $subnets; do
        if [[ $sn == $nns_subnet_id ]]; then
            # Skip NNS subnet when retrieving oldest revision from app subnets
            continue
        fi
        sn_revision=$("$(pwd)"/ic-admin --nns-url "$mainnet_nns" get-subnet "$sn" | jq '.records[0].value.replica_version_id' | xargs)
        depth=$(($(git rev-list --count "$sn_revision"..HEAD) - 1))

        if ((depth > max_depth)); then
            max_depth=$depth
            revision=$sn_revision
        fi
    done
    echo "Mainnet subnet $sn has oldest revision $revision with depth of $depth."
else
    # Find oldest NNS subnet revision
    revision=$("$(pwd)"/ic-admin --nns-url "$mainnet_nns" get-subnet $nns_subnet_id | jq '.records[0].value.replica_version_id' | xargs)
    echo "NNS subnet on mainnet has revision $revision"
fi

# Download Guest OS images matching mainnet revision
mkdir -p guestos-$subnet-subnet
"${ci_project_dir}"/gitlab-ci/src/artifacts/rclone_download.py --git-rev="$revision" --remote-path=guest-os --out="guestos-$subnet-subnet" --latest-to

ls "guestos-$subnet-subnet"
(
    cd "guestos-$subnet-subnet"
    # temporary workaround until disk-img.tar.gz is always in disk-img/ on subnet
    if [[ -r "$remote_image_name.tar.gz" ]]; then
        mkdir -p "$remote_image_name"
        mv "$remote_image_name.tar.gz" "$remote_image_name"/
    fi
    echo "Extracting $(pwd)/$remote_image_name/$remote_image_name.tar.gz"
    tar --sparse -xvf "$remote_image_name/$remote_image_name.tar.gz"
) # generates disk.img
ls -R "guestos-$subnet-subnet"

# Get tools and NNS canisters of mainnet subnet
mkdir -p "artifacts-$subnet-subnet"
mkdir -p "canisters-$subnet-subnet"
"${ci_project_dir}"/gitlab-ci/src/artifacts/rclone_download.py --git-rev="$revision" --remote-path=release --out="artifacts-$subnet-subnet" --latest-to
"${ci_project_dir}"/gitlab-ci/src/artifacts/rclone_download.py --git-rev="$revision" --remote-path=canisters --out="canisters-$subnet-subnet" --latest-to

(
    cd "artifacts-$subnet-subnet"
    for f in *.gz; do gunzip "$f"; done
    chmod u+x ./*
)
(
    cd "canisters-$subnet-subnet"
    for f in *.gz; do gunzip "$f"; done
)
ls -R "artifacts-$subnet-subnet"
ls -R "canisters-$subnet-subnet"

ls "${ci_project_dir}/ic-os/guestos/build-out"/{disk-img,update-img}
stat "${ci_project_dir}/ic-os/guestos/build-out/$local_image_name/$local_image_name.tar.gz"
tar --sparse -xvf "${ci_project_dir}/ic-os/guestos/build-out/$local_image_name/$local_image_name.tar.gz"

ls -lah

# Prepare network. There are more convenient ways to do it if requisite
# services are set up (which they aren't in a simple docker runner),
# but probably also helpful for debugging to have this "explicit" for now.

sudo ip link del ipv6_ic_node0 || true
sudo ip link del ipv6_ic_node1 || true
sudo ip link del ipv6_ic || true

sudo ip tuntap add ipv6_ic_node0 mode tap user ubuntu
sudo ip link set dev ipv6_ic_node0 up

sudo ip tuntap add ipv6_ic_node1 mode tap user ubuntu
sudo ip link set dev ipv6_ic_node1 up

sudo ip link add name ipv6_ic type bridge
sudo ip link set ipv6_ic_node0 master ipv6_ic
sudo ip link set ipv6_ic_node1 master ipv6_ic
sudo ip link set dev ipv6_ic up

sudo ip addr add fd00:2:1:1:1::1/64 dev ipv6_ic

# Output what image we are using:
if [[ $downgrade == "true" ]]; then
    GUESTOS_IMG="$(pwd)/disk.img"
    UPGRADE_IMG="$(pwd)/guestos-$subnet-subnet/update-img/update-img.tar.gz"
    UPGRADE_IMG_TAG=""
    direction="to"
    out_dir="e2e-downgrade-from-new-version-to-mainnet-$subnet-subnet"
else
    GUESTOS_IMG="$(pwd)/guestos-$subnet-subnet/disk.img"
    UPGRADE_IMG="${ci_project_dir}/ic-os/guestos/build-out/update-img/update-img.tar.gz"
    UPGRADE_IMG_TAG="$(openssl sha256 ${UPGRADE_IMG})" # For capsule to influence its input hash.
    direction="from"
    out_dir="e2e-upgrade-from-mainnet-$subnet-subnet-to-new-version"
fi
echo "Initial GuestOS image: ${GUESTOS_IMG}"
echo "Upgrade GuestOS image: ${UPGRADE_IMG}"

mkdir -p "${ci_project_dir}/ic-os/guestos/test-out/$out_dir"

if [[ $subnet == "nns" ]]; then
    upgrade_script="e2e-upgrade.py"
else
    upgrade_script="e2e-upgrade-appnet.py"
fi

# Actual test script, sets up VMs and drives the test.
capsule -v -i "../ic-os/guestos/tests/*.py" -i "**/*" -t "${UPGRADE_IMG_TAG}" -- \
    "${ci_project_dir}/ic-os/guestos/tests/${upgrade_script}" \
    --vmtoolscfg=internal \
    --disk_image "${GUESTOS_IMG}" \
    --ic_prep_bin "$(pwd)/ic-prep" \
    --install_nns_bin "$(pwd)/ic-nns-init" \
    --upgrade_tar "${UPGRADE_IMG}" \
    --ic_admin_bin "$(pwd)/ic-admin" \
    --nns_canisters "${ci_project_dir}/artifacts/canisters/" \
    --log_directory "${ci_project_dir}/ic-os/guestos/test-out/$out_dir" \
    --timeout "$E2E_TEST_TIMEOUT" \
    --ic_workload_generator_bin "$(pwd)/ic-workload-generator" \
    --is_upgrade_test \
    --request_type "${request_type}"
