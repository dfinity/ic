Adding new CI tests
----------

In order to add a new guest OS CI tests, do the following.

 1. Create a copy of an existing test, pick the one closes to your need:
    - `e2e_upgrade.py` boots a guest OS instance and upgrades it
    - `e2e_workload.py` boots a guest OS intance and runs the workload generator against it

 2. Register your test to gitlab CI. Add a new section to
    `gitlab-ci/config/47--guest-os-test--guest-os-e2e-test.yml`. Don't be shy to
    simply copy paste for now, we will clean up later. Be sure to rename the test to create
    a distinct pipeline step on CI (e.g. copy section `e2e-workload-test` and rename
    to `e2e-foobar-test`)

 3. Create a PR and ensure that your new test is running. It should be listed under Downstream >
    child pipeline.


Interactive testing
----------

You can also run your test manually. For that, you need to have a machine with qemu and kvm
set up. One such machine is `zh1-spm34.zh1.dfinity.network`. Be sure to ask Saša to put you in
the `kvm` group. It should look something like that.

    $ id
    uid=1031(skaestle) gid=1033(skaestle) groups=1033(skaestle),..,108(kvm),998(docker),1002(libvirt),30001(nix-users)


In order for the tests to run, you need to have a bunch of artifacts available. You can
download the latest ones from our S3 store. First, configure it:

    $ cat ~/.rclone.conf
    [public-s3]
    type = s3
    provider = AWS
    env_auth = false
    # Credentials should be set with environment variables:
    # export AWS_ACCESS_KEY_ID=xxx
    # export AWS_SECRET_ACCESS_KEY=yyyy
    region = eu-central-1
    location_constraint = eu-central-1

Then run to get build artifacts from master.

    GIT=$(git rev-parse --verify origin/master)

Or, if you want to run it on your branch, make sure to create a PR (so artifacts get built by CI) and do and then download artifacts.

    ic-os/guestos/scripts/get-artifacts.sh

You should now have all artifacts from master in folders `<REPO_ROOT>/artifacts/{canisters,release,guest-os,guest-os-master}`.

If you execute this on `zh1-spm22.zh1.dfinity.network` or `zh1-spm34.zh1.dfinity.network`, you are good to go. Otherwise, read under "Setting up the host machine" .

You can then execute the tests like this:

    mkdir -p artifacts/e2e-upgrade-logs
    ic-os/guestos/tests/e2e-upgrade.py \
          --vmtoolscfg=internal \
          --disk_image "artifacts/guest-os/disk-img/disk.img" \
          --ic_prep_bin "artifacts/release/ic-prep" \
          --install_nns_bin "artifacts/release/ic-nns-init" \
          --upgrade_tar "artifacts/guest-os/update-img/update-img.tar.gz" \
          --ic_admin_bin "artifacts/release/ic-admin" \
          --nns_canisters "artifacts/canisters/" \
          --log_directory "artifacts/e2e-upgrade-logs" \
          --timeout "60" \
          --ic_workload_generator_bin "artifacts/release/ic-workload-generator" \
          --is_upgrade_test


Interactive testing (experimental set up, Ubuntu host)
----------

Set up qemu to allow connecting VMs to these bridges by putting the following
into /etc/qemu/bridge.conf:

    allow ipv6_ic

and setting up qemu helper (as root):

    chmod u+s /usr/lib/qemu/qemu-bridge-helper

Lastly, put the provided vmtoolscfg-sample.json into /etc by the name of
/etc/vmtoolscfg.json. Afterwards, you can run tests with all network
set up taken care of:

    tests/e2e-upgrade.py \
        --disk_image guest-os/disk.img \
        --ic_prep_bin artifacts/ic-prep \
        --install_nns_bin "artifacts/ic-nns-init" \
        --upgrade_script "scripts/ci-upgrade.sh" \
        --upgrade_tar "$(pwd)/guest-os/update-img/update-img.tar.gz" \
        --ic_admin_bin "artifacts/ic-admin" \
        --nns_canisters "artifacts" \
        --version $(cat guest-os/version.txt)

Running on a new host
----------

If running on machine that hasn't been setup already you need to be `sudo`.
You need to run the following script before you want to run guest OS in qemu for the first time.

    #!/usr/bin/env bash
    if [ "$1" == up ]; then
        USER=$(id -nu)
        sudo ip tuntap add ipv6_ic_node0 mode tap user "$USER"
        sudo ip link set dev ipv6_ic_node0 up
        sudo ip tuntap add ipv6_ic_node1 mode tap user "$USER"
        sudo ip link set dev ipv6_ic_node1 up
        sudo ip link add name ipv6_ic type bridge
        sudo ip link set ipv6_ic_node0 master ipv6_ic
        sudo ip link set ipv6_ic_node1 master ipv6_ic
        sudo ip link set dev ipv6_ic up
        sudo ip addr add fd00:2:1:1:1::1/64 dev ipv6_ic
    fi
    if [ "$1" == down ]; then
        sudo ip link del ipv6_ic_node0
        sudo ip link del ipv6_ic_node1
        sudo ip link del ipv6_ic
    fi

Call it like this:

    sudo script.sh down
    sudo script.sh up


Running master to branch upgrade tests
----------

If you want to test upgrades between master an your branch, you first
need to get artifacts from master, similarly to before:

    # Find merge base to upgrade from
    GIT_REV=$(git merge-base HEAD origin/master)

    # Download artifacts from master
    ../../gitlab-ci/src/artifacts/rclone_download.py --git-rev $GIT_REV --out=guest-os-master --remote-path guest-os --latest-to
    ../../gitlab-ci/src/artifacts/rclone_download.py --git-rev $GIT_REV --out=artifacts-master --remote-path canisters --latest-to
    ../../gitlab-ci/src/artifacts/rclone_download.py --git-rev $GIT_REV --out=artifacts-master --remote-path release --latest-to

Extract the content of those directories as described above.

Then, in the e2e test change the arguments accordingly.

    tests/e2e-upgrade.py --disk_image guest-os-master/disk.img ...

Note that you should also use tools such as `ic-admin` from master.


How to build your own guest OS image
----------

 1. Put your replica and your node manager in `rootfs/opt/ic/bin`
 2. Copy `vsock_agent` from `artifacts` to `rootfs/opt/ic/bin`
 2. Build a new disk image: `scripts/build-disk-image.sh -o /tmp/disk.img`


Known issues
----------

If you get:

    subprocess.CalledProcessError: Command '['cp', '--sparse=always', 'guest-os/disk.img', '/tmp/disk-node0.img']' returned non-zero exit status 1.

Make sure `/tmp/disk-node*.img` doesn't already exist from a different user. If so, remove them first.
