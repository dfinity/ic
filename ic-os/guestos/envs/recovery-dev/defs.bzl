"""
Helper function to generate a dummy recovery archive for testing purposes.
"""

def generate_dummy_recovery_archive(name, seed):
    """
    Generates a dummy recovery archive for testing purposes. This is done with a genrule that outputs a tarball
    containing a dummy CUP and local store, along with the hash of this tarball and the modified recovery engine
    script that should be included in the disk image. It also outputs the base64-encoded contents of the CUP and
    local store files to be passed to the system test to verify the recovery process.

    Args:
        name: The name of the genrule target.
        seed: A seed string used to generate dummy data.
    Returns:
        This function does not return anything, but it defines one target for generating the recovery archive and
        one target for each of the output files.
        It does not return anything.
    """
    native.genrule(
        name = name,
        srcs = [
            "//ic-os/components:misc/guestos-recovery/guestos-recovery-engine/guestos-recovery-engine.sh",
        ],
        outs = [
            "recovery.tar.zst",
            "recovery_hash.txt",
            "cup.proto.b64",
            "ic_registry_local_store_1.b64",
            "ic_registry_local_store_2.b64",
            "guestos-recovery-engine.sh",
        ],
        cmd = r"""
            set -euo pipefail

            SEED="{seed}"

            # Dummy CUP (100 MB)
            head -c $$((100 * 1024 * 1024)) < <(yes "$$SEED") > cup.proto

            # Dummy Local Store (500 MB total)
            mkdir -p ic_registry_local_store/0001020304/05/06
            head -c $$((250 * 1024 * 1024)) < <(yes "$$SEED-store1") > ic_registry_local_store/0001020304/05/06/07.pb

            mkdir -p ic_registry_local_store/08090a0b0c/0d/0e
            head -c $$((250 * 1024 * 1024)) < <(yes "$$SEED-store2") > ic_registry_local_store/08090a0b0c/0d/0e/0f.pb

            # Archive the local store
            tar --zstd -cf ic_registry_local_store.tar.zst -C ic_registry_local_store .

            # Final archive
            tar --zstd -cf recovery.tar.zst cup.proto ic_registry_local_store.tar.zst

            base64 -w 0 cup.proto > cup.proto.b64
            base64 -w 0 ic_registry_local_store/0001020304/05/06/07.pb > ic_registry_local_store_1.b64
            base64 -w 0 ic_registry_local_store/08090a0b0c/0d/0e/0f.pb > ic_registry_local_store_2.b64


            cp -a $< guestos-recovery-engine.sh
            RECOVERY_HASH="$$(sha256sum recovery.tar.zst | cut -d' ' -f1)"
            sed -i "s/readonly EXPECTED_RECOVERY_HASH=\"\"/readonly EXPECTED_RECOVERY_HASH=\"$$RECOVERY_HASH\"/" guestos-recovery-engine.sh
            echo "$$RECOVERY_HASH" > recovery_hash.txt

            mv recovery.tar.zst recovery_hash.txt cup.proto.b64 ic_registry_local_store_1.b64 ic_registry_local_store_2.b64 guestos-recovery-engine.sh $(RULEDIR)
        """.format(seed = seed),
        visibility = [
            "//rs:ic-os-pkg",
        ],
    )

    native.filegroup(
        name = name + "_recovery.tar.zst",
        srcs = ["recovery.tar.zst"],
        visibility = [
            "//rs:system-tests-pkg",
        ],
    )

    native.filegroup(
        name = name + "_recovery_hash.txt",
        srcs = ["recovery_hash.txt"],
        visibility = [
            "//rs:system-tests-pkg",
        ],
    )

    native.filegroup(
        name = name + "_cup.proto.b64",
        srcs = ["cup.proto.b64"],
        visibility = [
            "//rs:system-tests-pkg",
        ],
    )

    native.filegroup(
        name = name + "_ic_registry_local_store_1.b64",
        srcs = ["ic_registry_local_store_1.b64"],
        visibility = [
            "//rs:system-tests-pkg",
        ],
    )

    native.filegroup(
        name = name + "_ic_registry_local_store_2.b64",
        srcs = ["ic_registry_local_store_2.b64"],
        visibility = [
            "//rs:system-tests-pkg",
        ],
    )

    native.filegroup(
        name = name + "_guestos-recovery-engine.sh",
        srcs = ["guestos-recovery-engine.sh"],
        visibility = [
            "//rs:ic-os-pkg",
        ],
    )
