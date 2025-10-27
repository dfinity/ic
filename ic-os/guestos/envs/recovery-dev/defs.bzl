"""
Helper function to generate a dummy recovery archive for testing purposes.
"""

def generate_dummy_recovery_archive(name):
    """ Generates a dummy recovery archive for testing purposes.

    Generating the dummy recovery archive is done with a genrule that outputs a tarball containing a dummy CUP
    and local store, along with the hash of this tarball and the modified recovery engine script that should be
    included in the disk image. It also outputs the base64-encoded contents of the CUP and local store files to
    be passed to the system test to verify the recovery process.

    Args:
        name: The name of the genrule target.
    Returns:
        This function does not return anything, but it defines one target for generating the recovery archive and
        one target for each of the output files.
    """
    native.genrule(
        name = name,
        outs = [
            "recovery.tar.zst",
            "recovery.tar.zst.sha256",
            "cup.proto.b64",
            "ic_registry_local_store_1.b64",
            "ic_registry_local_store_2.b64",
        ],
        cmd = r"""
            set -euo pipefail

            DATA="DATA"

            # Dummy CUP (5 MB)
            head -c $$((5 * 1024 * 1024)) < <(yes "$$DATA") > cup.proto

            # Dummy Local Store (500 MB total)
            mkdir -p ic_registry_local_store/0001020304/05/06
            head -c $$((250 * 1024 * 1024)) < <(yes "$$DATA") > ic_registry_local_store/0001020304/05/06/07.pb

            mkdir -p ic_registry_local_store/08090a0b0c/0d/0e
            head -c $$((250 * 1024 * 1024)) < <(yes "$$DATA") > ic_registry_local_store/08090a0b0c/0d/0e/0f.pb

            # Archive the local store
            tar --zstd -cf ic_registry_local_store.tar.zst -C ic_registry_local_store .

            # Final archive
            tar --zstd -cf recovery.tar.zst cup.proto ic_registry_local_store.tar.zst

            base64 -w 0 cup.proto > cup.proto.b64
            base64 -w 0 ic_registry_local_store/0001020304/05/06/07.pb > ic_registry_local_store_1.b64
            base64 -w 0 ic_registry_local_store/08090a0b0c/0d/0e/0f.pb > ic_registry_local_store_2.b64


            RECOVERY_HASH="$$(sha256sum recovery.tar.zst | cut -d' ' -f1)"
            echo "$$RECOVERY_HASH" > recovery.tar.zst.sha256

            mv recovery.tar.zst recovery.tar.zst.sha256 cup.proto.b64 ic_registry_local_store_1.b64 ic_registry_local_store_2.b64 $(RULEDIR)
        """,
        target_compatible_with = [
            "@platforms//os:linux",
        ],
        visibility = [
            "//rs:system-tests-pkg",
        ],
        tags = ["manual"],
    )
