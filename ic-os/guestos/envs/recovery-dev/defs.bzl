def generate_recovery_archive(name, seed, server_hostname):
    native.genrule(
        name = name,
        srcs = [
            "//ic-os/components:misc/guestos-recovery/guestos-recovery-engine/guestos-recovery-engine.sh",
        ],
        outs = [
            "recovery.tar.zst",
            "cup.proto.b64",
            "ic_registry_local_store_content1.b64",
            "ic_registry_local_store_content2.b64",
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
            tar --zstd -cf ic_registry_local_store.tar.zst ic_registry_local_store

            # Final archive
            tar --zstd -cf recovery.tar.zst cup.proto ic_registry_local_store.tar.zst

            base64 -w 0 cup.proto > cup.proto.b64
            base64 -w 0 ic_registry_local_store/0001020304/05/06/07.pb > ic_registry_local_store_content1.b64
            base64 -w 0 ic_registry_local_store/08090a0b0c/0d/0e/0f.pb > ic_registry_local_store_content2.b64


            cp -a $< guestos-recovery-engine.sh
            RECOVERY_HASH="$$(sha256sum recovery.tar.zst | cut -d' ' -f1)"
            sed -i "s/readonly EXPECTED_RECOVERY_HASH=\"\"/readonly EXPECTED_RECOVERY_HASH=\"$$RECOVERY_HASH\"/" guestos-recovery-engine.sh
            sed -i '/^base_urls=(/,/^)/c\base_urls=(\n    "http://{server_hostname}"\n)' guestos-recovery-engine.sh

            mv recovery.tar.zst cup.proto.b64 ic_registry_local_store_content1.b64 ic_registry_local_store_content2.b64 guestos-recovery-engine.sh $(RULEDIR)
        """.format(seed = seed, server_hostname = server_hostname),
        visibility = [
            "//rs:ic-os-pkg",
        ],
    )

    native.filegroup(
        name = name + "_recovery.tar.zst",
        srcs = [":guestos_recovery_archive"],
        visibility = [
            "//rs:system-tests-pkg",
        ],
    )

    native.filegroup(
        name = name + "_cup.proto.b64",
        srcs = [":guestos_recovery_archive"],
        visibility = [
            "//rs:system-tests-pkg",
        ],
    )

    native.filegroup(
        name = name + "_ic_registry_local_store_content1.b64",
        srcs = [":guestos_recovery_archive"],
        visibility = [
            "//rs:system-tests-pkg",
        ],
    )

    native.filegroup(
        name = name + "_ic_registry_local_store_content2.b64",
        srcs = [":guestos_recovery_archive"],
        visibility = [
            "//rs:system-tests-pkg",
        ],
    )

    native.filegroup(
        name = name + "_guestos-recovery-engine.sh",
        srcs = [":guestos_recovery_archive"],
        visibility = [
            "//rs:ic-os-pkg",
        ],
    )
