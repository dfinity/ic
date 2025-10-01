"""
This module defines a macro to generate a test DID given a main DID and a patch, as well as some
helper targets to generate the test DID and patch when the patch cannot be applied.
"""

def canister_test_did(name):
    """ Generates a test DID file from a main DID file and a patch file.

    Args:
        name: The name of the test DID file. Should be in the form of "*_test.did" while the main
        DID file is in the form of "*.did" and the patch file is in the form of "*_test.did.patch"
    """

    if not name.endswith("_test.did"):
        fail("Name must end with '_test.did'")

    canister_test_did = name
    canister_did = canister_test_did.replace("_test.did", ".did")
    canister_test_did_patch = canister_test_did + ".patch"
    canister_did_path = "$(location {})".format(canister_did)
    canister_test_did_patch_path = "$(location {})".format(canister_test_did_patch)
    target_base_name = native.package_name() + ":" + canister_test_did

    native.genrule(
        name = canister_test_did,
        srcs = [canister_did, canister_test_did_patch],
        outs = [canister_test_did],
        cmd = r"""
            if [ "$$(uname)" == "Linux" ]; then
              PATCH_OPTS="--follow-symlinks"
            else
              PATCH_OPTS=""
            fi
            if ! patch $$PATCH_OPTS {canister_did_path} -i {canister_test_did_patch_path} -o $@; then
                echo "Error generating {canister_test_did}, please run the //{target_base_name}_generate_test_did to edit the generated file"
                exit 1
            fi
            """
            .format(
            canister_did_path = canister_did_path,
            canister_test_did_patch_path = canister_test_did_patch_path,
            canister_test_did = canister_test_did,
            target_base_name = target_base_name,
        ),
    )

    srcs = [
        "//rs/nervous_system/patch_canister_did:helper.sh",
    ]

    data = [
        canister_did,
        canister_test_did_patch,
        "//:WORKSPACE.bazel",
    ]

    env = {
        "WORKSPACE": "$(rootpath //:WORKSPACE.bazel)",
        "TARGET_BASE_NAME": target_base_name,
    }

    args = [
        canister_did_path,
        canister_test_did_patch_path,
    ]

    native.sh_binary(
        name = canister_test_did + "_generate_test_did",
        srcs = srcs,
        data = data,
        env = env,
        args = args + [
            "--generate-test-did",
        ],
    )

    native.sh_binary(
        name = canister_test_did + "_update_patch",
        srcs = srcs,
        data = data,
        env = env,
        args = args + [
            "--update-patch",
        ],
    )
