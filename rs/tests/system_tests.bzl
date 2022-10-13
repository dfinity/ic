"""
Rules for system-tests.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")

def system_test(name, test_timeout = "long", **kwargs):
    """
    Declares a system-test.
    """
    rust_binary(
        name = name + "_bin",
        srcs = ["bin/" + name + ".rs"],
        **kwargs
    )

    IC_VERSION_ID = "c51e7175ad2d7c7c5327f832a5d9e1bd7f6889c5"

    native.sh_test(
        name = name,
        srcs = [(name + "_bin")],
        args = ["--working-dir", ".", "run"],
        timeout = test_timeout,
        tags = ["requires-network"],
        env = {
            "FARM_BASE_URL": "https://farm.dfinity.systems",
            "IC_OS_IMG_URL": "https://download.dfinity.systems/ic/{}/guest-os/disk-img-dev/disk-img.tar.zst".format(IC_VERSION_ID),
            "IC_OS_IMG_SHA256": "2cb880cc6fbb11b3ec29aa7b65d3643c1cbe74f73c2d0cd5dcae4cc7a8a7a243",
            "IC_OS_UPD_DEV_IMG_URL": "https://download.dfinity.systems/ic/{}/guest-os/update-img-dev/update-img.tar.zst".format(IC_VERSION_ID),
            "IC_OS_UPD_DEV_IMG_SHA256": "e67df14785c367c350fcbb5aa10ffd3773443e477be61d898e2dbd4b555ce700",
            "IC_VERSION_ID": IC_VERSION_ID,
        },
    )
