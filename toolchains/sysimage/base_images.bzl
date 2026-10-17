"""
Pulls the IC-OS base container images by digest, for building the IC-OS
container filesystems in a microVM instead of with `podman build`.

The digests are read from the docker-base* reference files, which the
"Container IC Base Images" workflow keeps up to date, so they stay the single
source of truth. The images are fetched as repository rules (and cached in the
repository cache) rather than pulled by build actions, so the builds need no
network.

For each image NAME below, `@NAME_linux_amd64//:NAME_linux_amd64` is its OCI
image layout directory.
"""

load("@rules_oci//oci:pull.bzl", "oci_pull")

ICOS_BASE_IMAGES = {
    "icos_base_bootloader": "//ic-os/bootloader:context/docker-base",
    "icos_base_guestos_dev": "//ic-os/guestos/context:docker-base.dev",
    "icos_base_guestos_prod": "//ic-os/guestos/context:docker-base.prod",
    "icos_base_hostos_dev": "//ic-os/hostos/context:docker-base.dev",
    "icos_base_hostos_prod": "//ic-os/hostos/context:docker-base.prod",
    "icos_base_setupos_dev": "//ic-os/setupos/context:docker-base.dev",
    "icos_base_setupos_prod": "//ic-os/setupos/context:docker-base.prod",
}

def _icos_base_images_impl(module_ctx):
    for name, reference_file in ICOS_BASE_IMAGES.items():
        image = module_ctx.read(module_ctx.path(Label(reference_file))).strip()
        if "@sha256:" not in image:
            fail("{} must reference the base image by digest, got {}".format(reference_file, image))
        oci_pull(
            name = name,
            image = image,
            platforms = ["linux/amd64"],
            is_bzlmod = True,
        )

    # Pinned by digest, so the extension is reproducible and needs no lock file entry.
    return module_ctx.extension_metadata(reproducible = True)

icos_base_images = module_extension(
    implementation = _icos_base_images_impl,
)
