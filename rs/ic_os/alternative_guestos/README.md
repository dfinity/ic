# alternative_guestos

Shared library for verifying NNS-signed `BlessAlternativeGuestOsVersion`
proposals for "alternative GuestOS" images (e.g. the SEV recovery image).

The same verification logic is used in two places:

- **At build time** by the build tool in `rs/ic_os/build_tools/alternative_guestos`,
  so that a proposal whose launch measurements do not match the image being
  built fails the build early.
- **In production** by `open_rootfs` on the GuestOS, which verifies the
  proposal embedded in the boot partition before switching to the alternative
  root partition.
