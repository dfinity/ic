# GuestOS kernel patches

Patches in this directory are applied (in lexicographic order) to Ubuntu's
`linux-hwe-6.17` source package in the `kernel-build` stage of
`Dockerfile.base`. The resulting `.deb` packages replace the stock kernel in
the final GuestOS base image.

## Conventions

- Name patches `NNNN-short-description.patch` so they apply in a deterministic
  order.
- Each patch file must be a single-commit `git format-patch` output and apply
  with `patch -p1` from the root of the kernel source tree.
- Include in the commit message: the upstream mainline commit SHA, the
  upstream stable branch it has (or has not) landed on, and the reason for
  carrying the patch locally.
- Remove a patch once it is no longer necessary (i.e. the Ubuntu package in
  use already contains the fix).

## Current patches

- `0001-mm-huge_memory-fix-folio_split-race-condition.patch` — backport of
  upstream `577a1f495fd78d8fb61b67ac3d3b595b01f6fcb0` ("mm/huge_memory: fix a
  folio_split() race condition with folio_try_get()"). Drop once the Ubuntu
  kernel in use (`linux-hwe-6.17` or a newer HWE track) ships this fix.
