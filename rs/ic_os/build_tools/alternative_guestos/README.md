# alternative_guestos (build tool)

Tools for building alternative GuestOS images (e.g. the SEV recovery image, see
`//ic-os/guestos/envs/sev-recovery:build-sev-recovery`).

Subcommands:

- `download-signed-proposal` — downloads the certified
  `BlessAlternativeGuestOsVersion` proposal from NNS governance and writes the
  verified, signed proposal as CBOR.
- `validate-measurements` — checks that the launch measurements generated for
  the image being built match those blessed in the proposal.