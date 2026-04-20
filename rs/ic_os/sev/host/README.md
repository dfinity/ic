# sev_host

Host-side SEV-SNP certificate-chain provider.

## How it works
- Reads host SEV platform identity information from the host firmware.
- Fetches the VCEK from AMD's key distribution service when needed.
- Caches the fetched certificate material locally so the node can keep starting
  even if AMD's key server is temporarily unavailable.
- Assembles the certificate chain expected by guest-side attestation
  verification code.

The cached certificate material is stable across normal operation: it only needs
to change when the platform firmware changes, so reusing the cached chain is the
intended fallback behavior while the host identity stays the same.

After a firmware update, the host reboots and reports a different TCB version.
That causes a lookup for a different cache entry; if the certificate chain for
that TCB is not cached yet, the host fetches and stores the new one.

`HostSevCertificateProvider` is the main API. `testing.rs` contains mocks and
fixtures used by higher-level HostOS components.
