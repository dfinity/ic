# The list of vulnerabilities that we ignore.

[
  # ID:       RUSTSEC-2020-0031
  # Crate:    tiny_http
  # Version:  0.7.0
  # Date:     2020-06-16
  # URL:      https://rustsec.org/advisories/RUSTSEC-2020-0031
  # Title:    HTTP Request smuggling through malformed Transfer Encoding headers
  # Solution:  No safe upgrade is available!
  # Dependency tree:
  # tiny_http 0.7.0
  # ├── ic-replica 0.1.0
  # │   ├── ic-starter 0.1.0
  # │   ├── ic-sdk 0.1.0
  # │   ├── ic-replica-tests 0.1.0
  # │   │   ├── ic-replica 0.1.0
  # │   │   └── canister-test 0.1.0
  # │   │       ├── web-server 0.1.0
  # │   │       │   └── registry-canister 0.1.0
  # │   │       ├── rust-canister-tests 0.1.0
  # │   │       ├── registry-canister 0.1.0
  # │   │       ├── pmap 0.1.0
  # │   │       ├── ic-scenario-tests 0.1.0
  # │   │       ├── ic-replica 0.1.0
  # │   │       ├── ic-registry-common 0.1.0
  # │   │       │   ├── ic-transport 0.1.0
  # │   │       │   │   ├── ic-replica 0.1.0
  # │   │       │   │   ├── ic-replica-tests 0.1.0
  # │   │       │   │   └── ic-p2p 0.1.0
  # │   │       │   │       ├── ic-replica 0.1.0
  # │   │       │   │       └── ic-drun 0.1.0
  # │   │       │   │           └── ic-sdk 0.1.0
  # │   │       │   ├── ic-test-utilities 0.1.0
  # │   │       │   │   ├── ic-wasm-utils 0.1.0
  # │   │       │   │   │   ├── ic-replicated-state 0.1.0
  # │   │       │   │   │   │   ├── ic-test-utilities 0.1.0
  # │   │       │   │   │   │   ├── ic-system-api 0.1.0
  # │   │       │   │   │   │   │   ├── ic-messaging 0.1.0
  # │   │       │   │   │   │   │   │   ├── ic-replica 0.1.0
  # │   │       │   │   │   │   │   │   ├── ic-p2p 0.1.0
  # │   │       │   │   │   │   │   │   ├── ic-drun 0.1.0
  # │   │       │   │   │   │   │   │   └── ic-consensus 0.1.0
  # │   │       │   │   │   │   │   │       ├── ic-replica 0.1.0
  # │   │       │   │   │   │   │   │       ├── ic-p2p 0.1.0
  # │   │       │   │   │   │   │   │       └── ic-drun 0.1.0
  # │   │       │   │   │   │   │   ├── ic-execution-environment 0.1.0
  # │   │       │   │   │   │   │   │   ├── ic-starter 0.1.0
  # │   │       │   │   │   │   │   │   ├── ic-replica 0.1.0
  # │   │       │   │   │   │   │   │   ├── ic-replica-tests 0.1.0
  # │   │       │   │   │   │   │   │   ├── ic-p2p 0.1.0
  # │   │       │   │   │   │   │   │   ├── ic-messaging 0.1.0
  # │   │       │   │   │   │   │   │   └── ic-drun 0.1.0
  # │   │       │   │   │   │   │   └── ic-embedders 0.1.0
  # │   │       │   │   │   │   │       └── ic-execution-environment 0.1.0
  # │   │       │   │   │   │   ├── ic-state-manager 0.1.0
  # │   │       │   │   │   │   │   ├── ic-starter 0.1.0
  # │   │       │   │   │   │   │   ├── ic-replica 0.1.0
  # │   │       │   │   │   │   │   ├── ic-replica-tests 0.1.0
  # │   │       │   │   │   │   │   ├── ic-prep 0.1.0
  # │   │       │   │   │   │   │   │   └── ic-starter 0.1.0
  # │   │       │   │   │   │   │   ├── ic-p2p 0.1.0
  # │   │       │   │   │   │   │   └── ic-drun 0.1.0
  # │   │       │   │   │   │   ├── ic-state-layout 0.1.0
  # │   │       │   │   │   │   │   ├── ic-state-manager 0.1.0
  # │   │       │   │   │   │   │   └── ic-execution-environment 0.1.0
  # │   │       │   │   │   │   ├── ic-replica 0.1.0
  # │   │       │   │   │   │   ├── ic-replica-tests 0.1.0
  # │   │       │   │   │   │   ├── ic-p2p 0.1.0
  # │   │       │   │   │   │   ├── ic-messaging 0.1.0
  # │   │       │   │   │   │   ├── ic-ingress-manager 0.1.0
  # │   │       │   │   │   │   │   ├── ic-replica 0.1.0
  # │   │       │   │   │   │   │   └── ic-p2p 0.1.0
  # │   │       │   │   │   │   ├── ic-http-handler 0.1.0
  # │   │       │   │   │   │   │   ├── ic-starter 0.1.0
  # │   │       │   │   │   │   │   ├── ic-replica 0.1.0
  # │   │       │   │   │   │   │   └── ic-prep 0.1.0
  # │   │       │   │   │   │   ├── ic-execution-environment 0.1.0
  # │   │       │   │   │   │   ├── ic-embedders 0.1.0
  # │   │       │   │   │   │   ├── ic-drun 0.1.0
  # │   │       │   │   │   │   └── ic-consensus 0.1.0
  # │   │       │   │   │   ├── ic-execution-environment 0.1.0
  # │   │       │   │   │   └── ic-embedders 0.1.0
  # │   │       │   │   ├── ic-types 0.1.0
  # │   │       │   │   │   ├── ic-workload-generator 0.1.0
  # │   │       │   │   │   │   └── canister-test 0.1.0
  # │   │       │   │   │   ├── ic-wasm-utils 0.1.0
  # │   │       │   │   │   ├── ic-transport 0.1.0
  # │   │       │   │   │   ├── ic-test-utilities 0.1.0
  # │   │       │   │   │   ├── ic-test-artifact-pool 0.1.0
  # │   │       │   │   │   │   └── ic-consensus 0.1.0
  # │   │       │   │   │   ├── ic-system-api 0.1.0
  # │   │       │   │   │   ├── ic-state-manager 0.1.0
  # │   │       │   │   │   ├── ic-state-layout 0.1.0
  # │   │       │   │   │   ├── ic-starter 0.1.0
  # │   │       │   │   │   ├── ic-scenario-tests 0.1.0
  # │   │       │   │   │   ├── ic-replicated-state 0.1.0
  # │   │       │   │   │   ├── ic-replica 0.1.0
  # │   │       │   │   │   ├── ic-replica-tests 0.1.0
  # │   │       │   │   │   ├── ic-registry-common 0.1.0
  # │   │       │   │   │   ├── ic-registry-client 0.1.0
  # │   │       │   │   │   │   ├── ic-transport 0.1.0
  # │   │       │   │   │   │   ├── ic-test-utilities 0.1.0
  # │   │       │   │   │   │   ├── ic-starter 0.1.0
  # │   │       │   │   │   │   ├── ic-replica 0.1.0
  # │   │       │   │   │   │   ├── ic-replica-tests 0.1.0
  # │   │       │   │   │   │   ├── ic-prep 0.1.0
  # │   │       │   │   │   │   ├── ic-p2p 0.1.0
  # │   │       │   │   │   │   ├── ic-messaging 0.1.0
  # │   │       │   │   │   │   ├── ic-ingress-manager 0.1.0
  # │   │       │   │   │   │   ├── ic-execution-environment 0.1.0
  # │   │       │   │   │   │   ├── ic-drun 0.1.0
  # │   │       │   │   │   │   ├── ic-crypto 0.1.0
  # │   │       │   │   │   │   │   ├── ic-workload-generator 0.1.0
  # │   │       │   │   │   │   │   ├── ic-test-utilities 0.1.0
  # │   │       │   │   │   │   │   ├── ic-test-artifact-pool 0.1.0
  # │   │       │   │   │   │   │   ├── ic-state-manager 0.1.0
  # │   │       │   │   │   │   │   ├── ic-starter 0.1.0
  # │   │       │   │   │   │   │   ├── ic-replica 0.1.0
  # │   │       │   │   │   │   │   ├── ic-replica-tests 0.1.0
  # │   │       │   │   │   │   │   ├── ic-prep 0.1.0
  # │   │       │   │   │   │   │   ├── ic-p2p 0.1.0
  # │   │       │   │   │   │   │   ├── ic-messaging 0.1.0
  # │   │       │   │   │   │   │   ├── ic-ingress-manager 0.1.0
  # │   │       │   │   │   │   │   ├── ic-drun 0.1.0
  # │   │       │   │   │   │   │   ├── ic-consensus-message 0.1.0
  # │   │       │   │   │   │   │   │   ├── ic-test-utilities 0.1.0
  # │   │       │   │   │   │   │   │   ├── ic-test-artifact-pool 0.1.0
  # │   │       │   │   │   │   │   │   ├── ic-consensus 0.1.0
  # │   │       │   │   │   │   │   │   ├── ic-artifact-pool 0.1.0
  # │   │       │   │   │   │   │   │   │   ├── ic-test-utilities 0.1.0
  # │   │       │   │   │   │   │   │   │   ├── ic-test-artifact-pool 0.1.0
  # │   │       │   │   │   │   │   │   │   ├── ic-replica 0.1.0
  # │   │       │   │   │   │   │   │   │   ├── ic-p2p 0.1.0
  # │   │       │   │   │   │   │   │   │   ├── ic-ingress-manager 0.1.0
  # │   │       │   │   │   │   │   │   │   ├── ic-consensus 0.1.0
  # │   │       │   │   │   │   │   │   │   └── ic-artifact-manager 0.1.0
  # │   │       │   │   │   │   │   │   │       └── ic-p2p 0.1.0
  # │   │       │   │   │   │   │   │   └── ic-artifact-manager 0.1.0
  # │   │       │   │   │   │   │   ├── ic-consensus 0.1.0
  # │   │       │   │   │   │   │   ├── ic-canister-client 0.1.0
  # │   │       │   │   │   │   │   │   ├── ic-workload-generator 0.1.0
  # │   │       │   │   │   │   │   │   ├── ic-scenario-tests 0.1.0
  # │   │       │   │   │   │   │   │   ├── ic-registry-common 0.1.0
  # │   │       │   │   │   │   │   │   ├── ic-prober 0.1.0
  # │   │       │   │   │   │   │   │   └── canister-test 0.1.0
  # │   │       │   │   │   │   │   ├── ic-artifact-pool 0.1.0
  # │   │       │   │   │   │   │   ├── ic-artifact-manager 0.1.0
  # │   │       │   │   │   │   │   └── ic-admin 0.1.0
  # │   │       │   │   │   │   ├── ic-consensus 0.1.0
  # │   │       │   │   │   │   └── ic-artifact-pool 0.1.0
  # │   │       │   │   │   ├── ic-prober 0.1.0
  # │   │       │   │   │   ├── ic-prep 0.1.0
  # │   │       │   │   │   ├── ic-p2p 0.1.0
  # │   │       │   │   │   ├── ic-messaging 0.1.0
  # │   │       │   │   │   ├── ic-logger 0.1.0
  # │   │       │   │   │   │   ├── nodemanager 0.1.0
  # │   │       │   │   │   │   ├── memory_tracker 0.1.0
  # │   │       │   │   │   │   │   └── ic-embedders 0.1.0
  # │   │       │   │   │   │   ├── ic-transport 0.1.0
  # │   │       │   │   │   │   ├── ic-test-utilities 0.1.0
  # │   │       │   │   │   │   ├── ic-test-artifact-pool 0.1.0
  # │   │       │   │   │   │   ├── ic-state-manager 0.1.0
  # │   │       │   │   │   │   ├── ic-starter 0.1.0
  # │   │       │   │   │   │   ├── ic-replica 0.1.0
  # │   │       │   │   │   │   ├── ic-registry-common 0.1.0
  # │   │       │   │   │   │   ├── ic-registry-client 0.1.0
  # │   │       │   │   │   │   ├── ic-prep 0.1.0
  # │   │       │   │   │   │   ├── ic-p2p 0.1.0
  # │   │       │   │   │   │   ├── ic-messaging 0.1.0
  # │   │       │   │   │   │   ├── ic-ingress-manager 0.1.0
  # │   │       │   │   │   │   ├── ic-http-handler 0.1.0
  # │   │       │   │   │   │   ├── ic-execution-environment 0.1.0
  # │   │       │   │   │   │   ├── ic-embedders 0.1.0
  # │   │       │   │   │   │   ├── ic-crypto 0.1.0
  # │   │       │   │   │   │   ├── ic-consensus 0.1.0
  # │   │       │   │   │   │   ├── ic-canister-client 0.1.0
  # │   │       │   │   │   │   ├── ic-artifact-pool 0.1.0
  # │   │       │   │   │   │   ├── ic-artifact-manager 0.1.0
  # │   │       │   │   │   │   └── ic-admin 0.1.0
  # │   │       │   │   │   ├── ic-interfaces 0.1.0
  # │   │       │   │   │   │   ├── ic-wasm-utils 0.1.0
  # │   │       │   │   │   │   ├── ic-transport 0.1.0
  # │   │       │   │   │   │   ├── ic-test-utilities 0.1.0
  # │   │       │   │   │   │   ├── ic-test-artifact-pool 0.1.0
  # │   │       │   │   │   │   ├── ic-system-api 0.1.0
  # │   │       │   │   │   │   ├── ic-state-manager 0.1.0
  # │   │       │   │   │   │   ├── ic-starter 0.1.0
  # │   │       │   │   │   │   ├── ic-replicated-state 0.1.0
  # │   │       │   │   │   │   ├── ic-replica 0.1.0
  # │   │       │   │   │   │   ├── ic-replica-tests 0.1.0
  # │   │       │   │   │   │   ├── ic-registry-common 0.1.0
  # │   │       │   │   │   │   ├── ic-registry-client 0.1.0
  # │   │       │   │   │   │   ├── ic-prep 0.1.0
  # │   │       │   │   │   │   ├── ic-p2p 0.1.0
  # │   │       │   │   │   │   ├── ic-messaging 0.1.0
  # │   │       │   │   │   │   ├── ic-ingress-manager 0.1.0
  # │   │       │   │   │   │   ├── ic-http-handler 0.1.0
  # │   │       │   │   │   │   ├── ic-execution-environment 0.1.0
  # │   │       │   │   │   │   ├── ic-embedders 0.1.0
  # │   │       │   │   │   │   ├── ic-drun 0.1.0
  # │   │       │   │   │   │   ├── ic-crypto 0.1.0
  # │   │       │   │   │   │   ├── ic-consensus 0.1.0
  # │   │       │   │   │   │   ├── ic-canister-client 0.1.0
  # │   │       │   │   │   │   ├── ic-artifact-pool 0.1.0
  # │   │       │   │   │   │   ├── ic-artifact-manager 0.1.0
  # │   │       │   │   │   │   └── ic-admin 0.1.0
  # │   │       │   │   │   ├── ic-ingress-manager 0.1.0
  # │   │       │   │   │   ├── ic-http-handler 0.1.0
  # │   │       │   │   │   ├── ic-execution-environment 0.1.0
  # │   │       │   │   │   ├── ic-embedders 0.1.0
  # │   │       │   │   │   ├── ic-drun 0.1.0
  # │   │       │   │   │   ├── ic-crypto 0.1.0
  # │   │       │   │   │   ├── ic-consensus-message 0.1.0
  # │   │       │   │   │   ├── ic-consensus 0.1.0
  # │   │       │   │   │   ├── ic-canister-client 0.1.0
  # │   │       │   │   │   ├── ic-artifact-pool 0.1.0
  # │   │       │   │   │   ├── ic-artifact-manager 0.1.0
  # │   │       │   │   │   ├── ic-admin 0.1.0
  # │   │       │   │   │   └── canister-test 0.1.0
  # │   │       │   │   ├── ic-transport 0.1.0
  # │   │       │   │   ├── ic-test-artifact-pool 0.1.0
  # │   │       │   │   ├── ic-system-api 0.1.0
  # │   │       │   │   ├── ic-state-manager 0.1.0
  # │   │       │   │   ├── ic-scenario-tests 0.1.0
  # │   │       │   │   ├── ic-replicated-state 0.1.0
  # │   │       │   │   ├── ic-replica 0.1.0
  # │   │       │   │   ├── ic-replica-tests 0.1.0
  # │   │       │   │   ├── ic-p2p 0.1.0
  # │   │       │   │   ├── ic-messaging 0.1.0
  # │   │       │   │   ├── ic-ingress-manager 0.1.0
  # │   │       │   │   ├── ic-http-handler 0.1.0
  # │   │       │   │   ├── ic-execution-environment 0.1.0
  # │   │       │   │   ├── ic-embedders 0.1.0
  # │   │       │   │   ├── ic-drun 0.1.0
  # │   │       │   │   ├── ic-crypto 0.1.0
  # │   │       │   │   ├── ic-consensus 0.1.0
  # │   │       │   │   ├── ic-canister-client 0.1.0
  # │   │       │   │   └── ic-artifact-pool 0.1.0
  # │   │       │   ├── ic-starter 0.1.0
  # │   │       │   ├── ic-replica 0.1.0
  # │   │       │   ├── ic-replica-tests 0.1.0
  # │   │       │   ├── ic-registry-client 0.1.0
  # │   │       │   ├── ic-prep 0.1.0
  # │   │       │   ├── ic-p2p 0.1.0
  # │   │       │   ├── ic-messaging 0.1.0
  # │   │       │   ├── ic-ingress-manager 0.1.0
  # │   │       │   ├── ic-execution-environment 0.1.0
  # │   │       │   ├── ic-drun 0.1.0
  # │   │       │   ├── ic-crypto 0.1.0
  # │   │       │   ├── ic-consensus 0.1.0
  # │   │       │   └── ic-admin 0.1.0
  # │   │       ├── ic-nns-proposals 0.1.0
  # │   │       ├── ic-nns-neurons 0.1.0
  # │   │       ├── dfn_core 0.1.0
  # │   │       │   ├── web-server 0.1.0
  # │   │       │   ├── rust-canister-tests 0.1.0
  # │   │       │   ├── registry-canister 0.1.0
  # │   │       │   ├── pmap 0.1.0
  # │   │       │   ├── ic-nns-proposals 0.1.0
  # │   │       │   ├── ic-nns-neurons 0.1.0
  # │   │       │   ├── ic-nns-common 0.1.0
  # │   │       │   │   └── ic-nns-neurons 0.1.0
  # │   │       │   ├── dfn_json 0.1.0
  # │   │       │   │   ├── web-server 0.1.0
  # │   │       │   │   ├── rust-canister-tests 0.1.0
  # │   │       │   │   ├── pmap 0.1.0
  # │   │       │   │   ├── dfn_core 0.1.0
  # │   │       │   │   └── big-map 0.1.0
  # │   │       │   ├── dfn_http 0.1.0
  # │   │       │   │   └── ic-http-handler 0.1.0
  # │   │       │   ├── dfn_candid 0.1.0
  # │   │       │   │   ├── ic-nns-neurons 0.1.0
  # │   │       │   │   ├── ic-nns-common 0.1.0
  # │   │       │   │   └── dfn_http 0.1.0
  # │   │       │   └── big-map 0.1.0
  # │   │       ├── dfn_candid 0.1.0
  # │   │       └── big-map 0.1.0
  # │   └── ic-drun 0.1.0
  # ├── ic-prober 0.1.0
  # ├── ic-messaging 0.1.0
  # └── ic-http-handler 0.1.0
  #
  # Reason for ignoring: In Tungsten, the auth gateway filters out requests that
  # do not contain a token required to access Tungsten. Beyond that, the
  # nodes check the signature contained in all call requests. So,
  # whether a malicious user smuggles in an additional request or sends
  # two requests, where both include the access-token, should not make a
  # difference.
  "RUSTSEC-2020-0031"

  # ID:       RUSTSEC-2020-0041
  # Crate:    sized-chunks
  # Version:  0.6.2
  # Date:     2020-09-06
  # URL:      https://rustsec.org/advisories/RUSTSEC-2020-0041
  # Title:    Multiple soundness issues in Chunk and InlineArray
  # Solution:  No safe upgrade is available!
  # Dependency tree:
  # sized-chunks 0.6.2
  # └── im 15.0.0
  #
  # We ignore this for now but this needs to be fixed before launch.
  # The issue will be handled by the execution team and is tracked in:
  # https://dfinity.atlassian.net/browse/OPS-127
  "RUSTSEC-2020-0041"

  # ID:       RUSTSEC-2021-0013
  # Crate:    raw-cpuid
  # Version:  6.1.0
  # Date:     2021-01-20
  # URL:      https://rustsec.org/advisories/RUSTSEC-2021-0013
  # Title:    Soundness issues in `raw-cpuid`
  # Solution:  upgrade to >= 9.0.0
  # Dependency tree:
  # raw-cpuid 6.1.0
  #
  # ID:       RUSTSEC-2021-0013
  # Crate:    raw-cpuid
  # Version:  7.0.3
  # Date:     2021-01-20
  # URL:      https://rustsec.org/advisories/RUSTSEC-2021-0013
  # Title:    Soundness issues in `raw-cpuid`
  # Solution:  upgrade to >= 9.0.0
  # Dependency tree:
  # raw-cpuid 7.0.3
  #
  # ID:       RUSTSEC-2021-0013
  # Crate:    raw-cpuid
  # Version:  8.1.2
  # Date:     2021-01-20
  # URL:      https://rustsec.org/advisories/RUSTSEC-2021-0013
  # Title:    Soundness issues in `raw-cpuid`
  # Solution:  upgrade to >= 9.0.0
  # Dependency tree:
  # raw-cpuid 8.1.2
  #
  # We've fixed the above vulnerabilties by patching the affected raw-cpuid
  # crates (see rs/Cargo.toml) and point them to our fixed fork.
  # https://github.com/dfinity-lab/dfinity/pull/8437
  #
  # However since the vulnerable versions are still listed in the Cargo.lock
  # file `cargo audit` will keep complaining about it which is why we ignore it
  # here:
  "RUSTSEC-2021-0013"
]
