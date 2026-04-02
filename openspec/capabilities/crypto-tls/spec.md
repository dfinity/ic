# Crypto: TLS Configuration Capability Specification

**Source narrative**: `openspec/specs/crypto/tls.md`
**Crates**: `ic-crypto-tls-cert-validation`, `ic-crypto-tls-interfaces`
**Key files**: `rs/crypto/tls_cert_validation/`, `rs/crypto/tls_interfaces/`

---

## REQ-TLS-001: TLS Server Config with Client Auth

The TLS layer MUST provide TLS 1.3 server configuration with mutual authentication.

### SCENARIO-TLS-001: Server config creation
**Given** `server_config` is called with `SomeOrAllNodes` and a registry version
**When** the config is created
**Then** minimum protocol version is TLS 1.3
**And** supported signature algorithm is Ed25519
**And** cipher suites are TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384
**And** client authentication is mandatory

### SCENARIO-TLS-002: Client authentication against registry
**Given** a client connects and presents a TLS certificate
**When** verification runs
**Then** the claimed `NodeId` is extracted from the certificate's subject name
**And** if `allowed_clients` is `Some(set)`, the NodeId must be in the set
**And** the registry certificate for that NodeId must equal the handshake certificate

### SCENARIO-TLS-003: Client not in allowed set
**Given** the connecting client's NodeId is not in the allowed set
**When** TLS handshake runs
**Then** the connection is rejected

---

## REQ-TLS-002: TLS Client Config

The TLS layer MUST provide client configuration that authenticates the server.

### SCENARIO-TLS-004: Client config with server verification
**Given** `client_config` is called with a target server NodeId
**When** the config is created
**Then** the client verifies the server's certificate against the registry
**And** the claimed NodeId in the certificate must equal the expected server NodeId

---

## REQ-TLS-003: TLS Certificate from Registry

TLS certificates MUST be fetchable from the IC registry.

### SCENARIO-TLS-005: Certificate not found in registry
**Given** `tls_cert_from_registry` is called for a node not in the registry at the given version
**When** the lookup runs
**Then** `TlsCertFromRegistryError::CertificateNotInRegistry` is returned

---

## REQ-TLS-004: TLS Public Key Certificate

The `TlsPublicKeyCert` type MUST wrap X.509 certificates in DER format.

### SCENARIO-TLS-006: Create from DER
**Given** `TlsPublicKeyCert::new_from_der` is called with valid DER bytes
**When** parsing runs
**Then** the bytes are parsed as an X.509 certificate
**And** the DER must be fully consumed (no remainder)

### SCENARIO-TLS-007: Create from PEM
**Given** `TlsPublicKeyCert::new_from_pem` is called with a PEM string
**When** parsing runs
**Then** the PEM is decoded to DER and validated

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-TLS-001 | Server config with client auth | narrative | rs/crypto/tls_cert_validation/ |
| REQ-TLS-002 | Client config | narrative | rs/crypto/tls_cert_validation/ |
| REQ-TLS-003 | Certificate from registry | narrative | rs/crypto/tls_cert_validation/ |
| REQ-TLS-004 | TLS public key certificate | narrative | rs/crypto/tls_cert_validation/ |
