# TLS Configuration and Handshake

**Crates**: `ic-crypto-tls-cert-validation`

## Requirements

### Requirement: TLS Server Configuration with Client Authentication
The `TlsConfig` trait provides TLS 1.3 configuration for node-to-node communication.

#### Scenario: Creating a server config with allowed clients
- **WHEN** `server_config` is called with `SomeOrAllNodes` and a registry version
- **THEN** a rustls `ServerConfig` is created with:
  - Minimum protocol version: TLS 1.3
  - Supported signature algorithms: Ed25519
  - Allowed cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
  - Mandatory client authentication with Ed25519 certificate
  - Maximum of 1 intermediate CA certificate
- **AND** the server's own TLS certificate is loaded from the vault
- **AND** the server's TLS secret key is loaded from the vault for signing

#### Scenario: Client authentication check
- **WHEN** a client connects and presents a certificate during the TLS handshake
- **THEN** the server extracts the claimed NodeId from the certificate's subject name
- **AND** if `allowed_clients` is `SomeOrAllNodes::Some(set)`, the claimed NodeId must be in the set
- **AND** the server queries the registry for the TLS certificate of the claimed NodeId
- **AND** the registry certificate must equal the handshake certificate

#### Scenario: Client not in allowed set
- **WHEN** the connecting client's NodeId is not in the allowed set
- **THEN** the TLS handshake fails and the connection is rejected

#### Scenario: Certificate mismatch
- **WHEN** the client's handshake certificate does not match the registry certificate
- **THEN** the TLS handshake fails

### Requirement: TLS Server Configuration without Client Authentication

#### Scenario: Creating a server config without client auth
- **WHEN** `server_config_without_client_auth` is called with a registry version
- **THEN** a rustls `ServerConfig` is created with:
  - Minimum protocol version: TLS 1.3
  - Supported signature algorithms: Ed25519
  - Allowed cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
  - No client authentication performed
- **AND** any client can connect without presenting a certificate

### Requirement: TLS Client Configuration

#### Scenario: Creating a client config
- **WHEN** `client_config` is called with a target server NodeId and registry version
- **THEN** a rustls `ClientConfig` is created with:
  - Minimum protocol version: TLS 1.3
  - Supported signature algorithms: Ed25519
  - Allowed cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
  - Mandatory server authentication with Ed25519 certificate
- **AND** the client's own TLS certificate and key are loaded from the vault

#### Scenario: Server authentication check
- **WHEN** the server presents a certificate during the handshake
- **THEN** the client extracts the claimed NodeId from the certificate's subject name
- **AND** the claimed NodeId must equal the expected `server` NodeId
- **AND** the client queries the registry for the TLS certificate of the server
- **AND** the registry certificate must equal the handshake certificate

### Requirement: TLS Configuration Error Handling

#### Scenario: Registry access error
- **WHEN** the registry cannot be accessed during TLS config creation
- **THEN** `TlsConfigError::RegistryError` is returned

#### Scenario: Certificate not in registry
- **WHEN** a node's TLS certificate is not found in the registry
- **THEN** `TlsConfigError::CertificateNotInRegistry` is returned with node_id and registry_version

#### Scenario: Malformed self-certificate
- **WHEN** the node's own TLS certificate is malformed
- **THEN** `TlsConfigError::MalformedSelfCertificate` is returned with an internal error message

#### Scenario: Missing or malformed secret key
- **WHEN** the secret key for the node's TLS certificate cannot be found or is malformed
- **THEN** the crypto component panics (this indicates an error in node setup)

### Requirement: TLS Public Key Certificate
The `TlsPublicKeyCert` type wraps an X.509 certificate in DER format.

#### Scenario: Creating from DER
- **WHEN** `TlsPublicKeyCert::new_from_der` is called with DER bytes
- **THEN** the bytes are parsed as an X.509 certificate
- **AND** the DER must be fully consumed (no remainder)
- **AND** a `TlsPublicKeyCertCreationError` is returned if parsing fails

#### Scenario: Creating from PEM
- **WHEN** `TlsPublicKeyCert::new_from_pem` is called with a PEM string
- **THEN** the PEM is decoded to DER
- **AND** the DER is validated as in the DER creation path

#### Scenario: Converting to protobuf
- **WHEN** `to_proto` is called on a `TlsPublicKeyCert`
- **THEN** an `X509PublicKeyCert` protobuf is returned with the DER bytes

### Requirement: TLS Certificate from Registry

#### Scenario: Fetching TLS certificate from registry
- **WHEN** `tls_cert_from_registry` is called with a node_id and registry_version
- **THEN** the registry is queried for the node's TLS certificate
- **AND** the raw certificate is converted to `TlsPublicKeyCert`

#### Scenario: Certificate not found
- **WHEN** the registry has no TLS certificate for the node at the given version
- **THEN** `TlsCertFromRegistryError::CertificateNotInRegistry` is returned

### Requirement: CSP Server Signing Key for TLS
A `CspServerSigningKey` wraps the vault's TLS signing capability into the rustls `SigningKey` interface.

#### Scenario: Signing during TLS handshake
- **WHEN** rustls needs a signature during the server handshake
- **THEN** the CSP vault's TLS signing method is called
- **AND** the algorithm is Ed25519
- **AND** the signature is produced using the node's TLS secret key

### Requirement: Node Certificate Verifier
A custom rustls `ClientCertVerifier` / `ServerCertVerifier` that verifies peer certificates against the IC registry.

#### Scenario: Verifying a peer certificate
- **WHEN** a peer presents a certificate during TLS handshake
- **THEN** the verifier extracts the NodeId from the certificate's subject name
- **AND** fetches the expected certificate from the IC registry
- **AND** compares the handshake certificate with the registry certificate
- **AND** accepts or rejects the connection based on the comparison
