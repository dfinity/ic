# Message Types

## Requirements

### Requirement: SignedIngressContent Ingress Message Structure
SignedIngressContent represents the contents of a signed ingress message, containing sender (UserId), canister_id, method_name, arg, ingress_expiry, and optional nonce.

#### Scenario: Ingress message fields
- **WHEN** a SignedIngressContent is constructed
- **THEN** sender() returns the UserId who sent the message
- **AND** canister_id() returns the target CanisterId
- **AND** method_name() returns the method being called
- **AND** arg() returns the argument bytes
- **AND** ingress_expiry() returns a Time computed from the nanos-since-epoch value

#### Scenario: Subnet-addressed ingress detection
- **WHEN** is_addressed_to_subnet() is called
- **THEN** it returns true if canister_id equals IC_00 (the management canister)
- **AND** false otherwise

### Requirement: SignedIngress Authenticated Ingress
SignedIngress combines SignedIngressContent with Authentication (signatures and delegation), providing the complete ingress message as received by the HTTP handler.

#### Scenario: SignedIngress identity
- **WHEN** id() is called on a SignedIngress
- **THEN** it returns the MessageId computed from the ingress content
- **AND** the MessageId is deterministic for the same content

#### Scenario: SignedIngress byte counting
- **WHEN** count_bytes() is called
- **THEN** it returns an estimate of the message size for resource tracking

### Requirement: Inter-Canister Request/Response Messages
Request and Response types model inter-canister communication, with Requests carrying calls and Responses carrying results or rejections.

#### Scenario: Request metadata tracking
- **WHEN** a Request is created with RequestMetadata
- **THEN** call_tree_depth starts at 0 for new call trees
- **AND** for_downstream_call() increments depth by 1
- **AND** call_tree_start_time remains unchanged for downstream calls

#### Scenario: Request deadline semantics
- **WHEN** a Request has deadline == NO_DEADLINE (CoarseTime 0)
- **THEN** it represents a guaranteed response call
- **WHEN** deadline is non-zero
- **THEN** it represents a best-effort call with a timeout

#### Scenario: CallbackId coupling
- **WHEN** a Request is sent with a CallbackId
- **THEN** the corresponding Response MUST reference the same CallbackId
- **AND** CallbackId is typed as Id<CallbackIdTag, u64>

### Requirement: MessageId Deterministic Identification
MessageId uniquely identifies an ingress message based on its content, computed as a representation-independent hash.

#### Scenario: MessageId length
- **WHEN** a MessageId is computed
- **THEN** its length equals EXPECTED_MESSAGE_ID_LENGTH (32 bytes / SHA-256)

#### Scenario: MessageId determinism
- **WHEN** the same ingress content is hashed twice
- **THEN** the resulting MessageIds are identical

### Requirement: IngressMessageId Composite Key
IngressMessageId combines an expiry time and MessageId, used as the primary key for ingress pool lookups.

#### Scenario: IngressMessageId construction
- **WHEN** IngressMessageId::new(expiry_time, message_id) is called
- **THEN** expiry() returns the expiry_time
- **AND** the embedded message_id is accessible

### Requirement: IngressPayload Block Inclusion
IngressPayload is the collection of ingress messages included in a block, with serialization/deserialization support.

#### Scenario: IngressPayload error handling
- **WHEN** deserialization of an IngressPayload fails
- **THEN** IngressPayloadError is returned with details about the failure

### Requirement: Ingress Status Lifecycle
IngressStatus tracks the lifecycle of an ingress message through the system: Received, Processing, Completed, Failed, or Unknown.

#### Scenario: WasmResult outcomes
- **WHEN** an ingress message execution completes
- **THEN** the result is either WasmResult::Reply(bytes) for success or WasmResult::Reject(string) for rejection

### Requirement: Query Message Read-Only Requests
Query messages represent read-only requests that do not modify canister state.

#### Scenario: Query structure
- **WHEN** a Query is constructed
- **THEN** it contains source (UserId), receiver (CanisterId), method_name, and method_payload

### Requirement: HttpRequest Envelope Authentication
HttpRequestEnvelope wraps HTTP request content with authentication data (sender_pubkey, sender_sig, sender_delegation).

#### Scenario: HttpRequest content types
- **WHEN** an HttpRequest is received
- **THEN** its content is one of HttpCallContent (canister update), HttpQueryContent, or HttpReadStateContent

### Requirement: Response Reject Codes
Responses can carry rejection information with typed RejectCode values from the IC specification.

#### Scenario: Reject code mapping
- **WHEN** a canister execution results in rejection
- **THEN** the RejectCode identifies the class of error (SysFatal, SysTransient, DestinationInvalid, CanisterReject, CanisterError)
