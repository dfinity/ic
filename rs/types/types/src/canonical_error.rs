// The following list is directly taken from https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto

use ::http::StatusCode;
use std::error::Error;
use std::fmt;

// Sometimes multiple error codes may apply.  Services should return
// the most specific error code that applies.  For example, prefer
// `OUT_OF_RANGE` over `FAILED_PRECONDITION` if both codes apply.
// Similarly prefer `NOT_FOUND` or `ALREADY_EXISTS` over `FAILED_PRECONDITION`.
#[derive(Debug, PartialEq, Clone)]
pub enum CanonicalErrorCode {
    // Two of the original error codes are missing - 'OK' and 'CANCELLED'.
    // Those two error codes don't make much sense when used in Rust.
    // Using the std::result::Result, makes the 'OK' error code obsolete.
    // Due to the asynchronous nature of networking in Rust and the fact
    // that cancellation is no cooperative this make 'CANCELLED' obsolete.

    // Unknown error.  For example, this error may be returned when
    // a `Status` value received from another address space belongs to
    // an error space that is not known in this address space.  Also
    // errors raised by APIs that do not return enough error information
    // may be converted to this error.
    //
    // HTTP Mapping: 500 Internal Server Error
    Unknown = 2,

    // The client specified an invalid argument.  Note that this differs
    // from `FAILED_PRECONDITION`.  `INVALID_ARGUMENT` indicates arguments
    // that are problematic regardless of the state of the system
    // (e.g., a malformed file name).
    //
    // HTTP Mapping: 400 Bad Request
    InvalidArgument = 3,

    // The deadline expired before the operation could complete. For operations
    // that change the state of the system, this error may be returned
    // even if the operation has completed successfully.  For example, a
    // successful response from a server could have been delayed long
    // enough for the deadline to expire.
    //
    // HTTP Mapping: 504 Gateway Timeout
    DeadlineExceeded = 4,

    // Some requested entity (e.g., file or directory) was not found.
    //
    // Note to server developers: if a request is denied for an entire class
    // of users, such as gradual feature rollout or undocumented whitelist,
    // `NOT_FOUND` may be used. If a request is denied for some users within
    // a class of users, such as user-based access control, `PERMISSION_DENIED`
    // must be used.
    //
    // HTTP Mapping: 404 Not Found
    NotFound = 5,

    // The entity that a client attempted to create (e.g., file or directory)
    // already exists.
    //
    // HTTP Mapping: 409 Conflict
    AlreadyExists = 6,

    // The caller does not have permission to execute the specified
    // operation. `PERMISSION_DENIED` must not be used for rejections
    // caused by exhausting some resource (use `RESOURCE_EXHAUSTED`
    // instead for those errors). `PERMISSION_DENIED` must not be
    // used if the caller can not be identified (use `UNAUTHENTICATED`
    // instead for those errors). This error code does not imply the
    // request is valid or the requested entity exists or satisfies
    // other pre-conditions.
    //
    // HTTP Mapping: 403 Forbidden
    PermissionDenied = 7,

    // The request does not have valid authentication credentials for the
    // operation.
    //
    // HTTP Mapping: 401 Unauthorized
    Unauthenticated = 16,

    // Some resource has been exhausted, perhaps a per-user quota, or
    // perhaps the entire file system is out of space.
    //
    // HTTP Mapping: 429 Too Many Requests
    ResourceExhausted = 8,

    // The operation was rejected because the system is not in a state
    // required for the operation's execution.  For example, the directory
    // to be deleted is non-empty, an rmdir operation is applied to
    // a non-directory, etc.
    //
    // Service implementors can use the following guidelines to decide
    // between `FAILED_PRECONDITION`, `ABORTED`, and `UNAVAILABLE`:
    //  (a) Use `UNAVAILABLE` if the client can retry just the failing call.
    //  (b) Use `ABORTED` if the client should retry at a higher level
    //      (e.g., when a client-specified test-and-set fails, indicating the
    //      client should restart a read-modify-write sequence).
    //  (c) Use `FAILED_PRECONDITION` if the client should not retry until
    //      the system state has been explicitly fixed.  E.g., if an "rmdir"
    //      fails because the directory is non-empty, `FAILED_PRECONDITION`
    //      should be returned since the client should not retry unless
    //      the files are deleted from the directory.
    //
    // HTTP Mapping: 400 Bad Request
    FailedPrecondition = 9,

    // The operation was aborted, typically due to a concurrency issue such as
    // a sequencer check failure or transaction abort.
    //
    // See the guidelines above for deciding between `FAILED_PRECONDITION`,
    // `ABORTED`, and `UNAVAILABLE`.
    //
    // HTTP Mapping: 409 Conflict
    Aborted = 10,

    // The operation was attempted past the valid range.  E.g., seeking or
    // reading past end-of-file.
    //
    // Unlike `INVALID_ARGUMENT`, this error indicates a problem that may
    // be fixed if the system state changes. For example, a 32-bit file
    // system will generate `INVALID_ARGUMENT` if asked to read at an
    // offset that is not in the range [0,2^32-1], but it will generate
    // `OUT_OF_RANGE` if asked to read from an offset past the current
    // file size.
    //
    // There is a fair bit of overlap between `FAILED_PRECONDITION` and
    // `OUT_OF_RANGE`.  We recommend using `OUT_OF_RANGE` (the more specific
    // error) when it applies so that callers who are iterating through
    // a space can easily look for an `OUT_OF_RANGE` error to detect when
    // they are done.
    //
    // HTTP Mapping: 400 Bad Request
    OutOfRange = 11,

    // The operation is not implemented or is not supported/enabled in this
    // service.
    //
    // HTTP Mapping: 501 Not Implemented
    Unimplemented = 12,

    // Internal errors.  This means that some invariants expected by the
    // underlying system have been broken.  This error code is reserved
    // for serious errors.
    //
    // HTTP Mapping: 500 Internal Server Error
    Internal = 13,

    // The service is currently unavailable.  This is most likely a
    // transient condition, which can be corrected by retrying with
    // a backoff. Note that it is not always safe to retry
    // non-idempotent operations.
    //
    // See the guidelines above for deciding between `FAILED_PRECONDITION`,
    // `ABORTED`, and `UNAVAILABLE`.
    //
    // HTTP Mapping: 503 Service Unavailable
    Unavailable = 14,

    // Unrecoverable data loss or corruption.
    //
    // HTTP Mapping: 500 Internal Server Error
    DataLoss = 15,
}

#[derive(Debug, PartialEq, Clone)]
pub struct CanonicalError {
    pub code: CanonicalErrorCode,
    pub message: String,
}

impl CanonicalError {
    fn new(code: CanonicalErrorCode, msg: String) -> Self {
        Self { code, message: msg }
    }
}

impl CanonicalErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            CanonicalErrorCode::Unknown => "Unknown",
            CanonicalErrorCode::InvalidArgument => "Invalid Argument",
            CanonicalErrorCode::DeadlineExceeded => "Deadline Exceeded",
            CanonicalErrorCode::NotFound => "Not Found",
            CanonicalErrorCode::AlreadyExists => "Already Exists",
            CanonicalErrorCode::PermissionDenied => "Permission Denied",
            CanonicalErrorCode::Unauthenticated => "Unauthenticated",
            CanonicalErrorCode::ResourceExhausted => "Resource Exhausted",
            CanonicalErrorCode::FailedPrecondition => "Failed Precondition",
            CanonicalErrorCode::Aborted => "Aborted",
            CanonicalErrorCode::OutOfRange => "Out of Range",
            CanonicalErrorCode::Unimplemented => "Unimplemented",
            CanonicalErrorCode::Internal => "Internal",
            CanonicalErrorCode::Unavailable => "Unavailable",
            CanonicalErrorCode::DataLoss => "Data Loss",
        }
    }
}

impl From<CanonicalErrorCode> for StatusCode {
    fn from(error_code: CanonicalErrorCode) -> Self {
        match error_code {
            CanonicalErrorCode::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
            CanonicalErrorCode::InvalidArgument => StatusCode::BAD_REQUEST,
            CanonicalErrorCode::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
            CanonicalErrorCode::NotFound => StatusCode::NOT_FOUND,
            CanonicalErrorCode::AlreadyExists => StatusCode::CONFLICT,
            CanonicalErrorCode::PermissionDenied => StatusCode::FORBIDDEN,
            CanonicalErrorCode::Unauthenticated => StatusCode::UNAUTHORIZED,
            CanonicalErrorCode::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
            CanonicalErrorCode::FailedPrecondition => StatusCode::BAD_REQUEST,
            CanonicalErrorCode::Aborted => StatusCode::CONFLICT,
            CanonicalErrorCode::OutOfRange => StatusCode::BAD_REQUEST,
            CanonicalErrorCode::Unimplemented => StatusCode::NOT_IMPLEMENTED,
            CanonicalErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            CanonicalErrorCode::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            CanonicalErrorCode::DataLoss => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl Error for CanonicalError {}

/// Returns 'Unknown' error if downcasting failed.
impl From<Box<(dyn Error + Send + Sync + 'static)>> for CanonicalError {
    fn from(boxed_error: Box<(dyn Error + Send + Sync + 'static)>) -> Self {
        *boxed_error
            .downcast::<CanonicalError>()
            .unwrap_or_else(|_| {
                Box::new(unknown_error(
                    "Could not convert Box<(dyn Error ...)> to CanonicalError.".to_string(),
                ))
            })
    }
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

// These convenience functions create an `CanonicalError` object with an error
// code as indicated by the associated function name, using the error message
// passed in `msg`.

pub fn unknown_error(msg: String) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::Unknown, msg)
}

pub fn invalid_argument_error(msg: String) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidArgument, msg)
}

pub fn deadline_exceeded_error(msg: String) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::DeadlineExceeded, msg)
}

pub fn not_found_error(msg: String) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::NotFound, msg)
}

pub fn already_exists_error(msg: String) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::AlreadyExists, msg)
}

pub fn permission_denied_error(msg: String) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::PermissionDenied, msg)
}

pub fn unauthenticated_error(msg: String) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::Unauthenticated, msg)
}

pub fn resource_exhausted_error(msg: String) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::ResourceExhausted, msg)
}

pub fn failed_precondition_error(msg: String) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::FailedPrecondition, msg)
}

pub fn aborted_error(msg: String) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::Aborted, msg)
}

pub fn out_of_range_error(msg: String) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::OutOfRange, msg)
}

pub fn unimplemented_error(msg: String) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::Unimplemented, msg)
}

pub fn internal_error(msg: String) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::Internal, msg)
}

pub fn unavailable_error(msg: String) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::Unavailable, msg)
}

pub fn data_loss_error(msg: String) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::DataLoss, msg)
}
