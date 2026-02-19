//! Fallible conversion from one type to another that can be used as a tower middleware.
//!
//! # Examples
//!
//! ## To convert requests
//!
//! A converter can be used to convert request types:
//! * If the result of the conversion is [`Ok`], the converted type will be forwarded to the inner service.
//! * If the result of the conversion is [`Err`], the error will be returned and the inner service will *not* be called.
//!
//! When used to convert requests (with [`ConvertRequestLayer`], the functionality offered by [`Convert`] is similar to that of
//! [`Predicate`](https://docs.rs/tower/0.5.2/tower/filter/trait.Predicate.html) in that it can act as a *filter*. The main difference is that the error does not need to be boxed.
//!
//! ```rust
//! use std::convert::Infallible;
//! use canhttp::convert::{Convert, ConvertServiceBuilder};
//! use tower::{ServiceBuilder, Service, ServiceExt};
//!
//!  async fn bare_bone_service(request: Vec<u8>) -> Result<Vec<u8>, Infallible> {
//!    Ok(request)
//!  }
//!
//! struct UsefulRequest(Vec<u8>);
//!
//! #[derive(Clone)]
//! struct UsefulRequestConverter;
//!
//! impl Convert<UsefulRequest> for UsefulRequestConverter {
//!     type Output = Vec<u8>;
//!     type Error = Infallible;
//!
//!     fn try_convert(&mut self, input: UsefulRequest) -> Result<Self::Output, Self::Error> {
//!         Ok(input.0)
//!     }
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut service = ServiceBuilder::new()
//!     .convert_request(UsefulRequestConverter)
//!     .service_fn(bare_bone_service);
//!
//! let request = UsefulRequest(vec![42]);
//!
//! let response = service
//!     .ready()
//!     .await?
//!     .call(request)
//!     .await?;
//!
//! assert_eq!(response, vec![42_u8]);
//! # Ok(())
//! # }
//! ```
//!
//! ## To convert responses
//!
//! A converter can be used to convert response types:
//! ```rust
//! use std::convert::Infallible;
//! use canhttp::convert::{Convert, ConvertServiceBuilder};
//! use tower::{ServiceBuilder, Service, ServiceExt};
//!
//!  async fn bare_bone_service(request: Vec<u8>) -> Result<Vec<u8>, Infallible> {
//!    Ok(request)
//!  }
//!
//! #[derive(Debug, PartialEq)]
//! struct UsefulResponse(Vec<u8>);
//!
//! #[derive(Clone)]
//! struct UsefulResponseConverter;
//!
//! impl Convert<Vec<u8>> for UsefulResponseConverter {
//!     type Output = UsefulResponse;
//!     type Error = Infallible;
//!
//!     fn try_convert(&mut self, input: Vec<u8>) -> Result<Self::Output, Self::Error> {
//!         Ok(UsefulResponse(input))
//!     }
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut service = ServiceBuilder::new()
//!     .convert_response(UsefulResponseConverter)
//!     .service_fn(bare_bone_service);
//!
//! let request = vec![42];
//!
//! let response = service
//!     .ready()
//!     .await?
//!     .call(request)
//!     .await?;
//!
//! assert_eq!(response, UsefulResponse(vec![42_u8]));
//! # Ok(())
//! # }
//! ```
//!
//! ## To convert errors
//!
//! A service that returns an error of type `Error` can be turned into a service that returns
//! errors of type `NewError`, if `Error` can be converted `Into` the type `NewError`.
//! This is automatically the case if `NewError` implements `From<Error>`.
//!
//! ```rust
//! use canhttp::convert::{Convert, ConvertServiceBuilder};
//! use tower::{ServiceBuilder, Service, ServiceExt};
//!
//!  enum Error {
//!     OhNo
//!  }
//!  async fn bare_bone_service(request: Vec<u8>) -> Result<Vec<u8>, Error> {
//!    Err(Error::OhNo)
//!  }
//!
//! #[derive(Debug, PartialEq)]
//! enum NewError {
//!     Oops
//! }
//!
//! impl From<Error> for NewError {
//!     fn from(value: Error) -> Self {
//!         match value {  
//!             Error::OhNo => NewError::Oops
//!         }
//!     }
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut service = ServiceBuilder::new()
//!     .convert_error::<NewError>()
//!     .service_fn(bare_bone_service);
//!
//! let request = vec![42];
//!
//! let response = service
//!     .ready()
//!     .await
//!     .unwrap()
//!     .call(request)
//!     .await;
//!
//! assert_eq!(response, Err(NewError::Oops));
//! # Ok(())
//! # }
//! ```

pub use error::{ConvertError, ConvertErrorLayer};
pub use request::{ConvertRequest, ConvertRequestLayer};
pub use response::{
    ConvertResponse, ConvertResponseLayer, CreateResponseFilter, CreateResponseFilterLayer,
    FilterResponse,
};

mod error;
mod request;
mod response;

use tower::ServiceBuilder;
use tower_layer::Stack;

/// Fallible conversion from one type to another.
pub trait Convert<Input> {
    /// Converted type if the conversion succeeds.
    type Output;
    /// Error type if the conversion fails
    type Error;

    /// Try to convert an instance of the input type to the output type.
    /// The conversion may fail, in which case an error is returned.
    fn try_convert(&mut self, input: Input) -> Result<Self::Output, Self::Error>;
}

/// Extension trait that adds methods to [`tower::ServiceBuilder`] for adding middleware
/// based on fallible conversion between types.
pub trait ConvertServiceBuilder<L> {
    /// Convert the request type.
    ///
    /// See the [module docs](crate::convert) for examples.
    fn convert_request<C>(self, f: C) -> ServiceBuilder<Stack<ConvertRequestLayer<C>, L>>;

    /// Convert the response type.
    ///
    /// See the [module docs](crate::convert) for examples.
    fn convert_response<C>(self, f: C) -> ServiceBuilder<Stack<ConvertResponseLayer<C>, L>>;

    /// Filter the response depending on the request.
    ///
    /// See the [module docs](crate::convert) for examples.
    fn filter_response<F>(self, f: F) -> ServiceBuilder<Stack<CreateResponseFilterLayer<F>, L>>;

    /// Convert the error type.
    ///
    /// See the [module docs](crate::convert) for examples.
    fn convert_error<NewError>(self) -> ServiceBuilder<Stack<ConvertErrorLayer<NewError>, L>>;
}

impl<L> ConvertServiceBuilder<L> for ServiceBuilder<L> {
    fn convert_request<C>(self, converter: C) -> ServiceBuilder<Stack<ConvertRequestLayer<C>, L>> {
        self.layer(ConvertRequestLayer::new(converter))
    }

    fn convert_response<C>(
        self,
        converter: C,
    ) -> ServiceBuilder<Stack<ConvertResponseLayer<C>, L>> {
        self.layer(ConvertResponseLayer::new(converter))
    }

    fn filter_response<F>(self, f: F) -> ServiceBuilder<Stack<CreateResponseFilterLayer<F>, L>> {
        self.layer(CreateResponseFilterLayer::new(f))
    }

    fn convert_error<NewError>(self) -> ServiceBuilder<Stack<ConvertErrorLayer<NewError>, L>> {
        self.layer(ConvertErrorLayer::new())
    }
}

/// Filter the response.
///
/// A specialized type of [`Convert`], where the [`Convert::Output`] type is the same as the input type.
pub trait Filter<Input> {
    /// Error type if the input is declared invalid.
    type Error;

    /// Filter the input and return an error if it fails.
    fn filter(&mut self, input: Input) -> Result<Input, Self::Error>;
}

impl<Input, F: Filter<Input>> Convert<Input> for F {
    type Output = Input;
    type Error = F::Error;

    fn try_convert(&mut self, response: Input) -> Result<Self::Output, Self::Error> {
        self.filter(response)
    }
}
