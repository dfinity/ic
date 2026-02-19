use crate::{retry::DoubleMaxResponseBytes, Client, HttpsOutcallError, IcError};
use tower::{ServiceBuilder, ServiceExt};

// Some middlewares like tower::retry need the underlying service to be cloneable.
#[test]
fn should_be_clone() {
    let client = Client::new_with_box_error();
    let _ = client.clone();

    let client = Client::new_with_error::<CustomError>();
    let _ = client.clone();
}

// Note that calling `Client::call` would require a canister environment.
// We just ensure that the trait bounds are satisfied to have a service.
#[tokio::test]
async fn should_be_able_to_use_retry_layer() {
    let mut service = ServiceBuilder::new()
        .retry(DoubleMaxResponseBytes)
        .service(Client::new_with_error::<CustomError>());
    let _ = service.ready().await.unwrap();

    let mut service = ServiceBuilder::new()
        .retry(DoubleMaxResponseBytes)
        .service(Client::new_with_box_error());
    let _ = service.ready().await.unwrap();
}

#[derive(Debug)]
struct CustomError(IcError);

impl HttpsOutcallError for CustomError {
    fn is_response_too_large(&self) -> bool {
        self.0.is_response_too_large()
    }
}

impl From<IcError> for CustomError {
    fn from(value: IcError) -> Self {
        CustomError(value)
    }
}
