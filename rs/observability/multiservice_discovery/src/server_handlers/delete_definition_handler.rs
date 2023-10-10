use std::sync::Arc;

use tokio::sync::Mutex;
use warp::Reply;

use crate::definition::Definition;
use crate::server_handlers::WebResult;

pub async fn delete_definition(
    name: String,
    definitions: Arc<Mutex<Vec<Definition>>>,
) -> WebResult<impl Reply> {
    if name == "ic" {
        return Ok(warp::reply::with_status(
            "Cannot delete ic definition".to_string(),
            warp::http::StatusCode::BAD_REQUEST,
        ));
    }

    let mut definitions = definitions.lock().await;

    let index = definitions.iter().position(|d| d.name == name);

    match index {
        Some(index) => {
            let definition = definitions.remove(index);
            definition.stop_signal_sender.send(()).unwrap();
            Ok(warp::reply::with_status(
                "success".to_string(),
                warp::http::StatusCode::OK,
            ))
        }
        None => Ok(warp::reply::with_status(
            "Definition with this name does not exist".to_string(),
            warp::http::StatusCode::BAD_REQUEST,
        )),
    }
}
