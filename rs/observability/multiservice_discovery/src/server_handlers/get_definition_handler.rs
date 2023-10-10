use std::sync::Arc;

use tokio::sync::Mutex;
use warp::reply::json;
use warp::Reply;

use crate::definition::Definition;
use crate::server_handlers::dto::DefinitionDto;
use crate::server_handlers::WebResult;

pub async fn get_definitions(definitions: Arc<Mutex<Vec<Definition>>>) -> WebResult<impl Reply> {
    let definitions = definitions.lock().await;

    Ok(json(
        &definitions
            .iter()
            .map(|d| d.into())
            .collect::<Vec<DefinitionDto>>(),
    ))
}
