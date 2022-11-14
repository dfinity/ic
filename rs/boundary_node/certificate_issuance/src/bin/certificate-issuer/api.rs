use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Body,
    extract::Path,
    http::{Request, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    certificate::Export,
    check::{Check, CheckError},
    registration::{Create, CreateError, Get, GetError},
    work::Queue,
};

#[derive(Deserialize)]
pub struct CreateHandlerRequest {
    pub domain: String,
}

#[derive(Serialize)]
pub struct CreateHandlerResponse {
    pub id: Uuid,
}

#[allow(clippy::type_complexity)]
pub async fn create_handler(
    Extension((ck, c, q)): Extension<(Arc<dyn Check>, Arc<dyn Create>, Arc<dyn Queue>)>,
    Json(CreateHandlerRequest { domain }): Json<CreateHandlerRequest>,
) -> Response<Body> {
    // Check request
    let canister = match ck.check(&domain).await {
        Ok(canister) => canister,
        Err(CheckError::UnexpectedError(_)) => {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap()
        }
        Err(err) => {
            return Response::builder()
                .status(500)
                .body(Body::from(err.to_string()))
                .unwrap()
        }
    };

    // Create registration
    let (id, is_duplicate) = match c.create(&domain, &canister).await {
        Ok(id) => (id, false),
        Err(CreateError::Duplicate(id)) => (id, true),
        Err(CreateError::UnexpectedError(_)) => {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap()
        }
    };

    // Queue task
    if !is_duplicate {
        let t = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(t) => t.as_millis() as u64,
            Err(_) => {
                return Response::builder()
                    .status(500)
                    .body(Body::from("unexpected error"))
                    .unwrap()
            }
        };

        if (q.queue(&id, t).await).is_err() {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap();
        }
    }

    let bs = match serde_json::ser::to_vec(&CreateHandlerResponse { id }) {
        Ok(bs) => bs,
        Err(_) => {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap()
        }
    };

    Response::builder()
        .status(200)
        .body(Body::from(bs))
        .unwrap()
}

pub async fn get_handler(
    Extension(g): Extension<Arc<dyn Get>>,
    Path(id): Path<Uuid>,
    _: Request<Body>,
) -> Response<Body> {
    let reg = match g.get(&id).await {
        Ok(reg) => reg,

        Err(GetError::NotFound(_)) => {
            return Response::builder()
                .status(404)
                .body(Body::from("not found"))
                .unwrap()
        }

        Err(GetError::UnexpectedError(_)) => {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap()
        }
    };

    let bs = match serde_json::ser::to_vec(&reg) {
        Ok(bs) => bs,
        Err(_) => {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap()
        }
    };

    Response::builder()
        .status(200)
        .body(Body::from(bs))
        .unwrap()
}

// TODO(or): wrap this export_handler with ttl-based caching and E-tag check
pub async fn export_handler(
    Extension(e): Extension<Arc<dyn Export>>,
    _: Request<Body>,
) -> Response<Body> {
    let pkgs = match e.export().await {
        Ok(pkgs) => pkgs,
        Err(_) => {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap()
        }
    };

    let bs = match serde_json::ser::to_vec(&pkgs) {
        Ok(bs) => bs,
        Err(_) => {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap()
        }
    };

    Response::builder()
        .status(200)
        .body(Body::from(bs))
        .unwrap()
}
