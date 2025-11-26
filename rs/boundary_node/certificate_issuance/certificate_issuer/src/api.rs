use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Extension, Json,
    body::Body,
    extract::Path,
    http::{Request, Response},
};
use serde::{Deserialize, Serialize};

use crate::{
    certificate::Export,
    check::{Check, CheckError},
    registration::{
        Create, CreateError, Get, GetError, Id, Remove, RemoveError, Update, UpdateError,
        UpdateType,
    },
    work::Queue,
};

#[derive(Deserialize)]
pub struct CreateHandlerRequest {
    pub name: Id,
}

#[derive(Serialize)]
pub struct CreateHandlerResponse {
    pub id: Id,
}

#[allow(clippy::type_complexity)]
pub async fn create_handler(
    Extension((ck, c, q)): Extension<(Arc<dyn Check>, Arc<dyn Create>, Arc<dyn Queue>)>,
    Json(CreateHandlerRequest { name }): Json<CreateHandlerRequest>,
) -> Response<Body> {
    // Check request
    let canister = match ck.check(&name).await {
        Ok(canister) => canister,
        Err(CheckError::UnexpectedError(_)) => {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap();
        }
        Err(err) => {
            return Response::builder()
                .status(400)
                .body(Body::from(err.to_string()))
                .unwrap();
        }
    };

    // Create registration
    let (id, is_duplicate) = match c.create(&name, &canister).await {
        Ok(id) => (id, false),
        Err(CreateError::Duplicate(id)) => (id, true),
        Err(CreateError::RateLimited(domain)) => {
            return Response::builder()
                .status(429)
                .body(Body::from(format!(
                    "rate limit exceeded for domain {domain}"
                )))
                .unwrap();
        }
        Err(CreateError::UnexpectedError(_)) => {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap();
        }
    };

    // Queue task
    if !is_duplicate {
        let t = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(t) => t.as_nanos() as u64,
            Err(_) => {
                return Response::builder()
                    .status(500)
                    .body(Body::from("unexpected error"))
                    .unwrap();
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
                .unwrap();
        }
    };

    Response::builder()
        .status(200)
        .body(Body::from(bs))
        .unwrap()
}

pub async fn get_handler(
    Extension(g): Extension<Arc<dyn Get>>,
    Path(id): Path<Id>,
    _: Request<Body>,
) -> Response<Body> {
    let reg = match g.get(&id).await {
        Ok(reg) => reg,

        Err(GetError::NotFound) => {
            return Response::builder()
                .status(404)
                .body(Body::from("not found"))
                .unwrap();
        }

        Err(GetError::UnexpectedError(_)) => {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap();
        }
    };

    let bs = match serde_json::ser::to_vec(&reg) {
        Ok(bs) => bs,
        Err(_) => {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap();
        }
    };

    Response::builder()
        .status(200)
        .body(Body::from(bs))
        .unwrap()
}

#[allow(clippy::type_complexity)]
pub async fn update_handler(
    Extension((ck, g, u)): Extension<(Arc<dyn Check>, Arc<dyn Get>, Arc<dyn Update>)>,
    Path(id): Path<Id>,
    _: Request<Body>,
) -> Response<Body> {
    let reg = match g.get(&id).await {
        Ok(reg) => reg,

        Err(GetError::NotFound) => {
            return Response::builder()
                .status(404)
                .body(Body::from("not found"))
                .unwrap();
        }

        Err(GetError::UnexpectedError(_)) => {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap();
        }
    };

    // Run through checker to get canister ID
    let canister = match ck.check(&reg.name).await {
        Ok(canister) => canister,
        Err(CheckError::UnexpectedError(_)) => {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap();
        }
        Err(err) => {
            return Response::builder()
                .status(400)
                .body(Body::from(err.to_string()))
                .unwrap();
        }
    };

    if reg.canister != canister {
        match u.update(&id, &UpdateType::Canister(canister)).await {
            Ok(()) => {}

            Err(UpdateError::NotFound) => {
                return Response::builder()
                    .status(404)
                    .body(Body::from("not found"))
                    .unwrap();
            }

            Err(UpdateError::UnexpectedError(_)) => {
                return Response::builder()
                    .status(500)
                    .body(Body::from("unexpected error"))
                    .unwrap();
            }
        };
    }

    Response::builder().status(200).body(Body::empty()).unwrap()
}

#[allow(clippy::type_complexity)]
pub async fn remove_handler(
    Extension((ck, g, r)): Extension<(Arc<dyn Check>, Arc<dyn Get>, Arc<dyn Remove>)>,
    Path(id): Path<Id>,
    _: Request<Body>,
) -> Response<Body> {
    let reg = match g.get(&id).await {
        Ok(reg) => reg,

        Err(GetError::NotFound) => {
            return Response::builder()
                .status(404)
                .body(Body::from("not found"))
                .unwrap();
        }

        Err(GetError::UnexpectedError(_)) => {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap();
        }
    };

    // Run checker to ensure either removal conditions are met:
    // 1. missing delegation cname record
    // 2. missing canister ID mapping
    match ck.check(&reg.name).await {
        Err(CheckError::MissingDnsCname { .. }) => {}
        Err(CheckError::MissingDnsTxtCanisterId { .. }) => {}
        Err(CheckError::MissingKnownDomains { .. }) => {}
        _ => {
            return Response::builder()
                .status(400)
                .body(Body::from("removal conditions not met: please ensure your delegation cname and canister mapping records are removed"))
                .unwrap();
        }
    };

    match r.remove(&id).await {
        Ok(()) => {}

        Err(RemoveError::NotFound) => {
            return Response::builder()
                .status(404)
                .body(Body::from("not found"))
                .unwrap();
        }

        Err(RemoveError::UnexpectedError(_)) => {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap();
        }
    };

    Response::builder().status(200).body(Body::empty()).unwrap()
}

pub async fn export_handler(
    Extension(e): Extension<Arc<dyn Export>>,
    _: Request<Body>,
) -> Response<Body> {
    let pkgs = match e
        .export(
            None,     // key
            u64::MAX, // limit
        )
        .await
    {
        Ok((pkgs, _)) => pkgs,
        Err(_) => {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap();
        }
    };

    let bs = match serde_json::ser::to_vec(&pkgs) {
        Ok(bs) => bs,
        Err(_) => {
            return Response::builder()
                .status(500)
                .body(Body::from("unexpected error"))
                .unwrap();
        }
    };

    Response::builder()
        .status(200)
        .body(Body::from(bs))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Error;
    use candid::Principal;
    use mockall::predicate;

    use crate::{
        check::MockCheck,
        registration::{MockGet, MockRemove, MockUpdate, Registration, State},
    };

    #[tokio::test]
    async fn update_ok() -> Result<(), Error> {
        let mut getter = MockGet::new();
        getter
            .expect_get()
            .times(1)
            .with(predicate::eq(Id::from("id")))
            .returning(|_| {
                Ok(Registration {
                    name: String::from("name"),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    state: State::PendingOrder,
                })
            });

        let mut checker = MockCheck::new();
        checker
            .expect_check()
            .times(1)
            .with(predicate::eq("name"))
            .returning(|_| Ok(Principal::from_text("2ibo7-dia").unwrap()));

        let mut updater = MockUpdate::new();
        updater
            .expect_update()
            .times(1)
            .with(
                predicate::eq(Id::from("id")),
                predicate::eq(UpdateType::Canister(
                    Principal::from_text("2ibo7-dia").unwrap(),
                )),
            )
            .returning(|_, _| Ok(()));

        let resp = update_handler(
            Extension((Arc::new(checker), Arc::new(getter), Arc::new(updater))),
            Path("id".into()),
            Request::builder().body(Body::empty())?,
        )
        .await;

        assert_eq!(resp.status(), 200);

        Ok(())
    }

    #[tokio::test]
    async fn update_skip() -> Result<(), Error> {
        let mut getter = MockGet::new();
        getter
            .expect_get()
            .times(1)
            .with(predicate::eq(Id::from("id")))
            .returning(|_| {
                Ok(Registration {
                    name: String::from("name"),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    state: State::PendingOrder,
                })
            });

        let mut checker = MockCheck::new();
        checker
            .expect_check()
            .times(1)
            .with(predicate::eq("name"))
            .returning(|_| Ok(Principal::from_text("aaaaa-aa").unwrap()));

        let mut updater = MockUpdate::new();
        updater.expect_update().never();

        let resp = update_handler(
            Extension((Arc::new(checker), Arc::new(getter), Arc::new(updater))),
            Path("id".into()),
            Request::builder().body(Body::empty())?,
        )
        .await;

        assert_eq!(resp.status(), 200);

        Ok(())
    }

    #[tokio::test]
    async fn remove_ok() -> Result<(), Error> {
        let mut getter = MockGet::new();
        getter
            .expect_get()
            .times(1)
            .with(predicate::eq(Id::from("id")))
            .returning(|_| {
                Ok(Registration {
                    name: String::from("name"),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    state: State::PendingOrder,
                })
            });

        let mut checker = MockCheck::new();
        checker
            .expect_check()
            .times(1)
            .with(predicate::eq("name"))
            .returning(|_| {
                Err(CheckError::MissingDnsCname {
                    src: "src".into(),
                    dst: "dst".into(),
                })
            });

        let mut remover = MockRemove::new();
        remover
            .expect_remove()
            .times(1)
            .with(predicate::eq(Id::from("id")))
            .returning(|_| Ok(()));

        let resp = remove_handler(
            Extension((Arc::new(checker), Arc::new(getter), Arc::new(remover))),
            Path("id".into()),
            Request::builder().body(Body::empty())?,
        )
        .await;

        assert_eq!(resp.status(), 200);

        Ok(())
    }

    #[tokio::test]
    async fn remove_bad_request() -> Result<(), Error> {
        let mut getter = MockGet::new();
        getter
            .expect_get()
            .times(1)
            .with(predicate::eq(Id::from("id")))
            .returning(|_| {
                Ok(Registration {
                    name: String::from("name"),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    state: State::PendingOrder,
                })
            });

        let mut checker = MockCheck::new();
        checker
            .expect_check()
            .times(1)
            .with(predicate::eq("name"))
            .returning(|_| Ok(Principal::from_text("aaaaa-aa").unwrap()));

        let mut remover = MockRemove::new();
        remover.expect_remove().never();

        let resp = remove_handler(
            Extension((Arc::new(checker), Arc::new(getter), Arc::new(remover))),
            Path("id".into()),
            Request::builder().body(Body::empty())?,
        )
        .await;

        assert_eq!(resp.status(), 400);

        Ok(())
    }
}
