use std::sync::Arc;
use std::thread::JoinHandle;

use slog::{info, Logger};
use tokio::sync::Mutex;
use warp::{Filter, Rejection};

use crate::definition::Definition;
use crate::server_handlers::add_boundary_node_to_definition_handler::add_boundary_node;
use crate::server_handlers::add_boundary_node_to_definition_handler::AddBoundaryNodeToDefinitionBinding;
use crate::server_handlers::add_definition_handler::{add_definition, AddDefinitionBinding};
use crate::server_handlers::delete_definition_handler::delete_definition;
use crate::server_handlers::export_prometheus_config_handler::{
    export_prometheus_config, ExportDefinitionConfigBinding,
};
use crate::server_handlers::export_targets_handler::export_targets;
use crate::server_handlers::export_targets_handler::ExportTargetsBinding;
use crate::server_handlers::get_definition_handler::get_definitions;
use crate::CliArgs;

mod add_boundary_node_to_definition_handler;
mod add_definition_handler;
mod delete_definition_handler;
pub mod dto;
mod export_prometheus_config_handler;
mod export_targets_handler;
mod get_definition_handler;

pub type WebResult<T> = Result<T, Rejection>;

pub async fn prepare_server(
    recv: tokio::sync::oneshot::Receiver<()>,
    log: Logger,
    items: Arc<Mutex<Vec<Definition>>>,
    cli: CliArgs,
    handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    rt: tokio::runtime::Handle,
) {
    let add_items = items.clone();
    let add_log = log.clone();
    let add = warp::path::end()
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::any().map(move || AddDefinitionBinding {
            definitions: add_items.clone(),
            log: add_log.clone(),
            poll_interval: cli.poll_interval,
            registry_query_timeout: cli.registry_query_timeout,
            registry_path: cli.targets_dir.clone(),
            handles: handles.clone(),
            rt: rt.clone(),
        }))
        .and_then(add_definition);

    let get_items = items.clone();
    let get = warp::path::end()
        .and(warp::get())
        .and(warp::any().map(move || get_items.clone()))
        .and_then(get_definitions);

    let delete_items = items.clone();
    let delete = warp::path!(String)
        .and(warp::delete())
        .and(warp::any().map(move || delete_items.clone()))
        .and_then(delete_definition);

    let export_items = items.clone();
    let export_prometheus = warp::path!("prom" / "targets")
        .and(warp::get())
        .and(warp::any().map(move || ExportDefinitionConfigBinding {
            definitions: export_items.clone(),
        }))
        .and_then(export_prometheus_config);

    let export_targets_items = items.clone();
    let export_targets = warp::path!("targets")
        .and(warp::get())
        .and(warp::any().map(move || ExportTargetsBinding {
            definitions: export_targets_items.clone(),
        }))
        .and_then(export_targets);

    let add_boundary_node_targets = items.clone();
    let add_boundary_node_log = log.clone();
    let add_boundary_node = warp::path!("add_boundary_node")
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::any().map(move || AddBoundaryNodeToDefinitionBinding {
            definitions: add_boundary_node_targets.clone(),
            log: add_boundary_node_log.clone(),
        }))
        .and_then(add_boundary_node);

    let routes = add
        .or(get)
        .or(delete)
        .or(export_prometheus)
        .or(export_targets)
        .or(add_boundary_node);

    let routes = routes.with(warp::log("multiservice_discovery"));
    let (_, server) =
        warp::serve(routes).bind_with_graceful_shutdown(([0, 0, 0, 0], 8000), async {
            recv.await.ok();
        });
    info!(log, "Server started on port {}", 8000);
    server.await;
    info!(log, "Server stopped");
}
