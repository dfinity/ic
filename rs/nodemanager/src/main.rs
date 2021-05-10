use ic_base_server::shutdown_signal;
use nodemanager::args::NodeManagerArgs;
use nodemanager::node_manager::NodeManager;
use structopt::StructOpt;

#[tokio::main]
async fn main() {
    let args = NodeManagerArgs::from_args();
    let mut node_manager = NodeManager::new(args).await;
    node_manager
        .start()
        .await
        .expect("Failed to start node manager");
    node_manager.spawn_wait_and_restart_replica();
    shutdown_signal(node_manager.logger.inner_logger.root.clone()).await;
    node_manager.stop_replica();
}
