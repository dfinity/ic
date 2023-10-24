use anyhow::Result;
use async_std::io;
use futures::{pin_mut, Stream, StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::Event;
use kube::{
    runtime::{metadata_watcher, watcher, WatchStreamExt},
    Api, Client, Config,
};
use std::time::Duration;
use tracing::*;

pub async fn wait_for_event(
    client: Client,
    message: &str,
    kind: &str,
    name: &str,
    ns: &str,
    timeout: u64,
) -> Result<()> {
    let events: Api<Event> = Api::namespaced(client, ns);
    let wc = watcher::Config::default();
    let ew = watcher(events, wc).applied_objects();

    info!("Waiting for event '{} for {} {}'", message, name, kind);
    pin_mut!(ew);
    io::timeout(Duration::from_secs(timeout), async {
        while let Ok(Some(ev)) = ew.try_next().await {
            let ev_message = ev.message.expect("Event has no message").trim().to_owned();
            let ev_obj_kind = ev.involved_object.kind.expect("Event has no kind");
            let ev_obj_name = ev.involved_object.name.expect("Event has no name");

            debug!("Event: {} {} {}", ev_message, ev_obj_kind, ev_obj_name);
            if ev_message == message && ev_obj_kind == kind && ev_obj_name == name {
                info!("Encountered event '{} for {} {}'", message, name, kind);
                return Ok(());
            }
        }
        Ok(())
    })
    .await?;

    Ok(())
}
