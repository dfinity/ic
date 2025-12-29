use std::sync::Arc;

use super::promdb::IndexedScrape;
use crossterm::event::Event as CrosstermEvent;
use futures_util::FutureExt;
use futures_util::StreamExt;
use reqwest::StatusCode;
use tokio::sync::mpsc;

/// Representation of all possible events.
#[derive(Debug)]
pub enum AppEvent {
    NewHostOSNodeExporterScrape(Result<IndexedScrape, String>),
    NewGuestOSNodeExporterScrape(Result<IndexedScrape, String>),
    NewGuestOSReplicaScrape(Result<IndexedScrape, String>),
    /// Crossterm events.
    ///
    /// These events are emitted by the terminal.
    Crossterm(CrosstermEvent),
    /// Signal to quit.
    Quit,
}

async fn scrape(client: Arc<reqwest::Client>, url: &str) -> Result<IndexedScrape, String> {
    let resp = client.get(url).send().await.map_err(|e| format!("{}", e))?;
    match resp.status() {
        StatusCode::OK => (),
        other => return Err(format!("non-OK status {other} from {url}")),
    }
    Ok(IndexedScrape::from(
        prometheus_parse::Scrape::parse(
            resp.text()
                .await
                .map_err(|e| format!("{}", e))?
                .lines()
                .map(|s| Ok(s.to_owned())),
        )
        .map_err(|e| format!("{}", e))?,
    ))
}

struct PollTask {
    /// Event sender channel.
    sender: mpsc::UnboundedSender<AppEvent>,
    client: Arc<reqwest::Client>,
}

impl PollTask {
    /// Constructs a new instance of [`EventThread`].
    fn new(sender: mpsc::UnboundedSender<AppEvent>) -> Self {
        Self {
            sender,
            client: Arc::new(
                reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .build()
                    .expect("reqwest::Client should have been built!"),
            ),
        }
    }

    /// Runs the event thread.
    ///
    /// This function emits tick events at a fixed rate and polls for crossterm events in between.
    async fn run(self, hostname: String, sample_freq: std::time::Duration) -> anyhow::Result<()> {
        let mut tick = tokio::time::interval(sample_freq);
        let hostos_node_exporter = format!("{hostname}:9100/metrics");
        let guestos_node_exporter = format!("{hostname}:42372/metrics/guestos_node_exporter");
        let guestos_replica_exporter = format!("{hostname}:42372/metrics/guestos_replica");
        loop {
            let tick_delay = tick.tick();
            tokio::select! {
              _ = self.sender.closed() => {
                break;
              }
              _ = tick_delay => {
                let (hn, gn, gr) = futures::join!(
                    scrape(self.client.clone(), hostos_node_exporter.as_str()),
                    scrape(self.client.clone(), guestos_node_exporter.as_str()),
                    scrape(self.client.clone(), guestos_replica_exporter.as_str()),
                );
                // Ignores the result because shutting down the app drops the receiver, which causes the send
                // operation to fail. This is expected behavior and should not panic.
                let _ = self.sender.send(AppEvent::NewHostOSNodeExporterScrape(hn));
                let _ = self.sender.send(AppEvent::NewGuestOSNodeExporterScrape(gn));
                let _ = self.sender.send(AppEvent::NewGuestOSReplicaScrape(gr));
              }
            };
        }
        Ok(())
    }
}

/// A thread that handles reading crossterm events and emitting tick events on a regular schedule.
struct EventTask {
    /// Event sender channel.
    sender: mpsc::UnboundedSender<AppEvent>,
}

impl EventTask {
    /// Constructs a new instance of [`EventThread`].
    fn new(sender: mpsc::UnboundedSender<AppEvent>) -> Self {
        Self { sender }
    }

    /// Runs the event thread.
    ///
    /// This function emits tick events at a fixed rate and polls for crossterm events in between.
    async fn run(self) -> anyhow::Result<()> {
        let mut reader = crossterm::event::EventStream::new();
        loop {
            let crossterm_event = reader.next().fuse();
            tokio::select! {
              _ = self.sender.closed() => {
                break;
              }
              Some(Ok(evt)) = crossterm_event => {
                self.send(AppEvent::Crossterm(evt));
              }
            };
        }
        Ok(())
    }

    /// Sends an event to the receiver.
    fn send(&self, event: AppEvent) {
        // Ignores the result because shutting down the app drops the receiver, which causes the send
        // operation to fail. This is expected behavior and should not panic.
        let _ = self.sender.send(event);
    }
}

#[derive(Debug)]
pub struct EventHandler {
    /// Event sender channel.
    sender: mpsc::UnboundedSender<AppEvent>,
    /// Event receiver channel.
    receiver: mpsc::UnboundedReceiver<AppEvent>,
}

impl EventHandler {
    /// Constructs a new instance of [`EventHandler`] and spawns a new thread to handle events.
    pub fn new(hostname: String, sample_freq: std::time::Duration) -> Self {
        #[allow(clippy::disallowed_methods)]
        let (sender, receiver) = mpsc::unbounded_channel();
        let actor = EventTask::new(sender.clone());
        let poller = PollTask::new(sender.clone());
        tokio::spawn(async move { actor.run().await });
        tokio::spawn(async move { poller.run(hostname, sample_freq).await });
        Self { sender, receiver }
    }

    /// Receives an event from the sender.
    ///
    /// This function blocks until an event is received.
    ///
    /// # Errors
    ///
    /// This function returns an error if the sender channel is disconnected. This can happen if an
    /// error occurs in the event thread. In practice, this should not happen unless there is a
    /// problem with the underlying terminal.
    pub async fn next(&mut self) -> anyhow::Result<AppEvent> {
        self.receiver
            .recv()
            .await
            .ok_or(anyhow::anyhow!("Failed to receive event"))
    }

    /// Queue an app event to be sent to the event receiver.
    ///
    /// This is useful for sending events to the event handler which will be processed by the next
    /// iteration of the application's event loop.
    pub fn send(&mut self, app_event: AppEvent) {
        // Ignore the result as the receiver cannot be dropped while this struct still has a
        // reference to it
        let _ = self.sender.send(app_event);
    }
}
