use tracing_subscriber::{Registry, layer::Layer, reload::Handle};

pub mod utils;

// We use dynamic dispatch here to make the ReloadHandles struct work with different
// layers.
type BoxedRegistryLayer = Box<dyn Layer<Registry> + Send + Sync>;

/// Queue of tracing reload handles.
#[derive(Clone)]
pub struct ReloadHandles(Handle<Vec<BoxedRegistryLayer>, Registry>);

impl ReloadHandles {
    pub fn new(handle: Handle<Vec<BoxedRegistryLayer>, Registry>) -> Self {
        Self(handle)
    }

    pub fn push(&self, layer: BoxedRegistryLayer) {
        // ignore errors
        let _ = self.0.modify(|layers| {
            // The layers variable can contain at most 5 elements thanks to the concurrency rate limiter.
            layers.insert(0, layer);
        });
    }

    pub fn pop(&self) {
        // ignore errors
        let _ = self.0.modify(|layers| {
            layers.pop();
        });
    }
}
