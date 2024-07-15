use tracing_subscriber::{layer::Layer, reload::Handle, Registry};

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
            layers.push(layer);
        });
    }

    pub fn pop(&self) {
        // ignore errors
        let _ = self.0.modify(|layers| {
            layers.pop();
        });
    }
}
