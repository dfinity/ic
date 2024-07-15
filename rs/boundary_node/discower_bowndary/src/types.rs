use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::{mpsc, watch};

pub type SenderWatch<T> = watch::Sender<Option<T>>;
pub type ReceiverWatch<T> = watch::Receiver<Option<T>>;

pub type SenderMpsc<T> = mpsc::Sender<T>;
pub type ReceiverMpsc<T> = mpsc::Receiver<T>;

pub type GlobalShared<T> = Arc<ArcSwap<T>>;
