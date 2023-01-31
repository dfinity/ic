use std::{
    fmt::Display,
    ops::DerefMut,
    str::FromStr,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use crossbeam_channel::{bounded, select, unbounded, Sender};
use serde::{Deserialize, Serialize};
use utils::thread::JoinOnDrop;

use super::process::ProcessEventPayload;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub enum TaskId {
    // Argument x must be unique across all TaskId::Test(x)
    Test(String),
    // Argument x in TaskId::Timeout(x) corresponds to x in TaskId::Test(x)
    Timeout(String),
}

impl Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskId::Test(test_name) => write!(f, "{}", test_name),
            TaskId::Timeout(task_id) => write!(f, "timeout({})", task_id),
        }
    }
}

/// invariant: Display . FromStr == id
impl FromStr for TaskId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let to = "timeout(";
        match s {
            s if s.starts_with(to) => {
                let name = &s[to.len()..s.len() - 1];
                Ok(TaskId::Timeout(name.to_string()))
            }
            s => Ok(TaskId::Test(s.to_string())),
        }
    }
}

impl TaskId {
    pub fn name(&self) -> String {
        format!("{self}")
    }
}

/// Represents an event in the system.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct Event {
    pub when: SystemTime,
    pub what: EventPayload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventPayload {
    TaskSpawned {
        task_id: TaskId,
    },
    ProcessEvent {
        task_id: TaskId,
        process_event: ProcessEventPayload,
    },
    TaskCaughtPanic {
        task_id: TaskId,
        msg: String,
    },
    TaskFailed {
        task_id: TaskId,
        msg: String,
    },
    TaskSubReport {
        task_id: TaskId,
        sub_report: String,
    },
    TaskStopped {
        task_id: TaskId,
    },
    StartSchedule,
}

impl Event {
    pub fn task_spawned(task_id: TaskId) -> Self {
        Self::now(EventPayload::TaskSpawned { task_id })
    }

    pub fn process_event(task_id: TaskId, process_event_payload: ProcessEventPayload) -> Self {
        Self::now(EventPayload::ProcessEvent {
            task_id,
            process_event: process_event_payload,
        })
    }

    pub fn task_caught_panic(task_id: TaskId, msg: String) -> Self {
        Self::now(EventPayload::TaskCaughtPanic { task_id, msg })
    }

    pub fn task_failed(task_id: TaskId, msg: String) -> Self {
        Self::now(EventPayload::TaskFailed { task_id, msg })
    }

    pub fn task_sub_report(task_id: TaskId, sub_report: String) -> Self {
        Self::now(EventPayload::TaskSubReport {
            task_id,
            sub_report,
        })
    }

    pub fn task_stopped(task_id: TaskId) -> Self {
        Self::now(EventPayload::TaskStopped { task_id })
    }

    fn now(what: EventPayload) -> Self {
        Self {
            when: SystemTime::now(),
            what,
        }
    }
}

pub trait Subscriber<E>: FnMut(E) + Send + Sync {}
impl<E, T: FnMut(E) + Send + Sync> Subscriber<E> for T {}

/// A function that takes an Event (and possibly mutates state) is an event
/// subscriber.
pub trait EventSubscriber: Subscriber<Event> {}
impl<T: FnMut(Event) + Send + Sync> EventSubscriber for T {}

/// EventSubscriber cannot be cloned in general. Thus, in cases where a
/// subscriber needs to subscribe to objects that are generated dynamically, a
/// SubscriberFactory can be used.
pub trait BroadcastingEventSubscriberFactory: Send + Sync {
    fn create_broadcasting_subscriber(&self) -> Box<dyn EventSubscriber>;

    fn broadcast(&self, event: Event) {
        (self.create_broadcasting_subscriber())(event)
    }
}

/// Broadcast incoming events to multiple outgoing channels.
///
/// If the incoming channel gets dropped, broadcasting stops.
///
/// When an outgoing channel gets dropped (or a send error happens), the
/// affected channel is removed from the list of outgoing channels.
///
/// If no outgoing channels are left, the broadcast stops.
pub struct EventBroadcaster {
    events: Sender<Event>,
    // The sending end of the drop channel is declared first. Thus, it will get
    // dropped before the drop_handler is dropped.
    stop: Sender<()>,

    subscribers: Arc<Mutex<Vec<Box<dyn EventSubscriber>>>>,

    // On drop, this will wait on the join handle of the background thread.
    _drop_handler: JoinOnDrop<()>,
}

impl EventBroadcaster {
    pub fn subscribe(&self, whom: Box<dyn EventSubscriber>) {
        let mut write_lock = self.subscribers.lock().unwrap();
        write_lock.push(whom);
    }

    pub fn start() -> Self {
        let (events, event_rcv) = unbounded::<Event>();
        // let's establish a rendez-vous channel to send the stop signal
        let (stop, stop_rcv) = bounded::<()>(0);
        let subscribers: Arc<Mutex<Vec<Box<dyn EventSubscriber>>>> = Arc::new(Mutex::new(vec![]));
        let join_handle = std::thread::spawn({
            let subscribers = subscribers.clone();
            move || {
                loop {
                    let evt = select! {
                        recv(event_rcv) -> evt => {
                            match evt {
                                Ok(evt) => evt,
                                // The sender was dropped. Break here.
                                Err(_) => break
                            }
                        },
                        recv(stop_rcv) -> _ => break,
                    };
                    let mut lock = subscribers.lock().unwrap();
                    for sub in lock.deref_mut().iter_mut() {
                        (sub)(evt.clone());
                    }
                }
            }
        });
        let _drop_handler = JoinOnDrop::new(join_handle);

        Self {
            events,
            stop,
            subscribers,
            _drop_handler,
        }
    }

    pub fn stop(&self) {
        let _ = self.stop.send(());
    }
}

impl BroadcastingEventSubscriberFactory for EventBroadcaster {
    fn create_broadcasting_subscriber(&self) -> Box<dyn EventSubscriber> {
        let event_recv = self.events.clone();
        let es = move |evt: Event| {
            event_recv.send(evt).expect("Could not send event!");
        };
        Box::new(es)
    }
}

pub mod test_utils {
    use std::sync::Arc;

    use super::*;
    use crossbeam_channel::{unbounded, Receiver, Sender};
    // A simple wrapper so that we can implement the EventSubscriberFactory
    // here.
    pub struct SubscriberFactorySender(Sender<Event>);

    impl BroadcastingEventSubscriberFactory for SubscriberFactorySender {
        fn create_broadcasting_subscriber(&self) -> Box<dyn EventSubscriber> {
            let new_sender = self.0.clone();

            Box::new(move |evt: Event| new_sender.send(evt).expect("Could not send event!"))
        }
    }

    /// Create a SubscriberFactory that is backed by a crossbeam channel.
    pub fn create_subfact() -> (Arc<dyn BroadcastingEventSubscriberFactory>, Receiver<Event>) {
        let (evt_send, evt_recv) = unbounded();
        (Arc::new(SubscriberFactorySender(evt_send)), evt_recv)
    }
}
