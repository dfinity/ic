use std::time::SystemTime;

use crossbeam_channel::{bounded, select, unbounded, Sender};
use utils::thread::JoinOnDrop;

use super::process::ProcessEventPayload;

pub type TaskId = String;

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
    TaskStopped {
        task_id: TaskId,
    },
    StartSchedule,
}

impl Event {
    pub fn task_failed(task_id: TaskId, msg: String) -> Self {
        Self::now(EventPayload::TaskFailed { task_id, msg })
    }

    pub fn task_stopped(task_id: TaskId) -> Self {
        Self::now(EventPayload::TaskStopped { task_id })
    }

    pub fn task_spawned(task_id: TaskId) -> Self {
        Self::now(EventPayload::TaskSpawned { task_id })
    }

    pub fn process_event(task_id: TaskId, process_event_payload: ProcessEventPayload) -> Self {
        Self::now(EventPayload::ProcessEvent {
            task_id,
            process_event: process_event_payload,
        })
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
pub trait EventSubscriberFactory: Send + Sync {
    fn create_subscriber(&self) -> Box<dyn EventSubscriber>;
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
    // On drop, this will wait on the join handle of the background thread.
    _drop_handler: JoinOnDrop<()>,
}

impl EventBroadcaster {
    pub fn start(mut subscribers: Vec<Box<dyn EventSubscriber>>) -> Self {
        let (events, event_rcv) = unbounded::<Event>();
        // let's establish a rendez-vous channel to send the stop signal
        let (stop, stop_rcv) = bounded::<()>(0);
        let join_handle = std::thread::spawn({
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
                    for sub in &mut subscribers {
                        (sub)(evt.clone());
                    }
                }
            }
        });
        let _drop_handler = JoinOnDrop::new(join_handle);

        Self {
            events,
            stop,
            _drop_handler,
        }
    }

    pub fn stop(&self) {
        let _ = self.stop.send(());
    }
}

impl EventSubscriberFactory for EventBroadcaster {
    fn create_subscriber(&self) -> Box<dyn EventSubscriber> {
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

    impl EventSubscriberFactory for SubscriberFactorySender {
        fn create_subscriber(&self) -> Box<dyn EventSubscriber> {
            let new_sender = self.0.clone();

            Box::new(move |evt: Event| new_sender.send(evt).expect("Could not send event!"))
        }
    }

    /// Create a SubscriberFactory that is backed by a crossbeam channel.
    pub fn create_subfact() -> (Arc<dyn EventSubscriberFactory>, Receiver<Event>) {
        let (evt_send, evt_recv) = unbounded();
        (Arc::new(SubscriberFactorySender(evt_send)), evt_recv)
    }
}
