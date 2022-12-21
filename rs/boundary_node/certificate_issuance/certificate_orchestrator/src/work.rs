use std::cmp::Reverse;

use certificate_orchestrator_interface::{Id, Registration};
use ic_cdk::{api::time, caller};
use ic_stable_structures::StableBTreeMap;
use priority_queue::PriorityQueue;

use crate::{
    acl::{Authorize, AuthorizeError, WithAuthorize},
    LocalRef, Memory,
};

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("Not found")]
    NotFound,
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Queue {
    fn queue(&self, id: String, timestamp: u64) -> Result<(), QueueError>;
}

pub struct Queuer {
    tasks: LocalRef<PriorityQueue<String, Reverse<u64>>>,
    registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>,
}

impl Queuer {
    pub fn new(
        tasks: LocalRef<PriorityQueue<String, Reverse<u64>>>,
        registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>,
    ) -> Self {
        Self {
            tasks,
            registrations,
        }
    }
}

impl Queue for Queuer {
    fn queue(&self, id: String, timestamp: u64) -> Result<(), QueueError> {
        self.registrations.with(|regs| {
            let regs = regs.borrow();
            regs.get(&id).ok_or(QueueError::NotFound)
        })?;

        self.tasks.with(|tasks| {
            let mut tasks = tasks.borrow_mut();
            tasks.push(id, Reverse(timestamp));
        });

        Ok(())
    }
}

impl<T: Queue, A: Authorize> Queue for WithAuthorize<T, A> {
    fn queue(&self, id: Id, timestamp: u64) -> Result<(), QueueError> {
        if let Err(err) = self.1.authorize(&caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => QueueError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => QueueError::UnexpectedError(err),
            });
        };

        self.0.queue(id, timestamp)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DispenseError {
    #[error("No tasks available")]
    NoTasksAvailable,
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Dispense {
    fn dispense(&self) -> Result<Id, DispenseError>;
    fn peek(&self) -> Result<Id, DispenseError>;
}

pub struct Dispenser {
    tasks: LocalRef<PriorityQueue<String, Reverse<u64>>>,
}

impl Dispenser {
    pub fn new(tasks: LocalRef<PriorityQueue<String, Reverse<u64>>>) -> Self {
        Self { tasks }
    }
}

impl Dispense for Dispenser {
    fn dispense(&self) -> Result<Id, DispenseError> {
        self.tasks.with(|tasks| {
            // Check for available task
            match tasks.borrow().peek() {
                None => return Err(DispenseError::NoTasksAvailable),
                Some((_, Reverse(timestamp))) => {
                    if time().lt(timestamp) {
                        return Err(DispenseError::NoTasksAvailable);
                    }
                }
            };

            let id = match tasks.borrow_mut().pop() {
                None => return Err(DispenseError::NoTasksAvailable),
                Some((id, _)) => id,
            };

            // TODO(or.ricon): Mark task as being in-progress

            Ok(id)
        })
    }

    fn peek(&self) -> Result<Id, DispenseError> {
        self.tasks.with(|tasks| {
            // Check for available task
            match tasks.borrow().peek() {
                None => Err(DispenseError::NoTasksAvailable),
                Some((id, Reverse(timestamp))) => {
                    if time().lt(timestamp) {
                        Err(DispenseError::NoTasksAvailable)
                    } else {
                        Ok(id.clone())
                    }
                }
            }
        })
    }
}

impl<T: Dispense, A: Authorize> Dispense for WithAuthorize<T, A> {
    fn dispense(&self) -> Result<Id, DispenseError> {
        if let Err(err) = self.1.authorize(&caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => DispenseError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => DispenseError::UnexpectedError(err),
            });
        };

        self.0.dispense()
    }

    fn peek(&self) -> Result<Id, DispenseError> {
        if let Err(err) = self.1.authorize(&caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => DispenseError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => DispenseError::UnexpectedError(err),
            });
        };

        self.0.peek()
    }
}
