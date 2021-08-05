#![allow(dead_code)]

#[derive(Debug, Clone)]
pub enum Fsm {
    Empty,
    Setup,
    Executing(bool),
    Paused(bool),
    Halt(bool),
    Committed,
}

impl Fsm {
    pub fn advance(self) -> Self {
        match self {
            Fsm::Empty => Fsm::Setup,
            Fsm::Setup => Fsm::Executing(false),
            Fsm::Executing(to_commit) => Fsm::Halt(to_commit),
            Fsm::Paused(to_commit) => Fsm::Paused(to_commit),
            Fsm::Halt(true) => Fsm::Committed,
            Fsm::Halt(false) => Fsm::Empty,
            Fsm::Committed => Fsm::Empty,
        }
    }

    pub fn halt(self) -> Self {
        match self {
            Fsm::Executing(to_commit) => Fsm::Halt(to_commit),
            _ => panic!("Wrong state!"),
        }
    }
    pub fn is_executing(&self) -> bool {
        matches!(self, Fsm::Executing(_))
    }
    pub fn to_commit(&self) -> bool {
        match self {
            Fsm::Empty => false,
            Fsm::Setup => false,
            Fsm::Executing(to_commit) => *to_commit,
            Fsm::Paused(to_commit) => *to_commit,
            Fsm::Halt(to_commit) => *to_commit,
            Fsm::Committed => false,
        }
    }

    pub fn pause(&mut self) -> bool {
        if let Fsm::Executing(to_commit) | Fsm::Paused(to_commit) = self {
            *self = Fsm::Paused(*to_commit);
            return true;
        }
        false
    }

    pub fn resume(mut self) -> Self {
        if let Fsm::Paused(to_commit) = self {
            self = Fsm::Executing(to_commit);
        }
        self
    }
}
