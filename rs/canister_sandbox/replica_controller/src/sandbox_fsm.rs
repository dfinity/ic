#![allow(dead_code)]

#[derive(Debug, Clone)]
pub enum FSM {
    Empty,
    Setup,
    Executing(bool),
    Paused(bool),
    Halt(bool),
    Committed,
}

impl FSM {
    pub fn advance(self) -> Self {
        match self {
            FSM::Empty => FSM::Setup,
            FSM::Setup => FSM::Executing(false),
            FSM::Executing(to_commit) => FSM::Halt(to_commit),
            FSM::Paused(to_commit) => FSM::Paused(to_commit),
            FSM::Halt(true) => FSM::Committed,
            FSM::Halt(false) => FSM::Empty,
            FSM::Committed => FSM::Empty,
        }
    }

    pub fn halt(self) -> Self {
        match self {
            FSM::Executing(to_commit) => FSM::Halt(to_commit),
            _ => panic!("Wrong state!"),
        }
    }
    pub fn is_executing(&self) -> bool {
        match self {
            FSM::Executing(_) => true,
            _ => false,
        }
    }
    pub fn to_commit(&self) -> bool {
        match self {
            FSM::Empty => false,
            FSM::Setup => false,
            FSM::Executing(to_commit) => *to_commit,
            FSM::Paused(to_commit) => *to_commit,
            FSM::Halt(to_commit) => *to_commit,
            FSM::Committed => false,
        }
    }

    pub fn pause(&mut self) -> bool {
        if let FSM::Executing(to_commit) | FSM::Paused(to_commit) = self {
            *self = FSM::Paused(*to_commit);
            return true;
        }
        false
    }

    pub fn resume(mut self) -> Self {
        if let FSM::Paused(to_commit) = self {
            self = FSM::Executing(to_commit);
        }
        self
    }
}
