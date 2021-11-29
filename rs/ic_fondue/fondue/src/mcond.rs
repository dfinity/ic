use std::ops::DerefMut;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::mvar::MVar;

pub struct MCond<'a, T> {
    var: MVar<()>,
    pred: Arc<RwLock<dyn FnMut(&T) -> bool + 'a>>,
}

impl<'a, T> Clone for MCond<'a, T> {
    fn clone(&self) -> Self {
        MCond {
            var: self.var.clone(),
            pred: self.pred.clone(),
        }
    }
}

impl<'a, T> MCond<'a, T> {
    pub fn new(pred: impl FnMut(&T) -> bool + 'a) -> Self {
        MCond {
            var: MVar::new_empty(),
            pred: Arc::new(RwLock::new(pred)),
        }
    }

    pub fn wait(&self) {
        self.var.take()
    }

    pub fn wait_timeout(&self, dur: Duration) -> bool {
        self.var.take_timeout(dur).is_some()
    }

    pub fn consider(&self, value: &T) {
        if (self.pred.write().unwrap().deref_mut())(value) {
            self.var.put(())
        }
    }

    pub fn consider_timeout(&self, value: &T, dur: Duration) -> bool {
        if (self.pred.write().unwrap().deref_mut())(value) {
            self.var.put_timeout((), dur)
        } else {
            false
        }
    }
}
