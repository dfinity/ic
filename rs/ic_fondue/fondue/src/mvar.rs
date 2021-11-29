use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Implements a Haskell-like MVar
/// (https://hackage.haskell.org/package/base-4.14.1.0/docs/Control-Concurrent-MVar.html)
/// which we can wait on.
pub struct MVar<T> {
    var: Arc<(Mutex<Option<T>>, Condvar)>,
}

impl<T> Clone for MVar<T> {
    fn clone(&self) -> Self {
        MVar {
            var: self.var.clone(),
        }
    }
}

impl<T> MVar<T> {
    pub fn new(value: T) -> Self {
        MVar {
            var: Arc::new((Mutex::new(Some(value)), Condvar::new())),
        }
    }

    pub fn new_empty() -> Self {
        MVar {
            var: Arc::new((Mutex::new(None), Condvar::new())),
        }
    }

    pub fn take(&self) -> T {
        let (lock, cvar) = &*self.var;
        let mut mutex = lock.lock().unwrap();
        loop {
            match mutex.take() {
                Some(x) => {
                    *mutex = None;
                    cvar.notify_one();
                    return x;
                }
                None => mutex = cvar.wait(mutex).unwrap(),
            }
        }
    }

    pub fn take_timeout(&self, dur: Duration) -> Option<T> {
        let (lock, cvar) = &*self.var;
        let mut mutex = lock.lock().unwrap();
        loop {
            match mutex.take() {
                Some(x) => {
                    *mutex = None;
                    cvar.notify_one();
                    return Some(x);
                }
                None => {
                    let result = cvar.wait_timeout(mutex, dur).ok()?;
                    mutex = result.0;
                    if result.1.timed_out() {
                        return None;
                    }
                }
            }
        }
    }

    pub fn put(&self, value: T) {
        let (lock, cvar) = &*self.var;
        let mut mutex = lock.lock().unwrap();
        loop {
            match &*mutex {
                Some(_) => mutex = cvar.wait(mutex).unwrap(),
                None => {
                    *mutex = Some(value);
                    cvar.notify_one();
                    break;
                }
            }
        }
    }

    pub fn put_timeout(&self, value: T, dur: Duration) -> bool {
        let (lock, cvar) = &*self.var;
        let mut mutex = lock.lock().unwrap();
        loop {
            match &*mutex {
                Some(_) => {
                    if let Ok(result) = cvar.wait_timeout(mutex, dur) {
                        mutex = result.0;
                        if result.1.timed_out() {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                None => {
                    *mutex = Some(value);
                    cvar.notify_one();
                    return true;
                }
            }
        }
    }

    pub fn read(&self) -> T
    where
        T: Clone,
    {
        let (lock, cvar) = &*self.var;
        let mut mutex = lock.lock().unwrap();
        loop {
            match mutex.take() {
                Some(x) => {
                    *mutex = Some(x.clone());
                    cvar.notify_one();
                    return x;
                }
                None => mutex = cvar.wait(mutex).unwrap(),
            }
        }
    }

    pub fn read_timeout(&self, dur: Duration) -> Option<T>
    where
        T: Clone,
    {
        let (lock, cvar) = &*self.var;
        let mut mutex = lock.lock().unwrap();
        loop {
            match mutex.take() {
                Some(x) => {
                    *mutex = Some(x.clone());
                    cvar.notify_one();
                    return Some(x);
                }
                None => {
                    let result = cvar.wait_timeout(mutex, dur).ok()?;
                    mutex = result.0;
                    if result.1.timed_out() {
                        return None;
                    }
                }
            }
        }
    }

    pub fn try_read(&self) -> Option<T>
    where
        T: Clone,
    {
        let (lock, _cvar) = &*self.var;
        let mut mutex = lock.lock().unwrap();
        let val = mutex.take();
        *mutex = val.clone();
        val
    }

    pub fn try_put(&self, value: T) -> bool {
        let (lock, cvar) = &*self.var;
        let mut mutex = lock.lock().unwrap();
        match &*mutex {
            Some(_) => false,
            None => {
                *mutex = Some(value);
                cvar.notify_one();
                true
            }
        }
    }

    pub fn try_take(&self) -> Option<T> {
        let (lock, cvar) = &*self.var;
        let mut mutex = lock.lock().unwrap();
        match mutex.take() {
            Some(x) => {
                *mutex = None;
                cvar.notify_one();
                Some(x)
            }
            None => None,
        }
    }

    pub fn swap(&self, value: T) -> T {
        let (lock, cvar) = &*self.var;
        let mut mutex = lock.lock().unwrap();
        loop {
            match mutex.take() {
                Some(x) => {
                    *mutex = Some(value);
                    cvar.notify_one();
                    return x;
                }
                None => mutex = cvar.wait(mutex).unwrap(),
            }
        }
    }

    pub fn swap_timeout(&self, value: T, dur: Duration) -> Option<T> {
        let (lock, cvar) = &*self.var;
        let mut mutex = lock.lock().unwrap();
        loop {
            match mutex.take() {
                Some(x) => {
                    *mutex = Some(value);
                    cvar.notify_one();
                    return Some(x);
                }
                None => {
                    let result = cvar.wait_timeout(mutex, dur).ok()?;
                    mutex = result.0;
                    if result.1.timed_out() {
                        return None;
                    }
                }
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        let (lock, _cvar) = &*self.var;
        let mutex = lock.lock().unwrap();
        mutex.is_some()
    }
}
