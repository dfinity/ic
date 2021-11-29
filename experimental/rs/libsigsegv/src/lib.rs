use libsigsegv_sys::{
    sigsegv_area_handler_t, sigsegv_dispatch, sigsegv_dispatcher, sigsegv_handler_t, sigsegv_init,
    sigsegv_install_handler, sigsegv_register, sigsegv_unregister,
};

use std::cell::RefCell;
use std::rc::Rc;

use slog::{debug, o};

use lazy_static::lazy_static;

////////////////////////////////////////////////////////////////////////////////////////////////////

thread_local! {
    // This structure represents a table of memory areas (address range intervals), with an local
    // SIGSEGV handler for each.
    pub static DISPATCHER: Dispatcher = Dispatcher::new(Some(sigsegv_global_handler));
}

lazy_static! {
    // Just so we can log nicely from the global handler.
    static ref DISPATCHER_LOG: slog::Logger =
        slog_scope::logger().new(o!("component" => "sigsegv_global_handler"));
}

// Global SIGSEGV handler that will dispatch requests to local handlers registered in the
// dispatcher structure above.
unsafe extern "C" fn sigsegv_global_handler(
    fault_address: *mut std::os::raw::c_void,
    _serious: std::os::raw::c_int,
) -> std::os::raw::c_int {
    debug!(
        *DISPATCHER_LOG,
        "fault_address = {:?}, serious = {}", fault_address, _serious
    );
    // Call the local SIGSEGV handler responsible for the given fault address.  Return the
    // handler's return value. 0 means that no handler has been found, or that a handler was found
    // but declined responsibility.
    DISPATCHER.with(|d| d.sigsegv_dispatch(fault_address))
}

pub struct Dispatcher(Rc<RefCell<sigsegv_dispatcher>>);

impl Dispatcher {
    // Creating a `Dispatcher` also installs a global sigsegv handler which will dispatch requests
    // to local handlers registered in said `Dispatcher`.
    pub fn new(handler: sigsegv_handler_t) -> Self {
        unsafe {
            let mut dsptch: sigsegv_dispatcher = sigsegv_dispatcher::default();
            sigsegv_init(&mut dsptch);
            sigsegv_install_handler(handler);
            Dispatcher(Rc::new(RefCell::new(dsptch)))
        }
    }

    pub fn sigsegv_dispatch(&self, fault_address: *mut libc::c_void) -> libc::c_int {
        unsafe { sigsegv_dispatch(&mut *(self.0.borrow_mut()), fault_address) }
    }

    pub fn sigsegv_register<T>(
        &self,
        base_address: *mut libc::c_void,
        length: usize,
        area_handler: sigsegv_area_handler_t,
        register_args: *mut T,
    ) -> *mut libc::c_void {
        unsafe {
            sigsegv_register(
                &mut *(self.0.borrow_mut()),
                base_address,
                length,
                area_handler,
                register_args as *mut libc::c_void,
            )
        }
    }

    pub fn sigsegv_unregister(&self, ticket: *mut libc::c_void) {
        unsafe { sigsegv_unregister(&mut *(self.0.borrow_mut()), ticket) }
    }
}
