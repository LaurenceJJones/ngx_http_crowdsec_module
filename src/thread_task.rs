//! Run blocking HTTP clients on nginx's native pool; touch requests only on the event loop.

use ngx::ffi::*;
use std::ffi::c_void;
use std::mem;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

static POOL: AtomicPtr<ngx_thread_pool_t> = AtomicPtr::new(ptr::null_mut());

/// Keep a non-cancelable timer while work is queued so a reloading worker does
/// not call `ngx_worker_process_exit` (no timers ⇒ exit, even with open sockets).
const KEEP_ALIVE_MS: ngx_msec_t = 1000;

pub unsafe fn configure(cf: *mut ngx_conf_t) -> bool {
    let pool = unsafe { ngx_thread_pool_add(cf, ptr::null_mut()) };
    POOL.store(pool, Ordering::Relaxed);
    !pool.is_null()
}

struct Task<F, T, C> {
    work: Option<F>,
    result: Option<Result<T, ()>>,
    complete: Option<C>,
    request: *mut ngx_http_request_t,
    keep: ngx_event_t,
}

/// The work closure owns all its input. nginx's blocked count protects the request
/// and task allocation until completion, including client disconnects.
pub unsafe fn post<F, T, C>(r: *mut ngx_http_request_t, work: F, complete: C) -> Result<(), ()>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
    C: FnOnce(*mut ngx_http_request_t, Result<T, ()>) + 'static,
{
    unsafe {
        let pool = POOL.load(Ordering::Relaxed);
        if pool.is_null() || (*r).aio() != 0 {
            return Err(());
        }
        let task = ngx_thread_task_alloc((*r).pool, 0);
        if task.is_null() {
            return Err(());
        }
        let data = Box::into_raw(Box::new(Task::<F, T, C> {
            work: Some(work),
            result: None,
            complete: Some(complete),
            request: r,
            keep: mem::zeroed(),
        }));
        (*task).ctx = data.cast();
        (*task).handler = Some(run::<F, T, C>);
        (*task).event.data = data.cast();
        (*task).event.handler = Some(done::<F, T, C>);
        (*task).event.log = (*(*r).connection).log;
        if ngx_thread_task_post(pool, task) != NGX_OK as ngx_int_t {
            drop(Box::from_raw(data));
            return Err(());
        }
        (*data).keep.handler = Some(keep_alive);
        (*data).keep.log = (*(*r).connection).log;
        ngx_add_timer(ptr::addr_of_mut!((*data).keep), KEEP_ALIVE_MS);
        let main = (*r).main;
        (*main).set_blocked((*main).blocked() + 1);
        (*r).set_aio(1);
        Ok(())
    }
}

unsafe extern "C" fn keep_alive(ev: *mut ngx_event_t) {
    unsafe {
        ngx_add_timer(ev, KEEP_ALIVE_MS);
    }
}

unsafe extern "C" fn run<F, T, C>(data: *mut c_void, _log: *mut ngx_log_t)
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
    C: FnOnce(*mut ngx_http_request_t, Result<T, ()>) + 'static,
{
    unsafe {
        let task = &mut *data.cast::<Task<F, T, C>>();
        task.result =
            Some(catch_unwind(AssertUnwindSafe(|| (task.work.take().unwrap())())).map_err(|_| ()));
    }
}

unsafe extern "C" fn done<F, T, C>(event: *mut ngx_event_t)
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
    C: FnOnce(*mut ngx_http_request_t, Result<T, ()>) + 'static,
{
    unsafe {
        let mut task = Box::from_raw((*event).data.cast::<Task<F, T, C>>());
        if task.keep.timer_set() != 0 {
            ngx_del_timer(ptr::addr_of_mut!(task.keep));
        }
        let r = task.request;
        let main = (*r).main;
        let connection = (*r).connection;
        (*main).set_blocked((*main).blocked() - 1);
        (*r).set_aio(0);
        // Match nginx's copy-filter thread completion for HTTP/2 streams.
        if (*r).http_version == 2000 {
            (*(*connection).write).set_ready(1);
            (*(*connection).write).set_active(0);
        }
        // `r->terminated` exists only on nginx ≥ 1.25.5; connection error is portable.
        if (*r).done() != 0 || (*connection).error() != 0 {
            if let Some(handler) = (*(*connection).write).handler {
                handler((*connection).write);
            }
            return;
        }
        (task.complete.take().unwrap())(r, task.result.take().unwrap_or(Err(())));
        ngx_http_run_posted_requests(connection);
    }
}
