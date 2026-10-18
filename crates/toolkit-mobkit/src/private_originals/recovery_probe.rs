//! Test-only observation on one actual PrivateOriginals owner and source key.
//! No task-local/global selector and no admission or lifecycle control.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Notify;
use toolkit_store::StoreKey;

pub(crate) struct MetadataRecoveryProbe {
    source: StoreKey,
    pub reads: AtomicUsize,
    pub polls: AtomicUsize,
    pub pages: AtomicUsize,
    pub wraps: AtomicUsize,
    pub drain: AtomicBool,
    pub page_boundary: AtomicBool,
    pause_page: AtomicBool,
    page_released: AtomicBool,
    released: AtomicBool,
    wake: Notify,
}
impl MetadataRecoveryProbe {
    pub fn new(source: StoreKey) -> Self {
        Self { source, reads: AtomicUsize::new(0), polls: AtomicUsize::new(0),
            pages: AtomicUsize::new(0), wraps: AtomicUsize::new(0), drain: AtomicBool::new(false),
            page_boundary: AtomicBool::new(false), pause_page: AtomicBool::new(false),
            page_released: AtomicBool::new(false), released: AtomicBool::new(false), wake: Notify::new() }
    }
    pub async fn after_read(&self, source: &StoreKey) {
        if source != &self.source { return; }
        self.reads.fetch_add(1, Ordering::SeqCst);
        loop {
            let changed = self.wake.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.released.load(Ordering::SeqCst) { return; }
            changed.await;
        }
    }
    pub fn polling(&self) {
        if self.reads.load(Ordering::SeqCst) != 0 && !self.released.load(Ordering::SeqCst) {
            self.polls.fetch_add(1, Ordering::SeqCst);
        }
    }
    pub fn paging(&self, at_start: bool) {
        self.pages.fetch_add(1, Ordering::SeqCst);
        if at_start { self.wraps.fetch_add(1, Ordering::SeqCst); }
    }
    pub fn arm_page_boundary(&self) { self.pause_page.store(true, Ordering::SeqCst); }
    pub async fn after_poll(&self) {
        if !self.pause_page.load(Ordering::SeqCst) { return; }
        self.page_boundary.store(true, Ordering::SeqCst);
        loop {
            let changed = self.wake.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.page_released.load(Ordering::SeqCst) { return; }
            changed.await;
        }
    }
    pub fn release_page_boundary(&self) {
        self.page_released.store(true, Ordering::SeqCst);
        self.wake.notify_waiters();
    }
    pub fn draining(&self) { self.drain.store(true, Ordering::SeqCst); }
    pub fn release(&self) { self.released.store(true, Ordering::SeqCst); self.release_page_boundary(); }
}
