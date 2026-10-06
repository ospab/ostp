//! How much a session may send to its client right now, for the tasks that
//! read from targets (`relay`).
//!
//! The packet loop sets each session's budget (frames the congestion window
//! and the pacing rate allow until the next tick) after every datagram from
//! that client and on every tick, and wakes the readers. A reader spends the
//! budget as it hands data over and waits for the next update when it runs
//! out. It used to poll every 5 ms a value refreshed every 10 ms, which read
//! zero whenever the pacing bucket happened to be empty at that instant:
//! sending stopped for the rest of the tick although the bucket refills in
//! microseconds.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use tokio::sync::Notify;

/// A reader never waits longer than this, so a session whose budget is never
/// refreshed (a bug, or a state nobody foresaw) slows down instead of
/// stalling its streams forever.
const MAX_WAIT: Duration = Duration::from_secs(2);

#[derive(Default)]
pub struct SendGate {
    budget: AtomicI64,
    notify: Notify,
}

impl SendGate {
    pub fn new(initial: i64) -> Self {
        Self { budget: AtomicI64::new(initial), notify: Notify::new() }
    }

    /// The loop's latest figure; wakes the readers when there is room.
    pub fn set(&self, packets: i64) {
        self.budget.store(packets, Ordering::Relaxed);
        if packets > 0 {
            self.notify.notify_waiters();
        }
    }

    /// Frames this reader may hand over now: waits until there is at least
    /// one (or MAX_WAIT passed, then 1).
    pub async fn acquire(&self) -> i64 {
        let deadline = tokio::time::Instant::now() + MAX_WAIT;
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let b = self.budget.load(Ordering::Relaxed);
            if b > 0 {
                return b;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return 1;
            }
        }
    }

    /// `packets` frames were handed over.
    pub fn spend(&self, packets: i64) {
        self.budget.fetch_sub(packets, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn a_reader_wakes_as_soon_as_there_is_room() {
        let gate = Arc::new(SendGate::new(0));
        let g = gate.clone();
        let waiter = tokio::spawn(async move { g.acquire().await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished(), "no budget, so it waits");
        let started = std::time::Instant::now();
        gate.set(7);
        let got = tokio::time::timeout(Duration::from_secs(1), waiter).await.unwrap().unwrap();
        assert_eq!(got, 7);
        assert!(started.elapsed() < Duration::from_millis(50), "woken by the update, not by a timer");
    }

    #[tokio::test]
    async fn spending_runs_the_budget_down() {
        let gate = SendGate::new(3);
        assert_eq!(gate.acquire().await, 3);
        gate.spend(3);
        assert!(tokio::time::timeout(Duration::from_millis(30), gate.acquire()).await.is_err());
    }
}
