//! How much a session may send to its client right now, for the tasks that
//! read from targets (`relay`).
//!
//! The packet loop sets each session's budget (frames the congestion window
//! and the pacing rate allow until the next tick) after every datagram from
//! that client and on every tick, and wakes the readers.
//!
//! The budget is closed-loop. A reader takes frames out of it atomically
//! (`claim`) for data it has already read, and those frames count as queued
//! until the loop has turned them into datagrams (`sent`). Every update from
//! the loop subtracts what is still queued: the congestion window counts only
//! frames already sent, so frames waiting in the channel to the loop used to
//! be invisible to it, every ACK handed the readers the whole window again,
//! and under load the backlog (and the ping behind it) grew without bound.
//! TCP never has more in flight than its window allows (RFC 5681, RFC 9002
//! section 7); this keeps sent plus queued within the window.
//!
//! Claiming after the read, for what was read, also keeps many readers that
//! wake together from taking the same budget: each takes its share or waits.

// portable_atomic: 32-bit MIPS has no 64-bit atomics in std.
use portable_atomic::AtomicI64;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::Notify;

/// A reader never waits longer than this, so a session whose budget is never
/// refreshed (a bug, or a state nobody foresaw) slows down instead of
/// stalling its streams forever.
const MAX_WAIT: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Budget {
    /// Frames that may still be handed over before the next update.
    free: i64,
    /// Frames handed over to the loop and not yet sent by it.
    queued: i64,
}

#[derive(Default)]
pub struct SendGate {
    // One lock for both figures: an update computes one from the other, and
    // with two separate atomics a claim could slip in between and be lost.
    budget: Mutex<Budget>,
    notify: Notify,
}

impl SendGate {
    pub fn new(initial: i64) -> Self {
        Self { budget: Mutex::new(Budget { free: initial, queued: 0 }), notify: Notify::new() }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Budget> {
        self.budget.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The loop's latest figure (frames the session may send now, by its
    /// congestion window and pacing): what is still queued is taken off it.
    /// Wakes the readers when there is room.
    pub fn set(&self, available: i64) {
        let open = {
            let mut b = self.lock();
            b.free = available - b.queued;
            b.free > 0
        };
        if open {
            self.notify.notify_waiters();
        }
    }

    /// Waits until there is room for at least one frame (or MAX_WAIT passed)
    /// and returns how many frames there were, without taking any: a hint
    /// for how much to read.
    pub async fn wait_for_room(&self) -> i64 {
        let deadline = tokio::time::Instant::now() + MAX_WAIT;
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let free = self.lock().free;
            if free > 0 {
                return free;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return 1;
            }
        }
    }

    /// Takes up to `want` frames (at least one), waiting while there is no
    /// room. They count as queued until the loop reports them `sent`. After
    /// MAX_WAIT without an update one frame is taken anyway.
    pub async fn claim(&self, want: i64) -> i64 {
        let want = want.max(1);
        let deadline = tokio::time::Instant::now() + MAX_WAIT;
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut b = self.lock();
                if b.free > 0 {
                    let got = b.free.min(want);
                    b.free -= got;
                    b.queued += got;
                    return got;
                }
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                let mut b = self.lock();
                b.free -= 1;
                b.queued += 1;
                return 1;
            }
        }
    }

    /// The loop has sent (or discarded) `frames` that a reader claimed.
    pub fn sent(&self, frames: i64) {
        let mut b = self.lock();
        b.queued = (b.queued - frames).max(0);
    }

    #[cfg(test)]
    fn figures(&self) -> (i64, i64) {
        let b = self.lock();
        (b.free, b.queued)
    }
}

/// One stream's flow-control window toward the client: what the server may
/// still send on it before the client grants more (`RelayMessage::Window`).
/// The reader of the target waits on it, so a program on the client that
/// reads slowly holds the target back instead of the server's memory.
pub struct StreamWindow {
    credit: AtomicI64,
    notify: Notify,
}

impl StreamWindow {
    pub fn new(initial: i64) -> Self {
        Self { credit: AtomicI64::new(initial), notify: Notify::new() }
    }

    pub fn grant(&self, bytes: i64) {
        self.credit.fetch_add(bytes, Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    /// Bytes that may be sent now; waits while there are none.
    pub async fn acquire(&self) -> i64 {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let c = self.credit.load(Ordering::Relaxed);
            if c > 0 {
                return c;
            }
            notified.await;
        }
    }

    pub fn spend(&self, bytes: i64) {
        self.credit.fetch_sub(bytes, Ordering::Relaxed);
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
        let waiter = tokio::spawn(async move { g.wait_for_room().await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished(), "no budget, so it waits");
        let started = std::time::Instant::now();
        gate.set(7);
        let got = tokio::time::timeout(Duration::from_secs(1), waiter).await.unwrap().unwrap();
        assert_eq!(got, 7);
        assert!(started.elapsed() < Duration::from_millis(50), "woken by the update, not by a timer");
    }

    #[tokio::test]
    async fn claiming_runs_the_budget_down() {
        let gate = SendGate::new(3);
        assert_eq!(gate.claim(10).await, 3);
        assert!(tokio::time::timeout(Duration::from_millis(30), gate.claim(1)).await.is_err());
        assert!(tokio::time::timeout(Duration::from_millis(30), gate.wait_for_room()).await.is_err());
    }

    /// Frames handed over but not yet sent are not handed out again by the
    /// next update: the window counts only frames already sent.
    #[tokio::test]
    async fn an_update_subtracts_what_is_still_queued() {
        let gate = SendGate::new(10);
        assert_eq!(gate.claim(6).await, 6);
        // The loop has sent nothing yet; its window still says 10.
        gate.set(10);
        assert_eq!(gate.figures(), (4, 6));
        assert_eq!(gate.claim(10).await, 4);
        // The loop sends the first six: they are in flight now, so the
        // window it reports is smaller by as many.
        gate.sent(6);
        gate.set(4);
        assert_eq!(gate.figures(), (0, 4));
        gate.sent(4);
        gate.set(10);
        assert_eq!(gate.figures(), (10, 0));
    }

    /// Readers woken together share the budget instead of each taking all of it.
    #[tokio::test]
    async fn readers_woken_together_never_take_more_than_the_budget() {
        let gate = Arc::new(SendGate::new(0));
        let mut readers = Vec::new();
        for _ in 0..30 {
            let g = gate.clone();
            readers.push(tokio::spawn(async move {
                tokio::time::timeout(Duration::from_millis(200), g.claim(12)).await.unwrap_or(0)
            }));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        gate.set(40);
        let mut total = 0;
        for r in readers {
            total += r.await.unwrap();
        }
        assert_eq!(total, 40, "the 30 readers took exactly the budget");
    }
}
