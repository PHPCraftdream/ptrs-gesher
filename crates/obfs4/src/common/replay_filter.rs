use ptrs::trace;
/// The replayfilter module implements a generic replay detection filter with a
/// caller specifiable time-to-live.  It only detects if a given byte sequence
/// has been seen before based on the SipHash-2-4 digest of the sequence.
/// Collisions are treated as positive matches, though the probability of this
/// happening is negligible.
use siphasher::{prelude::*, sip::SipHasher24};

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// maxFilterSize is the maximum capacity of a replay filter.  This value is
// more as a safeguard to prevent runaway filter growth, and is sized to be
// serveral orders of magnitude greater than the number of connections a busy
// bridge sees in one day, so in practice should never be reached.
const MAX_FILTER_SIZE: usize = 100 * 1024;

struct Entry {
    digest: u64,
    first_seen: Instant,
}

/// Thread-safe replay detection filter that tracks recently seen byte sequences by their SipHash-2-4 digest.
pub struct ReplayFilter(Arc<Mutex<InnerReplayFilter>>);

impl ReplayFilter {
    /// Create a new replay filter that evicts entries older than `ttl`.
    pub fn new(ttl: Duration) -> Self {
        Self(Arc::new(Mutex::new(InnerReplayFilter::new(
            ttl,
            MAX_FILTER_SIZE,
        ))))
    }

    /// Test whether `buf` has been seen before, then record it; returns `true` if it was a replay.
    pub fn test_and_set(&self, now: Instant, buf: impl AsRef<[u8]>) -> bool {
        // The filter is shared across every connection handled by a bridge. If
        // one task panics while holding this lock the mutex becomes poisoned;
        // recovering the inner value (rather than `.unwrap()` propagating the
        // panic) prevents a single unrelated panic from cascading into every
        // subsequent handshake and taking down the whole server. The replay set
        // is best-effort accounting, so continuing with the existing contents is
        // the correct fail-open-but-keep-serving choice here.
        let mut inner = self.0.lock().unwrap_or_else(|p| p.into_inner());
        inner.test_and_set(now, buf)
    }
}

struct InnerReplayFilter {
    filter: HashSet<u64>,
    fifo: VecDeque<Entry>,

    key: [u8; 16],
    ttl_limit: Duration,
    max_cap: usize,
    latest_time: Option<Instant>,
}

impl Drop for InnerReplayFilter {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

impl InnerReplayFilter {
    fn new(ttl_limit: Duration, max_cap: usize) -> Self {
        let mut key = [0_u8; 16];
        // SipHash key for the filter; a CSPRNG failure here is unrecoverable.
        getrandom::getrandom(&mut key).expect("system RNG failure seeding replay filter key");

        Self {
            filter: HashSet::new(),
            fifo: VecDeque::new(),
            key,
            ttl_limit,
            max_cap,
            latest_time: None,
        }
    }

    fn test_and_set(&mut self, now: Instant, buf: impl AsRef<[u8]>) -> bool {
        // Calls can capture `now` before waiting for the mutex and arrive out
        // of order. Clamp timestamps so stale callers cannot move time back.
        let now = match self.latest_time {
            Some(latest) if now < latest => latest,
            _ => now,
        };
        self.latest_time = Some(now);
        self.garbage_collect(now);

        let mut hash = SipHasher24::new_with_key(&self.key);
        let digest: u64 = {
            hash.write(buf.as_ref());
            hash.finish().to_be()
        };

        trace!("checking inner");
        if self.filter.contains(&digest) {
            return true;
        }

        if self.max_cap == 0 {
            return false;
        }
        while self.fifo.len() >= self.max_cap {
            self.evict_oldest();
        }

        trace!("not found: {digest}... inserting");
        let e = Entry {
            digest,
            first_seen: now,
        };

        self.fifo.push_front(e);
        self.filter.insert(digest);

        trace!("inserted: {}", self.filter.len());
        false
    }

    fn garbage_collect(&mut self, now: Instant) {
        if self.fifo.is_empty() {
            return;
        }

        while !self.fifo.is_empty() {
            let e = match self.fifo.back() {
                Some(e) => e,
                None => return,
            };

            trace!(
                "{}/{}[/{}] - {:?}",
                self.fifo.len(),
                self.filter.len(),
                self.max_cap,
                self.ttl_limit
            );
            let expired = self.ttl_limit.is_zero()
                || now.saturating_duration_since(e.first_seen) >= self.ttl_limit;
            if !expired {
                return;
            }
            self.evict_oldest();
        }
    }

    fn evict_oldest(&mut self) {
        if let Some(entry) = self.fifo.pop_back() {
            trace!("removing entry");
            self.filter.remove(&entry.digest);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::init_subscriber;
    use crate::Result;

    #[test]
    fn replay_filter_ops() -> Result<()> {
        init_subscriber();
        let ttl = Duration::from_secs(10);

        let f = &mut ReplayFilter::new(ttl);

        let buf = b"For a moment, nothing happened. Then, after a second or so, nothing continued to happen.";
        let mut now = Instant::now();

        // test_and_set into empty filter, returns false (not present).
        assert!(
            !f.test_and_set(now, buf),
            "test_and_set (mutex) empty filter returned true"
        );

        // test_and_set into filter containing entry, should return true(present).
        assert!(
            f.test_and_set(now, buf),
            "test_and_set (mutex) populated filter (replayed) returned false"
        );

        let f = &mut InnerReplayFilter::new(ttl, 2);

        // test_and_set into empty filter, returns false (not present).
        assert!(
            !f.test_and_set(now, buf),
            "test_and_set empty filter returned true"
        );

        // test_and_set into filter containing entry, should return true(present).
        assert!(
            f.test_and_set(now, buf),
            "test_and_set populated filter (replayed) returned false"
        );

        // test_and_set with time advanced.
        let buf2 = b"We demand rigidly defined areas of doubt and uncertainty!";
        now += ttl;
        assert!(
            !f.test_and_set(now, buf2),
            "test_and_set populated filter, 2nd entry returned true"
        );
        assert!(
            f.test_and_set(now, buf2),
            "test_and_set populated filter, 2nd entry (replayed) returned false"
        );

        // Ensure that the first entry has been removed by compact.
        assert!(
            !f.test_and_set(now, buf),
            "test_and_set populated filter, compact check returned true"
        );

        // A stale timestamp must not reset the filter or lose replay history.
        now = Instant::now();
        assert!(
            f.test_and_set(now, buf),
            "test_and_set populated filter, backward time jump lost replay history"
        );
        assert_eq!(
            f.fifo.len(),
            2,
            "filter fifo has a unexpected number of entries: {}",
            f.fifo.len()
        );
        assert_eq!(
            f.filter.len(),
            2,
            "filter map has a unexpected number of entries: {}",
            f.filter.len()
        );

        // The replay is still recognized after the stale call.
        assert!(
            f.test_and_set(now, buf),
            "test_and_set populated filter, post-backward clock jump returned false"
        );

        // Ensure that when the capacity limit is hit entries are evicted
        f.test_and_set(now, "message2");
        for i in 0..10 {
            assert_eq!(
                f.fifo.len(),
                2,
                "filter fifo has a unexpected number of entries: {}",
                f.fifo.len()
            );
            assert_eq!(
                f.filter.len(),
                2,
                "filter map has a unexpected number of entries: {}",
                f.filter.len()
            );
            assert!(
                !f.test_and_set(now, format!("message-1{i}")),
                "unique message failed insert (returned true)"
            );
        }

        Ok(())
    }

    #[test]
    fn replay_ttl_covers_mac_slack_window() {
        // Server accepts MACs computed for epoch_hour ± 1, so a recorded
        // handshake can be re-presented up to ~2h after capture.
        assert!(crate::constants::REPLAY_TTL >= Duration::from_secs(2 * 3600));
    }

    #[test]
    fn reversed_timestamps_keep_replay_history() {
        let mut filter = InnerReplayFilter::new(Duration::from_secs(10), 4);
        let base = Instant::now();
        assert!(!filter.test_and_set(base + Duration::from_secs(5), b"first"));
        assert!(filter.test_and_set(base, b"first"));
        assert_eq!(filter.fifo.len(), 1);
    }

    #[test]
    fn full_capacity_duplicate_oldest_is_not_evicted() {
        let mut filter = InnerReplayFilter::new(Duration::from_secs(10), 2);
        let now = Instant::now();
        assert!(!filter.test_and_set(now, b"oldest"));
        assert!(!filter.test_and_set(now, b"newest"));
        assert!(filter.test_and_set(now, b"oldest"));
        assert_eq!(filter.fifo.len(), 2);
        assert_eq!(filter.filter.len(), 2);
    }

    #[test]
    fn ttl_expires_at_boundary() {
        let ttl = Duration::from_secs(10);
        let mut filter = InnerReplayFilter::new(ttl, 2);
        let now = Instant::now();
        assert!(!filter.test_and_set(now, b"entry"));
        assert!(!filter.test_and_set(now + ttl, b"entry"));
    }

    #[test]
    fn unique_insertions_remain_bounded() {
        let mut filter = InnerReplayFilter::new(Duration::from_secs(60), 3);
        let now = Instant::now();
        for message in [b"one".as_slice(), b"two", b"three", b"four", b"five"] {
            assert!(!filter.test_and_set(now, message));
            assert!(filter.fifo.len() <= 3);
            assert!(filter.filter.len() <= 3);
        }
    }
}
