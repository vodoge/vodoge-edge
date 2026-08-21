//! In-process log ring the panel serves.
//!
//! The daemon's own output is the fastest way to see what a modem is doing,
//! but reaching it meant an SSH session and `journalctl`. That is exactly the
//! access an on-site operator does not have, so the same lines are kept in a
//! bounded ring and served over the LAN panel.
//!
//! The ring is process-global on purpose. Logging is ambient: threading a
//! handle through every call site that can fail would change a dozen
//! signatures to carry something none of them are about.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Lines retained. Enough to cover a failed operation and what led to it,
/// without letting a chatty poll loop grow without bound.
const CAPACITY: usize = 500;

static GLOBAL: OnceLock<Arc<LogRing>> = OnceLock::new();

/// One captured line.
#[derive(Clone, Debug, serde::Serialize)]
pub struct LogLine {
    /// Monotonic cursor. A reader passes the last one it saw to get only what
    /// came after, so a poll never re-delivers or skips a line.
    pub seq: u64,
    pub at: i64,
    pub text: String,
}

/// Bounded ring of recent log lines.
pub struct LogRing {
    lines: Mutex<VecDeque<LogLine>>,
    next: AtomicU64,
}

impl Default for LogRing {
    fn default() -> Self {
        Self::new()
    }
}

impl LogRing {
    pub fn new() -> Self {
        Self {
            lines: Mutex::new(VecDeque::with_capacity(CAPACITY)),
            next: AtomicU64::new(1),
        }
    }

    /// The ring this process logs into, created on first use.
    pub fn global() -> Arc<LogRing> {
        GLOBAL.get_or_init(|| Arc::new(LogRing::new())).clone()
    }

    pub fn push(&self, text: impl Into<String>) {
        let seq = self.next.fetch_add(1, Ordering::Relaxed);
        let line = LogLine {
            seq,
            at: now_ms(),
            text: text.into(),
        };
        let mut lines = self.lines.lock().expect("log ring");
        if lines.len() == CAPACITY {
            lines.pop_front();
        }
        lines.push_back(line);
    }

    /// Lines newer than `after`. Passing 0 returns everything retained.
    pub fn since(&self, after: u64) -> Vec<LogLine> {
        self.lines
            .lock()
            .expect("log ring")
            .iter()
            .filter(|line| line.seq > after)
            .cloned()
            .collect()
    }

    /// Cursor a reader should pass next time.
    pub fn cursor(&self) -> u64 {
        self.next.load(Ordering::Relaxed).saturating_sub(1)
    }
}

/// Print a line and keep it for the panel.
///
/// Both, not either: the operator on the panel and whatever collects the
/// service's output need the same record.
pub fn log_line(text: impl Into<String>) {
    let text = text.into();
    println!("{text}");
    LogRing::global().push(text);
}

/// Same, for a line that reports a failure.
pub fn log_error(text: impl Into<String>) {
    let text = text.into();
    eprintln!("{text}");
    LogRing::global().push(text);
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_returns_only_newer_lines() {
        let ring = LogRing::new();
        ring.push("one");
        ring.push("two");
        let first = ring.since(0);
        assert_eq!(first.len(), 2);
        let cursor = first.last().expect("line").seq;
        ring.push("three");
        let rest = ring.since(cursor);
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].text, "three");
    }

    /// A reader that polls with an up-to-date cursor must get nothing, not the
    /// last line again.
    #[test]
    fn an_current_cursor_returns_nothing() {
        let ring = LogRing::new();
        ring.push("one");
        assert!(ring.since(ring.cursor()).is_empty());
    }

    /// Sequence numbers keep rising after eviction, so a reader whose cursor
    /// points at a dropped line still gets everything still held rather than
    /// silently resyncing to the start.
    #[test]
    fn eviction_keeps_sequence_numbers_rising() {
        let ring = LogRing::new();
        for index in 0..CAPACITY + 10 {
            ring.push(format!("line {index}"));
        }
        let held = ring.since(0);
        assert_eq!(held.len(), CAPACITY);
        assert_eq!(held[0].text, "line 10");
        assert!(held[0].seq > 1);
        assert_eq!(held.last().expect("line").seq, ring.cursor());
    }

    #[test]
    fn the_global_ring_is_one_instance() {
        LogRing::global().push("shared");
        assert!(LogRing::global()
            .since(0)
            .iter()
            .any(|line| line.text == "shared"));
    }
}
