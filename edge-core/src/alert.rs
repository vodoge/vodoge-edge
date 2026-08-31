//! Telling the cloud something is wrong, without telling it three hundred times.
//!
//! The agent already writes everything it knows to a log ring, and the cloud
//! can now ask for it -- but asking is something a person has to think to do.
//! A fault that nobody thinks to look for is a fault nobody hears about: the
//! `/dev/cdc-wdm1` transport error on this bench had been repeating every poll
//! for hours with nothing upstream aware of it.
//!
//! # Why the throttle is the whole design
//!
//! Most of what goes wrong here goes wrong on a loop. The poll runs every few
//! seconds, so a module that has stopped answering produces an error every few
//! seconds for as long as it stays broken. Sending each one would put hundreds
//! of identical rows an hour on the uplink, which is worse than silence: an
//! operator learns to ignore the channel, and the one alert that mattered
//! arrives in the middle of a flood.
//!
//! So a code is announced when it starts, and then at most once per window
//! while it persists -- the repeat carrying how many times it happened, which
//! is the number that says "still broken" rather than "broke again".
//!
//! 🔴 **A code is a constant, never a formatted message.** The contract's
//! pattern (`^[a-z0-9_]{1,128}$`) would reject most messages anyway, but the
//! reason is the throttle: two occurrences are "the same fault" only if they
//! carry the same code, and a code with an IMEI or a port name interpolated
//! into it makes every occurrence unique and every alert unthrottled.

use std::collections::HashMap;

/// How long a code stays suppressed after it is announced.
///
/// Fifteen minutes: long enough that a poll loop failing every few seconds
/// produces four alerts an hour rather than nine hundred, short enough that an
/// operator watching a repair sees it stop.
pub const DEFAULT_WINDOW_MS: i64 = 15 * 60 * 1000;

/// Severity, matching the contract's enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlertLevel {
    Info,
    Warning,
    Error,
    Critical,
}

impl AlertLevel {
    pub fn wire(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

/// What the throttle decided about one occurrence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    /// Send it: this code is not currently being suppressed.
    Send,
    /// Hold it: the same code was announced recently.
    Suppress,
    /// Send it, and say how many were held back since the last announcement.
    /// `repeats` never includes this occurrence.
    Repeat { repeats: u32 },
}

/// Per-code suppression.
///
/// Deliberately pure and clock-free: `now` is handed in, so the rules are
/// testable without sleeping and the same decision is reachable from the poll
/// loop and from a test.
#[derive(Debug, Default)]
pub struct AlertThrottle {
    window_ms: i64,
    seen: HashMap<String, Seen>,
}

#[derive(Debug)]
struct Seen {
    announced_at: i64,
    held: u32,
}

impl AlertThrottle {
    pub fn new(window_ms: i64) -> Self {
        Self {
            window_ms: window_ms.max(0),
            seen: HashMap::new(),
        }
    }

    /// Decide what to do with one occurrence of `code`.
    pub fn consider(&mut self, code: &str, now: i64) -> Decision {
        match self.seen.get_mut(code) {
            None => {
                self.seen.insert(
                    code.to_owned(),
                    Seen {
                        announced_at: now,
                        held: 0,
                    },
                );
                Decision::Send
            }
            Some(entry) => {
                // `saturating_sub` rather than a subtraction: a clock that
                // steps backwards must not make the window look enormous and
                // release every suppressed code at once.
                if now.saturating_sub(entry.announced_at) < self.window_ms {
                    entry.held = entry.held.saturating_add(1);
                    Decision::Suppress
                } else {
                    let repeats = entry.held;
                    entry.announced_at = now;
                    entry.held = 0;
                    Decision::Repeat { repeats }
                }
            }
        }
    }

    /// Forget a code, so the next occurrence is announced as new.
    ///
    /// For a fault that has demonstrably ended: the next failure after a
    /// repair is a new event, not the continuation of the old one.
    pub fn clear(&mut self, code: &str) {
        self.seen.remove(code);
    }

    /// How many codes are being tracked. Bounded by the number of distinct
    /// codes the agent can emit, which is why codes must be constants.
    pub fn tracked(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔴 The property the whole thing exists for: a fault that repeats every
    /// poll is announced once, not once per poll. Without this, a single dead
    /// port puts hundreds of identical rows an hour on the uplink and the
    /// channel stops being worth reading.
    #[test]
    fn a_fault_that_repeats_every_poll_is_announced_once() {
        let mut throttle = AlertThrottle::new(DEFAULT_WINDOW_MS);
        assert_eq!(throttle.consider("qmi_transport_error", 0), Decision::Send);
        // Twelve seconds apart, for ten minutes.
        let mut sent = 0;
        for tick in 1..=50 {
            if throttle.consider("qmi_transport_error", tick * 12_000) != Decision::Suppress {
                sent += 1;
            }
        }
        assert_eq!(sent, 0, "a persisting fault spoke more than once inside the window");
    }

    /// And when the window passes it speaks again, carrying how many it held.
    /// The count is what distinguishes "still broken" from "broke again".
    #[test]
    fn a_persisting_fault_repeats_with_its_count() {
        let mut throttle = AlertThrottle::new(1_000);
        assert_eq!(throttle.consider("port_gone", 0), Decision::Send);
        for tick in 1..=4 {
            assert_eq!(throttle.consider("port_gone", tick * 100), Decision::Suppress);
        }
        assert_eq!(
            throttle.consider("port_gone", 2_000),
            Decision::Repeat { repeats: 4 },
            "the repeat did not carry what it held back"
        );
        // And the count starts over, so the next repeat is not cumulative.
        assert_eq!(throttle.consider("port_gone", 2_100), Decision::Suppress);
        assert_eq!(
            throttle.consider("port_gone", 4_000),
            Decision::Repeat { repeats: 1 }
        );
    }

    /// One noisy code must not silence a different one. They are separate
    /// faults and an operator needs to hear the second one start.
    #[test]
    fn codes_do_not_share_a_budget() {
        let mut throttle = AlertThrottle::new(DEFAULT_WINDOW_MS);
        assert_eq!(throttle.consider("first", 0), Decision::Send);
        for tick in 1..=20 {
            throttle.consider("first", tick * 1_000);
        }
        assert_eq!(
            throttle.consider("second", 21_000),
            Decision::Send,
            "a new fault was swallowed by an old one"
        );
    }

    /// 🔴 A clock that steps backwards must not release everything at once.
    /// `saturating_sub` is what keeps a backwards step from reading as an
    /// enormous elapsed time and turning every suppressed code loose.
    #[test]
    fn a_backwards_clock_does_not_release_the_flood() {
        let mut throttle = AlertThrottle::new(DEFAULT_WINDOW_MS);
        assert_eq!(throttle.consider("code", 1_000_000), Decision::Send);
        assert_eq!(
            throttle.consider("code", 0),
            Decision::Suppress,
            "time going backwards let a suppressed code through"
        );
    }

    /// Clearing means the next occurrence is a new event rather than the
    /// continuation of one that was repaired.
    #[test]
    fn clearing_makes_the_next_occurrence_new() {
        let mut throttle = AlertThrottle::new(DEFAULT_WINDOW_MS);
        assert_eq!(throttle.consider("code", 0), Decision::Send);
        assert_eq!(throttle.consider("code", 1_000), Decision::Suppress);
        throttle.clear("code");
        assert_eq!(throttle.consider("code", 2_000), Decision::Send);
        assert_eq!(throttle.tracked(), 1);
    }

    /// A zero window is "announce everything", which is what a test or a
    /// deliberately unthrottled deployment would ask for. It must not panic
    /// or divide by anything.
    #[test]
    fn a_zero_window_announces_every_occurrence() {
        let mut throttle = AlertThrottle::new(0);
        assert_eq!(throttle.consider("code", 0), Decision::Send);
        assert_eq!(throttle.consider("code", 0), Decision::Repeat { repeats: 0 });
    }
}
