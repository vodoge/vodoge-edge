//! Self-update rollback: a new binary that cannot Resume is discarded.

/// Tracks the running version and the previous version to restore.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateGuard {
    pub current: String,
    pub previous: Option<String>,
}

impl UpdateGuard {
    pub fn new(current: impl Into<String>) -> Self {
        Self {
            current: current.into(),
            previous: None,
        }
    }

    pub fn start(&mut self, next: impl Into<String>) {
        self.previous = Some(self.current.clone());
        self.current = next.into();
    }

    /// After a failed Resume/handshake, return the version to restore.
    pub fn rollback_if_handshake_failed(&mut self, handshake_ok: bool) -> Option<String> {
        if handshake_ok {
            self.previous = None;
            return None;
        }
        let previous = self.previous.take()?;
        self.current = previous.clone();
        Some(previous)
    }
}

#[cfg(test)]
mod tests {
    use super::UpdateGuard;

    #[test]
    fn failed_handshake_rolls_back_to_the_previous_version() {
        let mut guard = UpdateGuard::new("1.0.0");
        guard.start("1.1.0");
        assert_eq!(guard.rollback_if_handshake_failed(false).as_deref(), Some("1.0.0"));
        assert_eq!(guard.current, "1.0.0");
    }

    #[test]
    fn successful_handshake_keeps_the_new_version() {
        let mut guard = UpdateGuard::new("1.0.0");
        guard.start("1.1.0");
        assert!(guard.rollback_if_handshake_failed(true).is_none());
        assert_eq!(guard.current, "1.1.0");
    }
}
