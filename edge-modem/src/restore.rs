use std::time::Duration;

/// Run a destructive action, then `body`, and always restore.
///
/// `restore` uses `restore_budget`, never the caller's remaining body budget.
/// That is the radio-cycle invariant: a timed-out body is exactly when restore
/// must still run.
pub fn with_restore<T, E, D, R, B>(
    disrupt: D,
    restore: R,
    restore_budget: Duration,
    body: B,
) -> Result<T, E>
where
    D: FnOnce() -> Result<(), E>,
    R: FnOnce(Duration) -> Result<(), E>,
    B: FnOnce() -> Result<T, E>,
{
    disrupt()?;
    let body_result = body();
    let restore_result = restore(restore_budget);
    match (body_result, restore_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}
