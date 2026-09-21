// Outbound fetches with a time limit and a classified failure.

use std::pin::pin;
use std::time::Duration;

use futures_util::future::{select, Either};
use worker::*;

/// Why an outbound fetch got no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FetchFailure {
    TimedOut,
    /// The host name didn't resolve.
    Dns,
    /// Refused, reset, closed early, or an unparseable reply.
    Connection,
}

impl FetchFailure {
    /// Classifies a failed fetch by the runtime's error text, falling back to a
    /// generic connection failure.
    fn from_fetch_error(error: &Error) -> Self {
        if error.to_string().contains("DNS lookup failed") {
            Self::Dns
        } else {
            Self::Connection
        }
    }
}

impl std::fmt::Display for FetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TimedOut => "timeout",
            Self::Dns => "dns",
            Self::Connection => "connection",
        })
    }
}

/// Sends `req`, giving up after `timeout`.
pub(crate) async fn send_with_timeout(req: Request, timeout: Duration) -> std::result::Result<Response, FetchFailure> {
    let controller = AbortController::default();
    let signal = controller.signal();
    let fetch = Fetch::Request(req);
    let send = pin!(fetch.send_with_signal(&signal));
    let deadline = pin!(Delay::from(timeout));
    match select(send, deadline).await {
        Either::Left((result, _)) => result.map_err(|e| FetchFailure::from_fetch_error(&e)),
        Either::Right(..) => {
            controller.abort();
            Err(FetchFailure::TimedOut)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_failure_reasons() {
        assert_eq!(FetchFailure::TimedOut.to_string(), "timeout");
        assert_eq!(FetchFailure::Dns.to_string(), "dns");
        assert_eq!(FetchFailure::Connection.to_string(), "connection");
    }
}
