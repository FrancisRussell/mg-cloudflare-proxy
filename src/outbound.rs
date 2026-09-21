// Outbound fetches with a time limit and a classified failure.

use std::pin::pin;
use std::time::Duration;

use futures_util::future::{select, Either};
use http::StatusCode;
use thiserror::Error;
use worker::{AbortController, Delay, Error as WorkerError, Fetch, Request, Response};

/// Why an outbound fetch got no answer. The messages double as the reason
/// logged for a failed fetch, so they stay short and free of spaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum FetchFailure {
    /// The server didn't answer within the time allowed
    #[error("timeout")]
    TimedOut,

    /// The host name didn't resolve
    #[error("dns")]
    Dns,

    /// The connection was refused, reset or closed early, or the reply couldn't
    /// be parsed
    #[error("connection")]
    Connection,
}

impl FetchFailure {
    /// Classifies a failed fetch by the runtime's error text, falling back to a
    /// generic connection failure.
    fn from_fetch_error(error: &WorkerError) -> Self {
        if error.to_string().contains("DNS lookup failed") {
            Self::Dns
        } else {
            Self::Connection
        }
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

/// The status to answer the caller with when the server gave no answer: a
/// gateway timeout if it was too slow, otherwise a bad gateway.
impl From<FetchFailure> for StatusCode {
    fn from(failure: FetchFailure) -> Self {
        match failure {
            FetchFailure::TimedOut => Self::GATEWAY_TIMEOUT,
            FetchFailure::Dns | FetchFailure::Connection => Self::BAD_GATEWAY,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failure_status() {
        assert_eq!(StatusCode::from(FetchFailure::TimedOut), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(StatusCode::from(FetchFailure::Dns), StatusCode::BAD_GATEWAY);
        assert_eq!(StatusCode::from(FetchFailure::Connection), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_from_fetch_error_recognises_dns_failures() {
        // The runtime's wording for an unresolvable host.
        let dns = WorkerError::RustError("e = kj/async-io-unix.c++:1292: failed: DNS lookup failed.".to_string());
        assert_eq!(FetchFailure::from_fetch_error(&dns), FetchFailure::Dns);
    }

    #[test]
    fn test_from_fetch_error_treats_other_failures_as_connection_failures() {
        for text in ["Network connection lost.", "Error: connect refused", ""] {
            let error = WorkerError::RustError(text.to_string());
            assert_eq!(FetchFailure::from_fetch_error(&error), FetchFailure::Connection, "text: {text:?}");
        }
    }
}
