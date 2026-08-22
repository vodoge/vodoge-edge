//! Testing whether an upstream proxy is usable, from where the device sits.
//!
//! The probe has to run on the edge. The question is whether *this* box, over
//! *this* network path, can reach the proxy — which a probe from the cloud
//! would not answer, and which is exactly the question asked when a proxy
//! "isn't working".
//!
//! It reports the stage it reached rather than a yes or no. "Cannot connect"
//! and "connects but rejects the credentials" have completely different fixes,
//! and collapsing them into one boolean throws away the half of the answer
//! that says what to do next.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::bind;
use crate::socks5;

/// How far the probe got.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Could not open a TCP connection at all.
    TcpConnect,
    /// Connected, but the SOCKS5 negotiation failed.
    Handshake,
    /// Negotiated, but the credentials were refused.
    Authentication,
    /// Everything worked.
    Ok,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProbeResult {
    pub address: String,
    pub stage: Stage,
    pub ok: bool,
    pub duration_ms: u64,
    /// What went wrong, in terms an operator can act on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// What to try, when the failure has an obvious next step.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

impl ProbeResult {
    fn failed(address: &str, stage: Stage, started: Instant, error: String, hint: &str) -> Self {
        Self {
            address: address.to_string(),
            stage,
            ok: false,
            duration_ms: started.elapsed().as_millis() as u64,
            error: Some(error),
            hint: if hint.is_empty() {
                None
            } else {
                Some(hint.to_string())
            },
        }
    }
}

/// Probes one upstream, leaving over `interface` when one is given so the test
/// takes the same path the traffic would.
pub async fn probe(
    address: &str,
    username: &str,
    password: &str,
    interface: Option<&str>,
    timeout: Duration,
) -> ProbeResult {
    let started = Instant::now();

    let connect = tokio::time::timeout(timeout, bind::connect_via(address, interface)).await;
    let mut stream = match connect {
        Err(_) => {
            return ProbeResult::failed(
                address,
                Stage::TcpConnect,
                started,
                format!("no answer within {}ms", timeout.as_millis()),
                "check the address and that the device's network can reach it",
            )
        }
        Ok(Err(error)) => {
            return ProbeResult::failed(
                address,
                Stage::TcpConnect,
                started,
                error.to_string(),
                "check the address and that the device's network can reach it",
            )
        }
        Ok(Ok(stream)) => stream,
    };

    match tokio::time::timeout(timeout, negotiate(&mut stream, username, password)).await {
        Err(_) => ProbeResult::failed(
            address,
            Stage::Handshake,
            started,
            "the proxy accepted the connection but never completed the handshake".into(),
            "confirm it speaks SOCKS5 rather than HTTP",
        ),
        Ok(Err(failure)) => ProbeResult::failed(
            address,
            failure.stage,
            started,
            failure.error,
            failure.hint,
        ),
        Ok(Ok(())) => ProbeResult {
            address: address.to_string(),
            stage: Stage::Ok,
            ok: true,
            duration_ms: started.elapsed().as_millis() as u64,
            error: None,
            hint: None,
        },
    }
}

struct Failure {
    stage: Stage,
    error: String,
    hint: &'static str,
}

async fn negotiate(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
) -> Result<(), Failure> {
    let wants_auth = !username.is_empty();
    let offer: &[u8] = if wants_auth {
        &[socks5::VERSION, 1, socks5::AUTH_USER_PASSWORD]
    } else {
        &[socks5::VERSION, 1, socks5::AUTH_NONE]
    };
    stream.write_all(offer).await.map_err(|error| Failure {
        stage: Stage::Handshake,
        error: error.to_string(),
        hint: "the connection closed during the greeting",
    })?;

    let mut chosen = [0u8; 2];
    stream.read_exact(&mut chosen).await.map_err(|error| Failure {
        stage: Stage::Handshake,
        error: error.to_string(),
        hint: "confirm it speaks SOCKS5 rather than HTTP",
    })?;
    if chosen[0] != socks5::VERSION {
        return Err(Failure {
            stage: Stage::Handshake,
            error: format!("answered with version {} rather than 5", chosen[0]),
            hint: "confirm it speaks SOCKS5 rather than HTTP",
        });
    }
    if chosen[1] == socks5::AUTH_UNACCEPTABLE {
        return Err(Failure {
            stage: Stage::Handshake,
            error: "the proxy refused every authentication method offered".into(),
            hint: if wants_auth {
                "the proxy may not accept username and password authentication"
            } else {
                "the proxy requires a username and password"
            },
        });
    }

    if chosen[1] == socks5::AUTH_USER_PASSWORD {
        stream
            .write_all(&socks5::user_password_request(username, password))
            .await
            .map_err(|error| Failure {
                stage: Stage::Authentication,
                error: error.to_string(),
                hint: "",
            })?;
        let mut status = [0u8; 2];
        stream
            .read_exact(&mut status)
            .await
            .map_err(|error| Failure {
                stage: Stage::Authentication,
                error: error.to_string(),
                hint: "",
            })?;
        if status[1] != 0 {
            return Err(Failure {
                stage: Stage::Authentication,
                error: "the proxy rejected the username or password".into(),
                hint: "check the credentials stored for this upstream",
            });
        }
    }
    Ok(())
}
