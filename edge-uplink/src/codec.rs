//! Interim JSON envelope codec. MessagePack replaces this without changing the session.

use vodoge_contract::Envelope;

use crate::session::SessionError;

/// Encodes one envelope as a binary WebSocket payload.
pub fn encode_json(envelope: &Envelope) -> Result<Vec<u8>, SessionError> {
    serde_json::to_vec(envelope).map_err(|err| SessionError::InvalidEnvelope(err.to_string()))
}

/// Decodes one binary WebSocket payload into an envelope.
pub fn decode_json(frame: &[u8]) -> Result<Envelope, SessionError> {
    let envelope: Envelope = serde_json::from_slice(frame)
        .map_err(|err| SessionError::InvalidEnvelope(err.to_string()))?;
    envelope
        .validate_sequence()
        .map_err(SessionError::InvalidEnvelope)?;
    Ok(envelope)
}
