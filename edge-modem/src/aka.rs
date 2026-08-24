//! USIM AKA (3G security context) over the modem's **basic** channel.
//!
//! EAP-AKA needs an oracle that only the card can be: given a RAND and an AUTN
//! from the operator's AuC, produce RES/CK/IK. Nothing in this crate could do
//! that before — every `0x88`/CSIM string here belonged to eUICC profile
//! management — so the tunnel stack had no way to answer a challenge.
//!
//! Two decisions are load-bearing and both were settled by measurement on the
//! bench rather than by reading a spec:
//!
//! * **Basic channel, no logical channel.** `AT+CSIM=10,"00F2000000"` on both
//!   eUICC modules answers an FCP whose tag `84` is the USIM ADF AID, i.e. the
//!   application is already selected on channel 0 after boot. Opening a
//!   logical channel to select it again would compete with `IsdrSession` for
//!   the few channels an eUICC offers, and losing that race breaks profile
//!   management — a much worse failure than not authenticating.
//! * **The FCP is checked every time.** "Already selected" is one observation,
//!   not a guarantee: a card reset, a profile switch or somebody else's
//!   `SELECT` can change it, and an AUTHENTICATE sent to the wrong application
//!   is answered by the wrong keys. So every authentication re-reads the FCP
//!   and refuses to continue unless the USIM ADF is what is selected.
//!
//! Status words are classified here rather than left to the caller, because
//! the distinction between "the card rejected this challenge" and "the pipe is
//! broken" is exactly what the protocol layer above has to act on: a rejection
//! becomes an EAP Authentication-Reject or an AT_AUTS resynchronisation, a
//! broken pipe must not. `9862` — incorrect MAC — is the one rejection this
//! bench can reproduce on demand, with a synthetic AUTN, and it is a *correct*
//! answer: the card ran Milenage and did not like our MAC. A dead pipe answers
//! `6E00`/`6D00`/`6A81` instead.

use std::fmt;
use std::time::Duration;

use crate::at::{AtError, AtPort};
use crate::uim::{drain_get_response, ApduResponse};

/// RAND is 16 bytes and AUTN is 16 bytes; the card rejects anything else.
pub const RAND_BYTES: usize = 16;
pub const AUTN_BYTES: usize = 16;
/// AUTS, returned on a sequence-number synchronisation failure.
pub const AUTS_BYTES: usize = 14;
pub const CK_BYTES: usize = 16;
pub const IK_BYTES: usize = 16;
pub const KC_BYTES: usize = 8;
/// RES is variable length within these bounds (TS 33.102).
pub const RES_MIN_BYTES: usize = 4;
pub const RES_MAX_BYTES: usize = 16;

/// `STATUS` with P2=00, i.e. "return the FCP of the current application".
pub const STATUS_FCP_APDU: [u8; 5] = [0x00, 0xf2, 0x00, 0x00, 0x00];

/// RID + PIX of the 3GPP USIM application: `A0 00 00 00 87` + `10 02`.
///
/// Only the prefix is fixed; the rest of the AID is card specific. ISIM is
/// `1004` under the same RID, which is why the PIX is part of the check —
/// authenticating against ISIM would use a different security context.
pub const USIM_ADF_AID_PREFIX: [u8; 7] = [0xa0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

/// FCP template tag, and the FCI template some cards answer with instead.
const FCP_TEMPLATE_TAG: u8 = 0x62;
const FCI_TEMPLATE_TAG: u8 = 0x6f;
/// DF name (the AID of the selected application) inside a template.
const DF_NAME_TAG: u8 = 0x84;

/// Body tags of an AUTHENTICATE response (TS 31.102 §7.1.2).
const TAG_SUCCESS: u8 = 0xdb;
const TAG_SYNC_FAILURE: u8 = 0xdc;
const TAG_AUTH_FAILURE: u8 = 0xdd;

/// "Authentication error, incorrect MAC".
///
/// The only `98xx` this bench has ever produced, and the only one mapped
/// here. `9864` is *deliberately absent*: the mapping repeated in most
/// tooling is not something we have a first-hand source for, and guessing it
/// would turn an unknown card state into a confidently wrong protocol
/// decision. Everything else in the family comes back as
/// [`AkaError::UnknownStatusWord`] carrying the raw bytes.
pub const SW_INCORRECT_MAC: (u8, u8) = (0x98, 0x62);

/// Default budget for one AUTHENTICATE round trip.
///
/// Every caller of this is on a synchronous, timed path — IKE_AUTH, the IMS
/// REGISTER 401 challenge, up to five E911 entitlement rounds — so a card that
/// stops answering has to become an error quickly rather than hold the port
/// until the peer gives up on us.
pub const AKA_TIMEOUT: Duration = Duration::from_secs(10);

/// What the card said about one challenge.
///
/// Three outcomes, because the protocol above treats them as three different
/// messages: keys, a resynchronisation token, or a rejection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AkaOutcome {
    /// The card accepted the challenge.
    Success {
        res: Vec<u8>,
        ck: Vec<u8>,
        ik: Vec<u8>,
        /// Some USIMs append the GSM key; kept rather than dropped so a
        /// caller that needs GSM/UMTS interworking does not have to ask
        /// again.
        kc: Option<Vec<u8>>,
    },
    /// Sequence number out of range. `auts` goes back to the network in an
    /// `AT_AUTS` attribute; this is a recoverable condition, not a failure.
    SyncFailure { auts: Vec<u8> },
    /// The card refused the challenge. `sw1`/`sw2` are kept so a receipt can
    /// show which refusal it was.
    AuthenticationFailure {
        sw1: u8,
        sw2: u8,
        detail: &'static str,
    },
}

impl AkaOutcome {
    /// Short, stable label for logs and RPC responses.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Success { .. } => "success",
            Self::SyncFailure { .. } => "sync_failure",
            Self::AuthenticationFailure { .. } => "authentication_failure",
        }
    }
}

/// Everything that can go wrong that is *not* the card answering a challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AkaError {
    /// RAND or AUTN was not 16 bytes.
    BadChallengeLength { field: &'static str, actual: usize },
    /// The AT port refused the exchange, or the module answered `+CME ERROR`.
    Transport(String),
    /// `+CSIM:` was missing, malformed, or not valid hex.
    MalformedCsim(String),
    /// The card answered the FCP read with something other than `9000`.
    StatusRefused { sw1: u8, sw2: u8 },
    /// The FCP carried no tag `84`, so what is selected cannot be established.
    NoSelectedApplication { fcp: String },
    /// Something other than the USIM ADF is selected on the basic channel.
    ///
    /// Deliberately not repaired here: repairing it means `SELECT`, and this
    /// module's whole reason to exist is that it must not touch application
    /// selection while eUICC sessions are in flight.
    NotUsimAdf { aid: String },
    /// A status word with no mapping. Carries the raw bytes so the next
    /// person has the evidence rather than our guess.
    UnknownStatusWord { sw1: u8, sw2: u8, body: String },
    /// `9000`, but the body is not a shape TS 31.102 describes.
    MalformedResponse { reason: String, body: String },
    /// The card asked for more `GET RESPONSE` rounds than anyone should.
    TooManyGetResponseRounds { rounds: usize },
}

impl fmt::Display for AkaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadChallengeLength { field, actual } => {
                write!(formatter, "{field} must be 16 bytes, got {actual}")
            }
            Self::Transport(reason) => write!(formatter, "AT transport: {reason}"),
            Self::MalformedCsim(reason) => write!(formatter, "malformed +CSIM answer: {reason}"),
            Self::StatusRefused { sw1, sw2 } => write!(
                formatter,
                "card refused STATUS with SW {sw1:02X}{sw2:02X}, so the selected application \
                 is unknown"
            ),
            Self::NoSelectedApplication { fcp } => write!(
                formatter,
                "FCP has no tag 84, so no application is selected on the basic channel: {fcp}"
            ),
            Self::NotUsimAdf { aid } => write!(
                formatter,
                "basic channel has AID {aid} selected, not the USIM ADF; refusing to \
                 AUTHENTICATE against the wrong application"
            ),
            Self::UnknownStatusWord { sw1, sw2, body } => write!(
                formatter,
                "unmapped status word {sw1:02X}{sw2:02X} (body {body})"
            ),
            Self::MalformedResponse { reason, body } => {
                write!(formatter, "{reason} (body {body})")
            }
            Self::TooManyGetResponseRounds { rounds } => {
                write!(formatter, "card asked for more than {rounds} GET RESPONSE rounds")
            }
        }
    }
}

impl std::error::Error for AkaError {}

impl AkaError {
    /// Stable machine-readable code, for the RPC surface and for receipts.
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadChallengeLength { .. } => "bad_challenge_length",
            Self::Transport(_) => "at_transport_failed",
            Self::MalformedCsim(_) => "malformed_csim",
            Self::StatusRefused { .. } => "status_refused",
            Self::NoSelectedApplication { .. } => "no_selected_application",
            Self::NotUsimAdf { .. } => "not_usim_adf",
            Self::UnknownStatusWord { .. } => "unknown_status_word",
            Self::MalformedResponse { .. } => "malformed_response",
            Self::TooManyGetResponseRounds { .. } => "too_many_get_response_rounds",
        }
    }
}

impl From<AtError> for AkaError {
    fn from(error: AtError) -> Self {
        Self::Transport(error.to_string())
    }
}

/// One APDU in, one APDU answer out, on the basic channel.
///
/// A trait because the two things that matter about this code — the APDU it
/// builds and the answers it accepts — must be testable without a modem, and
/// because the same primitive should work over anything that can carry an
/// APDU later.
pub trait BasicChannel {
    fn transmit(&mut self, apdu: &[u8]) -> Result<ApduResponse, AkaError>;
}

/// The basic channel of a Quectel module, reached with `AT+CSIM`.
pub struct CsimChannel<'a> {
    port: &'a mut AtPort,
    timeout: Duration,
}

impl<'a> CsimChannel<'a> {
    pub fn new(port: &'a mut AtPort) -> Self {
        Self {
            port,
            timeout: AKA_TIMEOUT,
        }
    }

    pub fn with_timeout(port: &'a mut AtPort, timeout: Duration) -> Self {
        Self { port, timeout }
    }
}

impl BasicChannel for CsimChannel<'_> {
    fn transmit(&mut self, apdu: &[u8]) -> Result<ApduResponse, AkaError> {
        let exchange = self
            .port
            .command_with_timeout(&csim_command(apdu), self.timeout)?;
        if !exchange.succeeded() {
            return Err(AkaError::Transport(format!(
                "{} answered {}",
                exchange.command, exchange.terminator
            )));
        }
        parse_csim_answer(&exchange.lines)
    }
}

/// `AT+CSIM=<hex chars>,"<hex>"` for one APDU.
///
/// The length field counts hex characters, not bytes; getting that wrong
/// produces `+CME ERROR: 21` rather than anything that names the problem.
pub fn csim_command(apdu: &[u8]) -> String {
    format!("AT+CSIM={},\"{}\"", apdu.len() * 2, hex_upper(apdu))
}

/// The APDU an AUTHENTICATE looks like: `00 88 00 81 22 10<RAND>10<AUTN>` and
/// an `Le` byte.
///
/// CLA `00` is the basic channel; P2 `81` selects the 3G security context.
/// `Le` is included because that is the form the bench answered — the
/// 80-hex-character command in the T033 transcript is this one — and because
/// a card that wants it and does not get it answers `6700` instead of the
/// keys.
pub fn authenticate_apdu(rand16: &[u8], autn16: &[u8], include_le: bool) -> Result<Vec<u8>, AkaError> {
    if rand16.len() != RAND_BYTES {
        return Err(AkaError::BadChallengeLength {
            field: "RAND",
            actual: rand16.len(),
        });
    }
    if autn16.len() != AUTN_BYTES {
        return Err(AkaError::BadChallengeLength {
            field: "AUTN",
            actual: autn16.len(),
        });
    }
    let mut data = Vec::with_capacity(2 + RAND_BYTES + AUTN_BYTES);
    data.push(RAND_BYTES as u8);
    data.extend_from_slice(rand16);
    data.push(AUTN_BYTES as u8);
    data.extend_from_slice(autn16);

    let mut apdu = Vec::with_capacity(6 + data.len());
    apdu.extend_from_slice(&[0x00, 0x88, 0x00, 0x81, data.len() as u8]);
    apdu.extend_from_slice(&data);
    if include_le {
        apdu.push(0x00);
    }
    Ok(apdu)
}

/// Run one AKA challenge against whatever is selected on the basic channel.
///
/// Order matters: the FCP check comes first and a failure there stops the
/// sequence. Sending AUTHENTICATE blind to an unknown application is not a
/// smaller risk than not sending it — the answer would be indistinguishable
/// from a real one.
pub fn usim_authenticate(
    channel: &mut impl BasicChannel,
    rand16: &[u8],
    autn16: &[u8],
) -> Result<AkaOutcome, AkaError> {
    let apdu = authenticate_apdu(rand16, autn16, true)?;
    verify_usim_selected(channel)?;
    let response = exchange(channel, &apdu)?;
    classify_authenticate(&response)
}

/// Read the FCP of the current application and require it to be the USIM ADF.
///
/// Returns the AID, so a caller can put the actual bytes in a receipt instead
/// of "it looked right".
pub fn verify_usim_selected(channel: &mut impl BasicChannel) -> Result<Vec<u8>, AkaError> {
    let response = exchange(channel, &STATUS_FCP_APDU)?;
    if !response.is_success() {
        return Err(AkaError::StatusRefused {
            sw1: response.sw1,
            sw2: response.sw2,
        });
    }
    let aid = selected_aid(&response.data)?;
    if !aid.starts_with(&USIM_ADF_AID_PREFIX) {
        return Err(AkaError::NotUsimAdf {
            aid: hex_upper(&aid),
        });
    }
    Ok(aid)
}

/// Send one APDU and keep pulling until the card stops asking for more.
///
/// `61xx` and `6Cxx` are both "ask again differently" rather than results.
/// The `61xx` loop is the one `IsdrSession::transmit` already runs for ES10 —
/// same helper, so the two paths cannot drift apart.
fn exchange(channel: &mut impl BasicChannel, apdu: &[u8]) -> Result<ApduResponse, AkaError> {
    let first = channel.transmit(apdu)?;
    // `6C xx` means the Le we sent was wrong and xx is the right one. Only
    // one retry: a card that answers 6C twice is not negotiating.
    let first = if first.sw1 == 0x6c && !apdu.is_empty() {
        let mut retry = apdu.to_vec();
        let last = retry.len() - 1;
        retry[last] = first.sw2;
        channel.transmit(&retry)?
    } else {
        first
    };
    drain_get_response(
        first,
        |get_response| channel.transmit(get_response),
        |rounds| AkaError::TooManyGetResponseRounds { rounds },
    )
}

/// Turn a completed AUTHENTICATE exchange into one of the three outcomes.
pub fn classify_authenticate(response: &ApduResponse) -> Result<AkaOutcome, AkaError> {
    match (response.sw1, response.sw2) {
        (0x90, 0x00) => classify_body(&response.data),
        SW_INCORRECT_MAC => Ok(AkaOutcome::AuthenticationFailure {
            sw1: response.sw1,
            sw2: response.sw2,
            detail: "card rejected the challenge: incorrect MAC (SW 9862)",
        }),
        (sw1, sw2) => Err(AkaError::UnknownStatusWord {
            sw1,
            sw2,
            body: hex_upper(&response.data),
        }),
    }
}

/// Parse the body of a `9000` AUTHENTICATE answer.
///
/// The success body is *not* a BER-TLV, however much `DB 08 …` looks like
/// one: TS 31.102 defines it as a tag followed by a run of length-prefixed
/// fields, so the byte after `DB` is the length of RES and not of the whole
/// body. Some cards do wrap the whole thing in a real TLV as well, so both
/// readings are tried — plain first, because reading a wrapped body as plain
/// fails loudly (RES would have to be 42 bytes) while the reverse silently
/// truncates RES to the first eight.
fn classify_body(body: &[u8]) -> Result<AkaOutcome, AkaError> {
    let trimmed = strip_leading_padding(body);
    let malformed = |reason: String| AkaError::MalformedResponse {
        reason,
        body: hex_upper(body),
    };
    let Some(&tag) = trimmed.first() else {
        return Err(malformed("AUTHENTICATE answered 9000 with an empty body".into()));
    };
    match tag {
        TAG_SUCCESS => {
            if let Ok(outcome) = parse_success(&trimmed[1..], body) {
                return Ok(outcome);
            }
            match wrapped_value(trimmed) {
                Some(value) => parse_success(value, body),
                None => parse_success(&trimmed[1..], body),
            }
        }
        // The sync-failure body is length-prefixed either way, so one reading
        // covers both.
        TAG_SYNC_FAILURE => {
            let value = wrapped_value(trimmed)
                .ok_or_else(|| malformed("truncated AUTS field".into()))?;
            if value.len() != AUTS_BYTES {
                return Err(malformed(format!(
                    "AUTS must be {AUTS_BYTES} bytes, got {}",
                    value.len()
                )));
            }
            Ok(AkaOutcome::SyncFailure {
                auts: value.to_vec(),
            })
        }
        // Not seen on this bench. vowifi-go's simauth maps tag DD the same
        // way, which is the only corroboration we have; if a real challenge
        // ever lands here the receipt will say so.
        TAG_AUTH_FAILURE if trimmed.len() == 1 || wrapped_value(trimmed) == Some(&[][..]) => {
            Ok(AkaOutcome::AuthenticationFailure {
                sw1: 0x90,
                sw2: 0x00,
                detail: "card rejected the challenge: body tag DD",
            })
        }
        other => Err(malformed(format!(
            "unknown AUTHENTICATE body shape, tag {other:02X}"
        ))),
    }
}

/// `DB <len RES> RES <len CK> CK <len IK> IK [<len Kc> Kc]`.
fn parse_success(value: &[u8], body: &[u8]) -> Result<AkaOutcome, AkaError> {
    let malformed = |reason: String| AkaError::MalformedResponse {
        reason,
        body: hex_upper(body),
    };
    let mut cursor = Cursor::new(value);
    let res = cursor
        .take_lv()
        .ok_or_else(|| malformed("truncated RES".into()))?;
    if res.len() < RES_MIN_BYTES || res.len() > RES_MAX_BYTES {
        return Err(malformed(format!("RES length {} out of range", res.len())));
    }
    let ck = cursor
        .take_lv()
        .ok_or_else(|| malformed("truncated CK".into()))?;
    if ck.len() != CK_BYTES {
        return Err(malformed(format!("CK length {} is not {CK_BYTES}", ck.len())));
    }
    let ik = cursor
        .take_lv()
        .ok_or_else(|| malformed("truncated IK".into()))?;
    if ik.len() != IK_BYTES {
        return Err(malformed(format!("IK length {} is not {IK_BYTES}", ik.len())));
    }
    let kc = if is_padding(cursor.rest()) {
        None
    } else {
        match cursor.take_lv() {
            Some(kc) if kc.len() == KC_BYTES => Some(kc.to_vec()),
            Some(other) => {
                return Err(malformed(format!(
                    "trailing field of {} bytes is not a Kc",
                    other.len()
                )))
            }
            None => None,
        }
    };
    if !is_padding(cursor.rest()) {
        return Err(malformed(format!(
            "{} unexplained trailing bytes",
            cursor.rest().len()
        )));
    }
    Ok(AkaOutcome::Success {
        res: res.to_vec(),
        ck: ck.to_vec(),
        ik: ik.to_vec(),
        kc,
    })
}

/// The AID of the application a `STATUS` FCP says is selected.
pub fn selected_aid(fcp: &[u8]) -> Result<Vec<u8>, AkaError> {
    let body = strip_leading_padding(fcp);
    let inner = match split_tlv(body) {
        Some((tag, value)) if tag == FCP_TEMPLATE_TAG || tag == FCI_TEMPLATE_TAG => value,
        // Some cards answer with the bare template contents.
        _ => body,
    };
    find_tag(inner, DF_NAME_TAG)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| AkaError::NoSelectedApplication {
            fcp: hex_upper(fcp),
        })
}

/// First value with `tag` among a flat list of BER-TLVs.
fn find_tag(mut data: &[u8], tag: u8) -> Option<&[u8]> {
    while !data.is_empty() {
        if data[0] == 0x00 || data[0] == 0xff {
            data = &data[1..];
            continue;
        }
        let (found, value, rest) = read_tlv(data)?;
        if found == tag {
            return Some(value);
        }
        data = rest;
    }
    None
}

/// Split one BER-TLV off the front, requiring it to be the whole of `data`
/// apart from padding.
fn split_tlv(data: &[u8]) -> Option<(u8, &[u8])> {
    let (tag, value, rest) = read_tlv(strip_leading_padding(data))?;
    if !is_padding(rest) {
        return None;
    }
    Some((tag, value))
}

/// The value of `data` read as one whole BER-TLV, whatever its tag.
fn wrapped_value(data: &[u8]) -> Option<&[u8]> {
    split_tlv(data).map(|(_, value)| value)
}

/// One BER-TLV with a single-byte tag and a short or 1/2-byte long form
/// length. Longer forms do not occur in an FCP or an AKA answer.
fn read_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *data.first()?;
    let rest = &data[1..];
    let (length, rest) = match *rest.first()? {
        0x81 => (*rest.get(1)? as usize, &rest[2..]),
        0x82 => (
            usize::from(u16::from_be_bytes([*rest.get(1)?, *rest.get(2)?])),
            &rest[3..],
        ),
        short if short < 0x80 => (short as usize, &rest[1..]),
        _ => return None,
    };
    if rest.len() < length {
        return None;
    }
    Some((tag, &rest[..length], &rest[length..]))
}

/// Drop the `00`/`FF` filler some cards put in front of an answer.
///
/// Only the front. Trimming the tail as well is the obvious next line and it
/// is wrong: an AID, a CK or an IK is perfectly entitled to end in `00`, and
/// a trimmer that cannot tell filler from payload turns a valid answer into a
/// short one — which is how the first version of this file failed to find
/// tag `84` in a real FCP. Neither `00` nor `FF` is a legal BER tag, so the
/// leading case has no such ambiguity.
fn strip_leading_padding(mut data: &[u8]) -> &[u8] {
    while matches!(data.first(), Some(0x00 | 0xff)) {
        data = &data[1..];
    }
    data
}

/// Whether what is left after a complete TLV is only filler.
fn is_padding(data: &[u8]) -> bool {
    data.iter().all(|byte| matches!(byte, 0x00 | 0xff))
}

/// Walks a sequence of length-prefixed fields.
struct Cursor<'a> {
    data: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn take_lv(&mut self) -> Option<&'a [u8]> {
        let length = *self.data.first()? as usize;
        if self.data.len() < 1 + length {
            return None;
        }
        let value = &self.data[1..1 + length];
        self.data = &self.data[1 + length..];
        Some(value)
    }

    fn rest(&self) -> &'a [u8] {
        self.data
    }
}

/// The answer to `AT+CSIM`, which is `+CSIM: <chars>,"<hex>"`.
pub fn parse_csim_answer(lines: &[String]) -> Result<ApduResponse, AkaError> {
    let line = lines
        .iter()
        .map(|line| line.trim())
        .find(|line| line.starts_with("+CSIM:"))
        .ok_or_else(|| AkaError::MalformedCsim(format!("no +CSIM line in {lines:?}")))?;
    let payload = line
        .split_once(',')
        .map(|(_, tail)| tail.trim())
        .ok_or_else(|| AkaError::MalformedCsim(format!("no comma in {line:?}")))?;
    let hex = payload.trim_matches('"').trim();
    let bytes = decode_hex(hex)
        .ok_or_else(|| AkaError::MalformedCsim(format!("{hex:?} is not hex")))?;
    if bytes.len() < 2 {
        return Err(AkaError::MalformedCsim(format!(
            "{hex:?} is too short to carry a status word"
        )));
    }
    let split = bytes.len() - 2;
    Ok(ApduResponse {
        data: bytes[..split].to_vec(),
        sw1: bytes[split],
        sw2: bytes[split + 1],
    })
}

/// Uppercase hex, the form every AT command on this module expects.
pub fn hex_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

/// Bytes from a hex string, or `None` if it is not one.
pub fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.len() % 2 != 0 {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An FCP shaped like the one the bench answers with: file descriptor,
    /// file id, then tag `84` carrying a USIM AID. Synthetic — the real bench
    /// transcript is asserted in `tests/aka.rs`, where it belongs.
    const FCP_HEX: &str = "621A8202782183027FD08410A0000000871002FFFFFFFF8907090000";

    fn fcp() -> Vec<u8> {
        decode_hex(FCP_HEX).expect("fcp hex")
    }

    #[test]
    fn authenticate_apdu_is_the_basic_channel_form() {
        let apdu = authenticate_apdu(&[0x11; 16], &[0x22; 16], true).expect("apdu");
        assert_eq!(&apdu[..5], &[0x00, 0x88, 0x00, 0x81, 0x22]);
        assert_eq!(apdu[5], 0x10);
        assert_eq!(apdu[22], 0x10);
        assert_eq!(apdu.len(), 40);
        assert_eq!(*apdu.last().expect("le"), 0x00);
    }

    #[test]
    fn csim_length_counts_hex_characters() {
        let apdu = authenticate_apdu(&[0xab; 16], &[0xcd; 16], true).expect("apdu");
        let command = csim_command(&apdu);
        assert!(command.starts_with("AT+CSIM=80,\"0088008122"), "{command}");
    }

    #[test]
    fn selected_aid_reads_tag_84() {
        let aid = selected_aid(&fcp()).expect("aid");
        assert!(aid.starts_with(&USIM_ADF_AID_PREFIX), "{}", hex_upper(&aid));
    }

    #[test]
    fn fcp_without_tag_84_is_named() {
        let error = selected_aid(&decode_hex("6204820278218300").expect("hex")).unwrap_err();
        assert_eq!(error.code(), "no_selected_application");
    }
}
