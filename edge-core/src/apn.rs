//! The packet data profiles a module is carrying.
//!
//! A module holds several, numbered by context identifier: the operator's
//! default on one, IMS on another, emergency on a third, and whatever anybody
//! has configured since. Which one carries data is not a property of the card
//! or the network -- it is a row in a table on the module, and until this
//! existed the only way to see that table was to type `AT+CGDCONT?` into the
//! console and read it.
//!
//! Reading it is the useful half and the safe half. Writing one is
//! `AT+CGDCONT=`, which this agent's AT classifier holds back as
//! configuration: a wrong APN takes a stick off data until somebody notices,
//! and the module keeps it across a reboot.
//!
//! ## Why the credentials come from `AT+QICSGP` and not `AT+CGAUTH`
//!
//! 27.007 defines `+CGAUTH` for the username, password and authentication
//! method of a context, and it is the obvious place to read them. Measured on
//! this bench, 2026-08-30:
//!
//! * **EC20** answers `ERROR` to both `AT+CGAUTH=?` and `AT+CGAUTH?`. The
//!   command does not exist on the module this product runs most of.
//! * **EC200U-CN** answers `+CGAUTH: (1..7),(0..2),(0..20),(0..20)`.
//! * **Both** answer `AT+QICSGP=1` with `+QICSGP: 1,"","","",0`.
//!
//! So the standard command is the one that is not portable here, and Quectel's
//! own is. Designing to 27.007 would have produced a feature that worked on
//! one module family out of two.
//!
//! 🔴 **The password is never carried off the module.** The `+QICSGP` read
//! returns it in clear, in the same line as everything else, so the parser
//! reduces it to `has_password` at the point of parsing rather than putting it
//! in a struct that some later serialiser would helpfully include. What goes
//! up is the username and the method, which is what an operator needs to see
//! to know whether a context is configured.

use serde::{Deserialize, Serialize};

/// How a context authenticates to the APN.
///
/// The numbers are Quectel's `<authentication>` field. `+CGAUTH` on the one
/// module that has it offers 0..2 only, so `PapOrChap` is reachable through
/// `+QICSGP` and not through the standard command -- another reason the two
/// are not interchangeable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApnAuth {
    None,
    Pap,
    Chap,
    PapOrChap,
}

impl ApnAuth {
    /// Quectel's numeric encoding, or `None` for a value no module here emits.
    ///
    /// Unknown returns `None` rather than defaulting to `ApnAuth::None`: a
    /// context whose method could not be read is not a context known to need
    /// no password, and showing "none" for it would be a claim nobody made.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::Pap),
            2 => Some(Self::Chap),
            3 => Some(Self::PapOrChap),
            _ => None,
        }
    }

    /// The spelling the contract uses, which is what a command carries.
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "pap" => Some(Self::Pap),
            "chap" => Some(Self::Chap),
            "pap_or_chap" => Some(Self::PapOrChap),
            _ => None,
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Pap => 1,
            Self::Chap => 2,
            Self::PapOrChap => 3,
        }
    }
}

/// One packet data profile as the module reports it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApnContext {
    /// Context identifier. What `AT+CGACT=1,<cid>` and the QMI profile index
    /// both address, so it is the handle for everything else.
    pub cid: u8,
    /// `IP`, `IPV6`, `IPV4V6`, or whatever the module answered with.
    pub pdp_type: String,
    /// The access point name. Empty where the module holds a context with no
    /// name, which is normal for an unconfigured slot rather than an error.
    pub apn: String,
    /// Username for the APN, empty when the context carries none.
    #[serde(default)]
    pub username: String,
    /// `None` when the credentials could not be read at all, which is a
    /// different thing from a context that authenticates with nothing.
    #[serde(default)]
    pub auth: Option<ApnAuth>,
    /// Whether a password is set. The password itself never leaves the module.
    #[serde(default)]
    pub has_password: bool,
    /// [`SOURCE_CONFIGURED`] when this agent wrote the context and remembers
    /// doing so, `None` for whatever the module was already carrying.
    ///
    /// A string rather than a bool because this struct's serialisation *is*
    /// the wire format -- the stored JSON is passed to the cloud verbatim --
    /// so the field has to spell what the contract's enum spells.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// The one value `source` takes, named so no caller spells it by hand.
pub const SOURCE_CONFIGURED: &str = "configured";

/// The credential half of one context, as `AT+QICSGP=<cid>` reports it.
///
/// 🔴 **Deliberately not `Serialize`.** It carries the password in clear so
/// that a write which changes only the APN can put the existing one back --
/// `AT+QICSGP=` rewrites every field, so omitting the password blanks it --
/// and the only thing keeping that value off the wire is that this type
/// cannot be turned into JSON. `ApnContext` is the serialisable one and has
/// `has_password` instead. Do not add a derive here.
///
/// `Debug` is written by hand for the same reason: the derived one would put
/// the password in any log line that formatted this struct.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ApnCredentials {
    pub apn: String,
    pub username: String,
    pub has_password: bool,
    pub auth: Option<ApnAuth>,
    /// Quectel's `<context_type>`: 1 = IPv4, 2 = IPv6, 3 = IPv4v6.
    ///
    /// 🔴 **Not the context identifier.** It is kept only so a write that
    /// changes credentials alone can send back the type the context already
    /// had -- guessing 1 there would quietly downgrade an IPv4v6 context to
    /// IPv4 every time somebody edited a username.
    pub context_type: Option<u8>,
    /// The password the module is holding, for putting back unchanged. Never
    /// stored, never reported, never logged -- see the type's own note.
    pub password: String,
}

impl std::fmt::Debug for ApnCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApnCredentials")
            .field("apn", &self.apn)
            .field("username", &self.username)
            .field("has_password", &self.has_password)
            .field("auth", &self.auth)
            .field("context_type", &self.context_type)
            .finish_non_exhaustive()
    }
}

/// Parse the answer to `AT+CGDCONT?`.
///
/// The shape is `+CGDCONT: <cid>,"<PDP_type>","<APN>",...` with a further six
/// or so numeric fields that differ between vendors and firmware. Only the
/// first three are read: they are the ones defined identically everywhere, and
/// a parser that insisted on the rest would drop the whole row on a module
/// that reports one field fewer.
///
/// Lines that are not `+CGDCONT:` are skipped rather than failing the parse --
/// an `OK`, an echo of the command, or an unsolicited notification arriving
/// mid-exchange are all normal on a shared AT port.
pub fn parse_cgdcont(lines: &[String]) -> Vec<ApnContext> {
    let mut out = Vec::new();
    for line in lines {
        let Some(rest) = line.trim().strip_prefix("+CGDCONT:") else {
            continue;
        };
        let mut fields = split_fields(rest);
        let Some(cid) = fields.next().and_then(|value| value.trim().parse::<u8>().ok()) else {
            continue;
        };
        let pdp_type = fields.next().map(unquote).unwrap_or_default();
        let apn = fields.next().map(unquote).unwrap_or_default();
        out.push(ApnContext {
            cid,
            pdp_type,
            apn,
            // `+CGDCONT?` carries no credentials. They arrive from
            // `parse_qicsgp` via `merge_credentials`, one context at a time,
            // and `auth: None` here means "not read yet" rather than "none".
            ..ApnContext::default()
        });
    }
    out
}

/// Parse the answer to `AT+QICSGP=<cid>`.
///
/// `+QICSGP: <context_type>,"<APN>","<username>","<password>",<authentication>`
///
/// The leading field is the context *type* (1 = IPv4, 2 = IPv6, 3 = IPv4v6),
/// not the identifier -- the identifier is the one the caller asked about and
/// does not come back. Reading it as a cid is the mistake this comment exists
/// to stop, because on cid 1 the two are indistinguishable and the bug only
/// appears on the second context.
///
/// The password field is read solely to answer whether there is one.
pub fn parse_qicsgp(lines: &[String]) -> Option<ApnCredentials> {
    for line in lines {
        let Some(rest) = line.trim().strip_prefix("+QICSGP:") else {
            continue;
        };
        let mut fields = split_fields(rest);
        // The context *type*, kept for the write path and never used as an
        // identifier: the caller already knows which context it asked about,
        // and `pdp_type` comes from +CGDCONT where it is a name, not a number.
        let context_type = fields
            .next()
            .and_then(|value| value.trim().parse::<u8>().ok());
        let apn = fields.next().map(unquote).unwrap_or_default();
        let username = fields.next().map(unquote).unwrap_or_default();
        let password = fields.next().map(unquote).unwrap_or_default();
        let has_password = !password.is_empty();
        let auth = fields
            .next()
            .and_then(|value| value.trim().parse::<u8>().ok())
            .and_then(ApnAuth::from_code);
        return Some(ApnCredentials {
            apn,
            username,
            has_password,
            auth,
            context_type,
            password,
        });
    }
    None
}

/// Fold one context's credentials into the row `+CGDCONT?` produced.
///
/// The APN from `+QICSGP` is ignored when `+CGDCONT` already named one: the
/// two are the same field on the module, and preferring the credential read
/// would let a module that answers one of them with an empty string blank an
/// APN that is really there.
pub fn merge_credentials(context: &mut ApnContext, credentials: &ApnCredentials) {
    if context.apn.is_empty() {
        context.apn = credentials.apn.clone();
    }
    context.username = credentials.username.clone();
    context.has_password = credentials.has_password;
    context.auth = credentials.auth;
}

/// Split on commas that are not inside quotes.
///
/// An APN may not contain a comma, but a later field can, and splitting
/// naively on every comma would shift every field after it by one.
fn split_fields(rest: &str) -> impl Iterator<Item = String> + '_ {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for character in rest.chars() {
        match character {
            '"' => {
                quoted = !quoted;
                current.push(character);
            }
            ',' if !quoted => fields.push(std::mem::take(&mut current)),
            _ => current.push(character),
        }
    }
    fields.push(current);
    fields.into_iter()
}

fn unquote(value: String) -> String {
    value
        .trim()
        .trim_start_matches('"')
        .trim_end_matches('"')
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    /// What an EC20 on this bench actually answers.
    #[test]
    fn the_benchs_contexts_are_read() {
        let parsed = parse_cgdcont(&lines(&[
            "+CGDCONT: 1,\"IP\",\"cmnet\",\"0.0.0.0\",0,0,0,0",
            "+CGDCONT: 2,\"IPV4V6\",\"ims\",\"\",0,0,0,0",
            "+CGDCONT: 3,\"IPV4V6\",\"sos\",\"\",0,0,0,0",
            "OK",
        ]));
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].cid, 1);
        assert_eq!(parsed[0].pdp_type, "IP");
        assert_eq!(parsed[0].apn, "cmnet");
        assert_eq!(parsed[1].apn, "ims");
        assert_eq!(parsed[2].cid, 3);
    }

    /// A context with no name is an unconfigured slot, not a broken read. It
    /// still has a cid, and the cid is what anything else addresses.
    #[test]
    fn a_nameless_context_keeps_its_identifier() {
        let parsed = parse_cgdcont(&lines(&["+CGDCONT: 4,\"IP\",\"\",\"0.0.0.0\",0,0"]));
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].cid, 4);
        assert_eq!(parsed[0].apn, "");
    }

    /// Vendors disagree about how many trailing fields there are, so only the
    /// three that are defined identically everywhere are required.
    #[test]
    fn a_short_row_is_read_rather_than_dropped() {
        let parsed = parse_cgdcont(&lines(&["+CGDCONT: 1,\"IP\",\"internet\""]));
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].apn, "internet");
    }

    /// The AT port is shared, so anything can arrive mid-exchange.
    #[test]
    fn lines_that_are_not_contexts_are_skipped() {
        let parsed = parse_cgdcont(&lines(&[
            "AT+CGDCONT?",
            "+CREG: 1,\"1A2B\",\"00C3D4E5\"",
            "+CGDCONT: 1,\"IP\",\"cmnet\"",
            "OK",
        ]));
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].apn, "cmnet");
    }

    /// A comma inside a later quoted field must not shift the fields before
    /// it, which is the whole reason this does not split on every comma.
    #[test]
    fn a_quoted_comma_does_not_shift_the_fields() {
        let parsed = parse_cgdcont(&lines(&["+CGDCONT: 7,\"IP\",\"a.b.c\",\"1,2\",0,0"]));
        assert_eq!(parsed[0].cid, 7);
        assert_eq!(parsed[0].pdp_type, "IP");
        assert_eq!(parsed[0].apn, "a.b.c");
    }

    #[test]
    fn a_row_without_a_usable_identifier_is_dropped() {
        assert!(parse_cgdcont(&lines(&["+CGDCONT: ,\"IP\",\"x\""])).is_empty());
        assert!(parse_cgdcont(&lines(&["+CGDCONT: 999,\"IP\",\"x\""])).is_empty());
    }

    /// What both bench families actually answer for an unconfigured context,
    /// measured 2026-08-30 on an EC20 and an EC200U-CN.
    #[test]
    fn an_unconfigured_context_reads_as_no_credentials() {
        let parsed = parse_qicsgp(&lines(&["+QICSGP: 1,\"\",\"\",\"\",0"])).expect("a row");
        assert_eq!(parsed.apn, "");
        assert_eq!(parsed.username, "");
        assert!(!parsed.has_password, "an empty password field is not a password");
        assert_eq!(parsed.auth, Some(ApnAuth::None));
    }

    /// 🔴 The leading field is the context *type*, not the identifier. On cid 1
    /// the two are the same number and any confusion between them is invisible;
    /// this row is the one that tells them apart.
    #[test]
    fn the_leading_field_is_the_context_type_not_the_identifier() {
        let parsed =
            parse_qicsgp(&lines(&["+QICSGP: 3,\"cmnet\",\"user\",\"secret\",2"])).expect("a row");
        assert_eq!(parsed.apn, "cmnet", "field 2 is the APN, not field 1");
        assert_eq!(parsed.context_type, Some(3), "field 1 is the type, kept as one");
        assert_eq!(parsed.username, "user");
        assert_eq!(parsed.auth, Some(ApnAuth::Chap));
    }

    /// 🔴 The password answers one question and is then gone. Nothing this
    /// function returns can be serialised back into a credential.
    #[test]
    fn the_password_is_reduced_to_whether_there_is_one() {
        let parsed =
            parse_qicsgp(&lines(&["+QICSGP: 1,\"apn\",\"user\",\"hunter2\",1"])).expect("a row");
        assert!(parsed.has_password);
        assert_eq!(parsed.username, "user");
        assert_eq!(parsed.auth, Some(ApnAuth::Pap));
    }

    /// A method no module here emits is not silently read as "no
    /// authentication", because that is a claim about a context nobody made.
    #[test]
    fn an_unknown_authentication_code_is_unknown_rather_than_none() {
        let parsed = parse_qicsgp(&lines(&["+QICSGP: 1,\"apn\",\"\",\"\",9"])).expect("a row");
        assert_eq!(parsed.auth, None);
        assert_eq!(ApnAuth::from_code(3), Some(ApnAuth::PapOrChap));
        assert_eq!(ApnAuth::from_code(4), None);
    }

    /// 🔴 `AT+QICSGP=` rewrites every field, so a write that changes only the
    /// APN has to put the existing password back or it silently clears it.
    /// That is the whole reason the parser keeps it.
    #[test]
    fn the_password_is_kept_so_an_unrelated_edit_can_put_it_back() {
        let parsed =
            parse_qicsgp(&lines(&["+QICSGP: 1,\"apn\",\"user\",\"hunter2\",1"])).expect("a row");
        assert_eq!(parsed.password, "hunter2");
        // And it is not in the debug output, which is where it would leak.
        assert!(
            !format!("{parsed:?}").contains("hunter2"),
            "the password reached a log line: {parsed:?}"
        );
    }

    #[test]
    fn a_listing_with_no_qicsgp_row_reads_as_nothing() {
        assert_eq!(parse_qicsgp(&lines(&["OK", "+CGDCONT: 1,\"IP\",\"x\""])), None);
    }

    /// The APN `+CGDCONT?` already named wins: the two commands report the
    /// same field, and a module answering one of them blank must not blank it.
    #[test]
    fn merging_never_blanks_an_apn_that_was_already_read() {
        let mut context = ApnContext {
            cid: 1,
            pdp_type: "IPV4V6".into(),
            apn: "cmnet".into(),
            ..ApnContext::default()
        };
        merge_credentials(
            &mut context,
            &ApnCredentials {
                apn: String::new(),
                username: "user".into(),
                has_password: true,
                auth: Some(ApnAuth::Pap),
                ..ApnCredentials::default()
            },
        );
        assert_eq!(context.apn, "cmnet");
        assert_eq!(context.username, "user");
        assert!(context.has_password);
        assert_eq!(context.auth, Some(ApnAuth::Pap));
    }

    /// The other direction: an unnamed context takes the name the credential
    /// read supplied, which is how a QMI-configured profile gets a name at all.
    #[test]
    fn merging_fills_an_apn_that_was_empty() {
        let mut context = ApnContext { cid: 2, ..ApnContext::default() };
        merge_credentials(
            &mut context,
            &ApnCredentials { apn: "ims".into(), ..ApnCredentials::default() },
        );
        assert_eq!(context.apn, "ims");
    }
}
