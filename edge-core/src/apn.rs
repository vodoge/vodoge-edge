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

use serde::{Deserialize, Serialize};

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
        });
    }
    out
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
}
