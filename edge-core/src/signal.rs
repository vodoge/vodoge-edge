//! LTE radio quality parsed out of Quectel's `AT+QCSQ`.
//!
//! `AT+CSQ` was the only signal reading the agent had, and on this bench it
//! says nothing: all three modules sit close enough to a tower to peg the
//! 0-31 index at 31, which converts to -51 dBm for every one of them no
//! matter how they are actually doing. `+QCSQ` reports the measurements the
//! LTE radio genuinely makes -- RSRP, RSRQ and SINR -- and those are what
//! separate a link that will carry a VoWiFi call from one that will set it up
//! and then drop the audio.
//!
//! Parsing lives in this crate, which owns no I/O, so it is tested against
//! recorded module output instead of against a modem.

/// One `+QCSQ` reading.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Qcsq {
    /// The radio the module says it is on: `LTE`, `WCDMA`, `GSM`,
    /// `NOSERVICE`. Kept verbatim because the fields that follow it mean
    /// different things per mode, and a reader has to be able to tell which
    /// reading it is looking at.
    pub sysmode: String,
    /// Reference signal received power, dBm. LTE family only.
    pub rsrp_dbm: Option<i16>,
    /// Reference signal received quality, dB. LTE family only.
    pub rsrq_db: Option<i16>,
    /// Signal to interference-plus-noise ratio, dB. LTE family only.
    pub sinr_db: Option<i16>,
}

/// Modes whose `+QCSQ` fields are `<rssi>,<rsrp>,<sinr>,<rsrq>`.
///
/// `WCDMA` reports `<rssi>,<ecno>,<rscp>` and `GSM` reports `<rssi>` alone.
/// Reading either of those positionally as if it were LTE would file an Ec/No
/// as an RSRP -- a plausible-looking number that is not the quantity it
/// claims to be -- so anything not listed here reports its mode and no
/// metrics at all.
const LTE_FAMILY: &[&str] = &["LTE", "CAT-M1", "CAT-NB1", "eMTC", "NBIoT", "NR5G", "ENDC"];

/// `+QCSQ: "LTE",48,-74,250,-7`
///
/// Returns the mode with no metrics when the module answered but is not on an
/// LTE-family radio, and `None` only when there is no `+QCSQ` line to read.
/// Those are different facts: the first is "asked and answered, no LTE
/// measurements exist", the second is "never got an answer".
pub fn parse_qcsq(lines: &[String]) -> Option<Qcsq> {
    let value = lines
        .iter()
        .find_map(|line| line.trim().strip_prefix("+QCSQ:"))?;
    let mut fields = value.split(',').map(str::trim);
    let sysmode = fields.next()?.trim_matches('"').to_string();
    if !LTE_FAMILY.iter().any(|mode| mode.eq_ignore_ascii_case(&sysmode)) {
        return Some(Qcsq {
            sysmode,
            ..Qcsq::default()
        });
    }
    // Field order is rssi, rsrp, sinr, rsrq. The two quality figures are not
    // adjacent, which is exactly the kind of thing that gets transposed when
    // it is written from memory.
    let _rssi = fields.next();
    let rsrp_dbm = fields.next().and_then(parse_dbm);
    let sinr_db = fields.next().and_then(|raw| raw.parse::<i32>().ok()).and_then(sinr_db_from_raw);
    let rsrq_db = fields.next().and_then(parse_dbm);
    Some(Qcsq {
        sysmode,
        rsrp_dbm,
        rsrq_db,
        sinr_db,
    })
}

/// A signed power or quality figure the module already expressed in dB.
///
/// `-` alone, or an empty field, is how a module spells "not measured" in the
/// middle of a `+QCSQ` line, and must not become a zero reading.
fn parse_dbm(field: &str) -> Option<i16> {
    if field.is_empty() || field == "-" {
        return None;
    }
    field.parse::<i16>().ok()
}

/// Convert Quectel's raw SINR onto the dB scale it stands for.
///
/// The raw field is 0-250 mapping linearly onto -20 dB to +30 dB, i.e. steps
/// of 0.2 dB -- it is not already in dB. The bench module reads 250 while its
/// RSRP is -74 dBm and its CSQ is pegged at 31, so 250 is the top of that
/// scale (+30 dB) rather than 250 dB of anything.
///
/// A value outside the documented range is dropped rather than scaled. If a
/// future firmware reports dB directly, a bad reading is a worse outcome than
/// a missing one: nobody chases a blank, and everybody trusts a number.
fn sinr_db_from_raw(raw: i32) -> Option<i16> {
    if !(0..=250).contains(&raw) {
        return None;
    }
    Some((f32::from(raw as i16) / 5.0 - 20.0).round() as i16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &[&str]) -> Vec<String> {
        text.iter().map(|line| (*line).to_string()).collect()
    }

    #[test]
    fn reads_the_bench_module_verbatim() {
        // Captured from 867018069509705 through the console AT terminal.
        let parsed = parse_qcsq(&lines(&["+QCSQ: \"LTE\",48,-74,250,-7"])).expect("parsed");
        assert_eq!(parsed.sysmode, "LTE");
        assert_eq!(parsed.rsrp_dbm, Some(-74));
        assert_eq!(parsed.rsrq_db, Some(-7));
        // 250 is the top of the 0-250 scale, which is +30 dB.
        assert_eq!(parsed.sinr_db, Some(30));
    }

    #[test]
    fn sinr_is_scaled_not_taken_as_db() {
        let parsed = parse_qcsq(&lines(&["+QCSQ: \"LTE\",50,-95,100,-12"])).expect("parsed");
        assert_eq!(parsed.sinr_db, Some(0));
        let parsed = parse_qcsq(&lines(&["+QCSQ: \"LTE\",50,-95,0,-12"])).expect("parsed");
        assert_eq!(parsed.sinr_db, Some(-20));
        let parsed = parse_qcsq(&lines(&["+QCSQ: \"LTE\",50,-95,195,-12"])).expect("parsed");
        assert_eq!(parsed.sinr_db, Some(19));
    }

    #[test]
    fn out_of_range_sinr_is_dropped_rather_than_scaled() {
        let parsed = parse_qcsq(&lines(&["+QCSQ: \"LTE\",50,-95,900,-12"])).expect("parsed");
        assert_eq!(parsed.sinr_db, None);
        // The measurements either side still survive.
        assert_eq!(parsed.rsrp_dbm, Some(-95));
        assert_eq!(parsed.rsrq_db, Some(-12));
    }

    #[test]
    fn no_service_reports_the_mode_and_no_metrics() {
        let parsed = parse_qcsq(&lines(&["+QCSQ: \"NOSERVICE\""])).expect("parsed");
        assert_eq!(parsed.sysmode, "NOSERVICE");
        assert_eq!(parsed.rsrp_dbm, None);
        assert_eq!(parsed.rsrq_db, None);
        assert_eq!(parsed.sinr_db, None);
    }

    #[test]
    fn wcdma_fields_are_not_read_as_lte_ones() {
        // <rssi>,<ecno>,<rscp> -- filing -5 as an RSRQ would be a fabrication.
        let parsed = parse_qcsq(&lines(&["+QCSQ: \"WCDMA\",-60,-5,-70"])).expect("parsed");
        assert_eq!(parsed.sysmode, "WCDMA");
        assert_eq!(parsed.rsrp_dbm, None);
        assert_eq!(parsed.rsrq_db, None);
        assert_eq!(parsed.sinr_db, None);
    }

    #[test]
    fn gsm_reports_only_its_mode() {
        let parsed = parse_qcsq(&lines(&["+QCSQ: \"GSM\",-70"])).expect("parsed");
        assert_eq!(parsed.sysmode, "GSM");
        assert_eq!(parsed.rsrp_dbm, None);
    }

    #[test]
    fn a_missing_field_is_absent_rather_than_zero() {
        let parsed = parse_qcsq(&lines(&["+QCSQ: \"LTE\",48,-,250,"])).expect("parsed");
        assert_eq!(parsed.rsrp_dbm, None);
        assert_eq!(parsed.rsrq_db, None);
        assert_eq!(parsed.sinr_db, Some(30));
    }

    #[test]
    fn no_qcsq_line_at_all_is_none() {
        assert_eq!(parse_qcsq(&lines(&["OK"])), None);
        assert_eq!(parse_qcsq(&[]), None);
    }

    #[test]
    fn finds_the_reading_among_other_lines() {
        let parsed = parse_qcsq(&lines(&["AT+QCSQ", "", "+QCSQ: \"LTE\",48,-90,150,-9"]))
            .expect("parsed");
        assert_eq!(parsed.rsrp_dbm, Some(-90));
        assert_eq!(parsed.sinr_db, Some(10));
    }
}
