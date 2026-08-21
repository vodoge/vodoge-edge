//! Structured health report for one modem, collected over the AT port.
//!
//! Every field here answers a question an operator asks while diagnosing a
//! module: is there signal, did it register, on whose network, with which
//! subscriber identity, and is there an SMS centre to send through. QMI can
//! answer some of them, but not the vendor ones, and issuing a single AT batch
//! keeps the whole snapshot consistent in time.
//!
//! Parsing lives in free functions so it can be tested without a modem. Each
//! parser takes the response lines exactly as the module produced them.

use crate::at::{AtError, AtPort};

/// Registration state shared by `+CREG` (circuit switched) and `+CEREG`
/// (packet switched). The numbering is 3GPP 27.007.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Registration {
    NotRegistered,
    Home,
    Searching,
    Denied,
    Unknown,
    Roaming,
}

impl Registration {
    pub fn from_code(code: u8) -> Self {
        match code {
            1 => Self::Home,
            2 => Self::Searching,
            3 => Self::Denied,
            5 => Self::Roaming,
            0 => Self::NotRegistered,
            _ => Self::Unknown,
        }
    }

    /// Whether the module can actually use this domain.
    pub fn attached(self) -> bool {
        matches!(self, Self::Home | Self::Roaming)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotRegistered => "not_registered",
            Self::Home => "home",
            Self::Searching => "searching",
            Self::Denied => "denied",
            Self::Unknown => "unknown",
            Self::Roaming => "roaming",
        }
    }
}

/// Signal quality from `+CSQ`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signal {
    /// Raw 0-31 index. 99 means the module does not know.
    pub rssi_index: u8,
    /// Converted to dBm, absent when the index is the unknown marker.
    pub dbm: Option<i16>,
}

/// One modem's answers to the read-only diagnostic batch.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ModemReport {
    pub signal: Option<Signal>,
    pub cs_registration: Option<Registration>,
    pub ps_registration: Option<Registration>,
    pub operator: Option<String>,
    pub access_technology: Option<&'static str>,
    pub imsi: Option<String>,
    pub iccid: Option<String>,
    pub msisdn: Option<String>,
    pub firmware: Option<String>,
    pub sms_centre: Option<String>,
    /// Commands that did not answer `OK`, so a blank field can be told apart
    /// from a field the module refused to report.
    pub refused: Vec<String>,
}

/// The read-only batch. Nothing here changes module state.
const BATCH: &[&str] = &[
    "AT+CSQ",
    "AT+CREG?",
    "AT+CEREG?",
    "AT+COPS?",
    "AT+CIMI",
    "AT+QCCID",
    "AT+CNUM",
    "AT+QGMR",
    "AT+CSCA?",
];

/// Run the diagnostic batch against an open AT port.
///
/// A command the module refuses is recorded and the batch continues: one
/// unsupported vendor command must not cost the operator the whole snapshot.
pub fn collect(port: &mut AtPort) -> Result<ModemReport, AtError> {
    let mut report = ModemReport::default();
    for command in BATCH {
        let exchange = port.command(command)?;
        if !exchange.succeeded() {
            report.refused.push((*command).to_string());
            continue;
        }
        apply(&mut report, command, &exchange.lines);
    }
    Ok(report)
}

fn apply(report: &mut ModemReport, command: &str, lines: &[String]) {
    match command {
        "AT+CSQ" => report.signal = parse_csq(lines),
        "AT+CREG?" => report.cs_registration = parse_creg(lines, "+CREG:"),
        "AT+CEREG?" => report.ps_registration = parse_creg(lines, "+CEREG:"),
        "AT+COPS?" => {
            if let Some((operator, act)) = parse_cops(lines) {
                report.operator = Some(operator);
                report.access_technology = act;
            }
        }
        "AT+CIMI" => report.imsi = parse_bare_digits(lines),
        "AT+QCCID" => report.iccid = parse_iccid(lines),
        "AT+CNUM" => report.msisdn = parse_cnum(lines),
        "AT+QGMR" => report.firmware = lines.first().map(|line| line.trim().to_string()),
        "AT+CSCA?" => report.sms_centre = parse_csca(lines),
        _ => {}
    }
}

/// `+CSQ: 24,99` — index 99 is "unknown", not "excellent".
pub fn parse_csq(lines: &[String]) -> Option<Signal> {
    let value = field_after(lines, "+CSQ:")?;
    let index: u8 = value.split(',').next()?.trim().parse().ok()?;
    let dbm = if index == 99 {
        None
    } else {
        // 3GPP 27.007: 0 maps to -113 dBm and each step is 2 dB.
        Some(-113 + 2 * i16::from(index))
    };
    Some(Signal {
        rssi_index: index,
        dbm,
    })
}

/// `+CREG: <n>,<stat>[,...]` — the first field is the URC setting, not state.
pub fn parse_creg(lines: &[String], prefix: &str) -> Option<Registration> {
    let value = field_after(lines, prefix)?;
    let mut parts = value.split(',');
    let _urc_mode = parts.next()?;
    let state: u8 = parts.next()?.trim().parse().ok()?;
    Some(Registration::from_code(state))
}

/// `+COPS: 0,0,"CHN-UNICOM",7`
pub fn parse_cops(lines: &[String]) -> Option<(String, Option<&'static str>)> {
    let value = field_after(lines, "+COPS:")?;
    let parts: Vec<&str> = value.split(',').collect();
    // Fewer than three fields means the module reported no operator, which is
    // what `+COPS: 0` looks like while it is still searching.
    if parts.len() < 3 {
        return None;
    }
    let operator = parts[2].trim().trim_matches('"').to_string();
    if operator.is_empty() {
        return None;
    }
    let act = parts
        .get(3)
        .and_then(|value| value.trim().parse::<u8>().ok())
        .map(access_technology);
    Some((operator, act))
}

/// 3GPP 27.007 access technology codes.
fn access_technology(code: u8) -> &'static str {
    match code {
        0 => "GSM",
        1 => "GSM Compact",
        2 => "UTRAN",
        3 => "GSM/EGPRS",
        4 => "UTRAN/HSDPA",
        5 => "UTRAN/HSUPA",
        6 => "UTRAN/HSDPA+HSUPA",
        7 => "LTE",
        8 => "EC-GSM-IoT",
        9 => "LTE-M",
        10 => "NB-IoT",
        11 | 12 => "NR",
        _ => "unknown",
    }
}

/// `+CNUM: "","+8613800138000",145`
pub fn parse_cnum(lines: &[String]) -> Option<String> {
    let value = field_after(lines, "+CNUM:")?;
    let number = value.split(',').nth(1)?.trim().trim_matches('"').to_string();
    if number.is_empty() {
        None
    } else {
        Some(number)
    }
}

/// `+CSCA: "+8613800100500",145`
pub fn parse_csca(lines: &[String]) -> Option<String> {
    let value = field_after(lines, "+CSCA:")?;
    let centre = value.split(',').next()?.trim().trim_matches('"').to_string();
    if centre.is_empty() {
        None
    } else {
        Some(centre)
    }
}

/// A response whose payload is the whole line, such as `AT+CIMI`.
pub fn parse_bare_digits(lines: &[String]) -> Option<String> {
    lines
        .iter()
        .map(|line| line.trim())
        .find(|line| !line.is_empty() && line.chars().all(|c| c.is_ascii_digit()))
        .map(|line| line.to_string())
}

/// `+QCCID: 8985200014632179571F`
///
/// A 19-digit ICCID is padded to 20 on the card with a trailing `F`, and
/// `AT+QCCID` reports the padded form. The QMI path decodes `EF_ICCID` and
/// drops that padding, so leaving it here would show one card under two
/// different numbers depending on which path read it.
pub fn parse_iccid(lines: &[String]) -> Option<String> {
    let raw = parse_prefixed(lines, "+QCCID:")?;
    let trimmed = raw.trim_end_matches(['F', 'f']).to_string();
    if trimmed.is_empty() || !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(trimmed)
}

/// A response of the form `<prefix> <value>`.
pub fn parse_prefixed(lines: &[String], prefix: &str) -> Option<String> {
    field_after(lines, prefix).map(|value| value.trim_matches('"').to_string())
}

fn field_after(lines: &[String], prefix: &str) -> Option<String> {
    lines
        .iter()
        .find_map(|line| line.trim().strip_prefix(prefix))
        .map(|rest| rest.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn csq_converts_to_dbm() {
        let signal = parse_csq(&lines(&["+CSQ: 24,99"])).expect("signal");
        assert_eq!(signal.rssi_index, 24);
        assert_eq!(signal.dbm, Some(-65));
    }

    /// 99 is the "I do not know" marker. Treating it as an index would report
    /// the best possible signal for a module that has none.
    #[test]
    fn csq_unknown_index_has_no_dbm() {
        let signal = parse_csq(&lines(&["+CSQ: 99,99"])).expect("signal");
        assert_eq!(signal.rssi_index, 99);
        assert_eq!(signal.dbm, None);
    }

    #[test]
    fn creg_reads_state_not_urc_mode() {
        // The leading 0 is the URC setting; 5 is the registration state.
        assert_eq!(
            parse_creg(&lines(&["+CREG: 0,5"]), "+CREG:"),
            Some(Registration::Roaming)
        );
        assert_eq!(
            parse_creg(&lines(&["+CEREG: 2,1,\"1A2B\",\"01234567\",7"]), "+CEREG:"),
            Some(Registration::Home)
        );
    }

    #[test]
    fn roaming_and_home_are_attached_but_searching_is_not() {
        assert!(Registration::Roaming.attached());
        assert!(Registration::Home.attached());
        assert!(!Registration::Searching.attached());
        assert!(!Registration::Denied.attached());
    }

    #[test]
    fn cops_reads_operator_and_technology() {
        let parsed = parse_cops(&lines(&["+COPS: 0,0,\"CHN-UNICOM\",7"])).expect("cops");
        assert_eq!(parsed.0, "CHN-UNICOM");
        assert_eq!(parsed.1, Some("LTE"));
    }

    /// A module that is still searching answers `+COPS: 0` with no operator.
    #[test]
    fn cops_without_an_operator_is_none() {
        assert_eq!(parse_cops(&lines(&["+COPS: 0"])), None);
    }

    #[test]
    fn cnum_reads_the_number_field() {
        assert_eq!(
            parse_cnum(&lines(&["+CNUM: \"\",\"+8613800138000\",145"])),
            Some("+8613800138000".to_string())
        );
    }

    /// A SIM with no MSISDN written answers with an empty number rather than
    /// refusing, and an empty string is not a phone number.
    #[test]
    fn cnum_with_an_empty_number_is_none() {
        assert_eq!(parse_cnum(&lines(&["+CNUM: \"\",\"\",145"])), None);
    }

    #[test]
    fn csca_reads_the_centre_address() {
        assert_eq!(
            parse_csca(&lines(&["+CSCA: \"+85290240715\",145"])),
            Some("+85290240715".to_string())
        );
    }

    #[test]
    fn qccid_strips_the_prefix() {
        assert_eq!(
            parse_iccid(&lines(&["+QCCID: 89852351225042214201"])),
            Some("89852351225042214201".to_string())
        );
    }

    /// The AT and QMI paths must agree on one card's number. A 19-digit ICCID
    /// is padded to 20 with `F` on the card, and only the QMI decoder used to
    /// drop it.
    #[test]
    fn qccid_drops_the_padding_nibble() {
        assert_eq!(
            parse_iccid(&lines(&["+QCCID: 8985200014632179571F"])),
            Some("8985200014632179571".to_string())
        );
    }

    #[test]
    fn qccid_rejects_a_non_numeric_value() {
        assert_eq!(parse_iccid(&lines(&["+QCCID: FFFF"])), None);
    }

    #[test]
    fn cimi_takes_the_digit_line() {
        assert_eq!(
            parse_bare_digits(&lines(&["454006395021420"])),
            Some("454006395021420".to_string())
        );
    }

    #[test]
    fn apply_fills_the_matching_field_only() {
        let mut report = ModemReport::default();
        apply(&mut report, "AT+CSQ", &lines(&["+CSQ: 20,99"]));
        assert_eq!(report.signal.map(|s| s.dbm), Some(Some(-73)));
        assert_eq!(report.operator, None);
        assert!(report.refused.is_empty());
    }
}

/// One network a `AT+COPS=?` scan found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScannedOperator {
    /// 0 unknown, 1 available, 2 current, 3 forbidden.
    pub status: u8,
    pub long_name: String,
    pub short_name: String,
    /// MCC+MNC as the module reports it, e.g. `46001`.
    pub numeric: String,
    pub access_technology: Option<&'static str>,
}

impl ScannedOperator {
    pub fn status_label(&self) -> &'static str {
        match self.status {
            1 => "available",
            2 => "current",
            3 => "forbidden",
            _ => "unknown",
        }
    }
}

/// Parse `+COPS: (2,"CHN-UNICOM","UNICOM","46001",7),(1,...),,(0-4),(0-2)`.
///
/// The trailing `(0-4),(0-2)` groups describe the modes the module supports,
/// not networks, and they are separated from the list by an empty field. Taking
/// every parenthesised group would report them as two nameless operators.
pub fn parse_cops_scan(lines: &[String]) -> Vec<ScannedOperator> {
    let Some(value) = field_after(lines, "+COPS:") else {
        return Vec::new();
    };
    let mut operators = Vec::new();
    for group in parenthesised_groups(&value) {
        let fields = split_fields(&group);
        // A network entry carries status, long, short and numeric names. The
        // capability groups are a single range like `0-4`.
        if fields.len() < 4 {
            continue;
        }
        let Ok(status) = fields[0].parse::<u8>() else {
            continue;
        };
        let numeric = fields[3].clone();
        if numeric.is_empty() || !numeric.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        operators.push(ScannedOperator {
            status,
            long_name: fields[1].clone(),
            short_name: fields[2].clone(),
            numeric,
            access_technology: fields
                .get(4)
                .and_then(|value| value.parse::<u8>().ok())
                .map(access_technology),
        });
    }
    operators
}

/// Split on top-level parentheses, ignoring any inside quoted names.
fn parenthesised_groups(value: &str) -> Vec<String> {
    let mut groups = Vec::new();
    let mut current: Option<String> = None;
    let mut quoted = false;
    for character in value.chars() {
        match character {
            '"' => {
                quoted = !quoted;
                if let Some(buffer) = current.as_mut() {
                    buffer.push(character);
                }
            }
            '(' if !quoted => current = Some(String::new()),
            ')' if !quoted => {
                if let Some(buffer) = current.take() {
                    groups.push(buffer);
                }
            }
            _ => {
                if let Some(buffer) = current.as_mut() {
                    buffer.push(character);
                }
            }
        }
    }
    groups
}

/// Split a group on commas that are not inside a quoted name.
fn split_fields(group: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut buffer = String::new();
    let mut quoted = false;
    for character in group.chars() {
        match character {
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut buffer)),
            _ => buffer.push(character),
        }
    }
    fields.push(buffer);
    fields.into_iter().map(|field| field.trim().to_string()).collect()
}

#[cfg(test)]
mod scan_tests {
    use super::*;

    fn lines(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn scan_reads_each_network() {
        let found = parse_cops_scan(&lines(&[
            "+COPS: (2,\"CHN-UNICOM\",\"UNICOM\",\"46001\",7),(1,\"CHINA MOBILE\",\"CMCC\",\"46000\",0),,(0-4),(0-2)",
        ]));
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].numeric, "46001");
        assert_eq!(found[0].status_label(), "current");
        assert_eq!(found[0].access_technology, Some("LTE"));
        assert_eq!(found[1].long_name, "CHINA MOBILE");
        assert_eq!(found[1].access_technology, Some("GSM"));
    }

    /// The trailing `(0-4),(0-2)` groups are supported modes, not networks.
    #[test]
    fn scan_ignores_the_capability_groups() {
        let found = parse_cops_scan(&lines(&[
            "+COPS: (1,\"A\",\"A\",\"46001\",7),,(0-4),(0-2)",
        ]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].numeric, "46001");
    }

    /// A comma inside an operator name must not split the entry.
    #[test]
    fn scan_keeps_a_quoted_comma_together() {
        let found = parse_cops_scan(&lines(&[
            "+COPS: (1,\"Telecom, Ltd\",\"TL\",\"46011\",7)",
        ]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].long_name, "Telecom, Ltd");
    }

    #[test]
    fn scan_of_an_empty_response_is_empty() {
        assert!(parse_cops_scan(&lines(&["+COPS: "])).is_empty());
    }
}
