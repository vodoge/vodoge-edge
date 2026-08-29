//! Which AT commands the agent will send without being told twice.
//!
//! The raw AT console reaches every part of a module, including the parts that
//! take it off the network, spend the subscriber's money, or lock the card. It
//! is also the one path with no per-action confirmation of its own: a console
//! button for "restart modem" can be made to ask first, but a text box cannot,
//! because the dangerous thing is indistinguishable from the harmless thing
//! until somebody reads the string.
//!
//! So the string is read here. A command that only asks the module something is
//! sent; a command that changes radio, call, message, card or persistent
//! configuration state is refused and named, and the caller has to say `force`
//! to mean it. That makes the disruptive case deliberate rather than a typo,
//! which is the whole intent -- it is not a permission boundary, and it does
//! not try to be one. Who may reach the console at all is decided by the
//! console's own roles, upstream of this.

/// What kind of state a command reaches into.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisruptiveKind {
    /// Registration and radio power: can take the module off the network.
    Radio,
    /// Voice call origination and control.
    Call,
    /// Message submission and deletion. Sending costs money; deleting can
    /// destroy a received message before it has been carried upstream.
    Message,
    /// USSD. Operator-side actions, some of which are billable and none of
    /// which are reversible from here.
    Ussd,
    /// The UICC: PIN entry, locks, and raw APDU channels. A wrong PIN attempt
    /// is spent permanently and three of them need the PUK.
    Card,
    /// Persistent module configuration, resets, and power. Several of these
    /// survive a reboot or re-enumerate the USB device.
    Config,
    /// Not recognisably a single AT command. Refused rather than guessed at,
    /// which also covers `A/` -- "repeat the last command" -- whose effect is
    /// whatever was last sent and cannot be classified on its own.
    Unrecognised,
}

impl DisruptiveKind {
    /// A stable token for a receipt or a log line.
    pub fn wire(self) -> &'static str {
        match self {
            Self::Radio => "radio",
            Self::Call => "call",
            Self::Message => "message",
            Self::Ussd => "ussd",
            Self::Card => "card",
            Self::Config => "config",
            Self::Unrecognised => "unrecognised",
        }
    }

    /// Why this was held back, for an operator reading a refusal.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Radio => "changes radio or registration state",
            Self::Call => "originates or controls a voice call",
            Self::Message => "submits or deletes messages",
            Self::Ussd => "opens a USSD session with the operator",
            Self::Card => "changes UICC state, including PIN attempts",
            Self::Config => "changes persistent configuration, resets, or power",
            Self::Unrecognised => "is not a single recognisable AT command",
        }
    }
}

/// The verdict for one console submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtRisk {
    Safe,
    Disruptive(DisruptiveKind),
}

impl AtRisk {
    pub fn disruptive(self) -> Option<DisruptiveKind> {
        match self {
            Self::Safe => None,
            Self::Disruptive(kind) => Some(kind),
        }
    }
}

/// Commands whose *write* form is disruptive, by the state they reach.
///
/// Reads are not listed because reads of these are fine: `AT+CFUN?` asks what
/// the radio is doing and `AT+CFUN=0` turns it off. Only the second one is
/// held back, so the console stays useful for diagnosis without being useful
/// for accidents.
const WRITE_RISKS: &[(&str, DisruptiveKind)] = &[
    // Radio and registration.
    ("CFUN", DisruptiveKind::Radio),
    ("COPS", DisruptiveKind::Radio),
    ("CGATT", DisruptiveKind::Radio),
    ("CEREG", DisruptiveKind::Radio),
    ("CREG", DisruptiveKind::Radio),
    ("QCFG", DisruptiveKind::Config),
    ("CGACT", DisruptiveKind::Radio),
    ("QIACT", DisruptiveKind::Radio),
    ("QIDEACT", DisruptiveKind::Radio),
    // Messaging.
    //
    // `CNMI` is here and it is the least obvious entry in the table: it sets
    // where a new message goes. Routed to the terminal instead of to storage,
    // messages arrive as unsolicited output that nothing in this agent reads,
    // and the inbox sweep finds an empty store -- so the failure is silent
    // message loss rather than an error.
    ("CNMI", DisruptiveKind::Message),
    ("CMGS", DisruptiveKind::Message),
    ("CMGW", DisruptiveKind::Message),
    ("CMSS", DisruptiveKind::Message),
    ("CMGD", DisruptiveKind::Message),
    ("CNMA", DisruptiveKind::Message),
    ("QCMGS", DisruptiveKind::Message),
    // USSD.
    ("CUSD", DisruptiveKind::Ussd),
    // Card.
    ("CPIN", DisruptiveKind::Card),
    ("CLCK", DisruptiveKind::Card),
    ("CPWD", DisruptiveKind::Card),
    ("CSIM", DisruptiveKind::Card),
    ("CRSM", DisruptiveKind::Card),
    ("CCHO", DisruptiveKind::Card),
    ("CCHC", DisruptiveKind::Card),
    ("CGLA", DisruptiveKind::Card),
    ("QCCID", DisruptiveKind::Card),
    // Persistent configuration, reset, power.
    //
    // `EGMR` writes the IMEI. It is in this table for a different reason from
    // everything else here: the others are recoverable and this is not, and on
    // hardware nobody can physically reach an overwritten identity is
    // permanent. It is also not ours to change.
    ("EGMR", DisruptiveKind::Config),
    // Non-volatile memory and the module's own filesystem: a bad write here
    // is how a module stops enumerating at all.
    ("QNVW", DisruptiveKind::Config),
    ("QNVFW", DisruptiveKind::Config),
    ("QFDEL", DisruptiveKind::Config),
    ("QFUPL", DisruptiveKind::Config),
    // A shell on the module, which is every category at once.
    ("QLINUXCMD", DisruptiveKind::Config),
    ("CGDCONT", DisruptiveKind::Config),
    ("QPRTPARA", DisruptiveKind::Config),
    ("QPOWD", DisruptiveKind::Config),
    ("CRESET", DisruptiveKind::Config),
    ("QFOTADL", DisruptiveKind::Config),
    ("CSCA", DisruptiveKind::Config),
];

/// Bare commands -- no `+` prefix -- that are disruptive in any form.
///
/// These take no read form to distinguish: `ATD` dials whenever it is sent.
const BARE_RISKS: &[(&str, DisruptiveKind)] = &[
    ("D", DisruptiveKind::Call),
    ("A", DisruptiveKind::Call),
    ("H", DisruptiveKind::Call),
    ("O", DisruptiveKind::Call),
    ("&F", DisruptiveKind::Config),
    ("&W", DisruptiveKind::Config),
    ("Z", DisruptiveKind::Config),
];

/// Classify one console submission.
///
/// The most severe verdict across a chained command wins. Chaining is the
/// obvious way past a per-command check -- `AT+CSQ;+CFUN=0` is one string --
/// so every segment is classified, not just the first.
pub fn classify(command: &str) -> AtRisk {
    let upper = command.trim().to_ascii_uppercase();
    let Some(body) = strip_at_prefix(&upper) else {
        return AtRisk::Disruptive(DisruptiveKind::Unrecognised);
    };
    if body.is_empty() {
        // A bare `AT` is the liveness check and does nothing else.
        return AtRisk::Safe;
    }
    let mut verdict = AtRisk::Safe;
    for segment in body.split(';') {
        if let Some(kind) = segment_risk(segment) {
            // First disruptive kind found is reported. They are not ranked
            // against each other: "this command also dials" is not more
            // useful to a reader than the first reason it was held.
            return AtRisk::Disruptive(kind);
        }
        verdict = AtRisk::Safe;
    }
    verdict
}

/// `AT` prefix, or `None` for anything that is not an AT command at all.
///
/// `A/` is deliberately not accepted: it repeats whatever was sent last, so
/// its effect cannot be read off the string in front of us.
fn strip_at_prefix(upper: &str) -> Option<&str> {
    let rest = upper.strip_prefix("AT")?;
    if rest.starts_with('/') {
        return None;
    }
    Some(rest)
}

fn segment_risk(segment: &str) -> Option<DisruptiveKind> {
    let segment = segment.trim();
    if segment.is_empty() {
        return None;
    }
    if let Some(extended) = segment.strip_prefix('+') {
        let (name, rest) = split_name(extended);
        if !is_write(rest) {
            // A read (`?`) or a capability test (`=?`) of anything.
            return None;
        }
        return WRITE_RISKS
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, kind)| *kind);
    }
    // Bare form. Matched on the longest name first so `&W` is not read as `&`.
    BARE_RISKS
        .iter()
        .filter(|(name, _)| segment.starts_with(name))
        .max_by_key(|(name, _)| name.len())
        .map(|(_, kind)| *kind)
}

/// Split `CFUN=0` into `("CFUN", "=0")`.
fn split_name(extended: &str) -> (&str, &str) {
    let end = extended
        .find(|character: char| !character.is_ascii_alphanumeric())
        .unwrap_or(extended.len());
    extended.split_at(end)
}

/// True when what follows the command name sets something.
///
/// `=?` asks the module which values it would accept, which is a read however
/// it is spelled. Everything else after `=` is a value being written.
fn is_write(rest: &str) -> bool {
    match rest.strip_prefix('=') {
        Some(value) => value.trim() != "?",
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reading_a_dangerous_command_is_safe() {
        assert_eq!(classify("AT+CFUN?"), AtRisk::Safe);
        assert_eq!(classify("AT+CFUN=?"), AtRisk::Safe);
        assert_eq!(classify("AT+COPS?"), AtRisk::Safe);
        assert_eq!(classify("AT+CPIN?"), AtRisk::Safe);
        // The diagnostics the console exists for.
        assert_eq!(classify("AT+CSQ"), AtRisk::Safe);
        assert_eq!(classify("AT+QCSQ"), AtRisk::Safe);
        assert_eq!(classify("AT+CGSN"), AtRisk::Safe);
        assert_eq!(classify("AT"), AtRisk::Safe);
    }

    #[test]
    fn writing_one_is_held_back_and_named() {
        assert_eq!(
            classify("AT+CFUN=0").disruptive(),
            Some(DisruptiveKind::Radio)
        );
        assert_eq!(
            classify("AT+CUSD=1,\"*100#\",15").disruptive(),
            Some(DisruptiveKind::Ussd)
        );
        assert_eq!(
            classify("AT+CMGS=\"10086\"").disruptive(),
            Some(DisruptiveKind::Message)
        );
        assert_eq!(
            classify("AT+CPIN=1234").disruptive(),
            Some(DisruptiveKind::Card)
        );
        assert_eq!(
            classify("AT+CGDCONT=1,\"IP\",\"cmnet\"").disruptive(),
            Some(DisruptiveKind::Config)
        );
    }

    /// The obvious way past a per-command check is to send two at once.
    #[test]
    fn a_dangerous_command_hidden_behind_a_safe_one_is_still_caught() {
        assert_eq!(
            classify("AT+CSQ;+CFUN=0").disruptive(),
            Some(DisruptiveKind::Radio)
        );
        assert_eq!(
            classify("AT+CGMM;+CMGD=1").disruptive(),
            Some(DisruptiveKind::Message)
        );
    }

    #[test]
    fn dialling_and_the_ampersand_family_have_no_safe_form() {
        assert_eq!(classify("ATD10086;").disruptive(), Some(DisruptiveKind::Call));
        assert_eq!(classify("ATH").disruptive(), Some(DisruptiveKind::Call));
        assert_eq!(classify("AT&F").disruptive(), Some(DisruptiveKind::Config));
        assert_eq!(classify("AT&W").disruptive(), Some(DisruptiveKind::Config));
    }

    /// `A/` repeats the previous command, so whatever it does is not readable
    /// from this string. It is the one bypass a per-string check must refuse.
    #[test]
    fn a_repeat_and_a_non_at_string_are_refused_rather_than_guessed() {
        assert_eq!(
            classify("A/").disruptive(),
            Some(DisruptiveKind::Unrecognised)
        );
        assert_eq!(
            classify("hello").disruptive(),
            Some(DisruptiveKind::Unrecognised)
        );
    }

    /// The entries whose danger is not obvious from the name.
    #[test]
    fn the_quiet_ones_are_held_back_too() {
        // Silent message loss rather than an error: routed to the terminal,
        // arriving messages are never stored and the sweep finds nothing.
        assert_eq!(
            classify("AT+CNMI=2,2,0,0,0").disruptive(),
            Some(DisruptiveKind::Message)
        );
        // Permanent, and not ours to change.
        assert_eq!(
            classify("AT+EGMR=1,7,\"860000000000000\"").disruptive(),
            Some(DisruptiveKind::Config)
        );
        // A shell on the module.
        assert_eq!(
            classify("AT+QLINUXCMD=\"rm -rf /\"").disruptive(),
            Some(DisruptiveKind::Config)
        );
        // And their read forms stay available, which is the point of the
        // read/write split rather than a name list.
        assert_eq!(classify("AT+CNMI?"), AtRisk::Safe);
    }

    #[test]
    fn case_and_padding_do_not_change_the_verdict() {
        assert_eq!(
            classify("  at+cfun=0  ").disruptive(),
            Some(DisruptiveKind::Radio)
        );
        assert_eq!(classify("at+csq"), AtRisk::Safe);
    }
}
