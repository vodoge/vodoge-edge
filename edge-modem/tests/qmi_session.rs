use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use edge_modem::{
    parse_cfun, parse_cpin, parse_qinistat, parse_qsimstat, restart_radio, CardEvidence, CardState,
    ClientAllocationRequest, ModuleRadio, OperatingMode, QmiClient, QmiTransport, ServiceId,
    SessionError, CARD_RECOVERY_NOTE, CFUN_DISABLE_RF, CFUN_FULL, CFUN_OFFLINE, CFUN_RESET_NOTE,
    CTL_SYNC, GET_DEVICE_REV_ID, GET_DEVICE_SERIAL_NUMBERS, GET_MANUFACTURER, GET_MODEL_ID,
    GET_OPERATING_MODE, SET_OPERATING_MODE,
};

struct FakeModem {
    dms_client: u8,
}

impl QmiTransport for FakeModem {
    fn transact(&mut self, request: &[u8]) -> Result<Vec<u8>, SessionError> {
        if request.len() < 10 || request[0] != 0x01 {
            return Err(SessionError::transport("truncated QMUX request"));
        }

        let service = request[4];
        let client = request[5];
        let (transaction, message) = if service == ServiceId::CONTROL.as_u8() {
            (
                request[7] as u16,
                u16::from_le_bytes([request[8], request[9]]),
            )
        } else {
            (
                u16::from_le_bytes([request[7], request[8]]),
                u16::from_le_bytes([request[9], request[10]]),
            )
        };

        let payload = match (service, message) {
            (0x00, 0x0027) => success_result_tlv(),
            (0x00, 0x0022) => allocation_payload(ServiceId::DMS.as_u8(), self.dms_client),
            (0x02, 0x0025) => serial_payload(),
            (0x02, 0x0023) => string_payload(0x01, b"EC20CEAR02A13M4G"),
            (0x02, 0x0022) => string_payload(0x01, b"EC20-CE"),
            (0x02, 0x0021) => string_payload(0x01, b"Quectel"),
            (0x02, 0x002d) => {
                let mut payload = success_result_tlv();
                payload.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]);
                payload
            }
            (0x02, 0x002e) => success_result_tlv(),
            _ => {
                return Err(SessionError::transport(format!(
                    "unexpected service=0x{service:02x} message=0x{message:04x} client=0x{client:02x}"
                )))
            }
        };

        Ok(response_frame(service, client, transaction, message, &payload))
    }
}

#[test]
fn session_syncs_and_allocates_a_dms_client() {
    let mut client = QmiClient::new(FakeModem { dms_client: 0x04 });
    client.sync().expect("CTL sync succeeds");
    let assignment = client.allocate(ServiceId::DMS).expect("DMS client allocated");
    assert_eq!(assignment.service(), ServiceId::DMS);
    assert_eq!(assignment.client_id().as_u8(), 0x04);
    assert_eq!(client.client_for(ServiceId::DMS).unwrap().as_u8(), 0x04);
}

#[test]
fn session_reads_imei_revision_and_operating_mode() {
    let mut client = QmiClient::new(FakeModem { dms_client: 0x04 });
    client.sync().expect("CTL sync succeeds");

    let serials = client.get_serial_numbers().expect("serial numbers");
    assert_eq!(serials.imei.as_deref(), Some("860000000000001"));
    assert_eq!(client.get_revision().expect("revision").device_rev_id, "EC20CEAR02A13M4G");
    assert_eq!(client.get_model().expect("model"), "EC20-CE");
    assert_eq!(client.get_manufacturer().expect("manufacturer"), "Quectel");
    assert_eq!(
        client.get_operating_mode().expect("operating mode"),
        OperatingMode::Online
    );
    client
        .set_operating_mode(OperatingMode::LowPower)
        .expect("set operating mode");
}

#[test]
fn dms_message_ids_match_libqmi() {
    assert_eq!(CTL_SYNC.as_u16(), 0x0027);
    assert_eq!(ClientAllocationRequest::MESSAGE_ID.as_u16(), 0x0022);
    assert_eq!(GET_MANUFACTURER.as_u16(), 0x0021);
    assert_eq!(GET_MODEL_ID.as_u16(), 0x0022);
    assert_eq!(GET_DEVICE_REV_ID.as_u16(), 0x0023);
    assert_eq!(GET_DEVICE_SERIAL_NUMBERS.as_u16(), 0x0025);
    assert_eq!(GET_OPERATING_MODE.as_u16(), 0x002d);
    assert_eq!(SET_OPERATING_MODE.as_u16(), 0x002e);
}

fn success_result_tlv() -> Vec<u8> {
    vec![0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]
}

fn allocation_payload(service: u8, client: u8) -> Vec<u8> {
    let mut payload = success_result_tlv();
    payload.extend_from_slice(&[0x01, 0x02, 0x00, service, client]);
    payload
}

fn serial_payload() -> Vec<u8> {
    let mut payload = success_result_tlv();
    payload.extend_from_slice(&[0x11, 0x0f, 0x00]);
    payload.extend_from_slice(b"860000000000001");
    payload
}

fn string_payload(kind: u8, value: &[u8]) -> Vec<u8> {
    let mut payload = success_result_tlv();
    payload.push(kind);
    payload.extend_from_slice(&(value.len() as u16).to_le_bytes());
    payload.extend_from_slice(value);
    payload
}

fn response_frame(
    service: u8,
    client: u8,
    transaction: u16,
    message: u16,
    payload: &[u8],
) -> Vec<u8> {
    let is_control = service == ServiceId::CONTROL.as_u8();
    let qmi_header_length = if is_control { 6 } else { 7 };
    let qmux_length = 5 + qmi_header_length + payload.len();
    let mut frame = Vec::with_capacity(qmux_length + 1);

    frame.push(0x01);
    frame.extend_from_slice(&(qmux_length as u16).to_le_bytes());
    frame.push(0x80);
    frame.push(service);
    frame.push(client);
    frame.push(if is_control { 0x01 } else { 0x02 });
    if is_control {
        frame.push(transaction as u8);
    } else {
        frame.extend_from_slice(&transaction.to_le_bytes());
    }
    frame.extend_from_slice(&message.to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

// ───────────────────────────────────────────────────────────────────────────
// The Restart button, and the module it stranded
// ───────────────────────────────────────────────────────────────────────────
//
// On 2026-08-25 `restart_modem` ran QMI `Offline` then `Online`. `Offline` was
// accepted, `Online` came back `result 1 error 60`, and the module stopped at
// `+CFUN: 7` with every documented way out refused. Nobody can reach this
// hardware to pull a stick, so the bug is not reproduced here on purpose: the
// module below is a stand-in built to answer exactly what the bench answered,
// and `the_old_offline_online_sequence_strands_this_module` is the test that
// says so — it is the fixture's own credential, and it fails if the stand-in
// stops reproducing the failure the rest of these tests are about.

/// QMI error 60, as the bench reported it.
const QMI_ERROR_NO_EFFECT: u16 = 60;

// ── The bench's clock ──────────────────────────────────────────────────────
//
// Measured on `867018069509705` on 2026-08-25 (T085 §2 and §3), by sending
// `AT+CFUN=0`, waiting three seconds, and sending `AT+CFUN=1`. T0 below is the
// instant `AT+CFUN=1` answered `OK`, which is where T085 anchored its readings.
//
// These numbers are the whole point of this fixture. Before they were written
// down here, "a restart reports success while the card is still initialising"
// was an inference: T085 measured that `AT+CFUN=1` answers in 294ms and that
// the card is not ready for another two seconds, but it declined to spend a
// second write on a just-revived paid line to watch our own ladder do it.
// Encoding the timeline turns that inference into a property the test suite
// checks on every run.

/// `AT+CFUN=0` answered `OK` this long after it was issued.
const CFUN_ZERO_REPLY: Duration = Duration::from_millis(127);
/// `AT+CFUN=1` answered `OK` this long after it was issued. T0 is here.
const CFUN_ONE_REPLY: Duration = Duration::from_millis(294);
/// `AT+CPIN?` answered `+CME ERROR: 14` at T0+0.3s and `+CPIN: READY` here.
const CARD_READY_AT: Duration = Duration::from_millis(2_300);
/// `+QSIMSTAT: 0,1` here; it read `0,0` while the card was away.
const CARD_INSERTED_AT: Duration = Duration::from_millis(2_400);
/// `+CREG: 0,1` here — three seconds after the card was usable, and the reason
/// registration is not part of the restart's success criterion.
const REGISTERED_AT: Duration = Duration::from_millis(5_400);

/// Where the card is, on the bench's clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Card {
    /// Initialised and staying that way.
    Up,
    /// Answering `+CME ERROR: <code>` and not coming back by itself. This is
    /// the state T085 found `867018069509705` in: `+CME ERROR: 13`,
    /// `+QSIMSTAT: 0,0`, `+QINISTAT: 0`, on a module whose radio was fine.
    Gone(u16),
    /// Waiting for a code. No amount of patience changes this one.
    Locked(&'static str),
    /// Powered down and coming back, on the timeline above. `started` is T0.
    Initialising { started: Duration },
}

/// One EC20's radio state, shared by the QMI transport and the AT port.
///
/// Both live on the same stick, so they cannot be modelled as two independent
/// fakes: the whole point of reading `AT+CFUN?` after a QMI mode change is
/// that they are two views of one thing.
#[derive(Debug)]
struct Ec20 {
    /// What `AT+CFUN?` answers, once the change is visible.
    cfun: u8,
    /// What it answered before the most recent change.
    previous_cfun: u8,
    /// When the most recent functionality change was issued.
    radio_changed_at: Duration,
    /// How long after that the new value becomes visible on `AT+CFUN?`.
    ///
    /// Zero by default, which is T085's *inference*: it never sampled
    /// `AT+CFUN?` inside the recovery window, so the earliest moment the radio
    /// could look up is when the `OK` came back. The knob exists so a test can
    /// show the verdict does not depend on that one unmeasured number — any
    /// value below `CARD_READY_AT` produces the same window.
    radio_visible_after: Duration,
    /// Set once the module has been taken to QMI `Offline`. Afterwards every
    /// QMI mode change answers error 60 and every `AT+CFUN=` answers
    /// `+CME ERROR: 4`. This is the one-way door.
    offline_wedge: bool,
    /// Refuse `Online` with error 60 without needing the door: the shape of
    /// the failure, applied to a module that is merely in low power.
    refuse_online: bool,
    /// The AT port cannot be opened at all.
    at_dead: bool,
    /// `AT+CFUN=` always answers `+CME ERROR: 4`.
    at_cfun_refused: bool,
    /// `AT+CFUN=1` on its own is answered and refused, while the same command
    /// after an `AT+CFUN=0` is accepted. This is the precondition the ladder's
    /// last rung documents for itself, and it is how a test gets there.
    refuse_single_step_cfun: bool,
    /// Make `QMI_DMS_GET_OPERATING_MODE` disagree with `AT+CFUN?`.
    qmi_mode_override: Option<OperatingMode>,
    /// The card, and its clock.
    card: Card,
    /// Virtual time. Advanced by `pause` and by the two commands whose reply
    /// latency was measured.
    now: Duration,
    /// Every mode asked for over QMI, in order.
    qmi_requests: Vec<OperatingMode>,
    /// Every AT command issued, verbatim.
    at_commands: Vec<String>,
    /// The same, stamped with the virtual time each one was issued at.
    at_log: Vec<(Duration, String)>,
    /// Every answer `AT+CPIN?` gave, rendered. This is the sequence T085
    /// watched by hand, and the thing the ladder used never to look at.
    cpin_answers: Vec<String>,
}

impl Default for Ec20 {
    fn default() -> Self {
        Self {
            cfun: 1,
            previous_cfun: 1,
            radio_changed_at: Duration::ZERO,
            radio_visible_after: Duration::ZERO,
            offline_wedge: false,
            refuse_online: false,
            at_dead: false,
            at_cfun_refused: false,
            refuse_single_step_cfun: false,
            qmi_mode_override: None,
            card: Card::Up,
            now: Duration::ZERO,
            qmi_requests: Vec::new(),
            at_commands: Vec::new(),
            at_log: Vec::new(),
            cpin_answers: Vec::new(),
        }
    }
}

impl Ec20 {
    fn advance(&mut self, by: Duration) {
        self.now += by;
    }

    /// What `AT+CFUN?` would say right now.
    fn visible_cfun(&self) -> u8 {
        if self.now >= self.radio_changed_at + self.radio_visible_after {
            self.cfun
        } else {
            self.previous_cfun
        }
    }

    /// How long since the card was last taken down and told to come back.
    fn since_card_restart(&self) -> Option<Duration> {
        match self.card {
            Card::Initialising { started } => Some(self.now.saturating_sub(started)),
            _ => None,
        }
    }

    /// `AT+CPIN?`, as lines plus terminator — the split matters, because a
    /// busy or missing card puts its whole answer in the terminator.
    fn cpin_reply(&self) -> (Vec<String>, String) {
        let ready = (vec!["+CPIN: READY".to_string()], "OK".to_string());
        match self.card {
            Card::Up => ready,
            Card::Gone(code) => (Vec::new(), format!("+CME ERROR: {code}")),
            Card::Locked(code) => (vec![format!("+CPIN: {code}")], "OK".to_string()),
            Card::Initialising { started } => {
                if self.now.saturating_sub(started) >= CARD_READY_AT {
                    ready
                } else {
                    // The good intermediate state: busy, not failed.
                    (Vec::new(), "+CME ERROR: 14".to_string())
                }
            }
        }
    }

    fn qsimstat_reply(&self) -> Vec<String> {
        let inserted = match self.card {
            Card::Up | Card::Locked(_) => true,
            Card::Gone(_) => false,
            Card::Initialising { started } => {
                self.now.saturating_sub(started) >= CARD_INSERTED_AT
            }
        };
        vec![format!("+QSIMSTAT: 0,{}", u8::from(inserted))]
    }

    fn qinistat_reply(&self) -> Vec<String> {
        // 7 is CPIN, SMS and phonebook initialisation all finished, which is
        // what the bench read once the card was back; 0 is what it read while
        // the card was away.
        let done = match self.card {
            Card::Up => true,
            Card::Gone(_) | Card::Locked(_) => false,
            Card::Initialising { started } => self.now.saturating_sub(started) >= CARD_READY_AT,
        };
        vec![format!("+QINISTAT: {}", if done { 7 } else { 0 })]
    }

    fn registered(&self) -> bool {
        match self.card {
            Card::Up => true,
            Card::Gone(_) | Card::Locked(_) => false,
            Card::Initialising { started } => self.now.saturating_sub(started) >= REGISTERED_AT,
        }
    }

    fn creg_reply(&self) -> Vec<String> {
        vec![format!("+CREG: 0,{}", u8::from(self.registered()))]
    }

    fn mode(&self) -> OperatingMode {
        if let Some(mode) = self.qmi_mode_override {
            return mode;
        }
        match self.visible_cfun() {
            1 => OperatingMode::Online,
            7 => OperatingMode::Offline,
            _ => OperatingMode::LowPower,
        }
    }

    /// Note a functionality change without disturbing the card.
    ///
    /// `+CFUN: 4` is radio off with the card still initialised, so a
    /// `LowPower` / `Online` pair — which is what a healthy restart is — never
    /// takes the card down at all. Only `AT+CFUN=0` does that, and that is the
    /// pair the bench measured.
    fn change_cfun(&mut self, value: u8) {
        self.previous_cfun = self.visible_cfun();
        self.radio_changed_at = self.now;
        self.cfun = value;
    }

    /// `Err(error)` is a QMI result error code, not a transport failure.
    fn apply_mode(&mut self, mode: OperatingMode) -> Result<(), u16> {
        self.qmi_requests.push(mode);
        if self.offline_wedge {
            return Err(QMI_ERROR_NO_EFFECT);
        }
        match mode {
            OperatingMode::Offline => {
                self.change_cfun(7);
                self.offline_wedge = true;
                Ok(())
            }
            OperatingMode::Online => {
                if self.refuse_online {
                    return Err(QMI_ERROR_NO_EFFECT);
                }
                self.change_cfun(1);
                Ok(())
            }
            OperatingMode::LowPower => {
                self.change_cfun(4);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn at(&mut self, command: &str) -> Result<Vec<String>, String> {
        self.at_commands.push(command.to_string());
        self.at_log.push((self.now, command.to_string()));
        if self.at_dead {
            return Err("open /dev/ttyUSB2: No such device".to_string());
        }
        match command {
            "AT+CFUN?" => Ok(vec![format!("+CFUN: {}", self.visible_cfun())]),
            "AT+QSIMSTAT?" => Ok(self.qsimstat_reply()),
            "AT+QINISTAT" => Ok(self.qinistat_reply()),
            "AT+CREG?" => Ok(self.creg_reply()),
            _ => Err(format!("this stand-in was not taught {command}")),
        }
    }

    /// `AT+CPIN?`. Separate from `at` because its answer is a pair.
    fn at_cpin(&mut self) -> Result<(Vec<String>, String), String> {
        self.at_commands.push("AT+CPIN?".to_string());
        self.at_log.push((self.now, "AT+CPIN?".to_string()));
        if self.at_dead {
            return Err("open /dev/ttyUSB2: No such device".to_string());
        }
        let (lines, terminator) = self.cpin_reply();
        self.cpin_answers.push(if lines.is_empty() {
            terminator.clone()
        } else {
            lines.join(" ")
        });
        Ok((lines, terminator))
    }

    /// `Ok(false)` is `+CME ERROR: 4`, which is an answer and not a lost port.
    fn write_cfun(&mut self, value: u8) -> Result<bool, String> {
        self.at_commands.push(format!("AT+CFUN={value}"));
        self.at_log.push((self.now, format!("AT+CFUN={value}")));
        if self.at_dead {
            return Err("open /dev/ttyUSB2: No such device".to_string());
        }
        if self.offline_wedge || self.at_cfun_refused {
            return Ok(false);
        }
        if value == 1 && self.refuse_single_step_cfun && self.cfun != 0 {
            // Answered and refused: the module is taking commands, it just
            // will not come up from here in one step.
            return Ok(false);
        }
        self.change_cfun(value);
        match value {
            0 => {
                // The card goes down with the radio. What it answers between
                // the two commands was not sampled on the bench; 13 is the
                // shape this bench has twice shown for a card that is not
                // there, and nothing here depends on the choice.
                self.card = Card::Gone(13);
                self.advance(CFUN_ZERO_REPLY);
            }
            1 => {
                self.advance(CFUN_ONE_REPLY);
                if matches!(self.card, Card::Gone(_)) {
                    // T0. Everything the card does from here runs on the
                    // measured timeline.
                    self.card = Card::Initialising { started: self.now };
                }
                // The radio really came up, so QMI stops refusing too.
                self.refuse_online = false;
            }
            _ => {}
        }
        Ok(true)
    }
}

/// A QMI transport over one `Ec20`, answering DMS the way the bench does.
struct SharedTransport(Rc<RefCell<Ec20>>);

impl QmiTransport for SharedTransport {
    fn transact(&mut self, request: &[u8]) -> Result<Vec<u8>, SessionError> {
        if request.len() < 10 || request[0] != 0x01 {
            return Err(SessionError::transport("truncated QMUX request"));
        }
        let service = request[4];
        let client = request[5];
        let (transaction, message, payload_at) = if service == ServiceId::CONTROL.as_u8() {
            (request[7] as u16, u16::from_le_bytes([request[8], request[9]]), 12)
        } else {
            (
                u16::from_le_bytes([request[7], request[8]]),
                u16::from_le_bytes([request[9], request[10]]),
                13,
            )
        };

        let payload = match (service, message) {
            (0x00, 0x0027) => success_result_tlv(),
            (0x00, 0x0022) => allocation_payload(ServiceId::DMS.as_u8(), 0x04),
            (0x02, 0x0025) => serial_payload(),
            (0x02, 0x002d) => {
                let mut payload = success_result_tlv();
                payload.extend_from_slice(&[0x01, 0x01, 0x00, self.0.borrow().mode().as_u8()]);
                payload
            }
            (0x02, 0x002e) => {
                // TLV 0x01 of `SET_OPERATING_MODE` is the one-byte mode.
                let mode = request
                    .get(payload_at + 3)
                    .copied()
                    .map(OperatingMode::from_wire)
                    .ok_or_else(|| SessionError::transport("mode TLV missing"))?;
                match self.0.borrow_mut().apply_mode(mode) {
                    Ok(()) => success_result_tlv(),
                    Err(error) => failure_result_tlv(error),
                }
            }
            _ => {
                return Err(SessionError::transport(format!(
                    "unexpected service=0x{service:02x} message=0x{message:04x}"
                )))
            }
        };

        Ok(response_frame(service, client, transaction, message, &payload))
    }
}

/// Both control paths to the stand-in, wired to the trait the ladder uses.
struct Bench {
    client: QmiClient<SharedTransport>,
    state: Rc<RefCell<Ec20>>,
    /// Every pause the ladder asked for, in order and with its length. Kept as
    /// durations rather than a count so a test can say which wait it means.
    pauses: Vec<Duration>,
}

impl Bench {
    fn new(state: Ec20) -> Self {
        let state = Rc::new(RefCell::new(state));
        let mut client = QmiClient::new(SharedTransport(state.clone()));
        client.sync().expect("CTL sync");
        Self {
            client,
            state,
            pauses: Vec::new(),
        }
    }

    fn qmi_requests(&self) -> Vec<OperatingMode> {
        self.state.borrow().qmi_requests.clone()
    }

    fn at_commands(&self) -> Vec<String> {
        self.state.borrow().at_commands.clone()
    }

    fn issued(&self, command: &str) -> usize {
        self.state
            .borrow()
            .at_commands
            .iter()
            .filter(|issued| *issued == command)
            .count()
    }

    fn cfun(&self) -> u8 {
        self.state.borrow().cfun
    }

    fn now(&self) -> Duration {
        self.state.borrow().now
    }

    /// What `AT+CPIN?` would answer at this instant of virtual time — the
    /// question the whole card is about, asked from outside the ladder.
    fn card_now(&self) -> CardState {
        let (lines, terminator) = self.state.borrow().cpin_reply();
        parse_cpin(&lines, &terminator)
    }

    fn since_card_restart(&self) -> Option<Duration> {
        self.state.borrow().since_card_restart()
    }

    fn registered_now(&self) -> bool {
        self.state.borrow().registered()
    }

    fn cpin_answers(&self) -> Vec<String> {
        self.state.borrow().cpin_answers.clone()
    }

    /// The virtual time between two AT commands being issued.
    fn gap_between(&self, first: &str, second: &str) -> Option<Duration> {
        let log = self.state.borrow().at_log.clone();
        let start = log.iter().position(|(_, command)| command == first)?;
        let (issued_first, _) = log[start];
        log[start + 1..]
            .iter()
            .find(|(_, command)| command == second)
            .map(|(issued_second, _)| issued_second.saturating_sub(issued_first))
    }
}

impl ModuleRadio for Bench {
    fn operating_mode(&mut self) -> Result<OperatingMode, String> {
        self.client.get_operating_mode().map_err(|error| error.to_string())
    }

    fn set_operating_mode(&mut self, mode: OperatingMode) -> Result<(), String> {
        self.client
            .set_operating_mode(mode)
            .map_err(|error| error.to_string())
    }

    fn read_functionality(&mut self) -> Result<Option<u8>, String> {
        let lines = self.state.borrow_mut().at("AT+CFUN?")?;
        Ok(parse_cfun(&lines))
    }

    fn write_functionality(&mut self, value: u8) -> Result<bool, String> {
        self.state.borrow_mut().write_cfun(value)
    }

    fn read_card_state(&mut self) -> Result<CardState, String> {
        let (lines, terminator) = self.state.borrow_mut().at_cpin()?;
        // Through the real parser, so the fixture cannot agree with the code
        // under test by way of a second, friendlier reading of the same bytes.
        Ok(parse_cpin(&lines, &terminator))
    }

    fn read_card_evidence(&mut self) -> CardEvidence {
        let mut state = self.state.borrow_mut();
        let inserted = state.at("AT+QSIMSTAT?").ok().and_then(|lines| parse_qsimstat(&lines));
        let init_status = state.at("AT+QINISTAT").ok().and_then(|lines| parse_qinistat(&lines));
        CardEvidence {
            inserted,
            init_status,
        }
    }

    fn pause(&mut self, duration: Duration) {
        // Free in wall-clock terms, real on the fake's clock. Recorded so a
        // test can prove the ladder waits rather than hammering a module that
        // is mid-transition, and can say how long it waited for.
        self.pauses.push(duration);
        self.state.borrow_mut().advance(duration);
    }
}

/// The fixture's credential. If this stops failing the way the bench failed,
/// nothing else in this section is evidence about anything.
#[test]
fn the_old_offline_online_sequence_strands_this_module() {
    let mut bench = Bench::new(Ec20::default());

    bench
        .set_operating_mode(OperatingMode::Offline)
        .expect("offline is accepted, exactly as it was on the bench");
    let refusal = bench
        .set_operating_mode(OperatingMode::Online)
        .expect_err("online is refused");
    assert!(
        refusal.contains("error 60"),
        "the refusal has to be QMI error 60, got {refusal}"
    );

    // And now the module is where nobody could get it out of.
    assert_eq!(bench.cfun(), 7);
    assert!(bench
        .set_operating_mode(OperatingMode::LowPower)
        .unwrap_err()
        .contains("error 60"));
    for value in [0u8, 1, 4] {
        assert_eq!(
            bench.write_functionality(value),
            Ok(false),
            "AT+CFUN={value} answered +CME ERROR: 4 on the bench"
        );
    }
}

/// The fix, stated as the property that matters: the door is never opened.
#[test]
fn restart_never_asks_for_the_offline_operating_mode() {
    let mut bench = Bench::new(Ec20::default());

    let report = restart_radio(&mut bench).expect("a healthy module restarts");

    assert!(
        !bench.qmi_requests().contains(&OperatingMode::Offline),
        "restart asked for Offline, which is the one-way door: {:?}",
        bench.qmi_requests()
    );
    assert_eq!(
        bench.qmi_requests(),
        vec![OperatingMode::LowPower, OperatingMode::Online]
    );
    assert_eq!(report.cfun_before, Some(1));
    assert_eq!(report.cfun_after, Some(1));
    assert_eq!(report.mode_after, Some(OperatingMode::Online));
    assert_eq!(bench.cfun(), 1);
}

/// QMI error 60 on the way up, on a module whose AT port still works.
#[test]
fn restart_climbs_back_with_plain_cfun_when_qmi_refuses_online() {
    let mut bench = Bench::new(Ec20 {
        refuse_online: true,
        ..Ec20::default()
    });

    let report = restart_radio(&mut bench).expect("the ladder brings it back");

    assert!(report
        .steps
        .iter()
        .any(|step| step.contains("QMI online refused")));
    assert!(bench.at_commands().contains(&"AT+CFUN=1".to_string()));
    assert!(
        !bench.at_commands().iter().any(|c| c.contains("1,1")),
        "the reset form must never be issued automatically: {:?}",
        bench.at_commands()
    );
    assert!(
        !bench.pauses.is_empty(),
        "the ladder has to give the module time"
    );
    assert_eq!(bench.cfun(), 1);
    assert_eq!(report.cfun_after, Some(1));
}

/// QMI error 60 on the way up, and the AT port refuses `AT+CFUN=` too — the
/// bench's own combination. The module must not be left unrecoverable, and the
/// call must not report success.
#[test]
fn restart_that_cannot_climb_back_says_so_and_leaves_a_recoverable_module() {
    let mut bench = Bench::new(Ec20 {
        refuse_online: true,
        at_cfun_refused: true,
        ..Ec20::default()
    });

    let error = restart_radio(&mut bench).expect_err("this must not be reported as success");

    assert_eq!(error.code(), "restart_not_restored");
    let text = error.to_string();
    assert!(text.contains("+CFUN: 4"), "the error has to name the state: {text}");
    assert!(
        !bench.qmi_requests().contains(&OperatingMode::Offline),
        "the wedge is entered through Offline, and it was never asked for"
    );
    assert!(
        !bench.at_commands().iter().any(|c| c.contains("1,1")),
        "no automatic reset: {:?}",
        bench.at_commands()
    );
    // The point of the whole card: after error 60 the module is in low power,
    // not in the state with no way out.
    assert_eq!(bench.cfun(), 4);
    assert!(!bench.state.borrow().offline_wedge);
}

/// A module found at `+CFUN: 7` is not poked. Every QMI mode change from there
/// was measured to be refused, so the only thing another request buys is a
/// second failure to explain.
#[test]
fn restart_leaves_a_module_that_is_already_stranded_alone() {
    let mut bench = Bench::new(Ec20 {
        cfun: 7,
        offline_wedge: true,
        ..Ec20::default()
    });

    let error = restart_radio(&mut bench).expect_err("a stranded module cannot be restarted");

    assert_eq!(error.code(), "modem_already_stranded");
    assert!(
        bench.qmi_requests().is_empty(),
        "nothing should have been sent: {:?}",
        bench.qmi_requests()
    );
    let text = error.to_string();
    assert!(text.contains("+CFUN: 7"));
    assert!(
        text.contains("AT+CFUN=1,1"),
        "the one known cure has to be named for the operator: {text}"
    );
}

/// No read-back, no restart. The radio is not taken down when there would be
/// no way to tell whether it came back.
#[test]
fn restart_refuses_when_cfun_cannot_be_read() {
    let mut bench = Bench::new(Ec20 {
        at_dead: true,
        ..Ec20::default()
    });

    let error = restart_radio(&mut bench).expect_err("unverifiable means refused");

    assert_eq!(error.code(), "restart_unverifiable");
    assert!(
        bench.qmi_requests().is_empty(),
        "the radio was touched anyway: {:?}",
        bench.qmi_requests()
    );
}

/// Both readings have to agree. `+CFUN: 1` while QMI still says low power is
/// the exact shape of a success that is not one.
#[test]
fn restart_does_not_call_a_disagreement_a_success() {
    let mut bench = Bench::new(Ec20 {
        qmi_mode_override: Some(OperatingMode::LowPower),
        ..Ec20::default()
    });

    let error = restart_radio(&mut bench).expect_err("a disagreement is not a success");

    assert_eq!(error.code(), "restart_not_restored");
    assert!(error.to_string().contains("LowPower"));
    assert_eq!(bench.cfun(), 1, "the AT side did read full functionality");
}

/// The contradiction this card exists to record, kept honest by a test rather
/// than by a comment nobody rereads: `AT+CFUN=1,1` is the only measured cure
/// and is also the form the panel refuses to expose, so the note has to carry
/// both halves.
#[test]
fn the_reset_note_names_the_cure_and_why_it_is_not_automatic() {
    assert!(CFUN_RESET_NOTE.contains("AT+CFUN=1,1"));
    assert!(CFUN_RESET_NOTE.contains("/api/at"));
    assert!(CFUN_RESET_NOTE.contains("will not issue it by itself"));
}

#[test]
fn cfun_replies_are_read_the_way_the_module_writes_them() {
    assert_eq!(parse_cfun(&["+CFUN: 7".to_string()]), Some(CFUN_OFFLINE));
    assert_eq!(parse_cfun(&["+CFUN: 1".to_string()]), Some(CFUN_FULL));
    assert_eq!(parse_cfun(&["  +CFUN: 4 ".to_string()]), Some(CFUN_DISABLE_RF));
    // Some firmware appends the reset parameter to the query answer.
    assert_eq!(parse_cfun(&["+CFUN: 1,0".to_string()]), Some(CFUN_FULL));
    assert_eq!(parse_cfun(&["+CPIN: READY".to_string()]), None);
    assert_eq!(parse_cfun(&[]), None);
}

// ───────────────────────────────────────────────────────────────────────────
// The radio came back. That is not the same as the module being usable.
// ───────────────────────────────────────────────────────────────────────────
//
// On 2026-08-25 T085 revived `867018069509705` with `AT+CFUN=0` / `AT+CFUN=1`
// and timed what came back when: the `OK` at 294ms, the card two seconds after
// that, the network three seconds after the card. It then observed that the
// ladder's success criterion only polls `AT+CFUN?`, and reasoned that a
// restart would therefore report success into that window — but it marked that
// last step as an inference, because confirming it meant a second write on a
// paid line that had just been rescued.
//
// The timeline is in the stand-in above, so the inference is now a measurement
// of our own code against the bench's numbers rather than a paragraph.

/// The fixture's second credential. If these stop matching T085 §3, none of
/// the tests below are evidence about the hardware.
#[test]
fn the_stand_in_comes_back_on_the_timeline_the_bench_measured() {
    let mut ec20 = Ec20::default();

    // T085 §2: two commands, three seconds apart, and nothing else.
    assert_eq!(ec20.write_cfun(0), Ok(true));
    let zero_answered = ec20.now;
    assert_eq!(zero_answered, CFUN_ZERO_REPLY, "AT+CFUN=0 answered in 127ms");
    ec20.advance(Duration::from_millis(3_000));
    let one_issued = ec20.now;
    assert_eq!(ec20.write_cfun(1), Ok(true));
    // T0. The `OK` is back, and this is where T085 anchored everything else.
    assert_eq!(ec20.now - one_issued, CFUN_ONE_REPLY, "AT+CFUN=1 in 294ms");
    assert_eq!(ec20.since_card_restart(), Some(Duration::ZERO));

    // The radio is up at T0 — and this is the whole problem.
    assert_eq!(ec20.visible_cfun(), 1);
    assert_eq!(ec20.mode(), OperatingMode::Online);

    // t = 0.3s: SIM busy. Not "no card" (13) — busy (14), which is the module
    // saying it is working on it.
    ec20.advance(Duration::from_millis(300));
    assert_eq!(ec20.cpin_reply().1, "+CME ERROR: 14");
    assert_eq!(parse_cpin(&[], "+CME ERROR: 14"), CardState::Initialising);
    assert_eq!(ec20.qsimstat_reply(), vec!["+QSIMSTAT: 0,0".to_string()]);
    assert_eq!(ec20.qinistat_reply(), vec!["+QINISTAT: 0".to_string()]);

    // t = 2.2s: still not ready. The window is two full seconds wide.
    ec20.advance(Duration::from_millis(1_900));
    assert_eq!(ec20.cpin_reply().1, "+CME ERROR: 14");

    // t = 2.3s: READY.
    ec20.advance(Duration::from_millis(100));
    assert_eq!(ec20.since_card_restart(), Some(CARD_READY_AT));
    assert_eq!(ec20.cpin_reply().0, vec!["+CPIN: READY".to_string()]);
    assert_eq!(ec20.qinistat_reply(), vec!["+QINISTAT: 7".to_string()]);

    // t = 2.4s: `+QSIMSTAT: 0,1`.
    ec20.advance(Duration::from_millis(100));
    assert_eq!(ec20.qsimstat_reply(), vec!["+QSIMSTAT: 0,1".to_string()]);

    // And the network is still three seconds away, which is why registration
    // is not part of what a restart promises.
    assert!(!ec20.registered());
    assert_eq!(ec20.creg_reply(), vec!["+CREG: 0,0".to_string()]);
    ec20.advance(REGISTERED_AT - CARD_INSERTED_AT);
    assert!(ec20.registered());
    assert_eq!(ec20.creg_reply(), vec!["+CREG: 0,1".to_string()]);
}

/// The measurement T085 declined to take on hardware, taken here instead.
///
/// The module is brought back through the ladder's last rung, which is the
/// `AT+CFUN=0` / `AT+CFUN=1` pair the bench actually timed. Before this card,
/// `restart_radio` returned `Ok` as soon as `AT+CFUN?` read 1 — 294ms in, with
/// the card answering `+CME ERROR: 14`.
#[test]
fn restart_does_not_report_success_while_the_card_is_still_initialising() {
    let mut bench = Bench::new(Ec20 {
        refuse_online: true,
        refuse_single_step_cfun: true,
        ..Ec20::default()
    });

    let report = restart_radio(&mut bench).expect("the module does come back");

    // Where the ladder went, so a reader can see this really is the rung the
    // bench measured.
    assert!(bench.at_commands().contains(&"AT+CFUN=0".to_string()));
    assert!(
        !bench.at_commands().iter().any(|c| c.contains("1,1")),
        "no automatic reset: {:?}",
        bench.at_commands()
    );

    // The assertion this whole card exists for.
    assert!(
        bench.card_now().is_ready(),
        "Ok was returned over a card that reads {} — the radio was up and the \
         module was not usable",
        bench.card_now()
    );
    let waited = bench.since_card_restart().expect("the card was restarted");
    assert!(
        waited >= CARD_READY_AT,
        "returned {waited:?} after the radio came up, and the card is not ready \
         until {CARD_READY_AT:?}"
    );
    assert_eq!(report.card_after, Some(CardState::Ready));

    // The window was real: the first look at the card, taken at the instant
    // the old criterion was already satisfied, found it busy.
    assert_eq!(
        bench.cpin_answers().first().map(String::as_str),
        Some("+CME ERROR: 14"),
        "the first card reading should land in the window T085 measured: {:?}",
        bench.cpin_answers()
    );
    assert_eq!(report.card_evidence.inserted, Some(true));
    assert_eq!(report.card_evidence.init_status, Some(7));

    // It also did not wait for the network, which is a separate promise this
    // function deliberately does not make: registration was still three
    // seconds out and `Ok` was returned anyway.
    assert!(
        waited < REGISTERED_AT && !bench.registered_now(),
        "restart waited for registration ({waited:?}), which may never come"
    );
}

/// The one number in the fixture that T085 inferred rather than measured is
/// when `AT+CFUN?` starts reading 1. The verdict must not rest on it.
#[test]
fn the_verdict_does_not_depend_on_when_the_radio_becomes_visible() {
    for visible_after in [0u64, 700, 1_700] {
        let mut bench = Bench::new(Ec20 {
            refuse_online: true,
            refuse_single_step_cfun: true,
            radio_visible_after: Duration::from_millis(visible_after),
            ..Ec20::default()
        });

        let report = restart_radio(&mut bench)
            .unwrap_or_else(|error| panic!("visible after {visible_after}ms: {error}"));

        assert_eq!(
            report.card_after,
            Some(CardState::Ready),
            "visible after {visible_after}ms"
        );
        let waited = bench.since_card_restart().expect("the card was restarted");
        assert!(
            waited >= CARD_READY_AT,
            "visible after {visible_after}ms returned at {waited:?}"
        );
    }
}

/// The state T085 actually found on the bench: `+CFUN: 1`, radio fine, card
/// gone. A restart moves the radio, comes back, and changes nothing about the
/// card — and used to call that a success.
#[test]
fn restart_does_not_call_a_missing_card_a_successful_restart() {
    let mut bench = Bench::new(Ec20 {
        card: Card::Gone(13),
        ..Ec20::default()
    });

    let error = restart_radio(&mut bench).expect_err("a module with no card is not restored");

    assert_eq!(error.code(), "restart_card_not_ready");
    let report = error.report().expect("the report comes with it");
    assert_eq!(report.cfun_after, Some(1), "the radio really did come back");
    assert_eq!(report.mode_after, Some(OperatingMode::Online));
    assert_eq!(report.card_after, Some(CardState::Absent(13)));
    assert_eq!(report.card_evidence.inserted, Some(false));
    assert_eq!(report.card_evidence.init_status, Some(0));
}

/// "The radio did not come back" and "the radio came back over a card that did
/// not" are different outcomes with different next actions, and a caller has
/// to be able to tell them apart without reading English.
#[test]
fn a_card_that_never_arrives_is_not_reported_as_a_failed_restart() {
    let mut bench = Bench::new(Ec20 {
        card: Card::Gone(13),
        ..Ec20::default()
    });
    let card_missing = restart_radio(&mut bench).expect_err("not a success");

    let mut broken = Bench::new(Ec20 {
        refuse_online: true,
        at_cfun_refused: true,
        ..Ec20::default()
    });
    let radio_down = restart_radio(&mut broken).expect_err("not a success either");

    // Distinguishable by code, and by a predicate rather than by prose.
    assert_ne!(card_missing.code(), radio_down.code());
    assert!(card_missing.radio_restored());
    assert!(!radio_down.radio_restored());

    // And the message says which of the two it is.
    let text = card_missing.to_string();
    assert!(
        text.contains("the radio came back but the card did not"),
        "the operator has to be told the radio is fine: {text}"
    );
    assert!(
        text.contains("not a failed restart"),
        "and that another restart is not the fix: {text}"
    );

    // Bounded, and generous. `SETTLE_STEP` × `CARD_ATTEMPTS` has to outlast
    // the slowest card anybody has timed (about 15s on `867018069514820`,
    // T079) without becoming an unbounded wait.
    assert!(
        bench.now() >= Duration::from_secs(15),
        "gave up after {:?}, sooner than a card has been measured to take",
        bench.now()
    );
    assert!(
        bench.now() <= Duration::from_secs(60),
        "waited {:?}, which is not a bound",
        bench.now()
    );
}

/// The line this card is not allowed to cross.
///
/// `AT+CFUN=0` / `AT+CFUN=1` has cleared a fallen-off card twice on this
/// bench. Twice is a regularity, not a mechanism, and the ladder must not fire
/// it at a card just because the card is missing — it is only ever reached as
/// a way of bringing a *radio* back.
#[test]
fn restart_does_not_try_the_unexplained_card_remedy_by_itself() {
    let mut bench = Bench::new(Ec20 {
        card: Card::Gone(13),
        ..Ec20::default()
    });

    let error = restart_radio(&mut bench).expect_err("the card is still missing");

    assert_eq!(error.code(), "restart_card_not_ready");
    assert!(
        !bench.at_commands().contains(&"AT+CFUN=0".to_string()),
        "the radio came back on its own, so the ladder had no business \
         power-cycling the card: {:?}",
        bench.at_commands()
    );
    assert!(
        !bench.at_commands().iter().any(|c| c.contains("1,1")),
        "and certainly not the reset form: {:?}",
        bench.at_commands()
    );
    // What it does instead is say what a person could try.
    assert!(error.to_string().contains("AT+CFUN=0"));
}

/// A card waiting for a human is not going to become READY by being asked
/// twenty more times.
#[test]
fn waiting_for_the_card_stops_when_it_is_waiting_for_a_person() {
    let mut bench = Bench::new(Ec20 {
        card: Card::Locked("SIM PIN"),
        ..Ec20::default()
    });

    let error = restart_radio(&mut bench).expect_err("a locked card is not a ready one");

    assert_eq!(error.code(), "restart_card_not_ready");
    assert_eq!(
        error.report().and_then(|report| report.card_after.clone()),
        Some(CardState::Locked("SIM PIN".to_string()))
    );
    assert_eq!(
        bench.issued("AT+CPIN?"),
        1,
        "polling a card that needs a PIN is just noise: {:?}",
        bench.cpin_answers()
    );
}

/// The last rung waits the interval that was actually measured with it.
///
/// `SETTLE_STEP` is 1.5s and has never been tried between `AT+CFUN=0` and
/// `AT+CFUN=1`; three seconds is what T085 used, on the one run anybody has.
#[test]
fn the_last_rung_waits_the_interval_that_was_measured() {
    let mut bench = Bench::new(Ec20 {
        refuse_online: true,
        refuse_single_step_cfun: true,
        ..Ec20::default()
    });

    restart_radio(&mut bench).expect("the module comes back");

    let gap = bench
        .gap_between("AT+CFUN=0", "AT+CFUN=1")
        .expect("the ladder ran the pair");
    assert!(
        gap >= Duration::from_millis(3_000),
        "the only interval this pair has been measured with is 3s, got {gap:?}"
    );
    assert!(
        bench.pauses.contains(&Duration::from_millis(3_000)),
        "that gap should be a deliberate wait, not an accident of latency: {:?}",
        bench.pauses
    );
}

/// A healthy restart reads the card too, and carries the reading.
#[test]
fn a_restart_that_works_still_says_what_the_card_was_doing() {
    let mut bench = Bench::new(Ec20::default());

    let report = restart_radio(&mut bench).expect("a healthy module restarts");

    assert_eq!(report.card_after, Some(CardState::Ready));
    assert_eq!(report.card_evidence.inserted, Some(true));
    assert_eq!(report.card_evidence.init_status, Some(7));
    assert_eq!(
        bench.issued("AT+CPIN?"),
        1,
        "a card that is already up costs exactly one extra read"
    );
    // `+CFUN: 4` is radio off with the card still initialised, so the ordinary
    // low-power path never disturbs it and there is nothing to wait for.
    assert!(!bench.at_commands().contains(&"AT+CFUN=0".to_string()));
    assert!(report.to_string().contains("+CPIN: READY"));
}

/// The note has to carry both halves, like the reset one above: the thing that
/// has worked, and why the software will not do it.
#[test]
fn the_card_note_names_the_remedy_and_why_it_is_not_automatic() {
    assert!(CARD_RECOVERY_NOTE.contains("AT+CFUN=0"));
    assert!(CARD_RECOVERY_NOTE.contains("AT+CFUN=1"));
    assert!(CARD_RECOVERY_NOTE.contains("/api/at"));
    assert!(CARD_RECOVERY_NOTE.contains("will not issue it by itself"));
    assert!(
        CARD_RECOVERY_NOTE.contains("not an established mechanism"),
        "n=2 is a regularity, and the note has to say so"
    );
}

#[test]
fn card_answers_are_read_the_way_the_module_writes_them() {
    // The four the bench has actually produced, verbatim.
    assert_eq!(parse_cpin(&["+CPIN: READY".to_string()], "OK"), CardState::Ready);
    assert_eq!(parse_cpin(&[], "+CME ERROR: 14"), CardState::Initialising);
    assert_eq!(parse_cpin(&[], "+CME ERROR: 13"), CardState::Absent(13));
    assert_eq!(parse_cpin(&[], "+CME ERROR: 10"), CardState::Absent(10));
    // A lock is not a wait.
    assert_eq!(
        parse_cpin(&["+CPIN: SIM PIN".to_string()], "OK"),
        CardState::Locked("SIM PIN".to_string())
    );
    assert!(!CardState::Locked("SIM PUK".to_string()).waiting_can_help());
    assert!(CardState::Initialising.waiting_can_help());
    assert!(CardState::Absent(13).waiting_can_help(), "13 -> 14 -> READY has been watched happen");
    // Silence is not readiness.
    assert_eq!(parse_cpin(&[], ""), CardState::Unknown("no answer".to_string()));
    assert!(!parse_cpin(&[], "ERROR").is_ready());

    assert_eq!(parse_qsimstat(&["+QSIMSTAT: 0,1".to_string()]), Some(true));
    assert_eq!(parse_qsimstat(&["+QSIMSTAT: 0,0".to_string()]), Some(false));
    assert_eq!(parse_qsimstat(&["+CPIN: READY".to_string()]), None);
    assert_eq!(parse_qinistat(&["+QINISTAT: 7".to_string()]), Some(7));
    assert_eq!(parse_qinistat(&["+QINISTAT: 0".to_string()]), Some(0));
    assert_eq!(parse_qinistat(&[]), None);
}

fn failure_result_tlv(error: u16) -> Vec<u8> {
    let mut tlv = vec![0x02, 0x04, 0x00, 0x01, 0x00];
    tlv.extend_from_slice(&error.to_le_bytes());
    tlv
}
