use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use edge_modem::{
    parse_cfun, restart_radio, ClientAllocationRequest, ModuleRadio, OperatingMode, QmiClient,
    QmiTransport, ServiceId, SessionError, CFUN_DISABLE_RF, CFUN_FULL, CFUN_OFFLINE,
    CFUN_RESET_NOTE, CTL_SYNC, GET_DEVICE_REV_ID, GET_DEVICE_SERIAL_NUMBERS, GET_MANUFACTURER,
    GET_MODEL_ID, GET_OPERATING_MODE, SET_OPERATING_MODE,
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

/// One EC20's radio state, shared by the QMI transport and the AT port.
///
/// Both live on the same stick, so they cannot be modelled as two independent
/// fakes: the whole point of reading `AT+CFUN?` after a QMI mode change is
/// that they are two views of one thing.
#[derive(Debug)]
struct Ec20 {
    /// What `AT+CFUN?` answers.
    cfun: u8,
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
    /// Make `QMI_DMS_GET_OPERATING_MODE` disagree with `AT+CFUN?`.
    qmi_mode_override: Option<OperatingMode>,
    /// Every mode asked for over QMI, in order.
    qmi_requests: Vec<OperatingMode>,
    /// Every AT command issued, verbatim.
    at_commands: Vec<String>,
}

impl Default for Ec20 {
    fn default() -> Self {
        Self {
            cfun: 1,
            offline_wedge: false,
            refuse_online: false,
            at_dead: false,
            at_cfun_refused: false,
            qmi_mode_override: None,
            qmi_requests: Vec::new(),
            at_commands: Vec::new(),
        }
    }
}

impl Ec20 {
    fn mode(&self) -> OperatingMode {
        if let Some(mode) = self.qmi_mode_override {
            return mode;
        }
        match self.cfun {
            1 => OperatingMode::Online,
            7 => OperatingMode::Offline,
            _ => OperatingMode::LowPower,
        }
    }

    /// `Err(error)` is a QMI result error code, not a transport failure.
    fn apply_mode(&mut self, mode: OperatingMode) -> Result<(), u16> {
        self.qmi_requests.push(mode);
        if self.offline_wedge {
            return Err(QMI_ERROR_NO_EFFECT);
        }
        match mode {
            OperatingMode::Offline => {
                self.cfun = 7;
                self.offline_wedge = true;
                Ok(())
            }
            OperatingMode::Online => {
                if self.refuse_online {
                    return Err(QMI_ERROR_NO_EFFECT);
                }
                self.cfun = 1;
                Ok(())
            }
            OperatingMode::LowPower => {
                self.cfun = 4;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn at(&mut self, command: &str) -> Result<Vec<String>, String> {
        self.at_commands.push(command.to_string());
        if self.at_dead {
            return Err("open /dev/ttyUSB2: No such device".to_string());
        }
        if command == "AT+CFUN?" {
            return Ok(vec![format!("+CFUN: {}", self.cfun)]);
        }
        Err(format!("this stand-in was not taught {command}"))
    }

    /// `Ok(false)` is `+CME ERROR: 4`, which is an answer and not a lost port.
    fn write_cfun(&mut self, value: u8) -> Result<bool, String> {
        self.at_commands.push(format!("AT+CFUN={value}"));
        if self.at_dead {
            return Err("open /dev/ttyUSB2: No such device".to_string());
        }
        if self.offline_wedge || self.at_cfun_refused {
            return Ok(false);
        }
        self.cfun = value;
        if value == 1 {
            // The radio really came up, so QMI stops refusing too.
            self.refuse_online = false;
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
    pauses: usize,
}

impl Bench {
    fn new(state: Ec20) -> Self {
        let state = Rc::new(RefCell::new(state));
        let mut client = QmiClient::new(SharedTransport(state.clone()));
        client.sync().expect("CTL sync");
        Self {
            client,
            state,
            pauses: 0,
        }
    }

    fn qmi_requests(&self) -> Vec<OperatingMode> {
        self.state.borrow().qmi_requests.clone()
    }

    fn at_commands(&self) -> Vec<String> {
        self.state.borrow().at_commands.clone()
    }

    fn cfun(&self) -> u8 {
        self.state.borrow().cfun
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

    fn pause(&mut self, _: Duration) {
        // Free here, real on hardware. Counted so a test can prove the ladder
        // does wait rather than hammering a module that is mid-transition.
        self.pauses += 1;
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
    assert!(bench.pauses > 0, "the ladder has to give the module time");
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

fn failure_result_tlv(error: u16) -> Vec<u8> {
    let mut tlv = vec![0x02, 0x04, 0x00, 0x01, 0x00];
    tlv.extend_from_slice(&error.to_le_bytes());
    tlv
}
