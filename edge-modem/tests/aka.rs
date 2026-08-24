//! USIM AKA on the basic channel, and the local AT lease that rents the
//! serial port to the tunnel process.
//!
//! The cases here are the ones the bench can produce or the card is specified
//! to produce. The one that matters most is `9862`: with a synthetic AUTN
//! that is the *correct* answer from a working card, and telling it apart
//! from a broken pipe (`6E00`, `6D00`, `6A81`) is the entire difference
//! between "reject this challenge and move on" and "the module is gone".

use std::sync::Mutex;
use std::time::Duration;

use edge_modem::{
    authenticate_apdu, classify_authenticate, csim_command, decode_hex, handle_lease_request,
    hex_upper, parse_csim_answer, selected_aid, usim_authenticate, verify_usim_selected, AkaError,
    AkaOutcome, ApduResponse, AtExchange, AtLease, BasicChannel, LeaseFailure, ModemPriority,
    STATUS_FCP_APDU, USIM_ADF_AID_PREFIX,
};

/// The FCP shape `AT+CSIM=10,"00F2000000"` answers with when the USIM ADF is
/// selected on the basic channel: file descriptor, file id, then tag `84`
/// carrying the AID whose first seven bytes are the 3GPP USIM application.
const USIM_FCP: &str = "621A8202782183027FD08410A0000000871002FFFFFFFF8907090000";

/// The same FCP with an ISIM AID (`...1004`). Same card, wrong application:
/// authenticating here would use a different security context and produce
/// keys that the ePDG will reject for reasons nothing in our logs explains.
const ISIM_FCP: &str = "621A8202782183027FD08410A0000000871004FFFFFFFF8907090000";

struct Card {
    answers: Mutex<Vec<ApduResponse>>,
    sent: Mutex<Vec<Vec<u8>>>,
}

impl Card {
    fn new(answers: Vec<ApduResponse>) -> Self {
        Self {
            answers: Mutex::new(answers),
            sent: Mutex::new(Vec::new()),
        }
    }

    /// A card whose FCP says USIM, then one AUTHENTICATE answer.
    fn usim_then(answer: ApduResponse) -> Self {
        Self::new(vec![fcp_answer(USIM_FCP), answer])
    }

    fn sent(&self) -> Vec<Vec<u8>> {
        self.sent.lock().expect("sent").clone()
    }
}

impl BasicChannel for &Card {
    fn transmit(&mut self, apdu: &[u8]) -> Result<ApduResponse, AkaError> {
        self.sent.lock().expect("sent").push(apdu.to_vec());
        let mut answers = self.answers.lock().expect("answers");
        if answers.is_empty() {
            return Err(AkaError::Transport("card ran out of answers".into()));
        }
        Ok(answers.remove(0))
    }
}

fn fcp_answer(hex: &str) -> ApduResponse {
    ApduResponse {
        data: decode_hex(hex).expect("fcp hex"),
        sw1: 0x90,
        sw2: 0x00,
    }
}

fn answer(hex: &str, sw1: u8, sw2: u8) -> ApduResponse {
    ApduResponse {
        data: decode_hex(hex).expect("body hex"),
        sw1,
        sw2,
    }
}

fn rand16() -> Vec<u8> {
    decode_hex("000102030405060708090A0B0C0D0E0F").expect("rand")
}

fn autn16() -> Vec<u8> {
    decode_hex("101112131415161718191A1B1C1D1E1F").expect("autn")
}

#[test]
fn the_apdu_is_the_one_the_bench_answered() {
    let apdu = authenticate_apdu(&rand16(), &autn16(), true).expect("apdu");
    assert_eq!(
        hex_upper(&apdu),
        "0088008122\
         10000102030405060708090A0B0C0D0E0F\
         10101112131415161718191A1B1C1D1E1F\
         00"
        .replace(' ', "")
    );
    // 40 bytes is 80 hex characters, which is the length T033 recorded.
    assert_eq!(csim_command(&apdu).split(',').next(), Some("AT+CSIM=80"));
}

#[test]
fn a_challenge_that_is_not_sixteen_bytes_never_reaches_the_card() {
    let error = authenticate_apdu(&[0u8; 8], &autn16(), true).unwrap_err();
    assert_eq!(error.code(), "bad_challenge_length");
}

#[test]
fn the_selected_application_is_checked_before_authenticate() {
    let card = Card::usim_then(answer("", 0x98, 0x62));
    let outcome = usim_authenticate(&mut &card, &rand16(), &autn16()).expect("outcome");
    let sent = card.sent();
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert_eq!(sent[0], STATUS_FCP_APDU.to_vec());
    assert_eq!(&sent[1][..5], &[0x00, 0x88, 0x00, 0x81, 0x22]);
    assert!(matches!(outcome, AkaOutcome::AuthenticationFailure { .. }));
}

#[test]
fn a_card_with_isim_selected_is_refused_without_authenticating() {
    let card = Card::new(vec![fcp_answer(ISIM_FCP)]);
    let error = usim_authenticate(&mut &card, &rand16(), &autn16()).unwrap_err();
    assert_eq!(error.code(), "not_usim_adf");
    assert_eq!(card.sent(), vec![STATUS_FCP_APDU.to_vec()]);
}

#[test]
fn an_fcp_without_tag_84_is_refused_without_authenticating() {
    let card = Card::new(vec![fcp_answer("62088202782183027FD0")]);
    let error = usim_authenticate(&mut &card, &rand16(), &autn16()).unwrap_err();
    assert_eq!(error.code(), "no_selected_application");
    assert_eq!(card.sent().len(), 1);
}

#[test]
fn a_status_the_card_refuses_is_not_treated_as_selection() {
    let card = Card::new(vec![answer("", 0x6d, 0x00)]);
    let error = verify_usim_selected(&mut &card).unwrap_err();
    assert_eq!(error.code(), "status_refused");
}

#[test]
fn the_usim_aid_prefix_is_what_the_check_matches() {
    let aid = selected_aid(&decode_hex(USIM_FCP).expect("fcp")).expect("aid");
    assert!(aid.starts_with(&USIM_ADF_AID_PREFIX));
    assert_eq!(aid.len(), 16);
}

#[test]
fn nine_eight_six_two_is_a_named_rejection_not_an_opaque_error() {
    let outcome = classify_authenticate(&answer("", 0x98, 0x62)).expect("classified");
    match outcome {
        AkaOutcome::AuthenticationFailure { sw1, sw2, detail } => {
            assert_eq!((sw1, sw2), (0x98, 0x62));
            assert!(detail.contains("MAC"), "{detail}");
        }
        other => panic!("9862 became {other:?}"),
    }
}

#[test]
fn a_broken_pipe_is_not_a_rejection() {
    // What a module answers when the APDU never reached a card at all. If
    // these were folded into "authentication failed" the tunnel stack would
    // send an Authentication-Reject for a hardware fault and keep doing it.
    for (sw1, sw2) in [(0x6eu8, 0x00u8), (0x6d, 0x00), (0x6a, 0x81)] {
        let error = classify_authenticate(&answer("", sw1, sw2)).unwrap_err();
        assert_eq!(error.code(), "unknown_status_word");
    }
}

#[test]
fn nine_eight_six_four_is_reported_raw_rather_than_guessed() {
    // Every mapping we could find for 9864 traces back to the same unsourced
    // table. Reporting the bytes is the honest answer; inventing a class here
    // would make a wrong protocol decision look authoritative.
    let error = classify_authenticate(&answer("ABCD", 0x98, 0x64)).unwrap_err();
    match error {
        AkaError::UnknownStatusWord { sw1, sw2, body } => {
            assert_eq!((sw1, sw2), (0x98, 0x64));
            assert_eq!(body, "ABCD");
        }
        other => panic!("9864 became {other:?}"),
    }
}

#[test]
fn a_successful_challenge_yields_res_ck_ik() {
    let body = format!(
        "DB08{}10{}10{}",
        "1122334455667788",
        "00112233445566778899AABBCCDDEEFF",
        "FFEEDDCCBBAA99887766554433221100"
    );
    let outcome = classify_authenticate(&answer(&body, 0x90, 0x00)).expect("classified");
    match outcome {
        AkaOutcome::Success { res, ck, ik, kc } => {
            assert_eq!(hex_upper(&res), "1122334455667788");
            assert_eq!(hex_upper(&ck), "00112233445566778899AABBCCDDEEFF");
            assert_eq!(hex_upper(&ik), "FFEEDDCCBBAA99887766554433221100");
            assert_eq!(kc, None);
        }
        other => panic!("DB became {other:?}"),
    }
}

#[test]
fn a_card_that_appends_kc_still_parses() {
    let body = format!(
        "DB08{}10{}10{}08{}",
        "1122334455667788",
        "00112233445566778899AABBCCDDEEFF",
        "FFEEDDCCBBAA99887766554433221100",
        "0102030405060708"
    );
    match classify_authenticate(&answer(&body, 0x90, 0x00)).expect("classified") {
        AkaOutcome::Success { kc, .. } => {
            assert_eq!(kc.as_deref().map(hex_upper).as_deref(), Some("0102030405060708"))
        }
        other => panic!("DB with Kc became {other:?}"),
    }
}

#[test]
fn a_sync_failure_carries_auts() {
    let body = "DC0E0102030405060708090A0B0C0D0E";
    match classify_authenticate(&answer(body, 0x90, 0x00)).expect("classified") {
        AkaOutcome::SyncFailure { auts } => {
            assert_eq!(hex_upper(&auts), "0102030405060708090A0B0C0D0E")
        }
        other => panic!("DC became {other:?}"),
    }
}

#[test]
fn a_truncated_success_body_is_malformed_not_a_key() {
    let error = classify_authenticate(&answer("DB081122334455", 0x90, 0x00)).unwrap_err();
    assert_eq!(error.code(), "malformed_response");
}

#[test]
fn sixty_one_xx_is_collected_before_the_body_is_read() {
    // A basic-channel AUTHENTICATE that answers `61 2C` has said nothing yet;
    // classifying that as a failure would turn every successful challenge on
    // a card that behaves this way into a rejection.
    let body = format!(
        "DB08{}10{}10{}",
        "1122334455667788",
        "00112233445566778899AABBCCDDEEFF",
        "FFEEDDCCBBAA99887766554433221100"
    );
    let card = Card::new(vec![
        fcp_answer(USIM_FCP),
        answer("", 0x61, 0x2c),
        answer(&body, 0x90, 0x00),
    ]);
    let outcome = usim_authenticate(&mut &card, &rand16(), &autn16()).expect("outcome");
    assert!(matches!(outcome, AkaOutcome::Success { .. }));
    let sent = card.sent();
    assert_eq!(sent[2], vec![0x00, 0xc0, 0x00, 0x00, 0x2c]);
}

#[test]
fn six_c_xx_is_retried_with_the_length_the_card_asked_for() {
    let card = Card::new(vec![
        fcp_answer(USIM_FCP),
        answer("", 0x6c, 0x24),
        answer("", 0x98, 0x62),
    ]);
    let outcome = usim_authenticate(&mut &card, &rand16(), &autn16()).expect("outcome");
    assert!(matches!(outcome, AkaOutcome::AuthenticationFailure { .. }));
    let sent = card.sent();
    assert_eq!(sent.len(), 3);
    assert_eq!(*sent[2].last().expect("le"), 0x24);
    assert_eq!(&sent[2][..sent[2].len() - 1], &sent[1][..sent[1].len() - 1]);
}

#[test]
fn a_csim_answer_splits_body_from_status_word() {
    let response = parse_csim_answer(&["+CSIM: 4,\"9862\"".to_string()]).expect("parsed");
    assert_eq!(response.sw1, 0x98);
    assert_eq!(response.sw2, 0x62);
    assert!(response.data.is_empty());

    let response = parse_csim_answer(&["+CSIM: 8,\"DEAD9000\"".to_string()]).expect("parsed");
    assert_eq!(hex_upper(&response.data), "DEAD");
    assert!(response.is_success());
}

#[test]
fn a_csim_answer_that_is_not_hex_is_named() {
    let error = parse_csim_answer(&["+CSIM: 4,\"zzzz\"".to_string()]).unwrap_err();
    assert_eq!(error.code(), "malformed_csim");
    let error = parse_csim_answer(&["OK".to_string()]).unwrap_err();
    assert_eq!(error.code(), "malformed_csim");
}

// ---------------------------------------------------------------------------
// The local lease
// ---------------------------------------------------------------------------

struct BenchLease;

impl AtLease for BenchLease {
    fn execute(
        &self,
        _imei: Option<&str>,
        command: &str,
        _timeout: Duration,
        _priority: ModemPriority,
    ) -> Result<AtExchange, LeaseFailure> {
        Ok(AtExchange {
            command: command.to_string(),
            lines: vec!["Quectel".into(), "EC20F".into()],
            terminator: "OK".into(),
            elapsed: Duration::from_millis(3),
        })
    }

    fn authenticate(
        &self,
        _imei: Option<&str>,
        rand16: &[u8],
        autn16: &[u8],
    ) -> Result<AkaOutcome, LeaseFailure> {
        assert_eq!(rand16.len(), 16);
        assert_eq!(autn16.len(), 16);
        Ok(AkaOutcome::AuthenticationFailure {
            sw1: 0x98,
            sw2: 0x62,
            detail: "card rejected the challenge: incorrect MAC (SW 9862)",
        })
    }
}

#[test]
fn the_lease_refuses_a_request_it_does_not_understand() {
    for line in [
        "not json",
        "{}",
        "{\"op\":\"reboot\"}",
        "{\"op\":\"execute_at\"}",
        "{\"op\":\"execute_at\",\"command\":\"ATI\",\"timeout_ms\":0}",
        "{\"op\":\"execute_at\",\"command\":\"ATI\",\"priority\":\"urgent\"}",
    ] {
        let response = handle_lease_request(&BenchLease, line);
        let value: serde_json::Value = serde_json::from_str(&response).expect("json");
        assert_eq!(value["ok"], serde_json::json!(false), "{line} -> {response}");
        assert_eq!(value["error"], serde_json::json!("bad_request"), "{line}");
    }
}

#[cfg(unix)]
mod socket {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;

    use edge_modem::{bind_lease_socket, serve_lease};

    /// The lease over a real socket, because the thing being claimed is that
    /// another process can reach it — and that only a process the filesystem
    /// allows can.
    #[test]
    fn a_local_client_can_run_a_command_and_a_challenge() {
        let path = std::env::temp_dir().join(format!(
            "vodoge-at-lease-{}-{}.sock",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_file(&path);
        let listener = bind_lease_socket(&path).expect("bind");

        let mode = std::fs::metadata(&path)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the lease is complete control of the module");

        std::thread::spawn(move || serve_lease(listener, Arc::new(BenchLease)));

        let stream = UnixStream::connect(&path).expect("connect");
        let mut writer = stream.try_clone().expect("clone");
        let mut reader = BufReader::new(stream);

        writeln!(writer, "{{\"op\":\"execute_at\",\"command\":\"ATI\"}}").expect("write");
        let mut line = String::new();
        reader.read_line(&mut line).expect("read");
        let value: serde_json::Value = serde_json::from_str(&line).expect("json");
        assert_eq!(value["ok"], serde_json::json!(true));
        assert_eq!(value["response"], serde_json::json!("Quectel\nEC20F\nOK"));

        line.clear();
        writeln!(
            writer,
            "{{\"op\":\"authenticate\",\"rand\":\"{}\",\"autn\":\"{}\"}}",
            "11".repeat(16),
            "22".repeat(16)
        )
        .expect("write");
        reader.read_line(&mut line).expect("read");
        let value: serde_json::Value = serde_json::from_str(&line).expect("json");
        assert_eq!(
            value["outcome"],
            serde_json::json!("authentication_failure")
        );
        assert_eq!(value["sw"], serde_json::json!("9862"));

        let _ = std::fs::remove_file(&path);
    }
}
