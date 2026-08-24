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

/// What `867018069514820` answered to `AT+CSIM=10,"00F2000000"` after a
/// profile switch (T072) — tag `83` = `3F00`, the MF, and no tag `84` at all.
/// This is the state in which AUTHENTICATE answers `6985`.
const MF_FCP: &str = "62208202782183023F00A5068001718701018A01058B032F0602C606900100830101";

/// The same MF state re-measured on 2026-08-25, reached with nothing more
/// exotic than `AT+CFUN=0` / `AT+CFUN=1`. The profile switch is *a* way into
/// this state, not the only one, which is why the repair cannot be left to
/// whoever remembers to switch profiles carefully.
const MF_FCP_AFTER_CFUN_CYCLE: &str =
    "62238202782183023F00A5068001718701018A01058B032F0602C60990014083010183010A";

/// The FCP `867018069514820` answers to the SELECT below: tag `84` carrying
/// the full, card-specific USIM AID whose first seven bytes are the prefix we
/// asked for.
const SELECTED_USIM_FCP: &str = "62308202782183027FD08410A0000000871002FFFFF00189000001FF\
8A01058B032F0602C60C9001A083018183010183010A";

/// The same, from `867018069509705` — a plain USIM, not an eUICC (`AT+CCHO`
/// against the ISD-R AID is a bare `ERROR` there). Different AID bytes after
/// the prefix, which is exactly why the SELECT asks for a partial name.
const NON_EUICC_USIM_FCP: &str =
    "6229820278218410A0000000871002FF86FFFF89FFFFFFFF8A01058B032F0603C609900140830101830181";

/// The repair APDU: SELECT by DF name, first or only occurrence, answer with
/// the FCP, data = the seven-byte USIM RID+PIX.
const SELECT_USIM_ADF: &str = "00A4040407A000000087100200";

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
fn a_card_that_stays_on_isim_is_refused_without_authenticating() {
    // The repair is allowed to try; the gate is not allowed to give in. A
    // card that answers the SELECT with an ISIM FCP has said "no USIM here",
    // and no challenge may be sent to it.
    let card = Card::new(vec![fcp_answer(ISIM_FCP), fcp_answer(ISIM_FCP)]);
    let error = usim_authenticate(&mut &card, &rand16(), &autn16()).unwrap_err();
    assert_eq!(error.code(), "not_usim_adf");
    let sent = card.sent();
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert_eq!(hex_upper(&sent[1]), SELECT_USIM_ADF);
    assert!(!sent.iter().any(|apdu| apdu[1] == 0x88), "{sent:?}");
}

#[test]
fn an_fcp_that_still_has_no_tag_84_after_the_select_is_refused() {
    let bare = "62088202782183027FD0";
    let card = Card::new(vec![fcp_answer(bare), fcp_answer(bare)]);
    let error = usim_authenticate(&mut &card, &rand16(), &autn16()).unwrap_err();
    assert_eq!(error.code(), "no_selected_application");
    let sent = card.sent();
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert!(!sent.iter().any(|apdu| apdu[1] == 0x88), "{sent:?}");
}

#[test]
fn a_card_sitting_at_the_mf_is_selected_rather_than_refused() {
    // T079's regression: after a profile switch the basic channel is on the
    // MF, and every challenge died at the gate with `no_selected_application`
    // even though the card was perfectly able to answer it.
    for mf in [MF_FCP, MF_FCP_AFTER_CFUN_CYCLE] {
        let card = Card::new(vec![
            fcp_answer(mf),
            fcp_answer(SELECTED_USIM_FCP),
            answer("", 0x98, 0x62),
        ]);
        let outcome = usim_authenticate(&mut &card, &rand16(), &autn16()).expect("outcome");
        assert!(
            matches!(outcome, AkaOutcome::AuthenticationFailure { .. }),
            "{outcome:?}"
        );
        let sent = card.sent();
        assert_eq!(sent.len(), 3, "{sent:?}");
        assert_eq!(sent[0], STATUS_FCP_APDU.to_vec());
        assert_eq!(hex_upper(&sent[1]), SELECT_USIM_ADF);
        assert_eq!(&sent[2][..5], &[0x00, 0x88, 0x00, 0x81, 0x22]);
    }
}

#[test]
fn the_select_never_reaches_a_card_that_is_already_on_the_usim() {
    // A card that is already on the USIM must not be re-selected: the repair
    // has to be free once it has run. Two runs in a row therefore cost two
    // APDUs each, and neither of them may be a SELECT. Measured on
    // 867018069514820 as 39.1 ms for the round that repairs and 29.6 / 30.0 ms
    // for the two after it.
    let card = Card::new(vec![
        fcp_answer(SELECTED_USIM_FCP),
        answer("", 0x98, 0x62),
        fcp_answer(SELECTED_USIM_FCP),
        answer("", 0x98, 0x62),
    ]);
    for _ in 0..2 {
        usim_authenticate(&mut &card, &rand16(), &autn16()).expect("outcome");
    }
    let sent = card.sent();
    assert_eq!(sent.len(), 4, "{sent:?}");
    assert!(!sent.iter().any(|apdu| apdu[1] == 0xa4), "{sent:?}");
}

#[test]
fn a_card_that_refuses_the_select_says_so_instead_of_authenticating() {
    let card = Card::new(vec![fcp_answer(MF_FCP), answer("", 0x6a, 0x82)]);
    let error = usim_authenticate(&mut &card, &rand16(), &autn16()).unwrap_err();
    assert_eq!(error.code(), "usim_select_refused");
    assert!(error.to_string().contains("6A82"), "{error}");
    let sent = card.sent();
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert!(!sent.iter().any(|apdu| apdu[1] == 0x88), "{sent:?}");
}

#[test]
fn a_card_that_will_not_answer_status_is_reached_through_the_select() {
    // 867018069509705 answers 6E00 to STATUS with P2 00, 01 and 0C alike,
    // while answering SELECT and AUTHENTICATE normally. Treating an unhelpful
    // STATUS as a dead end would refuse a card that can prove what it is.
    let card = Card::new(vec![
        answer("", 0x6e, 0x00),
        fcp_answer(NON_EUICC_USIM_FCP),
        answer("", 0x98, 0x62),
    ]);
    let outcome = usim_authenticate(&mut &card, &rand16(), &autn16()).expect("outcome");
    assert!(matches!(outcome, AkaOutcome::AuthenticationFailure { .. }));
    let sent = card.sent();
    assert_eq!(sent.len(), 3, "{sent:?}");
    assert_eq!(hex_upper(&sent[1]), SELECT_USIM_ADF);
}

#[test]
fn a_dead_pipe_is_not_answered_with_a_select() {
    // Nothing came back at all, so nothing is known about the card. Sending a
    // repair down a pipe that just failed adds a second failure and no
    // information.
    let card = Card::new(Vec::new());
    let error = usim_authenticate(&mut &card, &rand16(), &autn16()).unwrap_err();
    assert_eq!(error.code(), "at_transport_failed");
    assert_eq!(card.sent(), vec![STATUS_FCP_APDU.to_vec()]);
}

#[test]
fn the_bench_transcript_from_mf_to_a_verdict_replays() {
    // 2026-08-25 on 867018069514820, every byte measured through /api/at:
    // STATUS -> MF; AUTHENTICATE there answered 6985; SELECT -> 6132;
    // GET RESPONSE -> the USIM FCP; AUTHENTICATE -> 9862, the card running
    // Milenage. The 61xx round is part of the transcript because the SELECT
    // is the APDU that produces it.
    let card = Card::new(vec![
        fcp_answer(MF_FCP_AFTER_CFUN_CYCLE),
        answer("", 0x61, 0x32),
        fcp_answer(SELECTED_USIM_FCP),
        answer("", 0x98, 0x62),
    ]);
    let outcome = usim_authenticate(&mut &card, &rand16(), &autn16()).expect("outcome");
    match outcome {
        AkaOutcome::AuthenticationFailure { sw1, sw2, .. } => assert_eq!((sw1, sw2), (0x98, 0x62)),
        other => panic!("bench transcript became {other:?}"),
    }
    let sent = card.sent();
    assert_eq!(sent.len(), 4, "{sent:?}");
    assert_eq!(hex_upper(&sent[1]), SELECT_USIM_ADF);
    assert_eq!(sent[2], vec![0x00, 0xc0, 0x00, 0x00, 0x32]);
    assert_eq!(&sent[3][..5], &[0x00, 0x88, 0x00, 0x81, 0x22]);
}

#[test]
fn the_selected_aid_is_read_out_of_a_real_select_answer() {
    let aid = selected_aid(&decode_hex(NON_EUICC_USIM_FCP).expect("fcp")).expect("aid");
    assert!(aid.starts_with(&USIM_ADF_AID_PREFIX), "{}", hex_upper(&aid));
    assert_eq!(hex_upper(&aid), "A0000000871002FF86FFFF89FFFFFFFF");
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
