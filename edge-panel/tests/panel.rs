use std::sync::Arc;

use std::sync::Mutex;

use edge_panel::{
    router, router_with_actions, Actions, AtResult, LogRing, MemoryInbox, PanelError, ProfileBody,
    ProfilesResult, ReportResult, ScanResult, ScannedOperatorBody, UsbResetResult, UssdResult,
};
use edge_store::{LocalMessage, LocalModem};
use http_body_util::BodyExt;
use tower::ServiceExt;

/// Fetch the panel page the way a browser would.
async fn panel_page() -> String {
    let app = router(Arc::new(MemoryInbox::default()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

/// Drop HTML comments before scanning the markup.
///
/// The page documents the no-external-references rule in a comment, so a
/// scanner that reads inert text would be tripped by the rule's own
/// description. A comment cannot load anything, which is why ignoring it
/// costs the check nothing.
fn markup_without_comments(page: &str) -> String {
    let mut kept = String::with_capacity(page.len());
    let mut rest = page;
    while let Some(start) = rest.find("<!--") {
        kept.push_str(&rest[..start]);
        rest = match rest[start..].find("-->") {
            Some(end) => &rest[start + end + 3..],
            None => "",
        };
    }
    kept.push_str(rest);
    kept
}

/// Every `<name ...>` opening tag in the markup, as written.
fn opening_tags<'a>(markup: &'a str, name: &str) -> Vec<&'a str> {
    let needle = format!("<{name}");
    let mut found = Vec::new();
    let mut rest = markup;
    while let Some(start) = rest.find(&needle) {
        let tag = &rest[start..];
        let end = tag.find('>').map(|at| at + 1).unwrap_or(tag.len());
        found.push(&tag[..end]);
        rest = &tag[end..];
    }
    found
}

/// The panel must load nothing from anywhere.
///
/// It is served over the site LAN to a machine that may have no route to the
/// internet at all. A linked stylesheet or a CDN script is not a dependency
/// here, it is an outage: the operator standing next to a wedged modem would
/// get an unstyled page with no behaviour at exactly the moment the panel is
/// the only tool they have. This is the assertion that keeps that true after
/// somebody reaches for a charting library.
#[tokio::test]
async fn the_panel_loads_nothing_from_outside_itself() {
    let page = panel_page().await;
    let markup = markup_without_comments(&page).to_lowercase();

    for tag in opening_tags(&markup, "script") {
        assert!(!tag.contains("src="), "script loads something external: {tag}");
    }
    for tag in opening_tags(&markup, "link") {
        assert!(
            tag.contains("href=\"data:"),
            "link points somewhere other than an inline data: uri: {tag}"
        );
    }
    assert!(!markup.contains("@import"), "css imports another sheet");
    assert!(!markup.contains("src=\"//"), "protocol-relative script source");
    assert!(!markup.contains("href=\"//"), "protocol-relative link target");

    // Fonts, icons and images all have to be inline too, so every url() in the
    // stylesheets has to resolve to a data: uri.
    let mut scanned = 0;
    let mut rest = markup.as_str();
    while let Some(at) = rest.find("url(") {
        let argument = rest[at + 4..].trim_start_matches(['"', '\'']);
        assert!(
            argument.starts_with("data:"),
            "stylesheet fetches something: url({}…)",
            argument.chars().take(40).collect::<String>()
        );
        scanned += 1;
        rest = &rest[at + 4..];
    }
    assert!(scanned > 0, "no url() found at all, so this check measured nothing");
}

/// The rule above is trivially satisfiable by shipping no framework, so this
/// asserts the frameworks are in fact there — inlined rather than dropped.
#[tokio::test]
async fn the_panel_carries_its_framework_inline() {
    let page = panel_page().await;
    assert!(page.contains("id=\"vendor-pico\""), "no inline Pico block");
    assert!(page.contains("Pico CSS"), "Pico's own banner is missing");
    assert!(page.contains("--pico-background-color"), "Pico's variables are missing");
    assert!(page.contains("id=\"vendor-alpine\""), "no inline Alpine block");
    assert!(page.contains("_x_dataStack"), "Alpine's runtime is missing");
    assert!(page.contains("alpine:init"), "the panel never registers its component");
    // Alpine self-starts, so the component has to be registered before it runs.
    let component = page.find("id=\"panel-script\"").expect("panel script");
    let alpine = page.find("id=\"vendor-alpine\"").expect("alpine script");
    assert!(component < alpine, "Alpine starts before the panel registers its component");
}

/// Reshaping the page must not quietly orphan an endpoint.
///
/// `/api/restart` is deliberately absent: it had no caller in the panel before
/// this layout either, so wiring one would be adding an action rather than
/// moving one. It is reported rather than invented here.
#[tokio::test]
async fn every_endpoint_the_panel_used_is_still_reachable_from_the_page() {
    let page = panel_page().await;
    for endpoint in [
        "/api/status",
        "/api/logs",
        "/api/messages",
        "/api/send",
        "/api/at",
        "/api/report",
        "/api/esim",
        "/api/esim/switch",
        "/api/scan",
        "/api/ussd",
        "/api/ussd/cancel",
        "/api/radio",
        "/api/usb-reset",
    ] {
        assert!(page.contains(endpoint), "nothing on the page calls {endpoint}");
    }
}

/// A section that has not been restyled yet has to say which card restyles it.
/// A placeholder that just says "coming soon" is how a migration loses a
/// feature without anybody noticing it went.
#[tokio::test]
async fn sections_awaiting_their_own_card_say_which_card_that_is() {
    let page = panel_page().await;
    for card in ["T004", "T005", "T006"] {
        assert!(page.contains(card), "no section points at {card}");
    }
}

/// The process-wide log ring is shared by every test in this binary, so the two
/// tests that write to it take turns. Without this, the six hundred lines one
/// of them pushes evict the single line the other is looking for.
static LOG_RING_TURN: Mutex<()> = Mutex::new(());

/// Read the panel's `/api/logs` the way the column does.
async fn read_logs(after: u64) -> serde_json::Value {
    let app = router(Arc::new(MemoryInbox::default()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri(format!("/api/logs?after={after}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

/// Pull an integer constant out of the page's script.
fn constant(page: &str, name: &str) -> u64 {
    let needle = format!("const {name} = ");
    let at = page
        .find(&needle)
        .unwrap_or_else(|| panic!("the page defines no {name}"));
    page[at + needle.len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '_')
        .filter(|c| *c != '_')
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("{name} is not a number"))
}

/// The premise the whole log column rests on: a served line carries a sequence
/// number, a timestamp and text, and nothing else.
///
/// `log_line` and `log_error` push into the same ring and the distinction is
/// dropped there, so severity, which module a line is about and which endpoint
/// produced it are all absent from the wire. The column therefore infers them
/// from the text. If this ever stops being true — if `logs.rs` grows a `level`
/// — this test fails and says so, which is the signal to delete the guessing
/// rather than to leave two sources of truth disagreeing.
#[tokio::test]
async fn a_served_log_line_carries_no_level_module_or_endpoint() {
    let _turn = LOG_RING_TURN.lock().unwrap_or_else(|held| held.into_inner());
    let marker = "panel-test-marker line for the shape assertion";
    LogRing::global().push(marker);

    let body = read_logs(0).await;
    let line = body["lines"]
        .as_array()
        .expect("lines")
        .iter()
        .find(|line| line["text"] == marker)
        .expect("the line just pushed is not in the ring");

    let mut fields: Vec<&str> = line
        .as_object()
        .expect("a line is an object")
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        ["at", "seq", "text"],
        "the served shape changed; the column's inferred level/module/source \
         should be replaced by the real field instead of layered on top"
    );
}

/// The panel must hold more history than the server does.
///
/// The ring keeps 500 lines. Measured on this fleet, the daemon prints about
/// 17.7 lines a minute with nothing wrong, so 500 lines is a 28-minute window:
/// once the panel has been open longer than that, its own buffer is the only
/// longer record that exists anywhere. A retention cap at or below the ring's
/// would make the buffer pointless.
#[tokio::test]
async fn the_column_retains_more_than_the_server_ring_does() {
    let _turn = LOG_RING_TURN.lock().unwrap_or_else(|held| held.into_inner());
    let ring = LogRing::global();
    for index in 0..600 {
        ring.push(format!("ring capacity probe {index}"));
    }
    let served = read_logs(0).await;
    let held = served["lines"].as_array().expect("lines").len();
    assert_eq!(held, 500, "the server ring no longer holds 500 lines");

    let page = panel_page().await;
    let keep = constant(&page, "LOG_KEEP");
    let render = constant(&page, "LOG_RENDER");
    assert!(
        keep > held as u64,
        "the column keeps {keep} lines but the server already holds {held}"
    );
    // Retaining and drawing are capped separately because their costs are
    // different: a retained line is a small object, a drawn one is four DOM
    // nodes and layout. Collapsing the two would either shrink how far a
    // search reaches or paint thousands of rows nobody asked for.
    assert!(
        render < keep,
        "the drawn cap ({render}) is not below the retained cap ({keep})"
    );
}

/// The column is a cursor poll, and has to keep saying so.
///
/// A log pane that looks like a tail and is not one is worse than an obviously
/// periodic one: the operator reads "nothing new" as "nothing happened" when it
/// may only mean the last request never came back.
#[tokio::test]
async fn the_log_column_admits_it_is_polling_rather_than_tailing() {
    let page = panel_page().await;
    assert!(page.contains("/api/logs?after="), "no cursor poll on the page");
    assert!(page.contains("s 轮询'"), "the poll interval is not on screen");
    assert!(page.contains("'刷新于 '"), "the last refresh time is not on screen");
    assert!(page.contains("logPollFailed"), "a failed poll is not reported");
    assert!(
        page.contains("不是推送流"),
        "the column does not say it is not a stream"
    );
}

/// Everything this card promised, pinned to the thing that implements it.
///
/// These are markers rather than wording: the copy will keep changing and the
/// mechanism should not.
#[tokio::test]
async fn the_log_column_has_what_a_debugging_log_needs() {
    let page = panel_page().await;
    for (feature, marker) in [
        ("level colouring", "log-row.lvl-err"),
        ("level filtering", "logLevels[level.key]"),
        ("level counts", "logCounts["),
        ("filter by module", "x-model=\"logImei\""),
        ("filter by source", "x-model=\"logTopic\""),
        ("search", "x-model=\"logQuery\""),
        ("search highlighting", "log-row mark"),
        ("walking the hits", "stepMatch("),
        ("pause and resume", "togglePause()"),
        ("copy one line", "className = \"log-copy\""),
        ("copy without a secure context", "execCommand(\"copy\")"),
        ("arrival cue", "@keyframes log-arrive"),
        ("arrival cue is applied to the new rows", "classList.add(\"is-new\")"),
        ("arrival cue while scrolled away", "logNewErr"),
        ("quieting the heartbeat", "logQuiet = !logQuiet"),
        // Only the `ok` form: folding in the `at-only` sibling would let
        // "静音" hide a module that answered over serial after QMI did not.
        ("the heartbeat is only the ok form", "imei=\\d+ ok$/i"),
        ("eviction is reported", "已丢弃最旧"),
    ] {
        assert!(page.contains(marker), "{feature} is missing: no {marker}");
    }
}

/// The inferred fields have to be labelled as inferred where they are used.
///
/// Colouring a line red on a guess is defensible; letting an operator believe
/// the daemon called it an error is not, because they will trust it in the one
/// case where the guess is wrong.
#[tokio::test]
async fn the_column_says_the_level_and_source_are_inferred() {
    let page = panel_page().await;
    assert!(
        page.contains("没有级别字段"),
        "the level control does not admit the level is inferred"
    );
    assert!(
        page.contains("日志里没有 /api 端点字段"),
        "the source control does not admit an endpoint is not in the data"
    );
}

#[tokio::test]
async fn panel_serves_embedded_html_and_local_json() {
    let inbox = Arc::new(MemoryInbox {
        messages: vec![LocalMessage {
            seq: 1,
            peer: "10086".into(),
            body: "hello".into(),
            bearer: "cellular".into(),
            direction: "inbound".into(),
            received_at: 1_700_000_000_000,
            modem_imei: Some("867018069509705".into()),
        }],
        modems: vec![LocalModem {
            imei: "867018069509705".into(),
            family: "EC20".into(),
            iccid: None,
            state: "registered".into(),
            last_seen: Some(1_700_000_000_000),
            mcc: Some(460),
            mnc: Some(0),
        home_mcc: None,
        home_mnc: None,
        imsi: None,
        }],
    });
    let app = router(inbox);

    let html = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(html.status(), 200);
    let page = String::from_utf8(html.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    // Assert on the endpoints and mount points the page is built around rather
    // than on its wording, which is copy and will keep changing.
    assert!(page.contains("/api/messages"));
    assert!(page.contains("/api/status"));
    assert!(page.contains("/api/at"));
    assert!(page.contains("x-ref=\"cmd\""));
    assert!(page.contains("/api/report"));
    assert!(page.contains("/api/logs"));

    let status = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/status")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), 200);
    let status_json: serde_json::Value =
        serde_json::from_slice(&status.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(status_json["mode"], "local");
    assert_eq!(status_json["modems"][0]["family"], "EC20");

    let messages = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/messages")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let inbox_json: serde_json::Value =
        serde_json::from_slice(&messages.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(inbox_json["messages"][0]["body"], "hello");
}

struct RecordingActions {
    sent: Mutex<Vec<(String, String)>>,
    at: Mutex<Vec<String>>,
    switched: Mutex<Vec<(String, bool)>>,
    ussd: Mutex<Vec<String>>,
    radio: Mutex<Vec<bool>>,
}

impl RecordingActions {
    fn new() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            at: Mutex::new(Vec::new()),
            switched: Mutex::new(Vec::new()),
            ussd: Mutex::new(Vec::new()),
            radio: Mutex::new(Vec::new()),
        }
    }
}

impl Actions for RecordingActions {
    fn send_sms(&self, to: String, body: String, _imei: Option<String>) -> Result<(), PanelError> {
        self.sent.lock().expect("sent").push((to, body));
        Ok(())
    }

    fn restart_modem(&self, _imei: String) -> Result<(), PanelError> {
        Ok(())
    }

    fn at_command(&self, _imei: Option<String>, command: String) -> Result<AtResult, PanelError> {
        self.at.lock().expect("at").push(command.clone());
        Ok(AtResult {
            port: "/dev/ttyUSB2".into(),
            command,
            lines: vec!["+CSQ: 24,99".into()],
            terminator: "OK".into(),
            ok: true,
            elapsed_ms: 7,
        })
    }

    fn usb_reset(&self, _imei: Option<String>) -> Result<UsbResetResult, PanelError> {
        Ok(UsbResetResult {
            device: "2-4.1".into(),
            node: "/dev/bus/usb/002/052".into(),
        })
    }

    fn modem_report(&self, imei: Option<String>) -> Result<ReportResult, PanelError> {
        Ok(ReportResult {
            imei,
            port: "/dev/ttyUSB2".into(),
            signal_dbm: Some(-65),
            operator: Some("CHN-UNICOM".into()),
            ..ReportResult::default()
        })
    }

    fn list_profiles(&self, imei: Option<String>) -> Result<ProfilesResult, PanelError> {
        Ok(ProfilesResult {
            imei,
            profiles: vec![ProfileBody {
                iccid: "89852351225042214201".into(),
                label: "WEBBING".into(),
                enabled: true,
                provider: Some("Saily".into()),
                name: Some("WEBBING".into()),
                nickname: None,
                class: Some(2),
                isdp_aid: None,
            }],
        })
    }

    fn switch_profile(
        &self,
        _imei: Option<String>,
        iccid: String,
        enable: bool,
    ) -> Result<(), PanelError> {
        self.switched.lock().expect("switched").push((iccid, enable));
        Ok(())
    }

    fn scan_operators(&self, imei: Option<String>) -> Result<ScanResult, PanelError> {
        Ok(ScanResult {
            imei,
            elapsed_ms: 42_000,
            operators: vec![ScannedOperatorBody {
                numeric: "46001".into(),
                long_name: "CHN-UNICOM".into(),
                short_name: "UNICOM".into(),
                status: "current".into(),
                access_technology: Some("LTE".into()),
            }],
        })
    }

    fn ussd(&self, _imei: Option<String>, code: String) -> Result<UssdResult, PanelError> {
        self.ussd.lock().expect("ussd").push(code.clone());
        Ok(UssdResult {
            code,
            stage: "complete".into(),
            text: "余额 12.30".into(),
            dcs: Some(72),
            expects_reply: false,
            elapsed_ms: 3200,
        })
    }

    fn ussd_cancel(&self, _imei: Option<String>) -> Result<(), PanelError> {
        Ok(())
    }

    fn set_radio(&self, _imei: Option<String>, online: bool) -> Result<(), PanelError> {
        self.radio.lock().expect("radio").push(online);
        Ok(())
    }
}

#[tokio::test]
async fn panel_sends_sms_locally() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/send")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"to":"10086","body":"hi"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        actions.sent.lock().expect("sent").as_slice(),
        &[("10086".into(), "hi".into())]
    );
}

#[tokio::test]
async fn panel_runs_an_at_command() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/at")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"command":"AT+CSQ"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["terminator"], "OK");
    assert_eq!(body["lines"][0], "+CSQ: 24,99");
    assert_eq!(actions.at.lock().expect("at").as_slice(), &["AT+CSQ"]);
}

/// A module that answers `+CME ERROR` has answered. The console must show that
/// as the module's reply, not as a transport failure.
#[tokio::test]
async fn panel_reports_a_rejected_at_command_as_a_reply() {
    struct Rejecting;
    impl Actions for Rejecting {
        fn send_sms(&self, _: String, _: String, _: Option<String>) -> Result<(), PanelError> {
            Ok(())
        }
        fn restart_modem(&self, _: String) -> Result<(), PanelError> {
            Ok(())
        }
        fn at_command(&self, _: Option<String>, command: String) -> Result<AtResult, PanelError> {
            Ok(AtResult {
                port: "/dev/ttyUSB2".into(),
                command,
                lines: Vec::new(),
                terminator: "+CME ERROR: 10".into(),
                ok: false,
                elapsed_ms: 3,
            })
        }

        fn usb_reset(&self, _imei: Option<String>) -> Result<UsbResetResult, PanelError> {
            Ok(UsbResetResult {
                device: "2-4.1".into(),
                node: "/dev/bus/usb/002/052".into(),
            })
        }

        fn modem_report(&self, _: Option<String>) -> Result<ReportResult, PanelError> {
            Ok(ReportResult::default())
        }

        fn list_profiles(&self, imei: Option<String>) -> Result<ProfilesResult, PanelError> {
            Ok(ProfilesResult {
                imei,
                profiles: Vec::new(),
            })
        }

        fn switch_profile(&self, _: Option<String>, _: String, _: bool) -> Result<(), PanelError> {
            Ok(())
        }

        fn scan_operators(&self, imei: Option<String>) -> Result<ScanResult, PanelError> {
            Ok(ScanResult {
                imei,
                elapsed_ms: 0,
                operators: Vec::new(),
            })
        }

        fn ussd(&self, _: Option<String>, code: String) -> Result<UssdResult, PanelError> {
            Ok(UssdResult {
                code,
                stage: "complete".into(),
                text: String::new(),
                dcs: None,
                expects_reply: false,
                elapsed_ms: 0,
            })
        }

        fn ussd_cancel(&self, _: Option<String>) -> Result<(), PanelError> {
            Ok(())
        }
        fn set_radio(&self, _: Option<String>, _: bool) -> Result<(), PanelError> {
            Ok(())
        }
    }

    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(Arc::new(Rejecting)));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/at")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"command":"AT+CPIN?"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["terminator"], "+CME ERROR: 10");
}

#[tokio::test]
async fn panel_rejects_an_empty_at_command() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/at")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"command":"   "}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(actions.at.lock().expect("at").is_empty());
}

#[tokio::test]
async fn panel_reports_modem_diagnostics() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/report")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"imei":"867018069514820"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["imei"], "867018069514820");
    assert_eq!(body["signal_dbm"], -65);
    assert_eq!(body["operator"], "CHN-UNICOM");
}

#[tokio::test]
async fn panel_lists_euicc_profiles() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/esim")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"imei":"867018069514820"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["profiles"][0]["label"], "WEBBING");
    assert_eq!(body["profiles"][0]["enabled"], true);
}

#[tokio::test]
async fn panel_switches_a_profile_by_iccid() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/esim/switch")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"iccid":"89852351225042214201","enable":true}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        actions.switched.lock().expect("switched").as_slice(),
        &[("89852351225042214201".to_string(), true)]
    );
}

/// Switching takes the modem off its network, so an unnamed profile must be
/// refused rather than guessed at.
#[tokio::test]
async fn panel_refuses_a_switch_without_an_iccid() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/esim/switch")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"iccid":"  ","enable":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(actions.switched.lock().expect("switched").is_empty());
}

#[tokio::test]
async fn panel_scans_for_operators() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/scan")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"imei":"867018069514820"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["operators"][0]["numeric"], "46001");
    assert_eq!(body["operators"][0]["status"], "current");
}

/// A modem mid-scan stops answering the poll loop for longer than the
/// staleness window. Reporting that as offline sends the operator looking for
/// a fault that is not there.
#[tokio::test]
async fn panel_reports_a_busy_modem_as_busy_not_offline() {
    struct Busy;
    impl Actions for Busy {
        fn send_sms(&self, _: String, _: String, _: Option<String>) -> Result<(), PanelError> {
            Ok(())
        }
        fn restart_modem(&self, _: String) -> Result<(), PanelError> {
            Ok(())
        }
        fn at_command(&self, _: Option<String>, command: String) -> Result<AtResult, PanelError> {
            Ok(AtResult {
                port: "/dev/ttyUSB2".into(),
                command,
                lines: Vec::new(),
                terminator: "OK".into(),
                ok: true,
                elapsed_ms: 1,
            })
        }
        fn usb_reset(&self, _: Option<String>) -> Result<UsbResetResult, PanelError> {
            Ok(UsbResetResult {
                device: "2-4.1".into(),
                node: "/dev/bus/usb/002/052".into(),
            })
        }
        fn modem_report(&self, _: Option<String>) -> Result<ReportResult, PanelError> {
            Ok(ReportResult::default())
        }
        fn list_profiles(&self, imei: Option<String>) -> Result<ProfilesResult, PanelError> {
            Ok(ProfilesResult {
                imei,
                profiles: Vec::new(),
            })
        }
        fn switch_profile(&self, _: Option<String>, _: String, _: bool) -> Result<(), PanelError> {
            Ok(())
        }
        fn scan_operators(&self, imei: Option<String>) -> Result<ScanResult, PanelError> {
            Ok(ScanResult {
                imei,
                elapsed_ms: 0,
                operators: Vec::new(),
            })
        }
        fn ussd(&self, _: Option<String>, code: String) -> Result<UssdResult, PanelError> {
            Ok(UssdResult {
                code,
                stage: "complete".into(),
                text: String::new(),
                dcs: None,
                expects_reply: false,
                elapsed_ms: 0,
            })
        }

        fn ussd_cancel(&self, _: Option<String>) -> Result<(), PanelError> {
            Ok(())
        }
        fn set_radio(&self, _: Option<String>, _: bool) -> Result<(), PanelError> {
            Ok(())
        }

        fn busy_modems(&self) -> Vec<String> {
            vec!["867018069509705".into()]
        }
    }

    // last_seen far in the past, so without the busy marker this is "Offline".
    let inbox = Arc::new(MemoryInbox {
        messages: Vec::new(),
        modems: vec![LocalModem {
            imei: "867018069509705".into(),
            family: "EC20".into(),
            iccid: None,
            state: "Registered".into(),
            last_seen: Some(1_700_000_000_000),
            mcc: None,
            mnc: None,
        home_mcc: None,
        home_mnc: None,
        imsi: None,
        }],
    });
    let app = router_with_actions(inbox, Some(Arc::new(Busy)));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/status")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["modems"][0]["state"], "Busy");
}

#[tokio::test]
async fn panel_runs_a_ussd_session() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/ussd")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"code":"*100#"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["text"], "余额 12.30");
    assert_eq!(body["expects_reply"], false);
    assert_eq!(actions.ussd.lock().expect("ussd").as_slice(), &["*100#"]);
}

#[tokio::test]
async fn panel_rejects_an_empty_ussd_code() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/ussd")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"code":"  "}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(actions.ussd.lock().expect("ussd").is_empty());
}
