use std::sync::Arc;

use std::sync::Mutex;

use edge_panel::{
    router, router_with_actions, Actions, AtResult, MemoryInbox, PanelError, ReportResult,
    UsbResetResult,
};
use edge_store::{LocalMessage, LocalModem};
use http_body_util::BodyExt;
use tower::ServiceExt;

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
    assert!(page.contains("id=\"at-log\""));

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
}

impl RecordingActions {
    fn new() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            at: Mutex::new(Vec::new()),
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
