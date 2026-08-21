use std::sync::Arc;

use std::sync::Mutex;

use edge_panel::{router, router_with_actions, Actions, MemoryInbox, PanelError};
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
    assert!(page.contains("本地面板"));
    assert!(page.contains("/api/messages"));

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
}

impl Actions for RecordingActions {
    fn send_sms(&self, to: String, body: String, _imei: Option<String>) -> Result<(), PanelError> {
        self.sent.lock().expect("sent").push((to, body));
        Ok(())
    }

    fn restart_modem(&self, _imei: String) -> Result<(), PanelError> {
        Ok(())
    }
}

#[tokio::test]
async fn panel_sends_sms_locally() {
    let actions = Arc::new(RecordingActions {
        sent: Mutex::new(Vec::new()),
    });
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
