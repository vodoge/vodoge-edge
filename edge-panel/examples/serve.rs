//! Run the panel against seeded in-memory data, for looking at it.
//!
//!     cargo run -p edge-panel --example serve
//!     # http://127.0.0.1:8790   /  是老面板, /next 是 Leptos 那个
//!
//! 🔴 **Why this is committed rather than retyped each time.** The cloud half
//! of this rebuild spent a large part of its effort re-inventing exactly this —
//! a way to render the real tree with believable data — twice, from scratch,
//! because the first one lived in a scratch directory and was thrown away. Its
//! surviving descendant, `apps/console/scripts/screenshots/stub-gateway.mjs`,
//! is committed for the same reason and carries the same warning: without it,
//! "does this actually render" is a question nobody can answer cheaply, so it
//! stops being asked.
//!
//! ⚠️ The rows below are fixtures, not fixtures shared with the tests. They are
//! deliberately *wider* than the tests' — a full firmware string, an ICCID, an
//! IMSI, a modem whose family is known but has no matrix rule (`UFI103S`, which
//! is why one row reads 回退) — because the thing being looked at here is the
//! layout, and layout breaks on the widest real value rather than the average
//! one.
use std::sync::Arc;
use edge_panel::{router_with_actions, Actions, AtResult, MemoryInbox, PanelError,
                 ProfilesResult, ReportResult, ScanResult, UsbResetResult, UssdResult};
use edge_store::{LocalMessage, LocalModem, LocalModemDiscovery};

#[tokio::main]
async fn main() {
    let inbox = Arc::new(MemoryInbox {
        messages: vec![LocalMessage {
            seq: 1,
            peer: "10086".into(),
            body: "本月流量已使用 78%。".into(),
            bearer: "cellular".into(),
            direction: "inbound".into(),
            received_at: 1_700_000_000_000,
            modem_imei: Some("867018069509705".into()),
        }],
        modems: vec![
            LocalModem {
                imei: "867018069509705".into(),
                family: "EC20".into(),
                firmware: Some("EC20CEHCLGR06A05M1G".into()),
                msisdn: None,
                msisdn_iccid: None,
                apn_contexts: None,
                iccid: Some("89860112345678901234".into()),
                state: "registered".into(),
                last_seen: Some(1_700_000_000_000),
                mcc: Some(460),
                mnc: Some(0),
                home_mcc: Some(460),
                home_mnc: Some(0),
                imsi: Some("460001234567890".into()),
                discovery: "qmi".into(),
                manageable: true,
                control_port: Some("/dev/cdc-wdm0".into()),
            },
            LocalModem {
                imei: "860000000000001".into(),
                family: "UFI103S".into(),
                firmware: None,
                msisdn: None,
                msisdn_iccid: None,
                apn_contexts: None,
                iccid: None,
                state: "searching".into(),
                last_seen: Some(1_700_000_000_000),
                mcc: None,
                mnc: None,
                home_mcc: None,
                home_mnc: None,
                imsi: None,
                discovery: "at".into(),
                manageable: false,
                control_port: Some("/dev/ttyUSB2".into()),
            },
        ],
        discoveries: vec![LocalModemDiscovery {
            candidate_key: "qmi:usb:2-4.1".into(),
            usb_device: Some("2-4.1".into()),
            transport: "qmi".into(),
            control_port: "/dev/cdc-wdm1".into(),
            vendor_id: Some("2c7c".into()),
            product_id: Some("0125".into()),
            state: "probe_failed".into(),
            imei: None,
            detail: "POLLERR".into(),
            last_seen: 1_700_000_000_000,
        }],
    });
    // 一个**只回答体检**的假 Actions：其余动作照实返回「没有配置」，因为这个
    // example 是给人看画面的，不是给人点硬件的。
    //
    // ⚠️ 体检回的这份数据是 867018069509705 的——**封禁表里那一根**。选它就能
    // 看到第四条判词，那正是这一页在发短信之前要说的话。
    struct BenchActions;
    impl Actions for BenchActions {
        fn modem_report(&self, imei: Option<String>) -> Result<ReportResult, PanelError> {
            Ok(ReportResult {
                imei,
                port: "/dev/cdc-wdm0".into(),
                signal_dbm: Some(-93),
                signal_index: Some(10),
                cs_registration: Some("home".into()),
                ps_registration: Some("home".into()),
                operator: Some("CHINA MOBILE".into()),
                access_technology: Some("LTE".into()),
                imsi: Some("460001234567890".into()),
                iccid: Some("89860112345678901234".into()),
                msisdn: None,
                firmware: Some("EC20CEHCLGR06A05M1G".into()),
                sms_centre: Some("+8613800100500".into()),
                refused: vec!["AT+CNUM".into()],
            })
        }
        fn send_sms(&self, _: String, _: String, _: Option<String>, _: bool) -> Result<(), PanelError> {
            Err(PanelError::Action("这个 example 只回答体检".into()))
        }
        fn restart_modem(&self, _: String) -> Result<(), PanelError> { Err(PanelError::Action("这个 example 只回答体检".into())) }
        fn at_command(&self, _: Option<String>, _: String, _: bool) -> Result<AtResult, PanelError> {
            Err(PanelError::Action("这个 example 只回答体检".into()))
        }
        fn usb_reset(&self, _: Option<String>) -> Result<UsbResetResult, PanelError> { Err(PanelError::Action("这个 example 只回答体检".into())) }
        fn list_profiles(&self, _: Option<String>) -> Result<ProfilesResult, PanelError> { Err(PanelError::Action("这个 example 只回答体检".into())) }
        fn switch_profile(&self, _: Option<String>, _: String, _: bool) -> Result<(), PanelError> { Err(PanelError::Action("这个 example 只回答体检".into())) }
        fn scan_operators(&self, _: Option<String>) -> Result<ScanResult, PanelError> { Err(PanelError::Action("这个 example 只回答体检".into())) }
        fn ussd(&self, _: Option<String>, _: String) -> Result<UssdResult, PanelError> { Err(PanelError::Action("这个 example 只回答体检".into())) }
        fn ussd_cancel(&self, _: Option<String>) -> Result<(), PanelError> { Err(PanelError::Action("这个 example 只回答体检".into())) }
        fn set_radio(&self, _: Option<String>, _: bool) -> Result<(), PanelError> { Err(PanelError::Action("这个 example 只回答体检".into())) }
    }

    let app = router_with_actions(inbox, Some(Arc::new(BenchActions)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8790").await.unwrap();
    println!("panel on http://127.0.0.1:8790  (/ 老面板, /next 新面板)");
    axum::serve(listener, app).await.unwrap();
}
