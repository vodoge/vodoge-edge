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
use edge_panel::{log_error, log_line, router_with_actions, Actions, AtResult, CandidateClaimResult,
                 MemoryInbox, ScannedOperatorBody, PanelError,
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
        },
        LocalMessage {
            seq: 2,
            peer: "8613800100500".into(),
            body: "test from the bench".into(),
            bearer: "cellular".into(),
            direction: "outbound".into(),
            received_at: 1_700_000_100_000,
            modem_imei: Some("860000000000001".into()),
        },
        // ⚠️ 故意留一条**没记模组**的。这一条在「只看某一根」时也必须还在 ——
        // 因为一个字段缺失就丢行，是收件箱悄悄丢信的方式。
        LocalMessage {
            seq: 3,
            peer: "12520".into(),
            body: "no modem recorded for this one".into(),
            bearer: "cellular".into(),
            direction: "inbound".into(),
            received_at: 1_700_000_200_000,
            modem_imei: None,
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
        },
        // 三种候选各一个，好看清那两个按钮什么时候出现、什么时候不出现。
        //
        // 这个是**可认领**的：串口、状态 found、还没人跟它说过话。
        LocalModemDiscovery {
            candidate_key: "serial:usb:2-4.2:port:/dev/ttyUSB8".into(),
            usb_device: Some("2-4.2".into()),
            transport: "serial".into(),
            control_port: "/dev/ttyUSB8".into(),
            vendor_id: Some("1e0e".into()),
            product_id: None,
            state: "found".into(),
            imei: None,
            detail: String::new(),
            last_seen: 1_700_000_000_000,
        },
        // 这个已经报过 IMEI 而且不在管理列表里，所以只该出现**纳管**。
        LocalModemDiscovery {
            candidate_key: "serial:usb:2-4.3:port:/dev/ttyUSB11".into(),
            usb_device: Some("2-4.3".into()),
            transport: "serial".into(),
            control_port: "/dev/ttyUSB11".into(),
            vendor_id: Some("2c7c".into()),
            product_id: Some("0296".into()),
            state: "atonly".into(),
            imei: Some("869999000000123".into()),
            detail: "answered AT+CGSN over serial only".into(),
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
        /// 认领是回应答的（好让「已纳入探测」那一格能被看到），但它**什么硬件
        /// 都不碰** —— 和真实实现一样，认领只是给下一轮轮询上膛。
        fn claim_modem_candidate(&self, candidate_key: String) -> Result<CandidateClaimResult, PanelError> {
            Ok(CandidateClaimResult { candidate_key })
        }
        fn send_sms(&self, _: String, _: String, _: Option<String>, _: bool) -> Result<(), PanelError> {
            Err(PanelError::Action("这个 example 只回答体检".into()))
        }
        fn restart_modem(&self, _: String) -> Result<(), PanelError> { Err(PanelError::Action("这个 example 只回答体检".into())) }
        /// ⚠️ 三种结局都能演出来，因为它们在屏幕上必须长得不一样：
        ///
        /// - `AT+CSQ` → 正常应答
        /// - 带 `CPIN` 的 → `+CME ERROR: 13`，**模组答了**，只是拒绝了这一条
        /// - 其余 → 连口都没够到
        fn at_command(&self, _: Option<String>, command: String, _: bool) -> Result<AtResult, PanelError> {
            let upper = command.to_uppercase();
            if upper.contains("CPIN") {
                return Ok(AtResult {
                    port: "/dev/ttyUSB2".into(),
                    command,
                    lines: vec!["+CME ERROR: 13".into()],
                    terminator: "+CME ERROR: 13".into(),
                    ok: false,
                    elapsed_ms: 34,
                });
            }
            if upper.starts_with("AT+CSQ") {
                return Ok(AtResult {
                    port: "/dev/ttyUSB2".into(),
                    command,
                    lines: vec!["+CSQ: 10,99".into(), "OK".into()],
                    terminator: "OK".into(),
                    ok: true,
                    elapsed_ms: 12,
                });
            }
            Err(PanelError::Action("控制口没有应答".into()))
        }
        fn usb_reset(&self, _: Option<String>) -> Result<UsbResetResult, PanelError> { Err(PanelError::Action("这个 example 只回答体检".into())) }
        fn list_profiles(&self, _: Option<String>) -> Result<ProfilesResult, PanelError> { Err(PanelError::Action("这个 example 只回答体检".into())) }
        fn switch_profile(&self, _: Option<String>, _: String, _: bool) -> Result<(), PanelError> { Err(PanelError::Action("这个 example 只回答体检".into())) }
        /// 故意慢：睡 8 秒再回。进度条、「已 N 秒」、「这一根此刻不服务」那句
        /// 话，都只有在请求真的挂着的时候才看得出来在不在动。
        fn scan_operators(&self, imei: Option<String>) -> Result<ScanResult, PanelError> {
            std::thread::sleep(std::time::Duration::from_secs(8));
            Ok(ScanResult {
                imei,
                elapsed_ms: 8_000,
                operators: vec![
                    ScannedOperatorBody {
                        numeric: "46000".into(),
                        long_name: "CHINA MOBILE".into(),
                        short_name: "CMCC".into(),
                        status: "current".into(),
                        access_technology: Some("LTE".into()),
                    },
                    ScannedOperatorBody {
                        numeric: "46001".into(),
                        long_name: "CHN-UNICOM".into(),
                        short_name: "UNICOM".into(),
                        status: "available".into(),
                        access_technology: Some("LTE".into()),
                    },
                    // 两个名字都空的一行 —— 那一格必须落回 MCC/MNC，不能是空的。
                    ScannedOperatorBody {
                        numeric: "46011".into(),
                        long_name: String::new(),
                        short_name: String::new(),
                        status: "forbidden".into(),
                        access_technology: None,
                    },
                ],
            })
        }
        fn ussd(&self, _: Option<String>, _: String) -> Result<UssdResult, PanelError> { Err(PanelError::Action("这个 example 只回答体检".into())) }
        fn ussd_cancel(&self, _: Option<String>) -> Result<(), PanelError> { Err(PanelError::Action("这个 example 只回答体检".into())) }
        fn set_radio(&self, _: Option<String>, _: bool) -> Result<(), PanelError> { Err(PanelError::Action("这个 example 只回答体检".into())) }
    }

    // 给日志栏灌一些真实形状的行：三种级别、几个话题、带 imei= 的和不带的，
    // 外加那条几乎占满整条流的心跳。心跳故意多来几条 —— 「静音心跳」那个开关
    // 要是没东西可静音，就看不出它在做什么。
    for line in [
        "vodoge-edge panel listening on 0.0.0.0:8790",
        "uplink connecting wss://cloud.example/edge",
        "uplink closed, reconnecting",
        "iccid 89860112345678901234 read",
        "EF_AD 8986…: QMI request rejected; assuming a 2-digit MNC",
        "restart 867018069509705: radio back, card not: timed out",
        "status report 0 is not hex: 079168AB",
        "sms queued for 8613800100500",
        "at lease listening on /dev/ttyUSB2",
        "usb recovery on /dev/ttyUSB2: re-enumerated",
    ] {
        log_line(line);
    }
    log_error("poll: /dev/cdc-wdm1 went away");
    log_error("command: refused, no such modem");
    for _ in 0..8 {
        log_line("poll /dev/cdc-wdm0 imei=867018069509705 ok");
        log_line("poll /dev/ttyUSB2 imei=860000000000001 at-only");
    }

    // 让这一栏活着：每秒一行。暂停缓冲、丢行计数、刷新徽章这些东西，静止的
    // 数据是看不出来的。
    std::thread::spawn(|| {
        let mut n = 0u32;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            n += 1;
            match n % 7 {
                0 => log_error(format!("poll: /dev/cdc-wdm1 vanished (#{n})")),
                3 => log_line(format!("uplink closed, reconnecting (#{n})")),
                _ => log_line("poll /dev/cdc-wdm0 imei=867018069509705 ok"),
            }
        }
    });

    let app = router_with_actions(inbox, Some(Arc::new(BenchActions)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8790").await.unwrap();
    println!("panel on http://127.0.0.1:8790  (/ 老面板, /next 新面板)");
    axum::serve(listener, app).await.unwrap();
}
