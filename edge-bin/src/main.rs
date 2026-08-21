//! Vodoge edge daemon: QMI modems, local panel, WSS uplink.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn main() {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("vodoge-edge runs on Linux");
        std::process::exit(2);
    }
    #[cfg(target_os = "linux")]
    if let Err(error) = linux::run() {
        eprintln!("vodoge-edge: {error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::MutexGuard;

    use edge_agent::{CommandExecutor, SendError, SendPort, SmsSend};
    use edge_core::CapabilityMatrix;
    use edge_modem::{
        collect_inbound, delete_inbound, encode_submit, CdcWdmDevice, OperatingMode, QmiClient,
    };
    use edge_panel::{
        serve, Actions, AtResult, Inbox, PanelError, ProfileBody, ProfilesResult, ReportResult,
        ScanResult, ScannedOperatorBody, UsbResetResult,
    };
    use edge_store::{DurableOutbox, LocalMessage, LocalModem, QueueError, Store};
    use edge_uplink::dial::{DialError, Socket};
    use edge_uplink::session::{Inbound, LinkConfig, Phase, ResumeSnapshot};
    use edge_uplink::tls::client_config;
    use edge_uplink::worker::{Outbox, RetainedRecord, UplinkWorker};
    use edge_uplink::{EnvelopeId, RetentionClass, UplinkAck, UplinkError};
    use rustls_pemfile::{certs, pkcs8_private_keys};
    use vodoge_contract::{Envelope, MessageKind, PROTOCOL_VERSION};

    const DEVICE_ID: &str = "b0000000-0000-4000-8000-00000000000b";

    /// Primary UICC slot. These modules expose one card slot, and the eUICC
    /// always sits in it.
    const ESIM_SLOT: u8 = 1;

    /// A full band sweep on an EC20 routinely runs past a minute, and the
    /// module answers nothing until it finishes.
    const SCAN_TIMEOUT: Duration = Duration::from_secs(180);

    struct SharedStore(Mutex<Store>);

    impl Inbox for SharedStore {
        fn list_messages(&self) -> Result<Vec<LocalMessage>, PanelError> {
            self.0
                .lock()
                .expect("store")
                .list_local_messages()
                .map_err(PanelError::Store)
        }
        fn list_modems(&self) -> Result<Vec<LocalModem>, PanelError> {
            self.0
                .lock()
                .expect("store")
                .list_local_modems()
                .map_err(PanelError::Store)
        }
    }

    #[derive(Clone)]
    struct Radio {
        lock: Arc<Mutex<()>>,
        by_imei: Arc<Mutex<BTreeMap<String, PathBuf>>>,
        /// Device currently held by an operator-initiated command.
        ///
        /// A band scan keeps the radio for over a minute, which is longer than
        /// the panel's staleness window, so without this the panel reports a
        /// modem as offline while it is busy doing exactly what was asked.
        busy: Arc<Mutex<Option<PathBuf>>>,
    }

    impl Radio {
        fn new() -> Self {
            Self {
                lock: Arc::new(Mutex::new(())),
                by_imei: Arc::new(Mutex::new(BTreeMap::new())),
                busy: Arc::new(Mutex::new(None)),
            }
        }

        fn remember(&self, imei: &str, path: &Path) {
            self.by_imei
                .lock()
                .expect("imei map")
                .insert(imei.to_string(), path.to_path_buf());
        }

        /// IMEIs whose device is mid-command right now.
        fn busy_imeis(&self) -> Vec<String> {
            let Some(path) = self.busy.lock().expect("busy").clone() else {
                return Vec::new();
            };
            self.by_imei
                .lock()
                .expect("imei map")
                .iter()
                .filter(|(_, known)| **known == path)
                .map(|(imei, _)| imei.clone())
                .collect()
        }

        /// Marks a device busy until the guard drops, including on a panic path.
        fn hold(&self, path: &Path) -> BusyGuard {
            *self.busy.lock().expect("busy") = Some(path.to_path_buf());
            BusyGuard {
                busy: self.busy.clone(),
            }
        }

        fn path_for(&self, imei: Option<&str>) -> Result<PathBuf, SendError> {
            let map = self.by_imei.lock().expect("imei map");
            let path = match imei {
                Some(value) if !value.is_empty() => map.get(value).cloned(),
                _ => map.values().next().cloned(),
            };
            path.ok_or_else(|| SendError::new("modem_not_found", "no matching QMI modem"))
        }

        /// Run work against the module's AT control port.
        ///
        /// This takes the same lock as `with_client`: AT and QMI talk to one
        /// module over separate USB interfaces, and issuing both at once is how
        /// a Quectel stack ends up answering a stale transaction.
        fn with_at_port<T>(
            &self,
            imei: Option<&str>,
            work: impl FnOnce(&mut edge_modem::AtPort) -> Result<T, SendError>,
        ) -> Result<T, SendError> {
            let _lock = self.lock.lock().expect("radio");
            let qmi_path = self.path_for(imei)?;
            let _busy = self.hold(&qmi_path);
            let at_path = edge_modem::at_port_for_qmi(&qmi_path).ok_or_else(|| {
                SendError::new(
                    "at_port_not_found",
                    format!("no AT control port beside {}", qmi_path.display()),
                )
            })?;
            let mut port = edge_modem::AtPort::open(&at_path)
                .map_err(|error| SendError::new("at_open_failed", error.to_string()))?;
            work(&mut port)
        }

        fn with_client<T>(
            &self,
            imei: Option<&str>,
            work: impl FnOnce(&mut QmiClient<CdcWdmDevice>) -> Result<T, SendError>,
        ) -> Result<T, SendError> {
            let _lock = self.lock.lock().expect("radio");
            let path = self.path_for(imei)?;
            let _busy = self.hold(&path);
            let device = CdcWdmDevice::open(&path)
                .map_err(|error| SendError::new("modem_open_failed", error.to_string()))?;
            let mut client = QmiClient::new(device);
            client
                .sync()
                .map_err(|error| SendError::new("modem_sync_failed", error.to_string()))?;
            work(&mut client)
        }
    }

    /// Clears the busy marker when the command finishes, however it finishes.
    struct BusyGuard {
        busy: Arc<Mutex<Option<PathBuf>>>,
    }

    impl Drop for BusyGuard {
        fn drop(&mut self) {
            *self.busy.lock().expect("busy") = None;
        }
    }

    struct RadioPort {
        radio: Radio,
    }

    impl SendPort for RadioPort {
        fn send_sms(&mut self, send: &SmsSend) -> Result<(), SendError> {
            let pdu = encode_submit(&send.to, &send.body)
                .map_err(|error| SendError::new("pdu_encode_failed", error.to_string()))?;
            self.radio
                .with_client(send.modem_imei.as_deref(), |client| {
                    client
                        .send_sms(0x06, &pdu)
                        .map(|_| ())
                        .map_err(|error| SendError::new("send_failed", error.to_string()))
                })
        }

        fn restart_modem(&mut self, imei: &str) -> Result<(), SendError> {
            self.radio.with_client(Some(imei), |client| {
                client
                    .set_operating_mode(OperatingMode::Offline)
                    .and_then(|_| client.set_operating_mode(OperatingMode::Online))
                    .map_err(|error| SendError::new("restart_failed", error.to_string()))
            })
        }
    }

    impl Actions for RadioPort {
        fn send_sms(&self, to: String, body: String, imei: Option<String>) -> Result<(), PanelError> {
            let mut port = RadioPort {
                radio: self.radio.clone(),
            };
            SendPort::send_sms(
                &mut port,
                &SmsSend {
                    to,
                    body,
                    modem_imei: imei,
                    iccid: None,
                },
            )
            .map_err(|error| PanelError::Action(error.to_string()))
        }

        fn restart_modem(&self, imei: String) -> Result<(), PanelError> {
            let mut port = RadioPort {
                radio: self.radio.clone(),
            };
            SendPort::restart_modem(&mut port, &imei)
                .map_err(|error| PanelError::Action(error.to_string()))
        }

        fn busy_modems(&self) -> Vec<String> {
            self.radio.busy_imeis()
        }

        fn scan_operators(&self, imei: Option<String>) -> Result<ScanResult, PanelError> {
            let wanted = imei.clone();
            self.radio
                .with_at_port(imei.as_deref(), |port| {
                    let exchange = port
                        .command_with_timeout("AT+COPS=?", SCAN_TIMEOUT)
                        .map_err(|error| SendError::new("scan_failed", error.to_string()))?;
                    if !exchange.succeeded() {
                        return Err(SendError::new("scan_rejected", exchange.terminator.clone()));
                    }
                    Ok(ScanResult {
                        imei: wanted,
                        elapsed_ms: exchange.elapsed.as_millis() as u64,
                        operators: edge_modem::parse_cops_scan(&exchange.lines)
                            .into_iter()
                            .map(|found| ScannedOperatorBody {
                                status: found.status_label().to_string(),
                                numeric: found.numeric,
                                long_name: found.long_name,
                                short_name: found.short_name,
                                access_technology: found
                                    .access_technology
                                    .map(|value| value.to_string()),
                            })
                            .collect(),
                    })
                })
                .map_err(|error| PanelError::Action(error.to_string()))
        }

        fn list_profiles(&self, imei: Option<String>) -> Result<ProfilesResult, PanelError> {
            let wanted = imei.clone();
            self.radio
                .with_client(imei.as_deref(), |client| {
                    let profiles = client
                        .list_profiles(ESIM_SLOT)
                        .map_err(|error| SendError::new("esim_list_failed", error.to_string()))?;
                    Ok(ProfilesResult {
                        imei: wanted,
                        profiles: profiles
                            .into_iter()
                            .map(|profile| ProfileBody {
                                label: profile.label(),
                                iccid: profile.iccid,
                                enabled: profile.enabled,
                                provider: profile.provider,
                                name: profile.name,
                                nickname: profile.nickname,
                                class: profile.class,
                                isdp_aid: profile.isdp_aid,
                            })
                            .collect(),
                    })
                })
                .map_err(|error| PanelError::Action(error.to_string()))
        }

        fn switch_profile(
            &self,
            imei: Option<String>,
            iccid: String,
            enable: bool,
        ) -> Result<(), PanelError> {
            self.radio
                .with_client(imei.as_deref(), |client| {
                    client
                        .set_profile(ESIM_SLOT, &iccid, enable)
                        .map_err(|error| SendError::new("esim_switch_failed", error.to_string()))
                })
                .map_err(|error| PanelError::Action(error.to_string()))
        }

        fn modem_report(&self, imei: Option<String>) -> Result<ReportResult, PanelError> {
            let wanted = imei.clone();
            self.radio
                .with_at_port(imei.as_deref(), |port| {
                    let path = port.path().display().to_string();
                    let report = edge_modem::collect_report(port)
                        .map_err(|error| SendError::new("report_failed", error.to_string()))?;
                    Ok(ReportResult {
                        imei: wanted,
                        port: path,
                        signal_dbm: report.signal.and_then(|signal| signal.dbm),
                        signal_index: report.signal.map(|signal| signal.rssi_index),
                        cs_registration: report
                            .cs_registration
                            .map(|state| state.as_str().to_string()),
                        ps_registration: report
                            .ps_registration
                            .map(|state| state.as_str().to_string()),
                        operator: report.operator,
                        access_technology: report
                            .access_technology
                            .map(|value| value.to_string()),
                        imsi: report.imsi,
                        iccid: report.iccid,
                        msisdn: report.msisdn,
                        firmware: report.firmware,
                        sms_centre: report.sms_centre,
                        refused: report.refused,
                    })
                })
                .map_err(|error| PanelError::Action(error.to_string()))
        }

        fn usb_reset(&self, imei: Option<String>) -> Result<UsbResetResult, PanelError> {
            // Held across the reset so a poll cannot open the character device
            // while the module is re-enumerating.
            let _lock = self.radio.lock.lock().expect("radio");
            let qmi_path = self
                .radio
                .path_for(imei.as_deref())
                .map_err(|error| PanelError::Action(error.to_string()))?;
            let _busy = self.radio.hold(&qmi_path);
            let reset = edge_modem::reset_for_qmi(&qmi_path)
                .map_err(|error| PanelError::Action(error.to_string()))?;
            Ok(UsbResetResult {
                device: reset.device,
                node: reset.node.display().to_string(),
            })
        }

        fn at_command(
            &self,
            imei: Option<String>,
            command: String,
        ) -> Result<AtResult, PanelError> {
            self.radio
                .with_at_port(imei.as_deref(), |port| {
                    let path = port.path().display().to_string();
                    let exchange = port
                        .command(&command)
                        .map_err(|error| SendError::new("at_failed", error.to_string()))?;
                    Ok(AtResult {
                        port: path,
                        command: exchange.command.clone(),
                        ok: exchange.succeeded(),
                        lines: exchange.lines.clone(),
                        terminator: exchange.terminator.clone(),
                        elapsed_ms: exchange.elapsed.as_millis() as u64,
                    })
                })
                .map_err(|error| PanelError::Action(error.to_string()))
        }
    }

    struct SharedOutbox(Arc<Mutex<DurableOutbox>>);

    impl SharedOutbox {
        fn lock(&self) -> MutexGuard<'_, DurableOutbox> {
            self.0.lock().expect("outbox")
        }
    }

    impl Outbox for SharedOutbox {
        type Error = QueueError;

        fn last_allocated(&self) -> u64 {
            self.lock().last_allocated()
        }

        fn committed_through(&self) -> u64 {
            self.lock().committed_through()
        }

        fn lowest_retained_seq(&self) -> Option<u64> {
            self.lock().lowest_retained_seq()
        }

        fn pending_gap_ids(&self) -> Vec<String> {
            self.lock().pending_gap_ids()
        }

        fn queue_records(&self) -> i64 {
            self.lock().queue_records()
        }

        fn queue_bytes(&self) -> Option<i64> {
            self.lock().queue_bytes()
        }

        fn observe_ack(&mut self, ack: UplinkAck) -> Result<Vec<u64>, Self::Error> {
            self.lock().observe_ack(ack)
        }

        fn retained(&self) -> Result<Vec<RetainedRecord>, Self::Error> {
            Outbox::retained(&*self.lock())
        }
    }

    pub fn run() -> Result<(), String> {
        let data_dir = env("VODOGE_EDGE_DATA", "/var/lib/vodoge-edge");
        std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
        let inbox_path = PathBuf::from(&data_dir).join("inbox.db");
        let outbox_path = PathBuf::from(&data_dir).join("outbox.db");
        let store = Store::open(&inbox_path).map_err(|e| e.to_string())?;
        let shared = Arc::new(SharedStore(Mutex::new(store)));
        let outbox = Arc::new(Mutex::new(
            DurableOutbox::open(&outbox_path, 100_000).map_err(|e| e.to_string())?,
        ));
        let radio = Radio::new();
        let executor = Arc::new(Mutex::new(CommandExecutor::new(RadioPort {
            radio: radio.clone(),
        })));
        let panel_actions = Arc::new(RadioPort {
            radio: radio.clone(),
        });

        // The panel reads this to report cloud vs local, so what it shows is the
        // real uplink rather than a fixed assumption.
        let uplink_online = Arc::new(AtomicBool::new(false));

        let panel_bind = env("VODOGE_EDGE_PANEL", "0.0.0.0:8743");
        let panel_store = shared.clone();
        let panel_online = uplink_online.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("tokio");
            if let Err(error) =
                runtime.block_on(serve(panel_bind, panel_store, Some(panel_actions), panel_online))
            {
                eprintln!("panel: {error}");
            }
        });

        let uplink_outbox = outbox.clone();
        let uplink_executor = executor.clone();
        std::thread::spawn(move || uplink_loop(uplink_outbox, uplink_executor, uplink_online));

        println!("vodoge-edge panel on {} device_id={DEVICE_ID}", env("VODOGE_EDGE_PANEL", "0.0.0.0:8743"));
        loop {
            if let Err(error) = poll_modems(&shared, &outbox, &radio) {
                eprintln!("poll: {error}");
            }
            std::thread::sleep(Duration::from_secs(8));
        }
    }

    fn poll_modems(
        shared: &Arc<SharedStore>,
        outbox: &Arc<Mutex<DurableOutbox>>,
        radio: &Radio,
    ) -> Result<(), String> {
        let mut paths = std::fs::read_dir("/dev")
            .map_err(|e| e.to_string())?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("cdc-wdm"))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        paths.sort();
        if paths.is_empty() {
            return Err("no /dev/cdc-wdm*".into());
        }
        for path in paths {
            match probe_one(&path, shared, outbox, radio) {
                Ok(imei) => println!("poll {} imei={imei} ok", path.display()),
                Err(error) => eprintln!("poll {} FAIL {error}", path.display()),
            }
        }
        Ok(())
    }

    fn probe_one(
        path: &Path,
        shared: &Arc<SharedStore>,
        outbox: &Arc<Mutex<DurableOutbox>>,
        radio: &Radio,
    ) -> Result<String, String> {
        let _busy = radio.lock.lock().expect("radio");
        let device = CdcWdmDevice::open(path).map_err(|e| e.to_string())?;
        let mut client = QmiClient::new(device);
        client.sync().map_err(|e| e.to_string())?;
        let serials = client.get_serial_numbers().map_err(|e| e.to_string())?;
        let imei = serials.imei.clone().ok_or_else(|| "missing IMEI".to_string())?;
        let family = client.get_model().unwrap_or_else(|_| "Quectel".into());
        // EF_ICCID identifies the active profile. On an eUICC that changes when a
        // different profile is enabled, so it is the only field that says which
        // SIM the modem is actually using. Failing to read it is not fatal, but
        // swallowing the error leaves a blank column with no way to find out why.
        let iccid = match client.read_iccid() {
            Ok(value) => Some(value),
            Err(error) => {
                eprintln!("iccid {} unavailable: {error}", path.display());
                None
            }
        };
        let serving = client.get_serving_system().ok();
        let state = match serving.as_ref() {
            Some(s) => format!("{:?}", s.registration_state),
            None => "unknown".into(),
        };
        let now = unix_ms();
        radio.remember(&imei, path);
        {
            let store = shared.0.lock().expect("store");
            store
                .upsert_local_modem(&LocalModem {
                    imei: imei.clone(),
                    family,
                    iccid,
                    state: state.clone(),
                    last_seen: Some(now),
                })
                .map_err(|e| e.to_string())?;
        }

        let pass = collect_inbound(&mut client).map_err(|e| e.to_string())?;
        for message in &pass.inbound {
            let (peer, body) = decode_deliver(&message.raw.pdu);
            let local = LocalMessage {
                seq: u64::from(message.index) + (now as u64 % 1_000_000) * 1000,
                peer: peer.clone(),
                body: body.clone(),
                bearer: "cellular".into(),
                direction: "inbound".into(),
                received_at: now,
                modem_imei: Some(imei.clone()),
            };
            shared
                .0
                .lock()
                .expect("store")
                .insert_local_message(&local)
                .map_err(|e| e.to_string())?;
            enqueue_sms(outbox, &imei, &peer, &body, now)?;
        }
        if !pass.inbound.is_empty() {
            let _ = delete_inbound(&mut client, &pass.inbound);
        }

        enqueue_device_state(outbox, &imei, &state, now)?;
        Ok(imei)
    }

    fn enqueue_sms(
        outbox: &Arc<Mutex<DurableOutbox>>,
        imei: &str,
        peer: &str,
        body: &str,
        now: i64,
    ) -> Result<(), String> {
        let payload = serde_json::json!({
            "modem_imei": imei,
            "peer": peer,
            "body": body,
            "received_at": now,
            "iccid": "",
            "bearer": "cellular",
            "encoding": "gsm7"
        });
        append_kind(outbox, "SmsReceived", payload)
    }

    fn enqueue_device_state(
        outbox: &Arc<Mutex<DurableOutbox>>,
        imei: &str,
        state: &str,
        now: i64,
    ) -> Result<(), String> {
        let payload = serde_json::json!({
            "observed_at": now,
            "modems": [{
                "modem_imei": imei,
                "state": state,
                "registration": state,
                "capability": {
                    "sms_mo": "cellular",
                    "sms_mt": "cellular",
                    "matrix_version": CapabilityMatrix::builtin()
                        .map(|m| m.version().to_string())
                        .unwrap_or_else(|_| "unversioned".into())
                }
            }]
        });
        append_kind(outbox, "DeviceState", payload)
    }

    fn append_kind(
        outbox: &Arc<Mutex<DurableOutbox>>,
        kind: &str,
        payload: serde_json::Value,
    ) -> Result<(), String> {
        let bytes = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
        let id = EnvelopeId::new(uuid::Uuid::new_v4().to_string()).map_err(|e| e.to_string())?;
        outbox
            .lock()
            .expect("outbox")
            .append(id, kind, bytes, RetentionClass::Protected)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn uplink_loop(
        outbox: Arc<Mutex<DurableOutbox>>,
        executor: Arc<Mutex<CommandExecutor<RadioPort>>>,
        online: Arc<AtomicBool>,
    ) {
        let url = env("VODOGE_UPLINK_URL", "wss://43.108.53.126:444/v1/edge");
        let cert_dir = env("VODOGE_EDGE_CERTS", "/etc/vodoge-edge");
        loop {
            let result = uplink_once(&url, &cert_dir, &outbox, &executor, &online);
            online.store(false, Ordering::Relaxed);
            match result {
                Ok(()) => eprintln!("uplink closed, reconnecting"),
                Err(error) => eprintln!("uplink: {error}"),
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    }

    fn uplink_once(
        url: &str,
        cert_dir: &str,
        outbox: &Arc<Mutex<DurableOutbox>>,
        executor: &Arc<Mutex<CommandExecutor<RadioPort>>>,
        online: &Arc<AtomicBool>,
    ) -> Result<(), String> {
        let tls = load_tls(Path::new(cert_dir))?;
        let mut socket = Socket::connect(url, tls).map_err(|e| e.to_string())?;
        let snapshot = {
            let box_ = outbox.lock().expect("outbox");
            ResumeSnapshot {
                last_assigned_seq: box_.last_allocated(),
                last_acked_seq: box_.committed_through(),
                lowest_retained_seq: box_.lowest_retained_seq(),
                pending_gap_ids: box_.pending_gap_ids(),
                capability_matrix_version: CapabilityMatrix::builtin()
                    .map(|m| m.version().to_string())
                    .unwrap_or_else(|_| "unversioned".into()),
                edge_version: Some(env!("CARGO_PKG_VERSION").into()),
                queue_records: Some(box_.queue_records()),
                queue_bytes: box_.queue_bytes(),
            }
        };
        let config = LinkConfig::new(DEVICE_ID, snapshot).map_err(|e| e.to_string())?;
        let mut worker = UplinkWorker::new(config, SharedOutbox(outbox.clone()));
        println!("uplink connecting {url}");
        let now = Instant::now();
        worker.start(&mut socket, now).map_err(|e| e.to_string())?;
        online.store(true, Ordering::Relaxed);
        loop {
            match socket.recv_envelope() {
                Ok(envelope) => {
                    let inbound = worker
                        .on_inbound(&mut socket, envelope, Instant::now())
                        .map_err(|e| e.to_string())?;
                    if let Inbound::CommandDeliver(deliver) = inbound {
                        if let Err(error) =
                            handle_command(&deliver, executor, &mut socket, outbox)
                        {
                            eprintln!("command: {error}");
                        }
                    }
                    if worker.session().phase() == Phase::Backoff {
                        return Ok(());
                    }
                }
                Err(DialError::Timeout) => {
                    worker
                        .poll(&mut socket, Instant::now())
                        .map_err(|e| e.to_string())?;
                    if worker.session().phase() == Phase::Backoff {
                        return Ok(());
                    }
                }
                Err(DialError::Closed) => {
                    worker.on_disconnect(Instant::now());
                    return Ok(());
                }
                Err(error) => {
                    worker.on_disconnect(Instant::now());
                    return Err(error.to_string());
                }
            }
        }
    }

    fn handle_command(
        envelope: &Envelope,
        executor: &Arc<Mutex<CommandExecutor<RadioPort>>>,
        socket: &mut Socket,
        outbox: &Arc<Mutex<DurableOutbox>>,
    ) -> Result<(), String> {
        let now = unix_ms();
        let outcome = executor
            .lock()
            .expect("executor")
            .handle_envelope(envelope, now)
            .map_err(|error| error.to_string())?;
        socket
            .send_envelope(&Envelope {
                v: PROTOCOL_VERSION,
                kind: MessageKind::CommandReceipt,
                id: uuid::Uuid::new_v4().to_string(),
                ts: now,
                device_id: DEVICE_ID.into(),
                seq: None,
                trace_id: None,
                payload: serde_json::to_value(&outcome.receipt).map_err(|e| e.to_string())?,
            })
            .map_err(|e| e.to_string())?;

        let result_bytes = serde_json::to_vec(&outcome.result).map_err(|e| e.to_string())?;
        let envelope_id = EnvelopeId::new(format!("command-result:{}", outcome.result.cmd_id))
            .map_err(|e| e.to_string())?;
        let sequence = match outbox.lock().expect("outbox").append(
            envelope_id,
            "CommandResult",
            result_bytes,
            RetentionClass::Protected,
        ) {
            Ok((sequence, _)) => sequence,
            Err(QueueError::Uplink(UplinkError::DuplicateEnvelopeId { sequence, .. })) => sequence,
            Err(error) => return Err(error.to_string()),
        };
        socket
            .send_envelope(&Envelope {
                v: PROTOCOL_VERSION,
                kind: MessageKind::CommandResult,
                id: format!("command-result:{}", outcome.result.cmd_id),
                ts: now,
                device_id: DEVICE_ID.into(),
                seq: Some(sequence),
                trace_id: None,
                payload: serde_json::to_value(&outcome.result).map_err(|e| e.to_string())?,
            })
            .map_err(|e| e.to_string())?;
        println!(
            "command {} {} seq={sequence}",
            outcome.result.cmd_id, outcome.result.status
        );
        Ok(())
    }

    fn load_tls(dir: &Path) -> Result<std::sync::Arc<rustls::ClientConfig>, String> {
        let mut ca = BufReader::new(File::open(dir.join("ca.crt")).map_err(|e| e.to_string())?);
        let mut device = BufReader::new(File::open(dir.join("device.crt")).map_err(|e| e.to_string())?);
        let mut key = BufReader::new(File::open(dir.join("device.key")).map_err(|e| e.to_string())?);
        let roots = certs(&mut ca)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let chain = certs(&mut device)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let keys = pkcs8_private_keys(&mut key)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let key = keys
            .into_iter()
            .next()
            .ok_or_else(|| "device key missing".to_string())?;
        client_config(
            roots,
            chain,
            rustls::pki_types::PrivateKeyDer::Pkcs8(key),
        )
        .map_err(|e| e.to_string())
    }

    fn decode_deliver(pdu: &[u8]) -> (String, String) {
        if pdu.is_empty() {
            return (String::new(), String::new());
        }
        let mut i = 0usize;
        let smsc_len = pdu[0] as usize;
        if 1 + smsc_len < pdu.len() {
            i = 1 + smsc_len;
        }
        if i + 2 >= pdu.len() {
            return (String::new(), hex(pdu));
        }
        i += 1;
        let oa_digits = pdu[i] as usize;
        i += 1;
        if i >= pdu.len() {
            return (String::new(), hex(pdu));
        }
        i += 1;
        let oa_bytes = oa_digits.div_ceil(2);
        if i + oa_bytes + 9 > pdu.len() {
            return (String::new(), hex(pdu));
        }
        let peer = bcd(&pdu[i..i + oa_bytes], oa_digits);
        i += oa_bytes;
        i += 1;
        let dcs = pdu[i];
        i += 1;
        i += 7;
        let udl = pdu[i] as usize;
        i += 1;
        let ud = if i <= pdu.len() { &pdu[i..] } else { &[] };
        let body = match dcs & 0x0c {
            0x08 => String::from_utf16_lossy(
                &ud.chunks(2)
                    .filter_map(|c| {
                        if c.len() == 2 {
                            Some(u16::from_be_bytes([c[0], c[1]]))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>(),
            ),
            _ => String::from_utf8_lossy(ud).chars().take(udl).collect(),
        };
        (peer, body)
    }

    fn bcd(bytes: &[u8], digits: usize) -> String {
        let mut out = String::new();
        for byte in bytes {
            let lo = byte & 0x0f;
            let hi = byte >> 4;
            if lo <= 9 && out.len() < digits {
                out.push(char::from(b'0' + lo));
            }
            if hi <= 9 && out.len() < digits {
                out.push(char::from(b'0' + hi));
            }
        }
        if out.starts_with('8') && out.len() > 11 {
            format!("+{out}")
        } else {
            out
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unix_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    fn env(name: &str, default: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| default.to_string())
    }
}
