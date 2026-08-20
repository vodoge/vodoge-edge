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
    use edge_core::CapabilityMatrix;
    use edge_modem::{collect_inbound, delete_inbound, CdcWdmDevice, QmiClient};
    use edge_panel::{serve, Inbox, PanelError};
    use edge_store::{DurableOutbox, LocalMessage, LocalModem, Store};
    use edge_uplink::dial::Socket;
    use edge_uplink::session::{Inbound, LinkConfig, ResumeSnapshot};
    use edge_uplink::tls::client_config;
    use edge_uplink::worker::UplinkWorker;
    use edge_uplink::{EnvelopeId, RetentionClass};
    use rustls_pemfile::{certs, pkcs8_private_keys};


    const DEVICE_ID: &str = "b0000000-0000-4000-8000-00000000000b";

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

        let panel_bind = env("VODOGE_EDGE_PANEL", "0.0.0.0:8743");
        let panel_store = shared.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("tokio");
            if let Err(error) = runtime.block_on(serve(panel_bind, panel_store)) {
                eprintln!("panel: {error}");
            }
        });

        let uplink_outbox = outbox.clone();
        std::thread::spawn(move || uplink_loop(uplink_outbox));

        println!("vodoge-edge panel on {} device_id={DEVICE_ID}", env("VODOGE_EDGE_PANEL", "0.0.0.0:8743"));
        loop {
            if let Err(error) = poll_modems(&shared, &outbox) {
                eprintln!("poll: {error}");
            }
            std::thread::sleep(Duration::from_secs(8));
        }
    }

    fn poll_modems(
        shared: &Arc<SharedStore>,
        outbox: &Arc<Mutex<DurableOutbox>>,
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
            match probe_one(&path, shared, outbox) {
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
    ) -> Result<String, String> {
        let device = CdcWdmDevice::open(path).map_err(|e| e.to_string())?;
        let mut client = QmiClient::new(device);
        client.sync().map_err(|e| e.to_string())?;
        let serials = client.get_serial_numbers().map_err(|e| e.to_string())?;
        let imei = serials.imei.clone().ok_or_else(|| "missing IMEI".to_string())?;
        let family = client.get_model().unwrap_or_else(|_| "Quectel".into());
        let serving = client.get_serving_system().ok();
        let state = match serving.as_ref() {
            Some(s) => format!("{:?}", s.registration_state),
            None => "unknown".into(),
        };
        let now = unix_ms();
        {
            let store = shared.0.lock().expect("store");
            store
                .upsert_local_modem(&LocalModem {
                    imei: imei.clone(),
                    family,
                    iccid: None,
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

    fn uplink_loop(outbox: Arc<Mutex<DurableOutbox>>) {
        let url = env("VODOGE_UPLINK_URL", "wss://43.108.53.126:444/v1/edge");
        let cert_dir = env("VODOGE_EDGE_CERTS", "/etc/vodoge-edge");
        loop {
            match uplink_once(&url, &cert_dir, &outbox) {
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
        let held = outbox.lock().expect("outbox");
        // DurableOutbox is not easily moved out of mutex for worker; clone via re-open is heavy.
        drop(held);
        let path = env("VODOGE_EDGE_DATA", "/var/lib/vodoge-edge") + "/outbox.db";
        let durable = DurableOutbox::open(path, 100_000).map_err(|e| e.to_string())?;
        let mut worker = UplinkWorker::new(config, durable);
        println!("uplink connecting {url}");
        worker.run(&mut socket, Instant::now()).map_err(|e| e.to_string())
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
