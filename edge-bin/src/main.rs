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
    use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
    use std::sync::MutexGuard;

    use edge_agent::{CommandExecutor, SendError, SendPort, SmsSend};
    use edge_core::{assemble, CapabilityMatrix, CarrierProfile, ConcatPart, ModemFamily, Network};
    use edge_modem::{
        collect_inbound, delete_inbound, encode_submit, CdcWdmDevice, NasRegistrationState,
        OperatingMode, QmiClient,
    };
    use edge_panel::{
        log_error, log_line, serve, Actions, AtResult, Inbox, PanelError, ProfileBody, ProfilesResult, ReportResult,
        ScanResult, ScannedOperatorBody, UsbResetResult, UssdResult,
    };
    use edge_store::{DurableOutbox, LocalMessage, LocalModem, QueueError, Store};
    use serde_json::Value as JsonValue;
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

    /// How long to wait for the network's `+CUSD:` report. Carriers routinely
    /// take several seconds, and a session that is never answered has to end
    /// rather than hold the radio.
    const USSD_TIMEOUT: Duration = Duration::from_secs(45);

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
        /// Asks the poll loop to look for modems now.
        ///
        /// Capacity one, and a full channel is not an error: a pending rescan
        /// is already what a second request wanted. Queueing one rescan per
        /// click would make an impatient operator wait longer, not less.
        rescan: SyncSender<()>,
    }

    impl Radio {
        /// Returns the handle and the receiving end of its rescan channel.
        ///
        /// The receiver goes to whoever owns the poll loop. Handing it back
        /// rather than storing it keeps `Radio` cloneable, and makes it plain
        /// that exactly one place is expected to act on the request.
        fn new() -> (Self, Receiver<()>) {
            let (rescan, requests) = sync_channel(1);
            let radio = Self {
                lock: Arc::new(Mutex::new(())),
                by_imei: Arc::new(Mutex::new(BTreeMap::new())),
                busy: Arc::new(Mutex::new(None)),
                rescan,
            };
            (radio, requests)
        }

        /// Cuts the poll loop's wait short. Never blocks.
        fn request_rescan(&self) {
            let _ = self.rescan.try_send(());
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
        proxies: Arc<ProxyRuntime>,
    }

    impl RadioPort {
        /// One AT exchange, with whatever the module answered left intact.
        fn at_exchange(
            &mut self,
            imei: &str,
            command: &str,
            timeout_ms: Option<i64>,
        ) -> Result<AtResult, SendError> {
            // The panel's AT action uses the port's own default timeout. A
            // command that asks for a longer one gets it here rather than
            // silently running with the default.
            match timeout_ms {
                Some(millis) => self.radio.with_at_port(Some(imei), |port| {
                    let started = Instant::now();
                    let exchange = port
                        .command_with_timeout(command, Duration::from_millis(millis as u64))
                        .map_err(|error| SendError::new("at_failed", error.to_string()))?;
                    Ok(AtResult {
                        port: String::new(),
                        command: exchange.command,
                        lines: exchange.lines,
                        ok: exchange.terminator == "OK",
                        terminator: exchange.terminator,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    })
                }),
                None => Actions::at_command(self, Some(imei.to_string()), command.to_string())
                    .map_err(action_failed),
            }
        }

        /// One AT exchange that has to have ended in `OK`.
        ///
        /// `run_at` deliberately reports `+CME ERROR` as a successful
        /// exchange: a raw AT console exists to show what the module said,
        /// and swallowing the answer would defeat it. A button labelled
        /// "turn data off" cannot afford the same generosity — a green
        /// receipt beside an unchanged modem is worse than an error, because
        /// nobody goes looking.
        fn at_ok(
            &mut self,
            imei: &str,
            command: &str,
            timeout_ms: Option<i64>,
        ) -> Result<AtResult, SendError> {
            let result = self.at_exchange(imei, command, timeout_ms)?;
            if !result.ok {
                return Err(SendError::new(
                    "at_rejected",
                    format!("{} answered {}", command, result.terminator),
                ));
            }
            Ok(result)
        }
    }

    /// The proxy listeners, and the runtime they live on.
    ///
    /// The manager is async and the command executor is not, so the proxies
    /// get their own runtime and the synchronous side blocks on it. The
    /// executor runs on the uplink thread, never on a tokio worker, which is
    /// what makes `block_on` safe here.
    struct ProxyRuntime {
        runtime: tokio::runtime::Runtime,
        manager: Arc<edge_proxy::ProxyManager>,
        radio: Radio,
    }

    impl ProxyRuntime {
        fn new(radio: Radio) -> Result<Self, String> {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("vodoge-proxy")
                .build()
                .map_err(|error| error.to_string())?;
            let manager = Arc::new(edge_proxy::ProxyManager::new(Arc::new(
                ModemInterfaces { radio: radio.clone() },
            )));
            Ok(Self {
                runtime,
                manager,
                radio,
            })
        }
    }

    /// Finds the network interface a modem's data session is using.
    ///
    /// Resolved on every start rather than remembered: the name is not stable
    /// across re-enumeration, so a modem that reset can come back as a
    /// different `wwan` and a cached name would bind the listener to an
    /// interface that no longer belongs to that SIM.
    struct ModemInterfaces {
        radio: Radio,
    }

    impl edge_proxy::InterfaceResolver for ModemInterfaces {
        fn interface_for(&self, modem_imei: &str) -> Option<String> {
            let qmi_path = self.radio.path_for(Some(modem_imei)).ok()?;
            let name = qmi_path.file_name()?.to_str()?;
            let device = PathBuf::from(format!("/sys/class/usbmisc/{name}/device"));
            edge_proxy::bind::interface_for_usb_device(&device)
        }
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

        // The relay. Each of these routes a cloud command into the very same
        // `Actions` method the local panel calls, so a diagnostic run from the
        // console and one from the panel cannot behave differently — there is
        // one implementation, not two.

        fn run_at(
            &mut self,
            imei: &str,
            command: &str,
            timeout_ms: Option<i64>,
        ) -> Result<JsonValue, SendError> {
            let result = self.at_exchange(imei, command, timeout_ms)?;
            json_details(&result)
        }

        fn send_ussd(&mut self, imei: &str, code: &str, stage: &str) -> Result<JsonValue, SendError> {
            match stage {
                "cancel" => {
                    Actions::ussd_cancel(self, Some(imei.to_string())).map_err(action_failed)?;
                    Ok(JsonValue::Null)
                }
                // A continue is the same request on an open session: the
                // module distinguishes them by whether one is already running,
                // not by a different command.
                _ => {
                    let result = Actions::ussd(self, Some(imei.to_string()), code.to_string())
                        .map_err(action_failed)?;
                    json_details(&result)
                }
            }
        }

        fn set_radio(&mut self, imei: &str, enabled: bool) -> Result<(), SendError> {
            Actions::set_radio(self, Some(imei.to_string()), enabled).map_err(action_failed)
        }

        fn scan_operators(&mut self, imei: &str) -> Result<JsonValue, SendError> {
            let result =
                Actions::scan_operators(self, Some(imei.to_string())).map_err(action_failed)?;
            json_details(&result)
        }

        fn select_operator(
            &mut self,
            imei: &str,
            mode: &str,
            plmn: Option<&str>,
        ) -> Result<JsonValue, SendError> {
            // 27.007: `AT+COPS=0` hands selection back to the module,
            // `AT+COPS=1,2,"46001"` pins it to one network in numeric format.
            let command = match (mode, plmn) {
                ("manual", Some(plmn)) => {
                    format!("AT+COPS=1,2,\"{}\"", plmn.replace('-', ""))
                }
                ("manual", None) => {
                    return Err(SendError::new(
                        "plmn_required",
                        "manual selection needs a plmn",
                    ))
                }
                _ => "AT+COPS=0".to_string(),
            };
            // Registering on a chosen network takes far longer than a normal
            // AT round trip, and the module stays silent until it settles.
            self.run_at(imei, &command, Some(120_000))
        }

        fn modem_report(&mut self, imei: &str) -> Result<JsonValue, SendError> {
            let result =
                Actions::modem_report(self, Some(imei.to_string())).map_err(action_failed)?;
            json_details(&result)
        }

        fn reset_usb(&mut self, imei: &str) -> Result<JsonValue, SendError> {
            let result = Actions::usb_reset(self, Some(imei.to_string())).map_err(action_failed)?;
            json_details(&result)
        }

        fn set_data_network(&mut self, imei: &str, enabled: bool) -> Result<JsonValue, SendError> {
            // 27.007 `AT+CGACT`, on context 1: the default bearer these
            // modules dial on. Contexts 2 and 3 are the IMS and emergency
            // ones, which belong to the network rather than to an operator.
            //
            // Quectel's own `AT+QNETDEVCTL` would be the other candidate and
            // reads better, but the EC20s on the bench answer it `ERROR`.
            let state = i32::from(enabled);
            // Attaching can take several seconds on a slow cell, and the
            // module stays silent until it settles.
            let wrote = self.at_ok(imei, &format!("AT+CGACT={state},1"), Some(60_000))?;
            // Read back rather than echo the request: a write can be accepted
            // and the bearer still fail to come up, and the whole point of
            // the button is knowing which happened.
            let now = self.at_exchange(imei, "AT+CGACT?", None)?;
            json_details(&serde_json::json!({
                "requested": if enabled { "up" } else { "down" },
                "elapsed_ms": wrote.elapsed_ms,
                "contexts": now.lines,
            }))
        }

        fn set_usbnet_mode(&mut self, imei: &str, mode: &str) -> Result<JsonValue, SendError> {
            // Quectel `AT+QCFG="usbnet"`. The bench modules advertise 0-4;
            // 4 is NCM on some firmware and undefined on others, so the
            // contract stops at the four that mean the same thing anywhere.
            let value = match mode {
                "rmnet" => 0,
                "ecm" => 1,
                "mbim" => 2,
                "rndis" => 3,
                other => {
                    return Err(SendError::new(
                        "unknown_usbnet_mode",
                        format!("{other} is not a usbnet mode"),
                    ))
                }
            };
            self.at_ok(imei, &format!("AT+QCFG=\"usbnet\",{value}"), None)?;
            // Read back rather than report the value that was sent: this is a
            // setting nobody can verify by looking at the modem, and it only
            // takes effect at the next restart, so a wrong write would go
            // unnoticed until the modem came back as something else.
            let readback = self.at_exchange(imei, "AT+QCFG=\"usbnet\"", None)?;
            json_details(&serde_json::json!({
                "mode": mode,
                "value": value,
                "reported": readback.lines,
                "applies_after_restart": true,
                // Every mode but rmnet takes away the QMI control port, which
                // is the only way this agent reaches a modem. Saying so here
                // is the difference between a planned change and a modem that
                // quietly leaves the fleet after its next restart, recoverable
                // only by someone standing next to it.
                "warning": if value == 0 {
                    JsonValue::Null
                } else {
                    JsonValue::from(
                        "restarting the modem in this mode removes its QMI port; \
                         the agent will lose it until the mode is set back to rmnet",
                    )
                },
            }))
        }

        fn reregister_network(&mut self, imei: &str) -> Result<JsonValue, SendError> {
            // 27.007: `AT+COPS=2` detaches, `AT+COPS=0` hands selection back
            // to the module. Detaching is the point — a modem that is
            // attached but passing nothing needs the network to forget it.
            let detached = self.at_exchange(imei, "AT+COPS=2", Some(60_000));
            // Re-attach whatever the detach reported, including a transport
            // error: returning early would leave the modem off-network, which
            // is a worse state than the fault this is meant to clear.
            self.at_ok(imei, "AT+COPS=0", Some(180_000))?;
            // `AT+COPS=0` came back in 62ms on the bench: it starts the
            // search, it does not wait for it. Asking once straight after
            // returns a bare `+COPS: 0` — that is the mode, and says nothing
            // about whether the modem got back on. So wait for an operator to
            // appear, and refuse if none does: a green receipt on a button
            // whose entire job is "get back on the network", beside a modem
            // that is still off it, is the one outcome nobody would check.
            let started = Instant::now();
            let mut serving = Vec::new();
            let mut registered = false;
            while !registered && started.elapsed() < REREGISTER_WAIT {
                if !serving.is_empty() {
                    std::thread::sleep(Duration::from_secs(2));
                }
                let answer = self.at_exchange(imei, "AT+COPS?", Some(30_000))?;
                // The operator's name only shows up once there is one, so a
                // response with no comma after the mode is "not yet".
                registered = answer.lines.iter().any(|line| line.contains(','));
                serving = answer.lines;
            }
            let waited_ms = started.elapsed().as_millis() as u64;
            if !registered {
                return Err(SendError::new(
                    "not_registered",
                    format!(
                        "detached and re-attached, but no operator after {}s: {}",
                        waited_ms / 1000,
                        serving.join(" ")
                    ),
                ));
            }
            json_details(&serde_json::json!({
                "detach": match &detached {
                    Ok(result) => result.terminator.clone(),
                    Err(error) => error.to_string(),
                },
                "serving": serving,
                "waited_ms": waited_ms,
            }))
        }

        fn refresh_modems(&mut self) -> Result<JsonValue, SendError> {
            // Reported before the rescan, not after: this is what the kernel
            // is showing right now, which is the fact an operator is asking
            // about when a stick does not appear. Turning these into
            // inventory entries is the poll loop's job and needs the radio
            // lock, so waiting for it here would park the command thread
            // behind whatever the loop is already doing to another modem.
            let ports = cdc_wdm_paths().map_err(|error| SendError::new("dev_scan_failed", error))?;
            self.radio.request_rescan();
            json_details(&serde_json::json!({
                "found": ports.len(),
                "control_ports": ports
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>(),
                "rescan": "requested",
            }))
        }

        fn list_esim_profiles(&mut self, imei: &str) -> Result<JsonValue, SendError> {
            let result =
                Actions::list_profiles(self, Some(imei.to_string())).map_err(action_failed)?;
            json_details(&result)
        }

        fn switch_esim_profile(
            &mut self,
            imei: &str,
            target_iccid: &str,
        ) -> Result<JsonValue, SendError> {
            Actions::switch_profile(self, Some(imei.to_string()), target_iccid.to_string(), true)
                .map_err(action_failed)?;
            Ok(JsonValue::Null)
        }

        fn configure_proxy(
            &mut self,
            instances: &JsonValue,
            upstreams: &JsonValue,
        ) -> Result<JsonValue, SendError> {
            let instances: Vec<edge_proxy::InstanceSpec> =
                serde_json::from_value(instances.clone())
                    .map_err(|error| SendError::new("bad_proxy_config", error.to_string()))?;
            let upstreams: Vec<edge_proxy::UpstreamSpec> =
                serde_json::from_value(upstreams.clone())
                    .map_err(|error| SendError::new("bad_proxy_config", error.to_string()))?;
            let manager = self.proxies.manager.clone();
            let statuses = self
                .proxies
                .runtime
                .block_on(async move { manager.apply(instances, upstreams).await });
            json_details(&statuses)
        }

        fn proxy_lifecycle(
            &mut self,
            instance_id: &str,
            action: &str,
        ) -> Result<JsonValue, SendError> {
            let manager = self.proxies.manager.clone();
            let id = instance_id.to_string();
            match action {
                "stop" => {
                    let stopped = self
                        .proxies
                        .runtime
                        .block_on(async move { manager.stop(&id).await });
                    if !stopped {
                        return Err(SendError::new(
                            "not_running",
                            format!("no listener {instance_id} is running"),
                        ));
                    }
                    Ok(JsonValue::Null)
                }
                "start" | "restart" => {
                    let status = self
                        .proxies
                        .runtime
                        .block_on(async move { manager.restart(&id).await });
                    match status {
                        // A start needs a configuration to start from, and the
                        // only place one comes from is the cloud.
                        None => Err(SendError::new(
                            "not_configured",
                            format!("no configuration for listener {instance_id}"),
                        )),
                        Some(status) => json_details(&status),
                    }
                }
                other => Err(SendError::new(
                    "unknown_action",
                    format!("proxy action {other} is not start, stop or restart"),
                )),
            }
        }

        fn probe_upstream_proxy(&mut self, upstream_id: &str) -> Result<JsonValue, SendError> {
            // The probe needs the upstream's address and credentials, which
            // only the last applied configuration holds — the cloud sends the
            // id, not the secret, and it should stay that way.
            let manager = self.proxies.manager.clone();
            let id = upstream_id.to_string();
            let upstream = self
                .proxies
                .runtime
                .block_on(async move { manager.upstream(&id).await });
            let upstream = upstream.ok_or_else(|| {
                SendError::new(
                    "unknown_upstream",
                    format!("no upstream {upstream_id} in the applied configuration"),
                )
            })?;
            let result = self.proxies.runtime.block_on(async move {
                edge_proxy::probe::probe(
                    &upstream.address,
                    &upstream.username,
                    &upstream.password,
                    None,
                    std::time::Duration::from_secs(10),
                )
                .await
            });
            json_details(&result)
        }

        fn rotate_ip(&mut self, imei: &str) -> Result<JsonValue, SendError> {
            // Taking the radio down and back up is what makes the network
            // assign a new address; there is no QMI request that says "give me
            // a different IP".
            self.radio.with_client(Some(imei), |client| {
                client
                    .set_operating_mode(OperatingMode::LowPower)
                    .and_then(|_| client.set_operating_mode(OperatingMode::Online))
                    .map_err(|error| SendError::new("rotate_failed", error.to_string()))
            })?;
            Ok(JsonValue::Null)
        }
    }

    fn action_failed(error: PanelError) -> SendError {
        SendError::new("action_failed", error.to_string())
    }

    /// Serialises an action's own result type into the command result.
    ///
    /// A diagnostic whose output cannot be encoded is a failure, not a success
    /// with an empty body: the console would otherwise show a green tick for a
    /// reading nobody can see.
    fn json_details<T: serde::Serialize>(value: &T) -> Result<JsonValue, SendError> {
        serde_json::to_value(value)
            .map_err(|error| SendError::new("details_encode_failed", error.to_string()))
    }

    impl Actions for RadioPort {
        fn send_sms(&self, to: String, body: String, imei: Option<String>) -> Result<(), PanelError> {
            let mut port = RadioPort {
                radio: self.radio.clone(),
                proxies: self.proxies.clone(),
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
                proxies: self.proxies.clone(),
            };
            SendPort::restart_modem(&mut port, &imei)
                .map_err(|error| PanelError::Action(error.to_string()))
        }

        fn set_radio(&self, imei: Option<String>, online: bool) -> Result<(), PanelError> {
            let mode = if online {
                OperatingMode::Online
            } else {
                OperatingMode::LowPower
            };
            self.radio
                .with_client(imei.as_deref(), |client| {
                    client
                        .set_operating_mode(mode)
                        .map_err(|error| SendError::new("radio_failed", error.to_string()))
                })
                .map_err(|error| PanelError::Action(error.to_string()))
        }

        fn ussd(&self, imei: Option<String>, code: String) -> Result<UssdResult, PanelError> {
            self.radio
                .with_at_port(imei.as_deref(), |port| {
                    let started = Instant::now();
                    // Start from a known state. A session left open by an
                    // earlier attempt changes how the module answers the next
                    // request, and the result is a reply that parses into
                    // nothing recognisable. The cancel is best-effort: there is
                    // usually no session to cancel.
                    let _ = port.command(edge_modem::ussd_cancel());
                    let exchange = port
                        .command(&edge_modem::ussd_request(&code))
                        .map_err(|error| SendError::new("ussd_failed", error.to_string()))?;
                    if !exchange.succeeded() {
                        return Err(SendError::new("ussd_rejected", exchange.terminator.clone()));
                    }
                    // Some networks report inside the command response instead
                    // of afterwards, so check what already arrived before
                    // waiting for a separate report.
                    let inline = exchange
                        .lines
                        .iter()
                        .find_map(|line| edge_modem::parse_ussd_reply(line));
                    let reply = match inline {
                        Some(reply) => Some(reply),
                        None => {
                            // The module may answer with a report or reject the
                            // session outright; waiting only for the former
                            // turns a one-second refusal into a full timeout.
                            let line = port
                                .wait_for_any_urc(
                                    &["+CUSD:", "+CME ERROR:", "+CMS ERROR:"],
                                    USSD_TIMEOUT,
                                )
                                .map_err(|error| {
                                    SendError::new("ussd_wait_failed", error.to_string())
                                })?;
                            match line {
                                Some(line) if line.starts_with("+CUSD:") => {
                                    let parsed = edge_modem::parse_ussd_reply(&line);
                                    // A report the parser cannot place is more
                                    // useful shown raw than summarised as
                                    // "other" with mangled text.
                                    match parsed {
                                        Some(reply) => Some(reply),
                                        // A report the parser cannot place is
                                        // more useful shown raw than summarised
                                        // into a shape it does not fit.
                                        None => {
                                            return Err(SendError::new("ussd_unparsed", line));
                                        }
                                    }
                                }
                                Some(line) => {
                                    return Err(SendError::new("ussd_rejected", line));
                                }
                                None => None,
                            }
                        }
                    };
                    let reply = reply.ok_or_else(|| {
                        SendError::new("ussd_no_reply", "network did not answer in time")
                    })?;
                    Ok(UssdResult {
                        code: code.clone(),
                        stage: reply.stage.as_str().to_string(),
                        expects_reply: reply.stage.expects_reply(),
                        text: reply.text,
                        dcs: reply.dcs,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    })
                })
                .map_err(|error| PanelError::Action(error.to_string()))
        }

        fn ussd_cancel(&self, imei: Option<String>) -> Result<(), PanelError> {
            self.radio
                .with_at_port(imei.as_deref(), |port| {
                    port.command(edge_modem::ussd_cancel())
                        .map(|_| ())
                        .map_err(|error| SendError::new("ussd_cancel_failed", error.to_string()))
                })
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
        let (radio, rescans) = Radio::new();
        let proxies = Arc::new(ProxyRuntime::new(radio.clone())?);
        let executor = Arc::new(Mutex::new(CommandExecutor::new(RadioPort {
            radio: radio.clone(),
            proxies: proxies.clone(),
        })));
        let panel_actions = Arc::new(RadioPort {
            radio: radio.clone(),
            proxies: proxies.clone(),
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
                log_error(format!("panel: {error}"));
            }
        });

        let uplink_outbox = outbox.clone();
        let uplink_executor = executor.clone();
        std::thread::spawn(move || uplink_loop(uplink_outbox, uplink_executor, uplink_online));

        log_line(format!(
            "vodoge-edge panel on {} device_id={DEVICE_ID}",
            env("VODOGE_EDGE_PANEL", "0.0.0.0:8743")
        ));
        // Traffic is reported far less often than modems are polled. The
        // cloud buckets it by hour, so a minute's resolution is already finer
        // than anything asked of it, and an idle listener sends nothing at all.
        let mut since_traffic_report = Duration::ZERO;
        let mut last_tick = Instant::now();
        loop {
            if let Err(error) = poll_modems(&shared, &outbox, &radio) {
                log_error(format!("poll: {error}"));
            }
            // Measured rather than assumed to be the poll interval: a rescan
            // request cuts the wait below short, and charging a full interval
            // for a pass that took two seconds would walk the traffic report
            // steadily earlier than the minute it claims.
            let tick = Instant::now();
            since_traffic_report += tick.duration_since(last_tick);
            last_tick = tick;
            if since_traffic_report >= TRAFFIC_REPORT_INTERVAL {
                since_traffic_report = Duration::ZERO;
                if let Err(error) = report_proxy_traffic(&proxies, &outbox) {
                    log_error(format!("proxy traffic: {error}"));
                }
            }
            // `RefreshModems` ends the wait early; timing out is the ordinary
            // case. A disconnected channel cannot happen while any `Radio`
            // handle is alive, but treating it as "poll now" would spin a
            // core, so it falls back to the timer it replaced.
            match rescans.recv_timeout(POLL_INTERVAL) {
                Ok(()) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => std::thread::sleep(POLL_INTERVAL),
            }
        }
    }

    const TRAFFIC_REPORT_INTERVAL: Duration = Duration::from_secs(60);

    /// How long the poll loop waits when nothing asks it to hurry.
    const POLL_INTERVAL: Duration = Duration::from_secs(8);

    /// How long a re-registration waits for the network to take the modem back.
    ///
    /// Generous for LTE, which is usually back inside fifteen seconds, and
    /// still short enough that the command answers rather than occupying the
    /// executor. A modem that has not returned by then is reported as not
    /// registered, which is what it is.
    const REREGISTER_WAIT: Duration = Duration::from_secs(45);

    /// Sends what the listeners carried since the last report.
    ///
    /// Nothing is queued when nothing moved: an envelope per minute per device
    /// saying "zero" would be the bulk of the uplink on a quiet deployment.
    fn report_proxy_traffic(
        proxies: &Arc<ProxyRuntime>,
        outbox: &Arc<Mutex<DurableOutbox>>,
    ) -> Result<(), String> {
        let manager = proxies.manager.clone();
        let deltas = proxies
            .runtime
            .block_on(async move { manager.drain_traffic().await });
        if deltas.is_empty() {
            return Ok(());
        }
        let payload = serde_json::json!({
            "reported_at": unix_ms(),
            "instances": deltas,
        });
        append_kind(outbox, "ProxyTraffic", payload)
    }

    /// The QMI control ports the kernel is currently showing, sorted.
    ///
    /// One modem is one `cdc-wdm`, so this is the whole inventory question:
    /// what is plugged in, before anything has been asked of it. Shared with
    /// `RefreshModems`, which answers that question without probing, so the
    /// rule for what counts as a modem lives in one place.
    fn cdc_wdm_paths() -> Result<Vec<PathBuf>, String> {
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
        Ok(paths)
    }

    fn poll_modems(
        shared: &Arc<SharedStore>,
        outbox: &Arc<Mutex<DurableOutbox>>,
        radio: &Radio,
    ) -> Result<(), String> {
        let paths = cdc_wdm_paths()?;
        if paths.is_empty() {
            return Err("no /dev/cdc-wdm*".into());
        }
        for path in paths {
            match probe_one(&path, shared, outbox, radio) {
                Ok(imei) => log_line(format!("poll {} imei={imei} ok", path.display())),
                Err(error) => log_error(format!("poll {} FAIL {error}", path.display())),
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
        // The model TLV alone is the USB descriptor string on these sticks;
        // the revision is what actually names the hardware. `detect` sorts
        // that out and is unit-tested against the bench modules' real strings.
        let model = client.get_model().unwrap_or_else(|_| "Quectel".into());
        let revision = client
            .get_revision()
            .map(|value| value.device_rev_id)
            .unwrap_or_default();
        let family = ModemFamily::detect(&model, &revision);
        // Unrecognised hardware takes the matrix fallback, so every capability
        // it reports is `unknown`. That is the honest answer but a useless
        // one, and without the strings that produced it there is no way to
        // find out which pattern is missing. Logged only when detection
        // actually falls through, so it stays quiet once a family is known.
        if matches!(family, ModemFamily::Other(_)) {
            log_error(format!(
                "family unrecognised model={model:?} revision={revision:?}"
            ));
        }
        let family_name = family.as_str().to_string();
        // EF_ICCID identifies the active profile. On an eUICC that changes when a
        // different profile is enabled, so it is the only field that says which
        // SIM the modem is actually using. Failing to read it is not fatal, but
        // swallowing the error leaves a blank column with no way to find out why.
        let iccid = match client.read_iccid() {
            Ok(value) => Some(value),
            Err(error) => {
                log_error(format!("iccid {} unavailable: {error}", path.display()));
                None
            }
        };
        // The home network. `serving` below says where the modem is registered,
        // which on a roaming card is a different operator entirely.
        let imsi = client.read_imsi().ok();
        let serving = client.get_serving_system().ok();
        // `Unknown(255)` is the honest answer when the serving system read
        // failed: the module is there, its network status is not known.
        let registration = serving
            .as_ref()
            .map(|s| s.registration_state)
            .unwrap_or(NasRegistrationState::Unknown(255));
        let state = registration.wire().to_string();
        // MCC is always three digits; the rest of a 15-digit IMSI is a
        // two-digit MNC in every network this runs on.
        let home = imsi.as_ref().and_then(|value| {
            let mcc = value.get(0..3)?.parse::<u16>().ok()?;
            let mnc = value.get(3..5)?.parse::<u16>().ok()?;
            Some(Network::new(mcc, mnc))
        });
        let serving_plmn = serving
            .as_ref()
            .and_then(|s| Some(Network::new(s.mcc?, s.mnc?)));
        // QMI has no signal-strength read here, and AT+CSQ is one command on
        // the port that is already paired with this modem. A stick with no
        // signal and a stick whose strength was never read look identical
        // upstream otherwise.
        let signal_dbm = read_signal_dbm(path);
        let now = unix_ms();
        radio.remember(&imei, path);
        {
            let store = shared.0.lock().expect("store");
            store
                .upsert_local_modem(&LocalModem {
                    imei: imei.clone(),
                    family: family_name.clone(),
                    iccid: iccid.clone(),
                    state: state.clone(),
                    last_seen: Some(now),
                    // Already in the serving-system read above; keeping it is
                    // what lets the panel say whose card this is without a
                    // separate probe per stick.
                    mcc: serving_plmn.map(|network| network.mcc),
                    mnc: serving_plmn.map(|network| network.mnc),
                    home_mcc: home.map(|network| network.mcc),
                    home_mnc: home.map(|network| network.mnc),
                    imsi: imsi.clone(),
                })
                .map_err(|e| e.to_string())?;
        }

        let pass = collect_inbound(&mut client).map_err(|e| e.to_string())?;

        // Fragments are joined before anything else sees them. A long message
        // arrives as several PDUs, and storing each one separately gives the
        // operator three truncated messages where the sender wrote one.
        let mut parts = Vec::with_capacity(pass.inbound.len());
        // Every fragment of one message shares its data coding scheme, so the
        // alphabet is recorded per group rather than threaded through
        // reassembly, which has no business knowing about encodings.
        let mut encodings: std::collections::BTreeMap<(String, u16), &'static str> =
            std::collections::BTreeMap::new();
        for message in &pass.inbound {
            let decoded = edge_core::decode_deliver(&message.raw.pdu);
            let (ref_id, total, seq) = decoded.concat.unwrap_or((0, 1, 1));
            encodings.insert((decoded.peer.clone(), ref_id), decoded.encoding);
            parts.push(ConcatPart {
                sender: decoded.peer,
                ref_id,
                total,
                seq,
                body: decoded.body,
            });
        }
        let (assembled, pending) = assemble(&parts);

        // A fragment whose siblings have not arrived stays on the modem, so
        // the next pass can complete it. Deleting it would lose half a message
        // permanently, which is worse than reading it twice.
        let incomplete: std::collections::BTreeSet<(String, u16)> = pending
            .iter()
            .map(|part| (part.sender.clone(), part.ref_id))
            .collect();
        if !incomplete.is_empty() {
            log_line(format!(
                "{} sms fragment(s) awaiting the rest, left on the modem",
                pending.len()
            ));
        }

        for (index, message) in assembled.iter().enumerate() {
            // assemble() drops the reference id, so the encoding is looked up
            // by sender: a single pass never holds two messages from the same
            // sender in different alphabets, and `unknown` is the honest answer
            // if it somehow did.
            let encoding = encodings
                .iter()
                .find(|((sender, _), _)| sender == &message.sender)
                .map(|(_, value)| *value)
                .unwrap_or("unknown");
            let local = LocalMessage {
                seq: (index as u64) + (now as u64 % 1_000_000) * 1000,
                peer: message.sender.clone(),
                body: message.body.clone(),
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
            enqueue_sms(outbox, &imei, &message.sender, &message.body, encoding, now)?;
        }

        // Delete only what was fully assembled.
        let complete: Vec<_> = pass
            .inbound
            .iter()
            .filter(|message| {
                let decoded = edge_core::decode_deliver(&message.raw.pdu);
                match decoded.concat {
                    None => true,
                    Some((ref_id, _, _)) => !incomplete.contains(&(decoded.peer, ref_id)),
                }
            })
            .cloned()
            .collect();
        if !complete.is_empty() {
            let _ = delete_inbound(&mut client, &complete);
        }

        enqueue_device_state(
            outbox,
            &ModemSnapshot {
                imei: &imei,
                registration,
                family: &family_name,
                iccid: iccid.as_deref(),
                imsi: imsi.as_deref(),
                home,
                serving: serving_plmn,
                signal_dbm,
            },
            now,
        )?;
        Ok(imei)
    }

    fn enqueue_sms(
        outbox: &Arc<Mutex<DurableOutbox>>,
        imei: &str,
        peer: &str,
        body: &str,
        encoding: &str,
        now: i64,
    ) -> Result<(), String> {
        let payload = serde_json::json!({
            "modem_imei": imei,
            "peer": peer,
            "body": body,
            "received_at": now,
            "iccid": "",
            // The contract's bearer is how the message was *delivered* —
            // `cs`, `ims` or `nas` — not which radio it arrived on. Messages
            // are read out of modem storage over QMI WMS, which does not say
            // which of those carried it, so the honest answer is `unknown`.
            // It used to send "cellular", which is not in the enum at all.
            "bearer": "unknown",
            // Reported rather than assumed. It was hardcoded to gsm7, which
            // was wrong for every Chinese message on the bench and wrong in a
            // more useful way for binary OTA traffic, where it is the field
            // that explains why the body is hex.
            "encoding": encoding
        });
        append_kind(outbox, "SmsReceived", payload)
    }

    /// One `AT+CSQ` on the control port paired with this QMI node.
    ///
    /// Best effort by design: the poll must not fail because a diagnostic
    /// reading did not come back. A stick whose AT port is busy simply reports
    /// no signal this round.
    fn read_signal_dbm(qmi_path: &Path) -> Option<i16> {
        let at_path = edge_modem::at_port_for_qmi(qmi_path)?;
        let mut port = edge_modem::AtPort::open(&at_path).ok()?;
        let exchange = port.command("AT+CSQ").ok()?;
        if !exchange.succeeded() {
            return None;
        }
        edge_modem::parse_csq(&exchange.lines).and_then(|signal| signal.dbm)
    }

    /// Everything the probe learned about one modem, in the shape the snapshot
    /// needs it. Passing eight positional arguments was how `state` and
    /// `registration` ended up carrying the same value.
    struct ModemSnapshot<'a> {
        imei: &'a str,
        registration: NasRegistrationState,
        family: &'a str,
        iccid: Option<&'a str>,
        imsi: Option<&'a str>,
        /// Who issued the card.
        home: Option<Network>,
        /// Where it is registered right now. Differs from `home` when roaming.
        serving: Option<Network>,
        signal_dbm: Option<i16>,
    }

    fn enqueue_device_state(
        outbox: &Arc<Mutex<DurableOutbox>>,
        modem: &ModemSnapshot<'_>,
        now: i64,
    ) -> Result<(), String> {
        let matrix = CapabilityMatrix::builtin().map_err(|error| error.to_string())?;
        // The matrix is keyed on the home carrier, not the serving one: what a
        // card can do is a property of the subscription, and a roaming card
        // keeps its own operator's rules.
        let carrier = CarrierProfile::from(
            modem
                .home
                .map(|network| network.carrier_profile())
                .unwrap_or("Generic-International"),
        );
        let capability = matrix
            .query(&ModemFamily::from(modem.family), &carrier)
            .capability
            .clone();

        let payload = serde_json::json!({
            "observed_at": now,
            "modems": [{
                "modem_imei": modem.imei,
                // The module answered over QMI, so it is present. Whether it
                // has a network is `registration`, which is a different
                // question and used to be given the same answer.
                "state": "online",
                "registration": modem.registration.wire(),
                // The cloud cannot tell which SIM a modem is using without
                // this. On an eUICC it is also the only field that changes
                // when a profile is switched, so leaving it out makes a switch
                // invisible upstream.
                "iccid": modem.iccid,
                "family": modem.family,
                "imsi": modem.imsi,
                "home_plmn": modem.home.map(|network| network.numeric()),
                "serving_plmn": modem.serving.map(|network| network.numeric()),
                "signal_dbm": modem.signal_dbm,
                "capability": {
                    "sms_mo": capability.sms_mo.wire(),
                    "sms_mt": capability.sms_mt.wire(),
                    "matrix_version": matrix.version()
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
                Ok(()) => log_error("uplink closed, reconnecting"),
                Err(error) => log_error(format!("uplink: {error}")),
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
        log_line(format!("uplink connecting {url}"));
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
                            log_error(format!("command: {error}"));
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
        // The command's own id: it is a UUID, it is the same on every replay
        // so the outbox deduplicates correctly, and there is exactly one
        // result per command. See result_envelope_id in edge-agent.
        let envelope_id = EnvelopeId::new(outcome.result.cmd_id.clone())
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
                id: outcome.result.cmd_id.clone(),
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
