//! Vodoge edge daemon: QMI modems, local panel, WSS uplink.

use std::fs::File;
use std::io::BufReader;
use std::net::ToSocketAddrs;
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
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
    use std::sync::MutexGuard;

    use edge_agent::{CommandExecutor, SendError, SendPort, SmsSend};
    use edge_core::{assemble, CapabilityMatrix, CarrierProfile, ConcatPart, ModemFamily, Network};
    use edge_modem::{
        collect_inbound_sweeping, delete_inbound, encode_submit, CdcWdmDevice,
        NasRegistrationState, OperatingMode, QmiClient,
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

    /// How many stored-message fingerprints are kept per module.
    ///
    /// The ledger has to outlive every message that could still be sitting on
    /// a modem, because forgetting one lets it be stored a second time. A
    /// modem store holds a few hundred entries at most and a fragment leaves
    /// it the first time a delete succeeds, so this is not a trade between
    /// safety and size -- it is more than an order of magnitude past the point
    /// where a dropped entry could ever be met again, and still a table small
    /// enough to keep forever.
    const SMS_LEDGER_KEEP: usize = 5_000;

    /// How many storage slots each pass reads directly.
    ///
    /// The listing cannot name a message anyone has marked read, so the only
    /// way to find one is to read its slot, and a read costs about eight
    /// milliseconds. Reading every slot of both stores on every pass would
    /// spend seconds per module on an uncommon case; thirty-two costs about a
    /// quarter of a second per store.
    const SMS_SWEEP_WINDOW: u32 = 32;

    /// One past the highest storage index worth reading.
    ///
    /// The SIM store on this bench holds fifty and the module store reports
    /// 255. A slot past the end of a store refuses as quickly as any other
    /// miss, so aiming high costs a fraction of a pass while aiming low would
    /// leave part of a store permanently unread.
    const SMS_SWEEP_LIMIT: u32 = 256;

    /// Which window the next pass reads.
    ///
    /// Kept here rather than in the driver because the QMI client is built
    /// fresh for every poll and has nowhere to keep it, and because how much
    /// of a pass to spend on the slow path is a policy question, not a
    /// property of the transport. Shared by all modules on purpose: with
    /// three of them and eight windows the counter is coprime with the
    /// rotation, so each module still walks the whole store, just offset from
    /// the others.
    static SMS_SWEEP_CURSOR: AtomicU32 = AtomicU32::new(0);

    /// One message read off a modem in this pass, with the identity our own
    /// books know it by.
    ///
    /// `slot` is its position in the pass, kept because the row that gets
    /// deleted afterwards has to be the row it was actually read from.
    struct InboundFragment {
        slot: usize,
        encoding: &'static str,
        fingerprint: String,
        part: ConcatPart,
    }

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
            let qmi_path = self.path_for(imei).ok();
            let at_path = match qmi_path
                .as_deref()
                .and_then(edge_modem::at_port_for_qmi)
            {
                Some(path) => path,
                None => at_port_by_imei(imei)?,
            };
            // Busy is keyed by the QMI port because that is what the panel's
            // staleness check compares against. A module with no QMI port is
            // not in that inventory to begin with, so its own port stands in.
            let _busy = self.hold(qmi_path.as_deref().unwrap_or(&at_path));
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
            // Who actually answered on that node.
            //
            // `path_for` returns a remembered `/dev/cdc-wdm*`, and on this
            // bench those names are recycled: the modules arrive over USB/IP,
            // one of them re-enumerates several times an hour, and the index
            // it comes back on is whichever is free. Between two polls the
            // node a command was aimed at can belong to a different SIM, and
            // the command with the worst consequence for getting that wrong
            // is the one that sends a message from it. Costs one DMS read on
            // operator-initiated commands only -- the poll loop opens its own
            // client and does not come through here.
            if let Some(expected) = imei.map(str::trim).filter(|value| !value.is_empty()) {
                let answered = client
                    .get_serial_numbers()
                    .map_err(|error| SendError::new("modem_sync_failed", error.to_string()))?
                    .imei;
                match answered.as_deref() {
                    Some(actual) if actual == expected => {}
                    Some(actual) => {
                        return Err(SendError::new(
                            "modem_moved",
                            format!(
                                "{} is imei {actual} right now, not the imei {expected} this \
                                 command names; refusing to run it on the wrong module",
                                path.display()
                            ),
                        ))
                    }
                    None => {
                        return Err(SendError::new(
                            "modem_moved",
                            format!(
                                "{} would not say which module it is, so it cannot be \
                                 confirmed as imei {expected}",
                                path.display()
                            ),
                        ))
                    }
                }
            }
            work(&mut client)
        }
    }

    /// Turns a failed WMS submit into something an operator can act on.
    ///
    /// `send_failed` is the right word for a module that refused the message.
    /// It is the wrong word for a module that took the message and then left
    /// the bus, which is what IMEI 867018069509705 does on this bench: it
    /// stalls its QMI interrupt endpoint on every MO submit, the USB/IP
    /// session is torn down, and the answer never comes back. The submit
    /// itself is not undone by that -- the SIM's own MO reference counter in
    /// `EF_SMSS` advanced by 34 over a day of sends the console recorded as
    /// failures, and 10086 kept replying to them. Told "failed", an operator
    /// resends and the recipient gets it twice.
    fn describe_send_failure(error: &edge_modem::SessionError) -> SendError {
        if error.left_the_bus_after_the_request() {
            return SendError::new(
                "modem_left_bus_after_submit",
                format!(
                    "{error}. The message was already handed to the module, so it may have \
                     been transmitted; check for a delivery receipt before sending it again."
                ),
            );
        }
        SendError::new("send_failed", error.to_string())
    }

    /// Finds a module's AT port by asking each control port who it is.
    ///
    /// The index the agent normally uses is built from QMI ports, so it has
    /// nothing to say about a module that has no QMI port — one switched out
    /// of rmnet — or about any module at all in the seconds before the first
    /// poll. Both cases used to answer "no matching QMI modem", which left
    /// the undo for a console button sitting behind a shell on the machine.
    ///
    /// Slow, so it is the fallback and not the path: a handful of ports, each
    /// opened and asked, with short timeouts. It runs under the radio lock,
    /// so nothing else is talking to these ports while it does.
    fn at_port_by_imei(imei: Option<&str>) -> Result<PathBuf, SendError> {
        let ports = edge_modem::at_control_ports();
        let Some(imei) = imei.filter(|value| !value.is_empty()) else {
            // No IMEI to match, so the first port that answers is as good an
            // answer as the QMI index would have given.
            return ports
                .into_iter()
                .next()
                .ok_or_else(|| SendError::new("modem_not_found", "no AT control port"));
        };
        for path in &ports {
            let Ok(mut port) = edge_modem::AtPort::open_with_timeout(path, AT_PROBE_TIMEOUT) else {
                continue;
            };
            let Ok(exchange) = port.command_with_timeout("AT+CGSN", AT_PROBE_TIMEOUT) else {
                continue;
            };
            if exchange.lines.iter().any(|line| line.trim() == imei) {
                return Ok(path.clone());
            }
        }
        Err(SendError::new(
            "modem_not_found",
            format!("no QMI port and no AT port answered to imei {imei}"),
        ))
    }

    /// Which USB device a reset is allowed to touch, and on what grounds.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct UsbAim {
        /// Bus position, e.g. `4-3`.
        device: String,
        /// `answering` when the module named itself just now, `remembered`
        /// when the aim rests on a recorded position that nothing
        /// contradicted. The receipt carries this: an operator about to take
        /// a module down is entitled to know how sure the agent is.
        evidence: &'static str,
        /// When the recorded position was observed, for a `remembered` aim.
        recorded_at: Option<i64>,
    }

    /// Decide which USB device `imei` may be reset at.
    ///
    /// `census` is `usb device -> imei` for every module that answered its AT
    /// control port just now. `remembered` is the last recorded position for
    /// this module, and `identity_now` is what sysfs says is at that position
    /// at this moment.
    ///
    /// # Why a recorded position can be trusted this far and no further
    ///
    /// The bench sticks report no USB serial and share one vendor/product
    /// pair, so nothing in the descriptors can tell two of them apart. There
    /// is therefore no way to *prove* that `4-2` is still the module it was
    /// an hour ago without asking the module — and the whole point of this
    /// command is that the module has stopped answering.
    ///
    /// What can be proved is the contrapositive, and it is the property that
    /// actually matters: every module that can still be identified is
    /// excluded from the target. A stick that answers neither QMI nor AT is
    /// by definition not the working modem an operator is afraid of losing.
    /// Add a position that only moves when the stick is re-attached (a
    /// `cdc-wdm` number moves whenever the driver rebinds — the bench watched
    /// `cdc-wdm2` come back on a different stick), a vendor/product pair that
    /// still matches, and a refusal in every other case, and the worst
    /// remaining outcome is resetting one silent module instead of another
    /// silent module.
    ///
    /// Every failure path here is a refusal. There is deliberately no
    /// "only one modem, so it must be that one" branch: the panel can ask for
    /// a reset with no IMEI at all, and the old code answered that by taking
    /// the first entry of a `BTreeMap`.
    fn aim_usb_reset(
        imei: Option<&str>,
        census: &BTreeMap<String, String>,
        remembered: Option<&edge_store::ModemUsbSite>,
        identity_now: Option<&edge_modem::UsbIdentity>,
    ) -> Result<UsbAim, SendError> {
        let Some(imei) = imei.map(str::trim).filter(|value| !value.is_empty()) else {
            return Err(SendError::new(
                "modem_not_specified",
                "a USB reset has to name the modem it is for; there is no default target",
            ));
        };
        if let Some((device, _)) = census.iter().find(|(_, found)| *found == imei) {
            return Ok(UsbAim {
                device: device.clone(),
                evidence: "answering",
                recorded_at: None,
            });
        }
        let Some(site) = remembered else {
            return Err(SendError::new(
                "modem_not_found",
                format!(
                    "imei {imei} did not answer on any control port, \
                     and no USB position was ever recorded for it"
                ),
            ));
        };
        let Some(identity) = identity_now else {
            return Err(SendError::new(
                "modem_not_found",
                format!(
                    "imei {imei} was last seen on USB device {}, which is not on the bus now",
                    site.usb_device
                ),
            ));
        };
        if identity.vendor != site.vendor_id || identity.product != site.product_id {
            return Err(SendError::new(
                "modem_moved",
                format!(
                    "USB device {} now reports {identity}, not the {}:{} recorded for imei {imei}",
                    site.usb_device, site.vendor_id, site.product_id
                ),
            ));
        }
        if let Some(other) = census.get(&site.usb_device) {
            return Err(SendError::new(
                "modem_moved",
                format!(
                    "USB device {} is imei {other} right now, not imei {imei}; \
                     refusing to reset a module that is answering",
                    site.usb_device
                ),
            ));
        }
        Ok(UsbAim {
            device: site.usb_device.clone(),
            evidence: "remembered",
            recorded_at: Some(site.seen_at),
        })
    }

    /// Ask every AT control port who is behind it, right now.
    ///
    /// Deliberately AT and not QMI. Opening a `cdc-wdm` node and sending
    /// `CTL SYNC` is itself how a healthy stick gets desynced — that is how
    /// this bench went from two working modules to one on 2026-08-23 — so a
    /// census taken in order to protect working modules must not use the
    /// channel that breaks them. The AT control interface is present in every
    /// usbnet mode and does not touch the QMI stack.
    ///
    /// Returns `usb device -> imei`, keyed by device because the question
    /// being asked is "who is at this position", not "where is this module".
    /// Ports that do not answer contribute nothing, which is correct: a
    /// silent port is not evidence about anybody.
    ///
    /// The caller must already hold the radio lock.
    fn usb_census() -> BTreeMap<String, String> {
        let mut census = BTreeMap::new();
        for path in edge_modem::at_control_ports() {
            let Some(device) = edge_modem::usb_device_of_at(&path) else {
                continue;
            };
            let Ok(mut port) = edge_modem::AtPort::open_with_timeout(&path, AT_PROBE_TIMEOUT) else {
                continue;
            };
            let Ok(exchange) = port.command_with_timeout("AT+CGSN", AT_PROBE_TIMEOUT) else {
                continue;
            };
            if !exchange.succeeded() {
                continue;
            }
            let Some(imei) = edge_modem::first_bare_digits(&exchange.lines) else {
                continue;
            };
            census.insert(device, imei);
        }
        census
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
        /// The local database, for the one command that has to work when
        /// nothing on the bench will answer. `reset_modem_usb` aims by the
        /// last recorded bus position, and an index that lives only in this
        /// process is empty exactly when it is needed most: the agent had
        /// been restarted, so the two desynced sticks on 2026-08-23 could not
        /// be named at all and the recovery answered `modem_not_found`.
        store: Arc<SharedStore>,
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

        /// Aim a USB recovery and carry it out.
        ///
        /// The single place both callers go through, so the panel and the
        /// cloud cannot end up with two different ideas of what is a legal
        /// target. Nothing here consults `Radio::by_imei`: that index is a
        /// cache of the last successful QMI probe and is never invalidated,
        /// so after a `cdc-wdm` number is reassigned it points at whichever
        /// stick inherited the number. Fine for a status read, not fine for
        /// deciding which module to take down.
        fn recover_usb(
            &self,
            imei: Option<&str>,
        ) -> Result<(UsbAim, edge_modem::UsbReset), SendError> {
            // Held across the whole thing so a poll cannot open the character
            // device while the module is de-authorised, and so the census is
            // taken with nothing else on these ports.
            let _lock = self.radio.lock.lock().expect("radio");
            let census = usb_census();
            let remembered = match imei.map(str::trim).filter(|value| !value.is_empty()) {
                Some(imei) => self
                    .store
                    .0
                    .lock()
                    .expect("store")
                    .modem_usb_site(imei)
                    .map_err(|error| SendError::new("store_unavailable", error.to_string()))?,
                None => None,
            };
            let identity_now = remembered
                .as_ref()
                .and_then(|site| edge_modem::usb_identity(&site.usb_device));
            let aim = aim_usb_reset(imei, &census, remembered.as_ref(), identity_now.as_ref())?;

            // The panel compares its busy marker against `cdc-wdm` paths, so
            // hold the node this device has right now if it has one. Resolved
            // from sysfs rather than from the index: the index is what may be
            // stale, and the point of holding it is to keep the poll loop off
            // this particular device. A module with no QMI node has its bus
            // position stand in, the same way `with_at_port` does.
            let holding = cdc_wdm_paths()
                .unwrap_or_default()
                .into_iter()
                .find(|path| {
                    edge_modem::usb_device_of_qmi(path).as_deref() == Some(aim.device.as_str())
                })
                .unwrap_or_else(|| PathBuf::from(&aim.device));
            let _busy = self.radio.hold(&holding);
            log_line(format!(
                "usb recovery imei={} device={} evidence={} census={}",
                imei.unwrap_or(""),
                aim.device,
                aim.evidence,
                census.len()
            ));
            let reset = edge_modem::recover_usb_device(&aim.device)
                .map_err(|error| SendError::new("usb_reset_failed", error.to_string()))?;
            // The index still holds the `cdc-wdm` path this module had before
            // it went away, and that path is about to belong to whoever the
            // kernel hands the number to next. Ask for a rescan so the poll
            // loop rebuilds it from what is actually on the bus.
            self.radio.request_rescan();
            Ok((aim, reset))
        }

        /// Reads `AT+QCFG="usbnet"` back after the module has re-enumerated.
        ///
        /// The obvious read-back — ask on the port the write just went to —
        /// cannot work on these EC20s. The write is applied on the spot and
        /// takes the module's USB device down with it, so the read lands on a
        /// handle with nothing behind it and sits there until it times out.
        /// Both directions of a working round trip reported `at_failed` that
        /// way, which is the worst shape a receipt can have: the change went
        /// through, and the console said it had not.
        ///
        /// So wait for the module to come back rather than racing it. Every
        /// attempt resolves the port again instead of reusing one, for two
        /// reasons: the numbering moves across a re-enumeration — `ttyUSB10`
        /// came back as `ttyUSB11` — and for every mode but rmnet there is no
        /// QMI port left to resolve through, so `at_port_by_imei` is what
        /// finds it. Failures in the first seconds are the module still
        /// coming up, and are only reported if it never does.
        fn usbnet_readback(&mut self, imei: &str) -> Result<AtResult, SendError> {
            let started = Instant::now();
            let mut last: Option<SendError> = None;
            while started.elapsed() < USBNET_SETTLE {
                std::thread::sleep(USBNET_RETRY);
                match self.at_exchange(imei, "AT+QCFG=\"usbnet\"", Some(USBNET_READ_MS)) {
                    Ok(result) => return Ok(result),
                    Err(error) => last = Some(error),
                }
            }
            Err(last.unwrap_or_else(|| {
                SendError::new(
                    "at_failed",
                    "the module did not answer after the usbnet mode change",
                )
            }))
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

    /// The next TP-MR to put on an outgoing SMS.
    ///
    /// One counter for the whole agent rather than one per module: the field
    /// is eight bits, a receipt is matched by device and recipient as well as
    /// by reference, and a shared counter makes two sends close together
    /// differ even when they leave on different sticks.
    static NEXT_MESSAGE_REFERENCE: AtomicU32 = AtomicU32::new(0);

    impl SendPort for RadioPort {
        fn send_sms(&mut self, send: &SmsSend) -> Result<JsonValue, SendError> {
            // TP-MR, chosen here and reported back. A delivery receipt names
            // the message it is about by this number and by nothing else, so
            // it has to be both known to us and different from the last one:
            // the encoder used to write a constant zero, which would make
            // every receipt on the device point at the same send.
            //
            // Eight bits is all the field has, so it wraps after 256 messages.
            // That is the protocol's limit, not a choice; the cloud narrows a
            // repeat by device and recipient and takes the most recent match.
            let reference = (NEXT_MESSAGE_REFERENCE.fetch_add(1, Ordering::Relaxed) & 0xff) as u8;
            let pdu = encode_submit(&send.to, &send.body, reference)
                .map_err(|error| SendError::new("pdu_encode_failed", error.to_string()))?;
            let assigned = self
                .radio
                .with_client(send.modem_imei.as_deref(), |client| {
                    client.send_sms(0x06, &pdu).map_err(|error| {
                        let described = describe_send_failure(&error);
                        log_error(format!(
                            "sms to {} failed: {} {}",
                            send.to, described.reason_code, described.message
                        ));
                        described
                    })
                })?;
            // The modem answers with the reference it actually used. It is
            // normally the one in the PDU -- RAW_SEND transmits the bytes as
            // given -- but where firmware substitutes its own, the report will
            // quote the firmware's and not ours, so the modem's answer wins
            // and ours is kept alongside to make a disagreement visible.
            if let Some(assigned) = assigned {
                if assigned != u16::from(reference) {
                    log_error(format!(
                        "sms reference {reference} was replaced by the modem with {assigned}"
                    ));
                }
            }
            Ok(serde_json::json!({
                "message_reference": assigned.unwrap_or(u16::from(reference)),
                "requested_reference": reference,
                "status_report_requested": true,
            }))
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
            // Not routed through `Actions::usb_reset`: that shape is the
            // panel's and carries only a device and a node. A destructive
            // action taken from the console has to say what it aimed by and
            // what the bus looked like afterwards, or the only way to find
            // out is to log in to the box — which is the situation this
            // command exists to avoid.
            let (aim, reset) = self.recover_usb(Some(imei))?;
            json_details(&serde_json::json!({
                "device": reset.device,
                "node": reset.node.display().to_string(),
                // `answering` or `remembered`. Worth reading: a remembered
                // aim is the best available guess at a module that has gone
                // silent, not a confirmed identification.
                "evidence": aim.evidence,
                "recorded_at": aim.recorded_at,
                // `reauthorize` or `port_reset`. On this bench the modules
                // arrive over USB/IP, where `vhci_hcd` answers a port reset
                // locally and the module never sees it -- a `USBDEVFS_RESET`
                // on 2026-08-23 left the stick just as desynced as it found
                // it. `reauthorize` unbinds every interface driver and puts
                // `SET_CONFIGURATION` on the wire, which does reach it.
                "recovery": reset.recovery.wire(),
                "devnum_before": reset.devnum_before,
                "devnum_after": reset.devnum_after,
                "returned_after_ms": reset.returned_after_ms,
            }))
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
            // Read back rather than report the value that was sent: nobody can
            // verify this one by looking at the modem, and a wrong write would
            // surface later as a module that came back wearing another face.
            //
            // There is no window to read it back on the port that was written
            // to. The EC20s on the bench apply this on the spot rather than at
            // the next restart — a write of 1 at 03:57:33 took the USB device
            // down in the same second — so the read-back has to wait for the
            // module to re-enumerate and then find it again.
            let readback = self.usbnet_readback(imei)?;
            json_details(&serde_json::json!({
                "mode": mode,
                "value": value,
                "reported": readback.lines,
                // Every mode but rmnet takes away the QMI control port, and
                // that port is how the agent finds a module at all. It comes
                // back through `at_port_by_imei`, which is why this is a
                // warning and not a refusal — but the module does leave the
                // inventory, and it leaves it now, not after a restart.
                "reenumerates": true,
                "warning": if value == 0 {
                    JsonValue::Null
                } else {
                    JsonValue::from(
                        "the modem re-enumerates immediately and loses its QMI port; \
                         it drops out of the inventory until the mode is set back to rmnet",
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
                store: self.store.clone(),
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
            .map(|_| ())
            .map_err(|error| PanelError::Action(error.to_string()))
        }

        fn restart_modem(&self, imei: String) -> Result<(), PanelError> {
            let mut port = RadioPort {
                radio: self.radio.clone(),
                proxies: self.proxies.clone(),
                store: self.store.clone(),
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
            // The panel's shape carries only where the reset landed. The
            // grounds it landed on are in the log line and in the cloud
            // receipt, which is where a destructive action gets read back.
            let (_aim, reset) = self
                .recover_usb(imei.as_deref())
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
            store: shared.clone(),
        })));
        let panel_actions = Arc::new(RadioPort {
            radio: radio.clone(),
            proxies: proxies.clone(),
            store: shared.clone(),
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
        // Carried across passes so the loop can tell "not reported this time"
        // from "gone", and so CPU is a percentage of an interval rather than
        // of all time since boot.
        let mut memory = PollMemory::default();
        loop {
            if let Err(error) = poll_modems(&shared, &outbox, &radio, &mut memory) {
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

    /// How long a module has to come back after a usbnet mode change.
    ///
    /// Re-enumeration on the bench completes in a few seconds; the rest is
    /// margin for a host that is busy enumerating three of these at once.
    /// Spending it is the exceptional path — the first attempt after the
    /// module returns is the one that answers.
    const USBNET_SETTLE: Duration = Duration::from_secs(30);

    /// Gap between read-back attempts while the module is away.
    ///
    /// Long enough that a module mid-enumeration is not hammered with opens,
    /// short enough that the receipt is not padded with waiting.
    const USBNET_RETRY: Duration = Duration::from_secs(2);

    /// Budget for a single usbnet read-back attempt.
    ///
    /// The default would spend ten seconds finding out what a port that is
    /// still gone has to say, which is a third of the settle budget on one
    /// answer already known.
    const USBNET_READ_MS: i64 = 3_000;

    /// Per-port budget when hunting for a module by IMEI.
    ///
    /// A module answers `AT+CGSN` immediately; a port that is going to answer
    /// at all answers well inside this. The budget is spent once per candidate
    /// port, so it is short on purpose.
    const AT_PROBE_TIMEOUT: Duration = Duration::from_millis(800);

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

    /// What the poll loop has to remember between passes.
    ///
    /// A pass on its own can only report what it can currently see, and the
    /// interesting failure on this bench is a module that stops being
    /// visible. Carrying the previous pass is what turns that from an absence
    /// of rows into a reported state.
    #[derive(Default)]
    struct PollMemory {
        /// Every module this process has ever found, by IMEI.
        seen: BTreeMap<String, SeenModem>,
        /// Previous `/proc/stat` totals, so a percentage can be taken over
        /// the interval rather than over all time since boot.
        cpu: Option<CpuTimes>,
        /// Last successful public address lookup and when it happened.
        public_ip: Option<(String, Instant)>,
    }

    /// The last thing known about a module that is not answering now.
    #[derive(Clone, Debug)]
    struct SeenModem {
        family: String,
        /// USB device the module was on, e.g. `2-4.1`. A silent serial port
        /// can be matched back to the module that owns it only through this.
        usb: Option<String>,
    }

    /// Accumulated jiffies from the aggregate line of `/proc/stat`.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct CpuTimes {
        total: u64,
        idle: u64,
    }

    /// How often the public address is looked up.
    ///
    /// It changes when the upstream link renegotiates, which is hours apart,
    /// so asking on every eight-second poll would be one outbound request per
    /// modem-poll for a value that is almost always the same one.
    const PUBLIC_IP_INTERVAL: Duration = Duration::from_secs(300);

    /// How long a public address stays reportable after its last lookup.
    ///
    /// Longer than the refresh interval so one failed lookup does not blank
    /// the field, short enough that a genuinely lost egress path stops being
    /// reported as a working one. A stale address shown as current is worse
    /// than no address: it is the field an operator uses to decide whether
    /// the box is reachable.
    const PUBLIC_IP_TTL: Duration = Duration::from_secs(1_800);

    /// Budget for the whole public address lookup.
    const PUBLIC_IP_TIMEOUT: Duration = Duration::from_secs(5);

    fn poll_modems(
        shared: &Arc<SharedStore>,
        outbox: &Arc<Mutex<DurableOutbox>>,
        radio: &Radio,
        memory: &mut PollMemory,
    ) -> Result<(), String> {
        let now = unix_ms();
        let qmi_paths = cdc_wdm_paths()?;
        let mut snapshots: Vec<ModemSnapshot> = Vec::new();
        // USB devices already accounted for over QMI. A module that answers
        // there is also listed by `at_control_ports`, and without this it
        // would be reported twice under one IMEI -- once managed, once not.
        let mut claimed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

        for path in &qmi_paths {
            match probe_one(path, shared, outbox, radio) {
                Ok(snapshot) => {
                    log_line(format!("poll {} imei={} ok", path.display(), snapshot.imei));
                    if let Some(usb) = edge_modem::usb_device_of_qmi(path) {
                        claimed.insert(usb);
                    }
                    snapshots.push(snapshot);
                }
                // Deliberately not claiming the USB device here. A module
                // whose QMI node is present but unusable is exactly what the
                // AT pass below is for, and skipping it would keep the
                // failure to the one log line it has always been.
                Err(error) => log_error(format!("poll {} FAIL {error}", path.display())),
            }
        }

        // Second enumeration, over serial rather than QMI.
        //
        // The agent indexed modules by `/dev/cdc-wdm*` alone, so a stick in a
        // usbnet mode that exposes no QMI node simply left the fleet, leaving
        // one `poll FAIL` line behind if it left anything at all. That is the
        // shape of the usbnet incident on this bench, and it is also what a
        // brand new module looks like before anybody has set it up.
        for at_path in edge_modem::at_control_ports() {
            let usb = edge_modem::usb_device_of_at(&at_path);
            if let Some(usb) = usb.as_ref() {
                if claimed.contains(usb) {
                    continue;
                }
            }
            match probe_at_only(&at_path, radio) {
                Some(snapshot) => {
                    log_line(format!(
                        "poll {} imei={} at-only",
                        at_path.display(),
                        snapshot.imei
                    ));
                    if let Some(usb) = usb.clone() {
                        claimed.insert(usb);
                    }
                    snapshots.push(snapshot);
                }
                None => {
                    // The port exists in sysfs and did not answer. If a
                    // module was last seen on this USB device the agent can
                    // still name it, which is the difference between
                    // "something is wedged" and "something is wedged, and it
                    // is this IMEI".
                    let known = usb.as_ref().and_then(|usb| {
                        memory
                            .seen
                            .iter()
                            .find(|(_, seen)| seen.usb.as_deref() == Some(usb.as_str()))
                            .map(|(imei, seen)| (imei.clone(), seen.clone()))
                    });
                    match known {
                        Some((imei, seen)) => {
                            log_error(format!(
                                "poll {} silent, last held imei={imei}",
                                at_path.display()
                            ));
                            snapshots.push(absent_snapshot(&imei, &seen, "unknown"));
                            claimed.extend(usb.clone());
                        }
                        None => log_error(format!("poll {} silent, unidentified", at_path.display())),
                    }
                }
            }
        }

        // Modules that answered on an earlier pass and are now nowhere in
        // either enumeration. Reported as offline rather than dropped: a row
        // that stops being updated looks the same as a healthy one to anybody
        // not watching `last_seen`, which is how a missing stick stayed
        // invisible for a whole afternoon.
        //
        // Guarded on having found something, so a pass where scanning itself
        // failed reports nothing rather than declaring the whole fleet gone.
        if !snapshots.is_empty() {
            let present: std::collections::BTreeSet<String> =
                snapshots.iter().map(|s| s.imei.clone()).collect();
            let missing: Vec<(String, SeenModem)> = memory
                .seen
                .iter()
                .filter(|(imei, _)| !present.contains(*imei))
                .map(|(imei, seen)| (imei.clone(), seen.clone()))
                .collect();
            for (imei, seen) in missing {
                log_error(format!("poll imei={imei} absent from both enumerations"));
                snapshots.push(absent_snapshot(&imei, &seen, "offline"));
            }
        }

        for snapshot in &snapshots {
            if snapshot.state == "online" {
                memory.seen.insert(
                    snapshot.imei.clone(),
                    SeenModem {
                        family: snapshot.family.clone(),
                        usb: snapshot.usb.clone(),
                    },
                );
                remember_usb_site(shared, &snapshot.imei, snapshot.usb.as_deref(), now);
            }
        }

        let host = host_stats(memory);
        enqueue_device_state(outbox, &snapshots, &host, now)?;
        if qmi_paths.is_empty() && snapshots.is_empty() {
            return Err("no /dev/cdc-wdm* and no AT control port answered".into());
        }
        Ok(())
    }

    /// Write down where a module was just proven to be.
    ///
    /// Only for snapshots the module itself produced — a `state == "online"`
    /// row means something answered, over QMI or over AT. An `absent_snapshot`
    /// is assembled from memory, and recording its position would turn a
    /// guess into a record and then, later, into the aim of a reset.
    ///
    /// Failure is logged and not propagated: losing this row degrades a
    /// future recovery to a clear refusal, which is a far smaller problem
    /// than a poll pass that stops reporting the fleet.
    fn remember_usb_site(
        shared: &Arc<SharedStore>,
        imei: &str,
        usb: Option<&str>,
        now: i64,
    ) {
        let Some(usb) = usb else { return };
        // Read now rather than assumed: the pair is what a recorded position
        // is checked against later, and recording a remembered value would
        // make that check compare the record with itself.
        let Some(identity) = edge_modem::usb_identity(usb) else {
            return;
        };
        if let Err(error) = shared
            .0
            .lock()
            .expect("store")
            .remember_modem_usb_site(&edge_store::ModemUsbSite {
                imei: imei.to_string(),
                usb_device: usb.to_string(),
                vendor_id: identity.vendor,
                product_id: identity.product,
                seen_at: now,
            })
        {
            log_error(format!("usb position for imei={imei} not recorded: {error}"));
        }
    }

    /// A module the agent knows about but cannot reach right now.
    ///
    /// Everything the contract requires is carried from the last pass that
    /// worked; everything that describes the present is left empty rather
    /// than repeated. Restating a registration or an RSRP from ten minutes
    /// ago as if it were current is how a dead module keeps looking healthy.
    fn absent_snapshot(imei: &str, seen: &SeenModem, state: &'static str) -> ModemSnapshot {
        ModemSnapshot {
            imei: imei.to_string(),
            state,
            registration: "unknown",
            family: seen.family.clone(),
            iccid: None,
            imsi: None,
            home: None,
            serving: None,
            quality: RadioQuality::default(),
            discovery: Discovery::At,
            manageable: false,
            usb: seen.usb.clone(),
        }
    }

    /// Identify a module through its AT control port alone.
    ///
    /// `AT+CGSN` and `AT+CIMI` answer on a port that is present in every
    /// usbnet mode, including the ones with no `cdc-wdm` at all, so a module
    /// that has dropped out of QMI can still say who it is. That is the whole
    /// of what this reports: it is a name and a signal reading, not a claim
    /// that anything can be done with the module.
    ///
    /// Returns `None` when the port did not yield an IMEI. The contract makes
    /// `modem_imei` required and the cloud projection keys on it, so there is
    /// no shape in which a nameless module can be reported -- and inventing
    /// an identifier for one would put a row in the fleet that matches no
    /// hardware.
    fn probe_at_only(at_path: &Path, radio: &Radio) -> Option<ModemSnapshot> {
        let _busy = radio.lock.lock().expect("radio");
        let mut port =
            edge_modem::AtPort::open_with_timeout(at_path, AT_PROBE_TIMEOUT.max(Duration::from_secs(2)))
                .ok()?;
        let exchange = port.command("AT+CGSN").ok()?;
        if !exchange.succeeded() {
            return None;
        }
        let imei = edge_modem::first_bare_digits(&exchange.lines)?;
        let imsi = port
            .command("AT+CIMI")
            .ok()
            .filter(edge_modem::AtExchange::succeeded)
            .and_then(|exchange| edge_modem::first_bare_digits(&exchange.lines));
        // Same derivation as the QMI path: MCC is three digits and every
        // network this runs on has a two digit MNC.
        let home = imsi.as_ref().and_then(|value| {
            let mcc = value.get(0..3)?.parse::<u16>().ok()?;
            let mnc = value.get(3..5)?.parse::<u16>().ok()?;
            Some(Network::new(mcc, mnc))
        });
        let family = port
            .command("AT+CGMM")
            .ok()
            .filter(edge_modem::AtExchange::succeeded)
            .and_then(|exchange| exchange.lines.first().map(|line| line.trim().to_string()))
            .filter(|model| !model.is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        // Packet-switched registration first: this is an LTE module and
        // `+CEREG` is the domain it actually attaches on. `+CREG` is the
        // fallback for a module that answered nothing there.
        let registration = registration_over_at(&mut port, "AT+CEREG?", "+CEREG:")
            .or_else(|| registration_over_at(&mut port, "AT+CREG?", "+CREG:"))
            .unwrap_or("unknown");
        let quality = read_radio_quality_on(&mut port);
        Some(ModemSnapshot {
            imei,
            // It answered, so it is present. What it is not is manageable:
            // every structured operation in this agent goes over QMI.
            state: "online",
            registration,
            family,
            iccid: None,
            imsi,
            home,
            // Serving network comes from the QMI serving-system read, which
            // is exactly what is unavailable here.
            serving: None,
            quality,
            discovery: Discovery::At,
            manageable: false,
            usb: edge_modem::usb_device_of_at(at_path),
        })
    }

    /// One `+CREG`-shaped query, mapped onto the contract's vocabulary.
    fn registration_over_at(
        port: &mut edge_modem::AtPort,
        command: &str,
        prefix: &str,
    ) -> Option<&'static str> {
        let exchange = port.command(command).ok()?;
        if !exchange.succeeded() {
            return None;
        }
        let state = edge_modem::parse_creg(&exchange.lines, prefix)?;
        Some(match state {
            edge_modem::Registration::Home | edge_modem::Registration::Roaming => "registered",
            edge_modem::Registration::Searching => "searching",
            edge_modem::Registration::Denied => "denied",
            edge_modem::Registration::NotRegistered => "unregistered",
            edge_modem::Registration::Unknown => "unknown",
        })
    }

    /// The edge host's own vitals.
    ///
    /// Every field is optional and independently so: a box whose `/proc` is
    /// readable but whose egress is down should still report its memory.
    fn host_stats(memory: &mut PollMemory) -> HostStats {
        let sample = std::fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|text| parse_proc_stat(&text));
        let cpu_percent = match (memory.cpu, sample) {
            (Some(previous), Some(current)) => cpu_percent_between(previous, current),
            _ => None,
        };
        if let Some(current) = sample {
            memory.cpu = Some(current);
        }
        let memory_reading = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|text| parse_meminfo(&text));

        let stale = memory
            .public_ip
            .as_ref()
            .map(|(_, at)| at.elapsed() >= PUBLIC_IP_INTERVAL)
            .unwrap_or(true);
        if stale {
            if let Some(address) = lookup_public_ip() {
                memory.public_ip = Some((address, Instant::now()));
            }
        }
        let public_ip = memory
            .public_ip
            .as_ref()
            .filter(|(_, at)| at.elapsed() < PUBLIC_IP_TTL)
            .map(|(address, _)| address.clone());

        HostStats {
            public_ip,
            cpu_percent,
            memory_used_bytes: memory_reading.map(|(total, available)| {
                total.saturating_sub(available)
            }),
            memory_total_bytes: memory_reading.map(|(total, _)| total),
        }
    }

    /// The aggregate `cpu` line of `/proc/stat`.
    ///
    /// Idle counts both `idle` and `iowait`: a box blocked on a disk is not
    /// doing work, and counting iowait as busy makes a quiet edge box read as
    /// loaded every time it flushes the outbox.
    fn parse_proc_stat(text: &str) -> Option<CpuTimes> {
        let line = text.lines().find(|line| line.starts_with("cpu "))?;
        let fields: Vec<u64> = line
            .split_whitespace()
            .skip(1)
            .filter_map(|field| field.parse::<u64>().ok())
            .collect();
        if fields.len() < 5 {
            return None;
        }
        let total: u64 = fields.iter().sum();
        let idle = fields[3] + fields[4];
        Some(CpuTimes { total, idle })
    }

    /// Busy share of the interval between two `/proc/stat` samples.
    ///
    /// Returns nothing when the counters did not advance or went backwards.
    /// The first case is a sample taken twice within one tick, the second is
    /// a counter reset; reporting either as 0% or as a wild number would be
    /// a measurement of the sampler rather than of the machine.
    fn cpu_percent_between(previous: CpuTimes, current: CpuTimes) -> Option<f64> {
        let total = current.total.checked_sub(previous.total)?;
        let idle = current.idle.checked_sub(previous.idle)?;
        if total == 0 || idle > total {
            return None;
        }
        let busy = total - idle;
        Some(((busy as f64) * 100.0 / (total as f64) * 10.0).round() / 10.0)
    }

    /// `MemTotal` and `MemAvailable` from `/proc/meminfo`, in bytes.
    ///
    /// `MemAvailable` rather than `MemFree`: free memory on Linux is mostly
    /// page cache, so a healthy box reports almost none of it and looks
    /// permanently out of memory.
    fn parse_meminfo(text: &str) -> Option<(u64, u64)> {
        let mut total = None;
        let mut available = None;
        for line in text.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let kib = value
                .split_whitespace()
                .next()
                .and_then(|field| field.parse::<u64>().ok());
            match key {
                "MemTotal" => total = kib,
                "MemAvailable" => available = kib,
                _ => {}
            }
        }
        Some((total?.saturating_mul(1024), available?.saturating_mul(1024)))
    }

    /// Ask an outside service what address this box comes from.
    ///
    /// The answer is the one thing about the egress path that cannot be
    /// determined locally: the box sees a private address on every interface
    /// it owns. Plain HTTP on purpose -- the endpoint is the same one the
    /// runbook's `curl -s ifconfig.me` uses, so the console and a shell agree
    /// by construction, and adding a TLS root store to this binary for a
    /// value that is published to the world anyway is not worth the
    /// dependency.
    fn lookup_public_ip() -> Option<String> {
        let url = env("VODOGE_PUBLIC_IP_URL", "http://ifconfig.me/ip");
        let body = http_get(&url, PUBLIC_IP_TIMEOUT)?;
        public_ip_from_body(&body)
    }

    /// The address out of a response body, or nothing.
    ///
    /// Parsed as an address rather than trimmed and trusted: these endpoints
    /// answer an HTML page to clients they do not recognise, and a page of
    /// markup stored as somebody's public IP is a worse outcome than an empty
    /// column.
    fn public_ip_from_body(body: &str) -> Option<String> {
        let candidate = body.trim();
        if candidate.is_empty() || candidate.len() > 45 {
            return None;
        }
        candidate.parse::<std::net::IpAddr>().ok().map(|address| address.to_string())
    }

    /// Minimal HTTP/1.1 GET returning the response body.
    ///
    /// Deliberately small: this binary has no HTTP client and pulling one in
    /// for a single fixed request would add a dependency tree larger than the
    /// agent. Anything other than a plain `200` is treated as no answer.
    fn http_get(url: &str, budget: Duration) -> Option<String> {
        let rest = url.strip_prefix("http://")?;
        let (authority, path) = match rest.split_once('/') {
            Some((authority, path)) => (authority, format!("/{path}")),
            None => (rest, "/".to_string()),
        };
        let host = authority.split(':').next()?.to_string();
        let target = if authority.contains(':') {
            authority.to_string()
        } else {
            format!("{authority}:80")
        };
        use std::io::{Read as _, Write as _};
        let address = target.to_socket_addrs().ok()?.next()?;
        let mut stream = std::net::TcpStream::connect_timeout(&address, budget).ok()?;
        stream.set_read_timeout(Some(budget)).ok()?;
        stream.set_write_timeout(Some(budget)).ok()?;
        // A user agent the endpoint recognises. Left blank, ifconfig.me
        // answers an HTML page instead of the address.
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).ok()?;
        let mut response = String::new();
        // Bounded read: a body this size is already two orders of magnitude
        // more than an address, and an endpoint that streams forever must not
        // hold the poll loop.
        let mut limited = std::io::Read::take(stream, 8192);
        limited.read_to_string(&mut response).ok()?;
        let (head, body) = response.split_once("\r\n\r\n")?;
        if !head.lines().next()?.contains(" 200") {
            return None;
        }
        Some(body.to_string())
    }

    fn probe_one(
        path: &Path,
        shared: &Arc<SharedStore>,
        outbox: &Arc<Mutex<DurableOutbox>>,
        radio: &Radio,
    ) -> Result<ModemSnapshot, String> {
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
        let at_pass = read_at_pass(path);
        let quality = at_pass.quality;
        let now = unix_ms();
        radio.remember(&imei, path);

        // Delivery receipts, before the inbox sweep and before anything can
        // return early. A receipt settles a message the console is already
        // showing as sent, so losing one leaves that message looking stuck
        // forever -- there is no second copy and the network does not resend.
        for report in &at_pass.reports {
            if report.peer.is_empty() {
                log_error(format!(
                    "status report ref={} has no recipient address; nothing to settle",
                    report.reference
                ));
                continue;
            }
            enqueue_status_report(outbox, &imei, report, now)?;
        }
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

        // One window of slots read directly, on top of the listing. Windows
        // are aligned so a rotation covers the store exactly, with no slot
        // read twice before every other slot has been read once.
        let sweep_window = SMS_SWEEP_CURSOR.fetch_add(1, Ordering::Relaxed)
            % (SMS_SWEEP_LIMIT / SMS_SWEEP_WINDOW);
        let pass = collect_inbound_sweeping(
            &mut client,
            sweep_window * SMS_SWEEP_WINDOW,
            SMS_SWEEP_WINDOW,
        )
        .map_err(|e| e.to_string())?;

        // Fragments are joined before anything else sees them. A long message
        // arrives as several PDUs, and storing each one separately gives the
        // operator three truncated messages where the sender wrote one.
        //
        // Every message the modem holds is decoded first, read and unread
        // alike, and only then are our own books asked which of them have
        // already been stored. The modem's read flag is consulted nowhere:
        // anything that reads a message flips it -- the console's AT terminal,
        // a diagnostic, our own troubleshooting -- and the collector used to
        // ask the modem for unread messages only, so a single `AT+CMGR` made a
        // message invisible to every later pass while it went on occupying a
        // storage slot. Read state is the modem's; what we have stored is
        // ours.
        let mut fragments: Vec<InboundFragment> = Vec::with_capacity(pass.inbound.len());
        for (slot, message) in pass.inbound.iter().enumerate() {
            let decoded = edge_core::decode_deliver(&message.raw.pdu);
            // The coding scheme, and what was made of it.
            //
            // `encoding` travels all the way to the console and the database,
            // and nothing recorded the byte it was derived from -- so a wrong
            // label could not be checked afterwards, because the message is
            // deleted from the modem within a poll of being read. Four
            // decoding faults stayed hidden for weeks for want of this line.
            // The header only: the body is the one part of a message that
            // does not belong in a log read this widely.
            log_line(format!(
                "sms from={} dcs={} encoding={} bytes={} udh={}",
                decoded.peer,
                decoded
                    .dcs
                    .map(|dcs| format!("{dcs:#04x}"))
                    .unwrap_or_else(|| "none".into()),
                decoded.encoding,
                message.raw.pdu.len(),
                decoded.concat.is_some()
            ));
            let (ref_id, total, seq) = decoded.concat.unwrap_or((0, 1, 1));
            let fingerprint = edge_modem::fragment_fingerprint(
                &decoded.peer,
                decoded.received_at,
                ref_id,
                total,
                seq,
                &decoded.body,
            );
            fragments.push(InboundFragment {
                slot,
                encoding: decoded.encoding,
                fingerprint,
                part: ConcatPart {
                    sender: decoded.peer,
                    ref_id,
                    total,
                    seq,
                    body: decoded.body,
                    received_at: decoded.received_at,
                },
            });
        }

        // What this module has had stored before, for exactly the fragments in
        // front of us. Asked per fingerprint rather than by loading the ledger
        // because a pass holds tens of rows and the ledger holds thousands.
        let ingested = {
            let store = shared.0.lock().expect("store");
            let mut counts: BTreeMap<String, u32> = BTreeMap::new();
            for fragment in &fragments {
                if counts.contains_key(&fragment.fingerprint) {
                    continue;
                }
                let copies = store
                    .ingested_sms_copies(&imei, &fragment.fingerprint)
                    .map_err(|e| e.to_string())?;
                if copies > 0 {
                    counts.insert(fragment.fingerprint.clone(), copies);
                }
            }
            counts.into_iter().collect::<std::collections::HashMap<_, _>>()
        };
        let seen = edge_modem::seen_before(
            &fragments
                .iter()
                .map(|fragment| fragment.fingerprint.clone())
                .collect::<Vec<_>>(),
            &ingested,
        );

        let mut parts = Vec::with_capacity(fragments.len());
        // Every fragment of one message shares its data coding scheme, so the
        // alphabet is recorded per fragment and read back off the fragment the
        // assembled message names. Looking it up by sender, as this did, gave
        // whichever alphabet that sender's *first* message of the pass used --
        // and this bench routinely holds several from 10086 in one pass.
        let mut encodings: Vec<&'static str> = Vec::with_capacity(fragments.len());
        let mut fingerprints: Vec<String> = Vec::with_capacity(fragments.len());
        // Where each fragment handed to `assemble` sits in the pass, so the
        // delete afterwards names the storage row it actually came from.
        let mut slots: Vec<usize> = Vec::with_capacity(fragments.len());
        let mut settled: Vec<edge_modem::CollectedMessage> = Vec::new();
        for (fragment, stored_before) in fragments.into_iter().zip(seen) {
            if stored_before {
                if let Some(row) = pass.inbound.get(fragment.slot) {
                    settled.push(row.clone());
                }
                continue;
            }
            encodings.push(fragment.encoding);
            fingerprints.push(fragment.fingerprint);
            slots.push(fragment.slot);
            parts.push(fragment.part);
        }

        // Rows our books already account for. A previous pass stored them and
        // the delete that should have followed did not take -- or somebody
        // read them out from under us. Storing them again would show the
        // operator the same message twice, so the slot is cleared instead.
        if !settled.is_empty() {
            log_line(format!(
                "{} sms already stored, clearing the modem's copy",
                settled.len()
            ));
            let _ = delete_inbound(&mut client, &settled);
        }

        let (assembled, pending) = assemble(&parts, now, edge_core::FRAGMENT_GRACE_MS);

        // A fragment whose siblings have not arrived stays on the modem, so
        // the next pass can complete it. Deleting it would lose half a message
        // permanently, which is worse than reading it twice.
        if !pending.is_empty() {
            log_line(format!(
                "{} sms fragment(s) awaiting the rest, left on the modem",
                pending.len()
            ));
        }

        for (index, message) in assembled.iter().enumerate() {
            if !message.missing.is_empty() {
                // Loud, because this is the one path that stores something the
                // sender did not write. It happens only after the grace period
                // and only for fragments the network never delivered.
                log_error(format!(
                    "sms from={} released after {} h with part(s) {:?} of {} never delivered",
                    message.sender,
                    edge_core::FRAGMENT_GRACE_MS / 3_600_000,
                    message.missing,
                    message.parts
                ));
            }
            // The alphabet of the fragment this message was built from. Every
            // fragment of one message shares its coding scheme, so the first
            // source answers for all of them.
            let encoding = message
                .sources
                .first()
                .and_then(|slot| encodings.get(*slot).copied())
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

        // Write down what was stored, then delete exactly those rows, and both
        // only after the loop above returned without an error -- a delete that
        // runs before the message is in the database loses it for good, and
        // there is no second copy anywhere.
        //
        // The ledger entry goes in before the delete, not after, and for the
        // same reason the delete goes last: the delete is the step that can
        // fail. A pass that stored a message and then failed to clear it will
        // meet that message again, and the entry written here is what stops it
        // from being stored twice.
        //
        // Named by position rather than re-derived from the PDU: two
        // deliveries can share a sender and a reference, so a filter on that
        // pair would sweep away a fragment that is still waiting for its
        // siblings along with the message that is done.
        let sources: Vec<usize> = assembled
            .iter()
            .flat_map(|message| message.sources.iter().copied())
            .collect();
        let stored_fingerprints: Vec<String> = sources
            .iter()
            .filter_map(|part| fingerprints.get(*part).cloned())
            .collect();
        let stored: Vec<_> = sources
            .iter()
            .filter_map(|part| slots.get(*part).copied())
            .filter_map(|slot| pass.inbound.get(slot).cloned())
            .collect();
        if !stored_fingerprints.is_empty() {
            let store = shared.0.lock().expect("store");
            store
                .record_ingested_sms(&imei, &stored_fingerprints, now)
                .map_err(|e| e.to_string())?;
            store
                .prune_ingested_sms(&imei, SMS_LEDGER_KEEP)
                .map_err(|e| e.to_string())?;
        }
        if !stored.is_empty() {
            let _ = delete_inbound(&mut client, &stored);
        }

        Ok(ModemSnapshot {
            imei,
            // The module answered over QMI, so it is present and drivable.
            // Whether it has a network is `registration`, which is a
            // different question that used to be given the same answer.
            state: "online",
            registration: registration.wire(),
            family: family_name,
            iccid,
            imsi,
            home,
            serving: serving_plmn,
            quality,
            discovery: Discovery::Qmi,
            usb: edge_modem::usb_device_of_qmi(path),
            manageable: true,
        })
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

    /// What one AT pass over a module's control port produced.
    struct AtPass {
        quality: RadioQuality,
        reports: Vec<edge_core::StatusReport>,
    }

    impl Default for AtPass {
        fn default() -> Self {
            Self {
                quality: RadioQuality::default(),
                reports: Vec::new(),
            }
        }
    }

    /// `AT+CSQ`, `AT+QCSQ` and the delivery-receipt store, on one open.
    ///
    /// Best effort by design: the poll must not fail because a diagnostic
    /// reading did not come back. A stick whose AT port is busy simply
    /// reports no quality and no receipts this round.
    ///
    /// All of it shares one open. These are asked of the same port a fraction
    /// of a second apart, and opening it repeatedly multiplies the chance of
    /// colliding with a command the console is running on the same port.
    fn read_at_pass(qmi_path: &Path) -> AtPass {
        let Some(at_path) = edge_modem::at_port_for_qmi(qmi_path) else {
            return AtPass::default();
        };
        let Ok(mut port) = edge_modem::AtPort::open(&at_path) else {
            return AtPass::default();
        };
        AtPass {
            quality: read_radio_quality_on(&mut port),
            reports: collect_status_reports(&mut port),
        }
    }

    /// Reads and clears the module's delivery receipts.
    ///
    /// Receipts are not in the inbox. `AT+CPMS=?` on these EC20s offers four
    /// stores -- ME, MT, SM, SR -- and a status report goes to SR, which QMI
    /// WMS cannot name at all: its storage enum is UIM and NV, so the QMI
    /// sweep that collects arriving messages will never see one. That is why
    /// this lives on the serial side rather than beside collect_inbound.
    ///
    /// Everything listed is deleted, decoded or not. The store holds a few
    /// hundred and every outbound message now asks for a receipt, so a reader
    /// that left behind what it could not parse would fill it and then stop
    /// receiving -- a fault that appears days later and looks like receipts
    /// going missing at random.
    fn collect_status_reports(port: &mut edge_modem::AtPort) -> Vec<edge_core::StatusReport> {
        if !enable_status_reports(port) {
            return Vec::new();
        }
        let Some(used) = select_report_store(port) else {
            return Vec::new();
        };
        if used == 0 {
            restore_message_store(port);
            return Vec::new();
        }

        let mut reports = Vec::new();
        // PDU mode. Text mode renders a status report as fields the module has
        // already interpreted, and TP-MR -- the only thing that ties it to a
        // send -- is not among them.
        if !at_ok(port, "AT+CMGF=0") {
            restore_message_store(port);
            return reports;
        }
        let listing = match port.command("AT+CMGL=4") {
            Ok(exchange) if exchange.succeeded() => exchange.lines,
            _ => {
                restore_message_store(port);
                return reports;
            }
        };

        let mut indexes = Vec::new();
        let mut pending_index: Option<u32> = None;
        for line in &listing {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("+CMGL:") {
                pending_index = rest
                    .split(',')
                    .next()
                    .and_then(|value| value.trim().parse::<u32>().ok());
                continue;
            }
            let Some(index) = pending_index.take() else {
                continue;
            };
            indexes.push(index);
            let Some(bytes) = decode_hex(line) else {
                log_error(format!("status report {index} is not hex: {line}"));
                continue;
            };
            // The bytes are logged whatever happens to them. A receipt is one
            // short line, one per sent message, and when a delivery lands on
            // the wrong conversation or on none the PDU is the only evidence
            // of what the network actually said.
            match edge_core::decode_status_report(&bytes) {
                Some(report) => {
                    log_line(format!(
                        "status report index={index} ref={} peer={} status={} code={:#04x} pdu={}",
                        report.reference, report.peer, report.status, report.status_code, line
                    ));
                    reports.push(report);
                }
                None => log_error(format!("status report {index} undecodable: pdu={line}")),
            }
        }

        for index in indexes {
            if !at_ok(port, &format!("AT+CMGD={index}")) {
                log_error(format!(
                    "status report {index} not deleted; the store will fill"
                ));
            }
        }
        restore_message_store(port);
        reports
    }

    /// Turns delivery receipts on, if they are not already.
    ///
    /// Two settings, both persistent per module, both off on this bench:
    ///
    /// AT+CSMS=1 selects phase 2+, without which the module has no way to hand
    /// a status report over at all. It read 0 on all three sticks.
    ///
    /// The fourth parameter of AT+CNMI is the one for status reports, and it
    /// read 0 -- discard. 2 stores the report and notifies, which is what this
    /// wants. 1 would deliver it straight to whichever serial port happens to
    /// be open, and in phase 2+ that also obliges the reader to acknowledge
    /// every one with +CNMA before the module will accept the next; a poll
    /// that opens the port for a moment every eight seconds would lose most of
    /// them and wedge the rest. Only that one parameter is touched, so the
    /// arriving-message path keeps whatever it was set to.
    fn enable_status_reports(port: &mut edge_modem::AtPort) -> bool {
        let service = at_fields(port, "AT+CSMS?", "+CSMS:")
            .and_then(|fields| fields.first().and_then(|value| value.parse::<u8>().ok()));
        if service != Some(1) && !at_ok(port, "AT+CSMS=1") {
            log_error("AT+CSMS=1 refused; delivery receipts stay off".to_string());
            return false;
        }
        let Some(cnmi) = at_fields(port, "AT+CNMI?", "+CNMI:") else {
            return false;
        };
        if cnmi.len() < 4 {
            return false;
        }
        if cnmi[3] == "2" {
            return true;
        }
        let bfr = cnmi.get(4).map(String::as_str).unwrap_or("0");
        let command = format!("AT+CNMI={},{},{},2,{}", cnmi[0], cnmi[1], cnmi[2], bfr);
        if !at_ok(port, &command) {
            log_error(format!("{command} refused; delivery receipts stay off"));
            return false;
        }
        true
    }

    /// Points reads and deletes at the status-report store, returning how many
    /// are in it. Only the read store moves, so where arriving messages are
    /// written is left exactly as it was.
    fn select_report_store(port: &mut edge_modem::AtPort) -> Option<u32> {
        at_fields(port, "AT+CPMS=\"SR\"", "+CPMS:")
            .and_then(|fields| fields.first().and_then(|value| value.parse::<u32>().ok()))
    }

    /// Puts the read store back so a console AT session finds the module as it
    /// was.
    fn restore_message_store(port: &mut edge_modem::AtPort) {
        let _ = port.command("AT+CPMS=\"ME\"");
    }

    fn at_ok(port: &mut edge_modem::AtPort, command: &str) -> bool {
        port.command(command)
            .map(|exchange| exchange.succeeded())
            .unwrap_or(false)
    }

    /// Runs a query and splits the named response line on commas.
    ///
    /// Quotes are stripped, so a caller never has to know which fields the
    /// module chose to quote. +CPMS answers with them and +CSMS without.
    fn at_fields(
        port: &mut edge_modem::AtPort,
        command: &str,
        prefix: &str,
    ) -> Option<Vec<String>> {
        let exchange = port.command(command).ok()?;
        if !exchange.succeeded() {
            return None;
        }
        let line = exchange
            .lines
            .iter()
            .find(|line| line.trim_start().starts_with(prefix))?;
        Some(
            line.trim_start()
                .trim_start_matches(prefix)
                .split(',')
                .map(|field| field.trim().trim_matches('"').to_string())
                .collect(),
        )
    }

    fn decode_hex(text: &str) -> Option<Vec<u8>> {
        let text = text.trim();
        if text.is_empty() || text.len() % 2 != 0 {
            return None;
        }
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
            .collect()
    }

    /// Queues one delivery receipt for the cloud.
    ///
    /// Deliberately its own uplink kind rather than a variant of SmsReceived.
    /// They are different events with different projections -- one inserts a
    /// message, the other settles one that already exists -- and folding them
    /// together would also fire the "new SMS" notification for every receipt.
    fn enqueue_status_report(
        outbox: &Arc<Mutex<DurableOutbox>>,
        imei: &str,
        report: &edge_core::StatusReport,
        now: i64,
    ) -> Result<(), String> {
        let mut payload = serde_json::json!({
            "modem_imei": imei,
            "peer": report.peer,
            "reference": report.reference,
            "status": report.status,
            "status_code": report.status_code,
            "reported_at": now,
        });
        // Absent rather than zero when the module gave a timestamp that is not
        // BCD. A discharge time of 1970 on an operator's screen is worse than
        // none, because it looks like an answer.
        if let Some(map) = payload.as_object_mut() {
            if let Some(at) = report.delivered_at {
                map.insert("delivered_at".into(), serde_json::json!(at));
            }
            if let Some(at) = report.submitted_at {
                map.insert("submitted_at".into(), serde_json::json!(at));
            }
        }
        append_kind(outbox, "SmsStatusReport", payload)
    }

    /// The same two readings on a port that is already open.
    ///
    /// Split out because the unmanaged path has a port but no QMI node to
    /// find one from, and reporting signal for managed modules only would
    /// leave the sticks an operator is most worried about as the blank ones.
    fn read_radio_quality_on(port: &mut edge_modem::AtPort) -> RadioQuality {
        let mut quality = RadioQuality::default();
        if let Ok(exchange) = port.command("AT+CSQ") {
            if exchange.succeeded() {
                quality.dbm = edge_modem::parse_csq(&exchange.lines).and_then(|signal| signal.dbm);
            }
        }
        // Quectel's own reading. `AT+CSQ` pegs at index 31 for every module on
        // this bench, so it cannot tell a good link from a saturated one;
        // RSRP, RSRQ and SINR are what stage 4 needs to explain a call that
        // set up and then sounded bad.
        if let Ok(exchange) = port.command("AT+QCSQ") {
            if exchange.succeeded() {
                if let Some(qcsq) = edge_core::parse_qcsq(&exchange.lines) {
                    quality.rsrp = qcsq.rsrp_dbm;
                    quality.rsrq = qcsq.rsrq_db;
                    quality.sinr = qcsq.sinr_db;
                }
            }
        }
        quality
    }

    /// What one module's radio reported about itself.
    #[derive(Clone, Copy, Debug, Default)]
    struct RadioQuality {
        /// Converted from the `AT+CSQ` index. Saturates near a tower.
        dbm: Option<i16>,
        rsrp: Option<i16>,
        rsrq: Option<i16>,
        sinr: Option<i16>,
    }

    /// How a module was found, which decides what can be asked of it.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Discovery {
        /// Answered on its QMI control node: the agent can drive it.
        Qmi,
        /// Only its AT control port answered. Everything the agent does over
        /// QMI -- eSIM, SMS, serving system -- is out of reach until it is
        /// back on a usbnet mode that exposes a `cdc-wdm`.
        At,
    }

    impl Discovery {
        fn wire(self) -> &'static str {
            match self {
                Self::Qmi => "qmi",
                Self::At => "at",
            }
        }
    }

    /// Everything the probe learned about one modem, in the shape the snapshot
    /// needs it. Passing eight positional arguments was how `state` and
    /// `registration` ended up carrying the same value.
    ///
    /// Owned rather than borrowed because a pass now collects every module
    /// before sending anything: one envelope per pass is what makes the
    /// payload a fleet inventory instead of three separate claims about one
    /// device, each overwriting the last.
    #[derive(Clone, Debug)]
    struct ModemSnapshot {
        imei: String,
        /// Contract `state`: whether the module is answering at all. This was
        /// the literal string "online" for every module the agent managed to
        /// talk to, which left the other three values in the enum unreachable
        /// and anything keyed on them testing a path that could not happen.
        state: &'static str,
        registration: &'static str,
        family: String,
        iccid: Option<String>,
        imsi: Option<String>,
        /// Who issued the card.
        home: Option<Network>,
        /// Where it is registered right now. Differs from `home` when roaming.
        serving: Option<Network>,
        quality: RadioQuality,
        discovery: Discovery,
        /// USB device the module sits on, e.g. `2-4.1`. Carried so a later
        /// pass can match a silent serial port back to the module that owns
        /// it, which is the only way to name hardware that has stopped
        /// answering.
        usb: Option<String>,
        /// Whether the agent can currently carry out commands against it.
        manageable: bool,
    }

    /// The edge host itself, as opposed to the radios plugged into it.
    #[derive(Clone, Debug, Default)]
    struct HostStats {
        public_ip: Option<String>,
        cpu_percent: Option<f64>,
        memory_used_bytes: Option<u64>,
        memory_total_bytes: Option<u64>,
    }

    fn enqueue_device_state(
        outbox: &Arc<Mutex<DurableOutbox>>,
        modems: &[ModemSnapshot],
        host: &HostStats,
        now: i64,
    ) -> Result<(), String> {
        if modems.is_empty() {
            // The contract requires at least one modem and there is nothing
            // honest to invent. A pass that found no hardware at all says so
            // in the log and sends nothing.
            return Ok(());
        }
        let matrix = CapabilityMatrix::builtin().map_err(|error| error.to_string())?;
        let mut entries = Vec::with_capacity(modems.len());
        for modem in modems {
            // The matrix is keyed on the home carrier, not the serving one:
            // what a card can do is a property of the subscription, and a
            // roaming card keeps its own operator's rules.
            let carrier = CarrierProfile::from(
                modem
                    .home
                    .map(|network| network.carrier_profile())
                    .unwrap_or("Generic-International"),
            );
            let capability = matrix
                .query(&ModemFamily::from(modem.family.as_str()), &carrier)
                .capability
                .clone();
            entries.push(serde_json::json!({
                "modem_imei": modem.imei,
                "state": modem.state,
                "registration": modem.registration,
                // The cloud cannot tell which SIM a modem is using without
                // this. On an eUICC it is also the only field that changes
                // when a profile is switched, so leaving it out makes a switch
                // invisible upstream.
                "iccid": modem.iccid,
                "family": modem.family,
                "imsi": modem.imsi,
                "home_plmn": modem.home.map(|network| network.numeric()),
                "serving_plmn": modem.serving.map(|network| network.numeric()),
                "signal_dbm": modem.quality.dbm,
                "rsrp": modem.quality.rsrp,
                "rsrq": modem.quality.rsrq,
                "sinr": modem.quality.sinr,
                "discovery": modem.discovery.wire(),
                "manageable": modem.manageable,
                "capability": {
                    "sms_mo": capability.sms_mo.wire(),
                    "sms_mt": capability.sms_mt.wire(),
                    "matrix_version": matrix.version()
                }
            }));
        }
        let payload = serde_json::json!({
            "observed_at": now,
            "modems": entries,
            "host": {
                "public_ip": host.public_ip,
                "cpu_percent": host.cpu_percent,
                "memory_used_bytes": host.memory_used_bytes,
                "memory_total_bytes": host.memory_total_bytes,
            }
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

    #[cfg(test)]
    mod host_tests {
        use super::*;

        #[test]
        fn cpu_totals_count_iowait_as_idle() {
            let text = "cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4 5\n";
            let parsed = parse_proc_stat(text).expect("parsed");
            assert_eq!(parsed.total, 1000);
            // idle 800 + iowait 50: a box blocked on a disk is not working.
            assert_eq!(parsed.idle, 850);
        }

        #[test]
        fn cpu_percent_is_taken_over_the_interval() {
            let previous = CpuTimes {
                total: 1000,
                idle: 900,
            };
            let current = CpuTimes {
                total: 2000,
                idle: 1650,
            };
            // 1000 jiffies passed, 750 of them idle.
            assert_eq!(cpu_percent_between(previous, current), Some(25.0));
        }

        #[test]
        fn a_counter_that_did_not_move_reports_nothing() {
            let same = CpuTimes {
                total: 1000,
                idle: 900,
            };
            assert_eq!(cpu_percent_between(same, same), None);
        }

        #[test]
        fn a_counter_that_went_backwards_reports_nothing() {
            let previous = CpuTimes {
                total: 2000,
                idle: 1000,
            };
            let current = CpuTimes {
                total: 1000,
                idle: 500,
            };
            assert_eq!(cpu_percent_between(previous, current), None);
        }

        #[test]
        fn memory_uses_available_not_free() {
            let text = concat!(
                "MemTotal:        2048000 kB\n",
                "MemFree:           64000 kB\n",
                "MemAvailable:    1024000 kB\n",
                "Buffers:           16000 kB\n"
            );
            let (total, available) = parse_meminfo(text).expect("parsed");
            assert_eq!(total, 2_048_000 * 1024);
            assert_eq!(available, 1_024_000 * 1024);
            // Free is a tenth of available here; reporting it would say the
            // box is nearly out of memory when it is half used.
            assert_eq!(total - available, 1_024_000 * 1024);
        }

        #[test]
        fn meminfo_without_the_fields_reports_nothing() {
            assert_eq!(parse_meminfo("Buffers: 16000 kB\n"), None);
        }

        #[test]
        fn a_public_address_is_parsed_not_trusted() {
            assert_eq!(
                public_ip_from_body("203.0.113.7\n"),
                Some("203.0.113.7".to_string())
            );
            assert_eq!(
                public_ip_from_body("  2001:db8::1  "),
                Some("2001:db8::1".to_string())
            );
        }

        #[test]
        fn a_page_of_markup_is_not_an_address() {
            // What these endpoints answer to a client they do not recognise.
            assert_eq!(public_ip_from_body("<!DOCTYPE html><html>"), None);
            assert_eq!(public_ip_from_body(""), None);
            assert_eq!(public_ip_from_body("not an address"), None);
        }

        #[test]
        fn an_absent_module_carries_its_name_and_nothing_current() {
            let seen = SeenModem {
                family: "EC20".to_string(),
                usb: Some("2-4.1".to_string()),
            };
            let snapshot = absent_snapshot("867018069509705", &seen, "offline");
            assert_eq!(snapshot.imei, "867018069509705");
            assert_eq!(snapshot.state, "offline");
            assert_eq!(snapshot.family, "EC20");
            assert!(!snapshot.manageable);
            // Nothing about the present is restated from the last good pass.
            assert_eq!(snapshot.registration, "unknown");
            assert_eq!(snapshot.iccid, None);
            assert_eq!(snapshot.serving, None);
            assert_eq!(snapshot.quality.rsrp, None);
        }

        #[test]
        fn discovery_spells_itself_the_way_the_contract_does() {
            assert_eq!(Discovery::Qmi.wire(), "qmi");
            assert_eq!(Discovery::At.wire(), "at");
        }
    }

    /// Aiming a USB recovery.
    ///
    /// Everything here is about a command that takes hardware down. The bench
    /// has three sticks, no second set, and nobody who can reach them, so the
    /// tests are written from the losing side: what must this refuse to do.
    #[cfg(test)]
    mod usb_aim_tests {
        use super::*;

        const ALIVE: &str = "867018069509705";
        const WEDGED: &str = "862547055142811";
        const OTHER: &str = "867018069514820";

        fn quectel() -> edge_modem::UsbIdentity {
            edge_modem::UsbIdentity {
                vendor: "2c7c".into(),
                product: "0125".into(),
            }
        }

        fn site(imei: &str, device: &str) -> edge_store::ModemUsbSite {
            edge_store::ModemUsbSite {
                imei: imei.into(),
                usb_device: device.into(),
                vendor_id: "2c7c".into(),
                product_id: "0125".into(),
                seen_at: 1_787_000_000_000,
            }
        }

        fn census(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(device, imei)| ((*device).to_string(), (*imei).to_string()))
                .collect()
        }

        /// The reason this card exists. Neither QMI nor AT can name the
        /// module, and the recovery still has to find it.
        #[test]
        fn a_silent_module_is_still_found_by_its_recorded_position() {
            let aim = aim_usb_reset(
                Some(WEDGED),
                &census(&[("4-3", ALIVE)]),
                Some(&site(WEDGED, "4-2")),
                Some(&quectel()),
            )
            .expect("aimed");
            assert_eq!(aim.device, "4-2");
            assert_eq!(aim.evidence, "remembered");
            assert_eq!(aim.recorded_at, Some(1_787_000_000_000));
        }

        /// A module that answers is identified, not looked up. The record is
        /// not even consulted, so a stale one cannot override the truth.
        #[test]
        fn a_module_that_answers_is_taken_at_its_word() {
            let aim = aim_usb_reset(
                Some(ALIVE),
                &census(&[("4-3", ALIVE)]),
                Some(&site(ALIVE, "4-1")),
                Some(&quectel()),
            )
            .expect("aimed");
            assert_eq!(aim.device, "4-3");
            assert_eq!(aim.evidence, "answering");
            assert_eq!(aim.recorded_at, None);
        }

        /// Red against the behaviour this replaces.
        ///
        /// `Radio::path_for(None)` answered a missing IMEI with
        /// `map.values().next()` — the first entry of a `BTreeMap` — and the
        /// local panel's reset endpoint takes `imei` as an `Option`. So a
        /// `POST /api/usb-reset {}` used to take down whichever module sorted
        /// first. There is no safe default target for this command.
        #[test]
        fn a_reset_with_no_target_named_is_refused() {
            for missing in [None, Some(""), Some("  ")] {
                let error = aim_usb_reset(
                    missing,
                    &census(&[("4-1", OTHER), ("4-2", WEDGED), ("4-3", ALIVE)]),
                    None,
                    None,
                )
                .expect_err("a reset with no target must be refused");
                assert_eq!(error.reason_code, "modem_not_specified");
            }
        }

        /// Nothing answered and nothing was ever recorded. The honest answer
        /// is that the module cannot be located, not a guess at the only
        /// device on the bus.
        #[test]
        fn an_unknown_module_is_refused_even_when_one_device_is_free() {
            let error = aim_usb_reset(
                Some(WEDGED),
                &census(&[("4-3", ALIVE)]),
                None,
                Some(&quectel()),
            )
            .expect_err("refused");
            assert_eq!(error.reason_code, "modem_not_found");
            assert!(
                error.message.contains("no USB position was ever recorded"),
                "{}",
                error.message
            );
        }

        /// A record whose device is gone is a record, not a target. Resetting
        /// "the closest thing still there" is how the wrong stick gets hit.
        #[test]
        fn a_recorded_position_that_is_empty_now_is_refused() {
            let error = aim_usb_reset(Some(WEDGED), &census(&[]), Some(&site(WEDGED, "4-2")), None)
                .expect_err("refused");
            assert_eq!(error.reason_code, "modem_not_found");
            assert!(error.message.contains("4-2"), "{}", error.message);
        }

        /// Something else is at that position now. Different hardware, so the
        /// record says nothing about it.
        #[test]
        fn a_position_holding_different_hardware_is_refused() {
            let error = aim_usb_reset(
                Some(WEDGED),
                &census(&[]),
                Some(&site(WEDGED, "4-2")),
                Some(&edge_modem::UsbIdentity {
                    vendor: "0e0f".into(),
                    product: "0002".into(),
                }),
            )
            .expect_err("refused");
            assert_eq!(error.reason_code, "modem_moved");
            assert!(error.message.contains("0e0f:0002"), "{}", error.message);
        }

        /// The one that matters most. Sticks do get re-enumerated onto other
        /// positions, and a stale record then points at a module that is
        /// perfectly healthy. Losing a working modem to a recovery aimed at a
        /// broken one is worse than not recovering the broken one.
        #[test]
        fn a_stale_record_never_takes_down_a_module_that_is_answering() {
            let error = aim_usb_reset(
                Some(WEDGED),
                &census(&[("4-2", ALIVE)]),
                Some(&site(WEDGED, "4-2")),
                Some(&quectel()),
            )
            .expect_err("refused");
            assert_eq!(error.reason_code, "modem_moved");
            assert!(error.message.contains(ALIVE), "{}", error.message);
            assert!(
                error.message.contains("refusing to reset a module that is answering"),
                "{}",
                error.message
            );
        }

        /// The record may be stale in the other direction too: the module has
        /// moved and is answering somewhere else. Its current position wins,
        /// and the position it used to hold is left alone.
        #[test]
        fn a_module_that_moved_is_reset_where_it_is_now() {
            let aim = aim_usb_reset(
                Some(ALIVE),
                &census(&[("4-1", ALIVE)]),
                Some(&site(ALIVE, "4-3")),
                Some(&quectel()),
            )
            .expect("aimed");
            assert_eq!(aim.device, "4-1");
            assert_eq!(aim.evidence, "answering");
        }

        /// A census with nothing in it means every port is silent, which is
        /// the shape of the 2026-08-23 bench. The recorded position is then
        /// the only evidence there is, and it is allowed to be used.
        #[test]
        fn a_wholly_silent_bench_can_still_be_aimed_at() {
            let aim = aim_usb_reset(
                Some(WEDGED),
                &census(&[]),
                Some(&site(WEDGED, "4-2")),
                Some(&quectel()),
            )
            .expect("aimed");
            assert_eq!(aim.device, "4-2");
            assert_eq!(aim.evidence, "remembered");
        }
    }

    /// Reporting a send that the module took and then died on.
    ///
    /// Written from the bench failure of 2026-08-23: every `send_sms` on IMEI
    /// 867018069509705 came back `send_failed: QMI transport error: cdc-wdm
    /// poll revents 0x18`, twenty-three times in eight hours, while the
    /// messages themselves were reaching 10086 and being answered.
    #[cfg(test)]
    mod send_failure_tests {
        use super::*;

        /// The exact failure the console recorded all day, and the two things
        /// its old wording got wrong: it said "failed" for a message that had
        /// already been handed over, and it said it in `revents` hex.
        #[test]
        fn a_module_that_left_the_bus_mid_send_is_not_reported_as_a_refusal() {
            let error = edge_modem::SessionError::Disconnected {
                device: "/dev/cdc-wdm2".into(),
                awaiting_response: true,
            };
            let described = describe_send_failure(&error);
            assert_eq!(described.reason_code, "modem_left_bus_after_submit");
            assert!(
                described.message.contains("may have been transmitted"),
                "an operator deciding whether to resend has to be told: {}",
                described.message
            );
            assert!(
                !described.message.contains("revents"),
                "the hex mask is not the finding: {}",
                described.message
            );
        }

        /// A module that was already gone before the write is a different
        /// story: nothing was submitted, and resending is the right move.
        #[test]
        fn a_module_that_was_gone_before_the_write_is_an_ordinary_failure() {
            let error = edge_modem::SessionError::Disconnected {
                device: "/dev/cdc-wdm2".into(),
                awaiting_response: false,
            };
            assert_eq!(describe_send_failure(&error).reason_code, "send_failed");
        }

        /// Everything the module itself answered stays exactly as it was.
        #[test]
        fn a_refusal_from_the_module_keeps_its_own_words() {
            let error = edge_modem::SessionError::transport("timed out waiting for QMI response");
            let described = describe_send_failure(&error);
            assert_eq!(described.reason_code, "send_failed");
            assert!(described.message.contains("timed out"));
        }
    }
}
