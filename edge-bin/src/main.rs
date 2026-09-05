//! Vodoge edge daemon: QMI modems, local panel, WSS uplink.

use std::fs::File;
use std::io::BufReader;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
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
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
    use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
    use std::sync::MutexGuard;

    use edge_agent::{CommandExecutor, SendError, SendPort, SmsSend};
    use edge_core::{
        CapabilityMatrix, CapabilityOrigin, CarrierProfile, ConcatPart, ModemFamily, Network,
    };
    use edge_modem::{
        collect_inbound_sweeping, delete_inbound, encode_submit, CdcWdmDevice, Es9pClient,
        EsimLocalInfo, NasRegistrationState, OperatingMode, QmiClient,
    };
    use edge_panel::{
        log_error, log_line, serve, Actions, AtResult, CandidateClaimResult, Inbox, PanelError,
        ProfileBody, ProfilesResult, RegistrationResult, ReportResult, RescanResult, ScanResult,
        ScannedOperatorBody, UsbResetResult, UssdResult,
    };
    use edge_store::{
        CardPolicy as StoredCardPolicy, DurableOutbox, LocalMessage, LocalModem,
        LocalModemDiscovery, ManualModemProfile, QueueError, Store,
    };
    use edge_uplink::dial::{DialError, Socket};
    use edge_uplink::session::{Inbound, LinkConfig, Phase, ResumeSnapshot};
    use edge_uplink::tls::client_config;
    use edge_uplink::worker::{Outbox, RetainedRecord, UplinkWorker};
    use edge_uplink::{EnvelopeId, RetentionClass, UplinkAck, UplinkError};
    use rustls_pemfile::{certs, pkcs8_private_keys};
    use serde_json::Value as JsonValue;
    use vodoge_contract::{
        CardPolicy as ContractCardPolicy, Envelope, EsimInventoryPayload, MessageKind,
        PROTOCOL_VERSION,
    };

    const DEVICE_ID: &str = "b0000000-0000-4000-8000-00000000000b";

    /// Primary UICC slot. These modules expose one card slot, and the eUICC
    /// always sits in it.
    const ESIM_SLOT: u8 = 1;

    /// How many times the chip is read back after a profile switch.
    ///
    /// An upper bound on patience, not a prediction. A REFRESH is a card
    /// re-initialisation rather than a module restart, and nobody has timed one
    /// on this bench — T031 switched twice and saw registration return without
    /// a single poll, which says it is quick but not how quick. Three attempts
    /// bound the extra time a switch takes at roughly three seconds.
    const ESIM_READBACK_ATTEMPTS: usize = 3;

    /// The gap between those attempts.
    ///
    /// The 1.5s `edge-modem` already gives a module to act on a mode change
    /// before a read-back is believed. Borrowed rather than measured, and said
    /// so: `readback_attempts` in the result is what will eventually replace
    /// this reasoning with a number.
    const ESIM_READBACK_GAP: Duration = Duration::from_millis(1_500);

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
    struct SharedStore(Mutex<Store>);

    impl Inbox for SharedStore {
        fn list_messages(&self) -> Result<Vec<LocalMessage>, PanelError> {
            self.0
                .lock()
                .expect("store")
                .list_local_messages()
                .map_err(PanelError::Store)
        }
        /// What the panel lists: the modules somebody adopted, not every
        /// module ever seen. Reading `list_local_modems` here is what kept
        /// showing hardware that had been unplugged and unregistered.
        fn list_modems(&self) -> Result<Vec<LocalModem>, PanelError> {
            self.0
                .lock()
                .expect("store")
                .list_managed_modems()
                .map_err(PanelError::Store)
        }
        /// 每根已纳管模组当前的闸标记。
        ///
        /// 逐根读而不是一次 JOIN：`gate_failure` 是按 IMEI 的单行查询，而
        /// 注册表在这台机器上是个位数。为一个位数的循环去开一个新查询，
        /// 换来的是它和 `enforce_registration` 读的是同一个函数 ——
        /// 面板显示的和判定依据的，不会有两套 SQL 各自演化。
        fn list_gate_failures(
            &self,
        ) -> Result<std::collections::BTreeMap<String, edge_store::GateFailure>, PanelError> {
            let store = self.0.lock().expect("store");
            let mut out = std::collections::BTreeMap::new();
            for row in store.registered_modems().map_err(PanelError::Store)? {
                if let Some(gate) = store.gate_failure(&row.imei).map_err(PanelError::Store)? {
                    out.insert(row.imei, gate);
                }
            }
            Ok(out)
        }

        fn retro_enforcing(&self) -> bool {
            // 同一个函数，不是同一条规则的第二份抄写。
            enforce_mode() == EnforceMode::Unbind
        }

        fn list_retirements(&self) -> Result<Vec<edge_store::Retirement>, PanelError> {
            self.0
                .lock()
                .expect("store")
                .list_retirements()
                .map_err(PanelError::Store)
        }

        fn list_modem_discoveries(&self) -> Result<Vec<LocalModemDiscovery>, PanelError> {
            self.0
                .lock()
                .expect("store")
                .list_local_modem_discoveries()
                .map_err(PanelError::Store)
        }
    }

    #[derive(Clone)]
    struct Radio {
        /// Serialises every conversation with a module, with AKA jumping the
        /// queue. See `edge_modem::ModemArbiter`: the tunnel process now asks
        /// for the same port on a timed protocol path, so "first waiter wins"
        /// stopped being good enough.
        arbiter: Arc<edge_modem::ModemArbiter>,
        by_imei: Arc<Mutex<BTreeMap<String, PathBuf>>>,
        /// Device currently held by an operator-initiated command.
        ///
        /// A band scan keeps the radio for over a minute, which is longer than
        /// the panel's staleness window, so without this the panel reports a
        /// modem as offline while it is busy doing exactly what was asked.
        busy: Arc<Mutex<Option<PathBuf>>>,
        /// Live packet data sessions, keyed by IMEI.
        ///
        /// 🔴 **The QMI client in here is why this map exists.** A packet data
        /// handle is owned by the client that started it, so the session ends
        /// the moment that client is released -- which is what every other
        /// operation on this bench does, because `with_client` opens a device,
        /// does its work and drops it. A data path has to outlive the call
        /// that asked for it, so the client is parked here and stays open.
        sessions: Arc<Mutex<BTreeMap<String, DataSession>>>,
        /// Asks the poll loop to look for modems now.
        ///
        /// Capacity one, and a full channel is not an error: a pending rescan
        /// is already what a second request wanted. Queueing one rescan per
        /// click would make an impatient operator wait longer, not less.
        rescan: SyncSender<()>,
    }

    /// One running packet data session and everything it took to make it.
    struct DataSession {
        /// Kept open for the session's lifetime. Dropping it ends the session.
        client: QmiClient<CdcWdmDevice>,
        handle: edge_modem::PacketDataHandle,
        interface: String,
        address: String,
        prefix: u8,
        gateway: Option<String>,
    }

    impl DataSession {
        fn describe(&self) -> serde_json::Value {
            serde_json::json!({
                "interface": self.interface,
                "address": self.address,
                "prefix": self.prefix,
                "gateway": self.gateway,
            })
        }
    }

    /// Run one `ip` invocation, naming what failed.
    fn run_step(step: &edge_modem::Step) -> Result<(), SendError> {
        let output = std::process::Command::new(step.program)
            .args(&step.args)
            .output()
            .map_err(|error| {
                SendError::new(
                    "data_plane_tool_missing",
                    format!("{}: {error}", step.program),
                )
            })?;
        if output.status.success() || step.tolerant {
            return Ok(());
        }
        // The tool's own message, not the exit code: "RTNETLINK answers: File
        // exists" and "Network is unreachable" are different faults and the
        // number is the same.
        Err(SendError::new(
            "data_plane_step_failed",
            format!(
                "{} {}: {}",
                step.program,
                step.args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ))
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
                arbiter: Arc::new(edge_modem::ModemArbiter::new()),
                by_imei: Arc::new(Mutex::new(BTreeMap::new())),
                busy: Arc::new(Mutex::new(None)),
                sessions: Arc::new(Mutex::new(BTreeMap::new())),
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

        /// Bring a module's data path up: QMI session, then the interface.
        ///
        /// The APN comes from the module's own context 1 rather than from the
        /// caller. That is the context these modules dial on, it is what
        /// `configure_apn` writes, and taking one here would let the data path
        /// use a name that is not in the table an operator can see.
        fn start_data(&self, imei: &str, apn: &str) -> Result<serde_json::Value, SendError> {
            let _lock = self.arbiter.acquire(edge_modem::ModemPriority::Normal);
            let path = self.path_for(Some(imei))?;
            let _busy = self.hold(&path);
            let sysfs = Path::new("/sys");
            let interface = edge_modem::interface_for(sysfs, &path).ok_or_else(|| {
                SendError::new(
                    "no_data_interface",
                    format!("{} has no wwan interface behind it", path.display()),
                )
            })?;

            // Down before the framing changes: `raw_ip` returns EBUSY on a live
            // interface, and an interface left in Ethernet framing passes no
            // traffic while looking entirely healthy.
            run_step(&edge_modem::Step {
                program: "ip",
                args: vec![
                    "link".into(),
                    "set".into(),
                    interface.clone(),
                    "down".into(),
                ],
                tolerant: false,
            })?;
            let raw_ip = edge_modem::raw_ip_path(sysfs, &interface);
            std::fs::write(&raw_ip, b"Y").map_err(|error| {
                SendError::new("raw_ip_refused", format!("{}: {error}", raw_ip.display()))
            })?;

            let device = CdcWdmDevice::open(&path)
                .map_err(|error| SendError::new("modem_open_failed", error.to_string()))?;
            let mut client = QmiClient::new(device);
            client
                .sync()
                .map_err(|error| SendError::new("modem_sync_failed", error.to_string()))?;
            // Before the session, and before anything is written to the
            // interface: the modem has to be told the same framing the sysfs
            // toggle just set on the host. Without this the two disagree and
            // every packet is dropped in both directions while every status
            // command reports a healthy connection.
            let settled = client
                .set_data_format(edge_modem::LinkLayer::RawIp)
                .map_err(|error| SendError::new("data_format_refused", error.to_string()))?;
            if settled != edge_modem::LinkLayer::RawIp {
                return Err(SendError::new(
                    "data_format_mismatch",
                    format!("the modem kept {settled:?} framing while the host is raw-ip"),
                ));
            }
            let handle = client
                .start_data_session(apn, None, None, edge_modem::AuthPreference::None)
                .map_err(|error| SendError::new("data_session_failed", error.to_string()))?;
            let settings = client
                .data_settings()
                .map_err(|error| SendError::new("data_settings_failed", error.to_string()))?;

            let address = settings
                .address
                .map(std::net::Ipv4Addr::from)
                .ok_or_else(|| {
                    SendError::new("no_address_assigned", "the session carried no IPv4 address")
                })?;
            let prefix = settings.prefix_length().unwrap_or(32);
            let gateway = settings
                .gateway
                .map(std::net::Ipv4Addr::from)
                .map(|v| v.to_string());
            let view = edge_modem::Ipv4View {
                address: address.to_string(),
                prefix,
                gateway: gateway.clone(),
                mtu: settings.mtu,
            };
            // A half-configured interface is worse than an unconfigured one: it
            // has an address, so everything downstream reads it as connected.
            // Undo before reporting.
            for step in edge_modem::bring_up(&interface, &view) {
                if let Err(error) = run_step(&step) {
                    // ⚠️ 回滚失败**必须留痕**。上一行注释写着「半配置的接口
                    //    比没配置的更糟：它有地址，下游一律读成已连接」——而
                    //    这正是回滚没跑完时的样子。静默吞掉的话，接口停在半
                    //    配置状态，屏幕上和日志里都没有任何东西说过这件事。
                    for undo in edge_modem::tear_down(&interface, Some(&view.address)) {
                        if let Err(undo_error) = run_step(&undo) {
                            eprintln!(
                                "data-plane rollback step failed on {interface}:                                  {undo_error} (interface may be half-configured)"
                            );
                        }
                    }
                    return Err(error);
                }
            }

            let session = DataSession {
                client,
                handle,
                interface,
                address: address.to_string(),
                prefix,
                gateway,
            };
            let described = session.describe();
            self.sessions
                .lock()
                .expect("sessions")
                .insert(imei.to_owned(), session);
            Ok(described)
        }

        /// Take a module's data path down, and forget the session.
        fn stop_data(&self, imei: &str) -> Result<serde_json::Value, SendError> {
            let _lock = self.arbiter.acquire(edge_modem::ModemPriority::Normal);
            let mut session = match self.sessions.lock().expect("sessions").remove(imei) {
                Some(session) => session,
                None => {
                    return Err(SendError::new(
                        "no_data_session",
                        "this agent is not holding a data session for that module",
                    ))
                }
            };
            // The interface comes down whatever the modem says: leaving a
            // stale address on a link whose session has ended is worse than a
            // failed stop, because everything after it looks connected.
            let mut trouble: Option<SendError> = None;
            if let Err(error) = session.client.stop_data_session(session.handle) {
                trouble = Some(SendError::new("data_stop_failed", error.to_string()));
            }
            for step in edge_modem::tear_down(&session.interface, Some(&session.address)) {
                if let Err(error) = run_step(&step) {
                    trouble.get_or_insert(error);
                }
            }
            match trouble {
                Some(error) => Err(error),
                None => Ok(serde_json::json!({ "interface": session.interface })),
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
            self.with_at_port_at(imei, edge_modem::ModemPriority::Normal, work)
        }

        /// The same, for a caller that says how urgent it is.
        ///
        /// Only USIM authentication asks for anything but `Normal`, and it
        /// does so because its deadline belongs to a remote peer rather than
        /// to us: an ePDG or an IMS core drops the exchange while our request
        /// is still queued behind a band scan, and the failure surfaces
        /// nowhere near the queue that caused it.
        fn with_at_port_at<T>(
            &self,
            imei: Option<&str>,
            priority: edge_modem::ModemPriority,
            work: impl FnOnce(&mut edge_modem::AtPort) -> Result<T, SendError>,
        ) -> Result<T, SendError> {
            let _lock = self.arbiter.acquire(priority);
            let qmi_path = self.path_for(imei).ok();
            let at_path = match qmi_path.as_deref().and_then(edge_modem::at_port_for_qmi) {
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
            // Normal priority, and that includes eUICC logical-channel work:
            // an AKA challenge must never land in the middle of an ES10
            // sequence, so the two are mutually exclusive here rather than
            // merely ordered.
            let _lock = self.arbiter.acquire(edge_modem::ModemPriority::Normal);
            let path = self.path_for(imei)?;
            let _busy = self.hold(&path);
            let device = CdcWdmDevice::open(&path)
                .map_err(|error| SendError::new("modem_open_failed", error.to_string()))?;
            let mut client = QmiClient::new(device);
            client
                .sync()
                .map_err(|error| SendError::new("modem_sync_failed", error.to_string()))?;
            confirm_imei(&mut client, imei, &path)?;
            work(&mut client)
        }

        /// Both control paths to one module, under a single arbiter lease.
        ///
        /// A radio restart has to read `AT+CFUN?` around a QMI mode change,
        /// and those two live on different USB interfaces of the same stick.
        /// The lease is taken once and held across the whole sequence on
        /// purpose: if another command slipped in between the mode change and
        /// the read-back, the read-back would be describing somebody else's
        /// work, and a read-back that can describe somebody else's work is
        /// not a check. The ports are still only ever used one at a time —
        /// what wedges a Quectel stack is issuing AT and QMI concurrently,
        /// not alternating between them.
        fn with_module_control<T>(
            &self,
            imei: Option<&str>,
            work: impl FnOnce(&mut ModuleControl) -> Result<T, SendError>,
        ) -> Result<T, SendError> {
            let _lock = self.arbiter.acquire(edge_modem::ModemPriority::Normal);
            let qmi_path = self.path_for(imei)?;
            let at_path = match edge_modem::at_port_for_qmi(&qmi_path) {
                Some(path) => path,
                None => at_port_by_imei(imei)?,
            };
            let _busy = self.hold(&qmi_path);
            let device = CdcWdmDevice::open(&qmi_path)
                .map_err(|error| SendError::new("modem_open_failed", error.to_string()))?;
            let mut client = QmiClient::new(device);
            client
                .sync()
                .map_err(|error| SendError::new("modem_sync_failed", error.to_string()))?;
            confirm_imei(&mut client, imei, &qmi_path)?;
            let mut control = ModuleControl {
                client,
                at_path,
                at: None,
            };
            work(&mut control)
        }
    }

    /// Check that the module answering on `path` is the one named.
    ///
    /// `path_for` returns a remembered `/dev/cdc-wdm*`, and on this bench
    /// those names are recycled: the modules arrive over USB/IP, one of them
    /// re-enumerates several times an hour, and the index it comes back on is
    /// whichever is free. Between two polls the node a command was aimed at
    /// can belong to a different SIM, and the command with the worst
    /// consequence for getting that wrong is the one that sends a message from
    /// it. Costs one DMS read on operator-initiated commands only -- the poll
    /// loop opens its own client and does not come through here.
    fn confirm_imei(
        client: &mut QmiClient<CdcWdmDevice>,
        imei: Option<&str>,
        path: &Path,
    ) -> Result<(), SendError> {
        let Some(expected) = imei.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(());
        };
        let answered = client
            .get_serial_numbers()
            .map_err(|error| SendError::new("modem_sync_failed", error.to_string()))?
            .imei;
        match answered.as_deref() {
            Some(actual) if actual == expected => Ok(()),
            Some(actual) => Err(SendError::new(
                "modem_moved",
                format!(
                    "{} is imei {actual} right now, not the imei {expected} this command \
                     names; refusing to run it on the wrong module",
                    path.display()
                ),
            )),
            None => Err(SendError::new(
                "modem_moved",
                format!(
                    "{} would not say which module it is, so it cannot be confirmed as \
                     imei {expected}",
                    path.display()
                ),
            )),
        }
    }

    /// How long `AT+CFUN=<n>` is given to answer.
    ///
    /// Longer than the port default: a functionality change re-initialises the
    /// card, and the bench has measured about fifteen seconds from the command
    /// to `+CPIN: READY`. The `OK` comes back sooner than that, but not always
    /// within the ordinary ten.
    const CFUN_TIMEOUT: Duration = Duration::from_secs(30);

    /// One module reached through both of its control interfaces.
    ///
    /// The AT port is opened lazily. Most of what runs here is QMI, and
    /// opening a serial port that is never used is not free: on these sticks
    /// it is the operation that puts a controlling terminal on a daemon if
    /// anyone ever gets the flags wrong.
    struct ModuleControl {
        client: QmiClient<CdcWdmDevice>,
        at_path: PathBuf,
        at: Option<edge_modem::AtPort>,
    }

    impl ModuleControl {
        fn at_port(&mut self) -> Result<&mut edge_modem::AtPort, String> {
            if self.at.is_none() {
                self.at = Some(
                    edge_modem::AtPort::open(&self.at_path).map_err(|error| error.to_string())?,
                );
            }
            Ok(self.at.as_mut().expect("just opened"))
        }
    }

    impl edge_modem::ModuleRadio for ModuleControl {
        fn operating_mode(&mut self) -> Result<OperatingMode, String> {
            self.client
                .get_operating_mode()
                .map_err(|error| error.to_string())
        }

        fn set_operating_mode(&mut self, mode: OperatingMode) -> Result<(), String> {
            self.client
                .set_operating_mode(mode)
                .map_err(|error| error.to_string())
        }

        fn read_functionality(&mut self) -> Result<Option<u8>, String> {
            let exchange = self
                .at_port()?
                .command("AT+CFUN?")
                .map_err(|error| error.to_string())?;
            // A `+CME ERROR` here is not a reading. The caller treats `Err` as
            // "the state cannot be established" and refuses to move the radio,
            // which is the right answer to a module that will not say where it
            // is -- the bench has seen `AT+CFUN?` answer `+CME ERROR: 4`.
            if !exchange.succeeded() {
                return Err(format!("AT+CFUN? answered {}", exchange.terminator));
            }
            Ok(edge_modem::parse_cfun(&exchange.lines))
        }

        fn write_functionality(&mut self, value: u8) -> Result<bool, String> {
            // One parameter, always. The reset form `AT+CFUN=1,1` cannot be
            // expressed through this signature, and that is deliberate: see
            // the contradiction note in `edge_modem::restart_radio`.
            let command = format!("AT+CFUN={value}");
            let exchange = self
                .at_port()?
                .command_with_timeout(&command, CFUN_TIMEOUT)
                .map_err(|error| error.to_string())?;
            Ok(exchange.succeeded())
        }

        fn read_card_state(&mut self) -> Result<edge_modem::CardState, String> {
            let exchange = self
                .at_port()?
                .command("AT+CPIN?")
                .map_err(|error| error.to_string())?;
            // Unlike `AT+CFUN?`, an error result code here is the reading. A
            // card that is initialising answers `+CME ERROR: 14` with no
            // lines at all, and that is the single most informative thing this
            // whole sequence can be told, so the terminator goes to the parser
            // rather than being turned into an `Err`.
            Ok(edge_modem::parse_cpin(
                &exchange.lines,
                &exchange.terminator,
            ))
        }

        fn read_card_evidence(&mut self) -> edge_modem::CardEvidence {
            // Best effort by construction: these two are corroboration for the
            // operator reading the report, never a criterion, so a module that
            // will not answer them simply leaves the fields unread.
            let mut evidence = edge_modem::CardEvidence::default();
            if let Ok(port) = self.at_port() {
                if let Ok(exchange) = port.command("AT+QSIMSTAT?") {
                    evidence.inserted = edge_modem::parse_qsimstat(&exchange.lines);
                }
            }
            if let Ok(port) = self.at_port() {
                if let Ok(exchange) = port.command("AT+QINISTAT") {
                    evidence.init_status = edge_modem::parse_qinistat(&exchange.lines);
                }
            }
            evidence
        }

        fn pause(&mut self, duration: Duration) {
            std::thread::sleep(duration);
        }
    }

    /// Renting the module out to the tunnel process.
    ///
    /// The VoWiFi stack has to be a separate Go process on this machine — it
    /// opens `/dev/net/tun`, shells out to `ip`, and its IKE and ESP packets
    /// have to leave through the same NAT binding — but only this daemon may
    /// own the serial ports, because it is also the thing running eUICC
    /// sessions on them. So the port is lent, one command at a time, through
    /// a socket that the arbiter above serialises.
    ///
    /// A rejection from the module is a successful lease call: `+CME ERROR`
    /// is the module's answer and the caller has to see it. Only losing the
    /// port is an error here.
    impl edge_modem::AtLease for Radio {
        fn execute(
            &self,
            imei: Option<&str>,
            command: &str,
            timeout: Duration,
            priority: edge_modem::ModemPriority,
        ) -> Result<edge_modem::AtExchange, edge_modem::LeaseFailure> {
            self.with_at_port_at(imei, priority, |port| {
                port.command_with_timeout(command, timeout)
                    .map_err(|error| SendError::new("at_failed", error.to_string()))
            })
            .map_err(lease_failure)
        }

        fn authenticate(
            &self,
            imei: Option<&str>,
            rand16: &[u8],
            autn16: &[u8],
        ) -> Result<edge_modem::AkaOutcome, edge_modem::LeaseFailure> {
            self.with_at_port_at(imei, edge_modem::ModemPriority::Aka, |port| {
                let mut channel = edge_modem::CsimChannel::new(port);
                edge_modem::usim_authenticate(&mut channel, rand16, autn16)
                    .map_err(|error| SendError::new(error.code(), error.to_string()))
            })
            .map_err(lease_failure)
        }
    }

    fn lease_failure(error: SendError) -> edge_modem::LeaseFailure {
        edge_modem::LeaseFailure::new(error.reason_code, error.message)
    }

    /// Start the AT lease, or say why it could not start.
    ///
    /// Not fatal. The lease exists for the tunnel process, and a daemon that
    /// refuses to run the fleet because a socket path is unusable would be
    /// trading the working half of the machine for the new half.
    fn start_at_lease(radio: &Radio) {
        let path = edge_modem::lease_socket_path();
        match edge_modem::bind_lease_socket(&path) {
            Ok(listener) => {
                log_line(format!("at lease listening on {}", path.display()));
                let lease = Arc::new(radio.clone());
                std::thread::spawn(move || edge_modem::serve_lease(listener, lease));
            }
            Err(error) => log_error(format!("at lease not started: {error}")),
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
            let Ok(mut port) = edge_modem::AtPort::open_with_timeout(&path, AT_PROBE_TIMEOUT)
            else {
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
        /// 这份矩阵是**哪来的**：库里恢复的、云端刚推的，还是回落到内置的。
        ///
        /// 🔴 `CapabilityOrigin::Fallback` 回答不了这个问题 —— 它说的是
        /// 「这一对没人写过规则」，和「矩阵丢了」共用一个词。追溯执行要靠
        /// 这个值决定敢不敢删东西，所以权威性必须从矩阵**外面**带进来。
        ///
        /// 原子量而不是再加一把锁：这个值被启动路径、uplink 线程、poll 线程
        /// 三边碰，而这个文件对锁序有过一次血的教训（见 `live_matrix` 那段
        /// 「叶子锁」注释）。不参与任何锁序的原子量从根上没有这个问题。
        matrix_authority: Arc<AtomicU8>,
        /// The capability matrix as it currently stands, including anything
        /// the cloud has pushed.
        ///
        /// Held so the LAN panel's own send is decided by the same three
        /// layers the cloud's is. Without it the panel was the way round the
        /// ledger: a pairing nobody has measured could not be sent on from
        /// the console and could be sent on from a browser on the same
        /// network as the box, which is not the more trusted of the two.
        ///
        /// Shared rather than rebuilt here, and that distinction has bitten
        /// before -- see the note where this is created: two sites each
        /// building `CapabilityMatrix::builtin()` is how a pushed matrix
        /// changed the executor's routing and nothing else.
        matrix: Arc<Mutex<CapabilityMatrix>>,
    }

    impl RadioPort {
        /// `Err` when the three layers do not allow this operation.
        ///
        /// Sits on the port rather than in the agent because both entry points
        /// need it and only one of them is the agent. The agent keeps its own
        /// copy of the rule for the commands it executes; this is the same
        /// resolution, reached from the panel.
        fn refuse_unsupported(
            &self,
            imei: Option<&str>,
            operation: edge_core::Operation,
        ) -> Result<(), SendError> {
            let context = {
                let mut port = RadioPort {
                    radio: self.radio.clone(),
                    proxies: self.proxies.clone(),
                    store: self.store.clone(),
                    matrix_authority: self.matrix_authority.clone(),
                    matrix: self.matrix.clone(),
                };
                SendPort::operating_context(&mut port, imei)?
            };
            let ledger = {
                let matrix = self.matrix.lock().expect("capability matrix");
                edge_core::SupportLedger::from_matrix(&matrix)
            };
            let registry = edge_core::builtin_strategy_registry(ledger)
                .map_err(|error| SendError::new("strategy_registry_invalid", error.to_string()))?;
            match registry
                .resolve(
                    &context.family,
                    &context.carrier,
                    &context.subscription,
                    operation,
                )
                .support
            {
                edge_core::Support::Supported(_) => Ok(()),
                edge_core::Support::Unsupported { by, reason } => Err(SendError::new(
                    format!("{}_refused_by_{}", operation.wire(), by.wire()),
                    reason,
                )),
            }
        }

        /// Read the chip back after a switch, waiting for it to come back.
        ///
        /// `set_profile` asks the card for a REFRESH, so the card re-initialises
        /// and the ISD-R channel this needs cannot be opened until it has.
        ///
        /// Never an error to the caller. The profile is already enabled by the
        /// time this runs; a failure here means the picture of the card is
        /// missing, not that the switch is in doubt, and turning it into one
        /// would invite a retry of an operation that already happened.
        fn esim_inventory_after_switch(&mut self, imei: &str) -> EsimReadback {
            let mut last_error: Option<String> = None;
            for attempt in 1..=ESIM_READBACK_ATTEMPTS {
                if attempt > 1 {
                    std::thread::sleep(ESIM_READBACK_GAP);
                }
                match self.radio.with_client(Some(imei), |client| {
                    client
                        .read_esim_local_info(ESIM_SLOT)
                        .map_err(|error| SendError::new("esim_info_failed", error.to_string()))
                }) {
                    Ok(info) => {
                        let inventory = info.inventory_json(imei, unix_ms());
                        // A chip that answered but cannot be expressed says so
                        // with its own words where it has them: an incomplete
                        // profile list is the reason that will actually happen.
                        let error = match (&inventory, &info.profiles_error) {
                            (Some(_), _) => None,
                            (None, Some(reason)) => Some(reason.clone()),
                            (None, None) => Some(
                                "chip read back but does not fit an inventory payload".to_string(),
                            ),
                        };
                        return EsimReadback {
                            inventory,
                            error,
                            attempts: attempt,
                        };
                    }
                    Err(error) => last_error = Some(error.to_string()),
                }
            }
            EsimReadback {
                inventory: None,
                error: last_error,
                attempts: ESIM_READBACK_ATTEMPTS,
            }
        }

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
                // Forced, because this is the internal primitive rather than
                // an entry point. Both raw-console entries classify before
                // they reach it, and everything else that lands here is a
                // purpose-built operation -- `AT+COPS=2` for a re-register,
                // `AT+QCFG="usbnet"` for a mode read -- which carries its own
                // command kind and its own confirmation in the console. Left
                // unforced, the classifier would refuse this agent's own
                // buttons while the console's text box still worked.
                None => {
                    Actions::at_command(self, Some(imei.to_string()), command.to_string(), true)
                        .map_err(action_failed)
                }
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
            let _lock = self
                .radio
                .arbiter
                .acquire(edge_modem::ModemPriority::Normal);
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
    }

    impl ProxyRuntime {
        fn new(radio: Radio) -> Result<Self, String> {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("vodoge-proxy")
                .build()
                .map_err(|error| error.to_string())?;
            let manager = Arc::new(edge_proxy::ProxyManager::new(Arc::new(ModemInterfaces {
                radio: radio.clone(),
            })));
            // ⚠️ `radio` **不**存进 `ProxyRuntime`。真正用到它的是上面那个
            //    `ModemInterfaces`，多存一份从来没人读（rustc 的 dead_code
            //    警告一直在说）。那份多余的克隆是「把射频操作收进代理侧」这个
            //    没做完的打算留下的痕迹，不是接线漏了。
            Ok(Self { runtime, manager })
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

    impl RadioPort {
        /// Fold one written context into this module's cached table.
        fn cache_apn_context(
            &self,
            imei: &str,
            written: &edge_core::ApnContext,
        ) -> Result<(), String> {
            let store = self.store.0.lock().expect("store");
            let modems = store
                .list_local_modems()
                .map_err(|error| error.to_string())?;
            let Some(modem) = modems.iter().find(|modem| modem.imei == imei) else {
                return Ok(());
            };
            let mut contexts: Vec<edge_core::ApnContext> = modem
                .apn_contexts
                .as_deref()
                .and_then(|json| serde_json::from_str(json).ok())
                .unwrap_or_default();
            match contexts
                .iter_mut()
                .find(|context| context.cid == written.cid)
            {
                Some(existing) => *existing = written.clone(),
                None => contexts.push(written.clone()),
            }
            contexts.sort_by_key(|context| context.cid);
            let encoded = serde_json::to_string(&contexts).map_err(|error| error.to_string())?;
            store
                .set_apn_contexts(imei, &encoded)
                .map_err(|error| error.to_string())
        }
    }

    impl RadioPort {
        /// The APN the data path should dial, read off the module.
        ///
        /// Context 1 rather than an argument: it is the one these modules dial
        /// on, it is what `configure_apn` writes, and accepting a name here
        /// would let the data path use one that is not in the table an
        /// operator can see.
        fn apn_for_data(&mut self, imei: &str) -> Result<String, SendError> {
            let listing = self.at_exchange(imei, "AT+CGDCONT?", None)?;
            let apn = edge_core::parse_cgdcont(&listing.lines)
                .into_iter()
                .find(|context| context.cid == 1)
                .map(|context| context.apn)
                .unwrap_or_default();
            if apn.is_empty() {
                return Err(SendError::new(
                    "no_apn_configured",
                    "context 1 carries no APN; set one before bringing data up",
                ));
            }
            Ok(apn)
        }
    }

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
            // A module with no QMI interface is not a module that cannot send.
            // The EC200U series exposes no `cdc-wdm` at all -- its USB
            // composition simply has none -- so every structured operation
            // this agent performs was unavailable on it, and a China Telecom
            // card in one could be seen, identified and registered while
            // nothing could be asked of it. The AT path is for exactly those.
            //
            // Tried only after QMI, and only when QMI could not find the
            // module: a module that has QMI and refused is a refusal to
            // report, not a reason to try a second way in.
            let assigned = match self
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
                }) {
                Ok(assigned) => assigned,
                Err(error) if error.reason_code == "modem_not_found" => {
                    let to = send.to.clone();
                    let body = send.body.clone();
                    let outcome = self
                        .radio
                        .with_at_port(send.modem_imei.as_deref(), |port| {
                            edge_modem::send_sms_over_at(port, &to, &body, reference).map_err(
                                |error| SendError::new("at_send_failed", error.to_string()),
                            )
                        })?;
                    return json_details(&serde_json::json!({
                        "message_reference": outcome
                            .reference
                            .map(u16::from)
                            .unwrap_or(u16::from(reference)),
                        "requested_reference": reference,
                        // The AT submission asks for no status report, so a
                        // later `+CDS` is not expected and must not be waited
                        // for. Said here rather than left to be inferred from
                        // its absence.
                        "status_report_requested": false,
                        "transport": "at",
                    }));
                }
                Err(error) => return Err(error),
            };
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

        /// Take the module's radio down and bring it back.
        ///
        /// This used to be `set_operating_mode(Offline)` followed by
        /// `set_operating_mode(Online)`, and on 2026-08-25 the second half was
        /// refused with QMI error 60 and left a module at `+CFUN: 7` with no
        /// way back that anyone could reach. The sequence, the reasons for
        /// every rung of it, and the one recovery it deliberately refuses to
        /// perform now live in `edge_modem::restart_radio`; this end owns the
        /// ports and the log line and nothing else.
        fn restart_modem(&mut self, imei: &str) -> Result<(), SendError> {
            let report = self.radio.with_module_control(Some(imei), |control| {
                edge_modem::restart_radio(control).map_err(|error| {
                    // Logged here as well as returned: a command result
                    // carries one line, and the report says which rungs
                    // were tried, which is the part the next operator
                    // needs.
                    //
                    // Two different things can arrive here and they are
                    // logged differently on purpose: a radio that did not
                    // come back is a failed restart, while a radio that
                    // came back over a card that did not is a working
                    // module with a card problem. Reading the second as
                    // the first produces exactly the wrong next action —
                    // another restart.
                    if error.radio_restored() {
                        log_line(format!("restart {imei}: radio back, card not: {error}"));
                    } else {
                        log_error(format!("restart {imei}: {error}"));
                    }
                    SendError::new(error.code(), error.to_string())
                })
            })?;
            log_line(format!("restart {imei}: {report}"));
            Ok(())
        }

        // The relay. Each of these routes a cloud command into the very same
        // `Actions` method the local panel calls, so a diagnostic run from the
        // console and one from the panel cannot behave differently — there is
        // one implementation, not two.

        fn persist_capability_matrix(
            &mut self,
            version: &str,
            sha256: &str,
            document: &str,
        ) -> Result<(), SendError> {
            self.store
                .0
                .lock()
                .expect("store")
                .save_capability_matrix(version, sha256, document, unix_ms())
                .map_err(|error| SendError::new("matrix_not_stored", error.to_string()))?;
            // 🔴 只在**落库成功之后**才升级权威性。
            //
            // 落库失败时这份矩阵只活在内存里，重启就没了 —— 而追溯执行的删除
            // 是不可逆的。用一份重启后会消失的矩阵去做不可逆的事，是这套设计
            // 里最不该出现的组合。
            self.matrix_authority
                .store(edge_core::MatrixAuthority::Stored.as_u8(), Ordering::Relaxed);
            Ok(())
        }

        /// What module this is, on whose network, with what plan on the card.
        ///
        /// Read from the local store rather than the hardware: the poll loop
        /// has already established all three and re-reading them here would
        /// take the radio away from it to learn something already known.
        ///
        /// The carrier comes from the **home** network, not the serving one.
        /// What a card is entitled to do belongs to its subscription, and a
        /// roaming card keeps its own operator's rules -- the same reason the
        /// capability matrix is keyed that way.
        fn operating_context(
            &mut self,
            imei: Option<&str>,
        ) -> Result<edge_core::OperatingContext, SendError> {
            let store = self.store.0.lock().expect("store");
            let modems = store
                .list_local_modems()
                .map_err(|error| SendError::new("store_unavailable", error.to_string()))?;
            let modem = match imei {
                Some(imei) => modems.iter().find(|modem| modem.imei == imei),
                // No IMEI named and exactly one module present is
                // unambiguous; more than one is not, and picking would decide
                // which card a message is billed to by list order.
                None if modems.len() == 1 => modems.first(),
                None => {
                    return Err(SendError::new(
                        "modem_ambiguous",
                        format!(
                            "{} modules are present, so one has to be named",
                            modems.len()
                        ),
                    ))
                }
            }
            .ok_or_else(|| {
                SendError::new(
                    "modem_not_found",
                    format!("no module in the inventory for {imei:?}"),
                )
            })?;

            let carrier = CarrierProfile::from(
                modem
                    .home_mcc
                    .zip(modem.home_mnc)
                    .map(|(mcc, mnc)| Network::new(mcc as u16, mnc as u16).carrier_profile())
                    .unwrap_or("Generic-International"),
            );

            // The plan is keyed on the card, so a module with no readable
            // ICCID has no declaration -- which withholds nothing, and leaves
            // the ledger and the hardware to decide.
            let subscription = modem
                .iccid
                .as_deref()
                .and_then(|iccid| store.card_policy(iccid).ok().flatten())
                .map(|policy| edge_core::SubscriptionCapability {
                    sms_send: policy.sms_send,
                    sms_receive: policy.sms_receive,
                    data: policy.data,
                    voice: policy.voice,
                })
                .unwrap_or_default();

            Ok(edge_core::OperatingContext {
                family: ModemFamily::from(modem.family.as_str()),
                carrier,
                subscription,
            })
        }

        fn run_at(
            &mut self,
            imei: &str,
            command: &str,
            timeout_ms: Option<i64>,
            force: bool,
        ) -> Result<JsonValue, SendError> {
            refuse_disruptive_at(command, force)?;
            let result = self.at_exchange(imei, command, timeout_ms)?;
            json_details(&result)
        }

        fn send_ussd(
            &mut self,
            imei: &str,
            code: &str,
            stage: &str,
        ) -> Result<JsonValue, SendError> {
            match stage {
                "cancel" => {
                    Actions::ussd_cancel(self, Some(imei.to_string())).map_err(action_failed)?;
                    Ok(JsonValue::Null)
                }
                // A continue is the same command on a session that is already
                // open: `AT+CUSD=1,"2",15` is how a menu selection is sent,
                // because the module tells a selection from a fresh request by
                // whether a session is already running, not by a different
                // command. That is exactly why the session has to survive the
                // call, and why only this stage asks for `KeepSession` --
                // releasing the session first would turn the operator's "2"
                // into a brand new, chargeable request for a USSD code named
                // `2`, and the reply to that is not menu item two.
                stage => {
                    let result = self
                        .ussd_staged(
                            Some(imei.to_string()),
                            code.to_string(),
                            preempt_for_stage(stage),
                        )
                        .map_err(action_failed)?;
                    json_details(&result)
                }
            }
        }

        fn set_radio(&mut self, imei: &str, enabled: bool) -> Result<(), SendError> {
            Actions::set_radio(self, Some(imei.to_string()), enabled).map_err(action_failed)
        }

        /// Write one packet data context with `AT+QICSGP`.
        ///
        /// 🔴 **The password appears in the command string and nowhere else.**
        /// It is not logged, not echoed into the result, and not read back:
        /// the verification below compares the APN, the username and the
        /// method, and asks only whether *a* password is now set. A result
        /// that carried the command text would put the credential in the
        /// cloud's command journal.
        fn configure_apn(
            &mut self,
            request: &edge_agent::ApnWrite<'_>,
        ) -> Result<JsonValue, SendError> {
            // AT has no escape for a quote inside a quoted field, so a value
            // containing one cannot be sent correctly. Refusing is the only
            // honest answer; stripping it would write a different APN than the
            // one asked for and report success.
            for (name, value) in [
                ("apn", Some(request.apn)),
                ("username", request.username),
                ("password", request.password),
            ] {
                if value.is_some_and(|value| {
                    value.contains('"') || value.contains('\r') || value.contains('\n')
                }) {
                    return Err(SendError::new(
                        "apn_value_unquotable",
                        format!(
                            "{name} contains a character AT cannot carry inside a quoted field"
                        ),
                    ));
                }
            }
            let auth = match request.auth {
                Some(value) => Some(edge_core::ApnAuth::from_wire(value).ok_or_else(|| {
                    SendError::new(
                        "apn_auth_unknown",
                        format!("unknown authentication method {value:?}"),
                    )
                })?),
                None => None,
            };
            let requested_type = match request.pdp_type {
                None => None,
                Some("IP") => Some(1u8),
                Some("IPV6") => Some(2),
                Some("IPV4V6") => Some(3),
                Some(other) => {
                    return Err(SendError::new(
                        "apn_pdp_type_unknown",
                        format!("unknown PDP type {other:?}"),
                    ))
                }
            };
            let cid = request.cid;
            let apn = request.apn.to_string();
            // Held as options and resolved against the module's own reading
            // inside the closure: `AT+QICSGP=` rewrites every field, so a
            // request that names no credential must put back the one the
            // context already had rather than send two empty strings and
            // clear it.
            let username = request.username.map(str::to_owned);
            let password = request.password.map(str::to_owned);
            let imei = request.imei.to_string();
            self.radio
                .with_at_port(Some(&imei), move |port| {
                    let read = |port: &mut edge_modem::AtPort| {
                        port.command(&format!("AT+QICSGP={cid}"))
                            .ok()
                            .filter(edge_modem::AtExchange::succeeded)
                            .and_then(|exchange| edge_core::parse_qicsgp(&exchange.lines))
                    };
                    // Read before writing, for the same reason the radio does:
                    // an edit that only changes a username must send back the
                    // context type and method the context already had, and
                    // defaulting them would silently downgrade an IPv4v6
                    // context to IPv4 or drop CHAP to none.
                    let before = read(port);
                    let context_type = requested_type
                        .or_else(|| before.as_ref().and_then(|value| value.context_type))
                        .unwrap_or(1);
                    let auth_code = auth
                        .or_else(|| before.as_ref().and_then(|value| value.auth))
                        .map(edge_core::ApnAuth::code)
                        .unwrap_or(0);
                    let username = username
                        .or_else(|| before.as_ref().map(|value| value.username.clone()))
                        .unwrap_or_default();
                    let password = password
                        .or_else(|| before.as_ref().map(|value| value.password.clone()))
                        .unwrap_or_default();
                    let exchange = port
                        .command(&format!(
                            "AT+QICSGP={cid},{context_type},\"{apn}\",\"{username}\",\"{password}\",{auth_code}"
                        ))
                        .map_err(|error| SendError::new("apn_write_failed", error.to_string()))?;
                    if !exchange.succeeded() {
                        return Err(SendError::new(
                            "apn_write_refused",
                            format!("module answered {}", exchange.terminator),
                        ));
                    }
                    // 🔴 The reading after the write decides the outcome, not
                    // the `OK`. A module that answers OK and keeps its old
                    // context is the failure this exists to catch -- the same
                    // one `+CFUN` taught on this bench.
                    let after = read(port).ok_or_else(|| {
                        SendError::new(
                            "apn_write_unverified",
                            "the module accepted the write and would not read the context back",
                        )
                    })?;
                    if after.apn != apn || after.username != username {
                        return Err(SendError::new(
                            "apn_write_not_applied",
                            "the module answered OK and the context did not change",
                        ));
                    }
                    Ok(edge_core::ApnContext {
                        cid,
                        pdp_type: match context_type {
                            2 => "IPV6",
                            3 => "IPV4V6",
                            _ => "IP",
                        }
                        .to_string(),
                        apn: after.apn,
                        username: after.username,
                        auth: after.auth,
                        has_password: after.has_password,
                        source: Some(edge_core::SOURCE_CONFIGURED.to_string()),
                    })
                })
                .map_err(|error| SendError::new("apn_write_failed", error.to_string()))
                .map(|written| {
                    // Put the result back in the cache the poll loop reads.
                    // Failing to do so is not worth failing the command over --
                    // the write happened -- so it is logged and the console
                    // catches up when the card next changes.
                    if let Err(error) = self.cache_apn_context(&imei, &written) {
                        log_line(format!("apn cache not updated for {imei}: {error}"));
                    }
                    serde_json::json!({
                        "cid": written.cid,
                        "pdp_type": written.pdp_type,
                        "apn": written.apn,
                        "username": written.username,
                        "auth": written.auth,
                        "has_password": written.has_password,
                    })
                })
        }
        /// Approve one observed endpoint, the same act as the panel's button.
        ///
        /// Routed through the panel's `Actions` rather than reimplemented so
        /// there is one approval path: the rule that a claim only ever names
        /// something already discovered lives there, and a second copy of it
        /// here is where the two would drift.
        fn claim_modem_candidate(&mut self, candidate_key: &str) -> Result<JsonValue, SendError> {
            let result = Actions::claim_modem_candidate(self, candidate_key.to_string())
                .map_err(action_failed)?;
            Ok(serde_json::json!({ "candidate_key": result.candidate_key }))
        }

        /// The agent's own log ring, the one the LAN panel serves.
        ///
        /// Bounded at 500 lines, which a healthy poll loop fills in about
        /// twenty minutes, so the default here is smaller than the ring on
        /// purpose: a caller who wants the lot asks for it, and a caller who
        /// wants the tail is not made to carry the rest of it over the link.
        ///
        /// `contains` is applied here rather than in the cloud for the same
        /// reason: filtering after the transfer is the transfer.
        /// Adopt from the cloud, through the same code the panel uses.
        ///
        /// One implementation for both entry points on purpose: two copies of
        /// "which IMEIs may be adopted" would drift, and the one that drifts
        /// is the one that lets somebody adopt hardware that is not there.
        fn register_modem(
            &mut self,
            imei: &str,
            note: Option<&str>,
        ) -> Result<JsonValue, SendError> {
            let result =
                Actions::register_modem(self, imei.to_string(), "cloud").map_err(action_failed)?;
            if let Some(note) = note.filter(|value| !value.trim().is_empty()) {
                log_line(format!("modem {imei} adopted from the cloud: {note}"));
            }
            json_details(&result)
        }

        fn unregister_modem(&mut self, imei: &str) -> Result<JsonValue, SendError> {
            let result =
                Actions::unregister_modem(self, imei.to_string()).map_err(action_failed)?;
            json_details(&result)
        }

        fn read_logs(
            &mut self,
            after: Option<u64>,
            limit: Option<u32>,
            contains: Option<&str>,
        ) -> Result<JsonValue, SendError> {
            const DEFAULT_LINES: usize = 200;
            let ring = edge_panel::LogRing::global();
            let cursor = ring.cursor();
            let needle = contains.map(str::to_lowercase);
            let mut lines: Vec<edge_panel::LogLine> = ring
                .since(after.unwrap_or(0))
                .into_iter()
                .filter(|line| match needle.as_deref() {
                    Some(needle) => line.text.to_lowercase().contains(needle),
                    None => true,
                })
                .collect();
            // The tail, not the head: what just happened is what somebody
            // reading a log is looking for, and dropping from the front is how
            // a limit keeps that.
            let keep = limit.map_or(DEFAULT_LINES, |value| value as usize);
            if lines.len() > keep {
                lines.drain(..lines.len() - keep);
            }
            serde_json::to_value(serde_json::json!({
                "lines": lines,
                // Where to resume from, which is the ring's own cursor rather
                // than the last line returned: a filtered read must not make
                // the caller re-fetch everything the filter dropped.
                "cursor": cursor,
            }))
            .map_err(|error| SendError::new("logs_unreadable", error.to_string()))
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
            //
            // Forced: `select_operator` is its own command kind with its own
            // confirmation, and the string it builds is `AT+COPS=`, which the
            // classifier holds back for the raw console. The guard is there to
            // catch a typed command nobody meant, not to disable the button
            // whose entire purpose is this.
            self.run_at(imei, &command, Some(120_000), true)
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
            // 🔴 拉数据面之前问一次能力矩阵。以前这条路直奔
            //    `apn_for_data` → `start_data`，中间**一次都不问**：云端把某个
            //    (模组, 运营商) 组合的 data 标成 unsupported，边缘侧照样去拉，
            //    改矩阵没有任何效果、也没有报错。整个 SupportLedger
            //    「未测即不支持」的约束当时只在发短信那一条路上生效。
            //
            // ⚠️ 只在**开**的时候问，理由见 `data_capability_gate`。
            if let Some(operation) = data_capability_gate(enabled) {
                self.refuse_unsupported(Some(imei), operation)?;
            }
            // The QMI path first, because it is the one that produces a usable
            // interface. `AT+CGACT` attaches the bearer and stops there: it
            // leaves the `wwan` device down with no address, which is how this
            // bench came to have four registered modules, a populated APN
            // table, and no data path at all.
            //
            // Falling back only on `modem_not_found` keeps the AT path for the
            // modules that have no QMI to use -- the EC200U-CN speaks AT only.
            // Any other failure is a real fault on a module that does have
            // QMI, and swallowing it would hide the reason behind a second
            // attempt that cannot work either.
            let attempt = if enabled {
                match self.apn_for_data(imei) {
                    Ok(apn) => self.radio.start_data(imei, apn.as_str()),
                    Err(error) => Err(error),
                }
            } else {
                self.radio.stop_data(imei)
            };
            match attempt {
                Ok(details) => {
                    return json_details(&serde_json::json!({
                        "requested": if enabled { "up" } else { "down" },
                        "transport": "qmi",
                        "session": details,
                    }))
                }
                Err(error)
                    if error.reason_code == "modem_not_found"
                        || error.reason_code == "no_data_interface" => {}
                Err(error) => return Err(error),
            }

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
                "transport": "at",
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
            let ports = visible_control_ports()
                .map_err(|error| SendError::new("dev_scan_failed", error))?;
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

        /// Store the pushed card policy set, replacing whatever was held.
        ///
        /// The receipt names the ICCIDs actually written rather than only a
        /// count. A policy set is keyed on cards this device may well not
        /// have: the cloud pushes the tenant's whole set to every device, so
        /// "stored 4" tells an operator nothing about whether the card they
        /// just edited is one of them, while the list can be compared against
        /// the modems on the same page.
        fn update_card_policies(
            &mut self,
            policy_version: &str,
            policies: &[ContractCardPolicy],
        ) -> Result<JsonValue, SendError> {
            let stored: Vec<StoredCardPolicy> = policies
                .iter()
                .map(|policy| StoredCardPolicy {
                    iccid: policy.iccid.clone(),
                    cellular_enabled: policy.cellular_enabled,
                    vertical: policy.vertical.clone(),
                    apn: policy.apn.clone(),
                    // What the operator declared this plan is sold as doing.
                    // Absent from an older console, which is the same as
                    // declaring nothing and withholds nothing. Each field
                    // stays three-valued all the way down: `None` is
                    // undeclared, and only `Some(false)` takes anything away.
                    sms_send: policy.capability.as_ref().and_then(|it| it.sms_send),
                    sms_receive: policy.capability.as_ref().and_then(|it| it.sms_receive),
                    data: policy.capability.as_ref().and_then(|it| it.data),
                    voice: policy.capability.as_ref().and_then(|it| it.voice),
                })
                .collect();
            let written = self
                .store
                .0
                .lock()
                .expect("store")
                .replace_card_policies(&stored, policy_version, unix_ms())
                .map_err(|error| SendError::new("card_policy_not_stored", error.to_string()))?;
            json_details(&serde_json::json!({
                "policy_version": policy_version,
                "stored": written,
                "iccids": stored
                    .iter()
                    .map(|policy| policy.iccid.clone())
                    .collect::<Vec<_>>(),
            }))
        }

        fn list_esim_profiles(&mut self, imei: &str) -> Result<JsonValue, SendError> {
            let result =
                Actions::list_profiles(self, Some(imei.to_string())).map_err(action_failed)?;
            json_details(&result)
        }

        /// Enable one profile, then read the chip back.
        ///
        /// The read-back is what lets the cloud inventory keep up with an
        /// operator. A switch is the only thing that changes which ICCID is
        /// enabled, so without a fresh reading the stored inventory would
        /// contradict the card from the moment somebody pressed the button.
        ///
        /// It is one extra read after a deliberate action, not a poll, and it
        /// can never fail the switch: the profile has already been enabled by
        /// the time it runs, and reporting failure would invite a retry of an
        /// operation that already happened.
        fn switch_esim_profile(
            &mut self,
            imei: &str,
            target_iccid: &str,
        ) -> Result<JsonValue, SendError> {
            Actions::switch_profile(self, Some(imei.to_string()), target_iccid.to_string(), true)
                .map_err(action_failed)?;
            let readback = self.esim_inventory_after_switch(imei);
            json_details(&SwitchEsimBody {
                imei: imei.to_string(),
                target_iccid: target_iccid.to_string(),
                inventory: readback.inventory,
                inventory_error: readback.error,
                readback_attempts: readback.attempts,
            })
        }

        /// Rename one profile, or clear its name with an empty string.
        ///
        /// The inventory is re-read afterwards for the same reason the switch
        /// re-reads it: what the console shows has to come from the card, not
        /// from the fact that the command returned without an error.
        fn rename_esim_profile(
            &mut self,
            imei: &str,
            iccid: &str,
            nickname: &str,
        ) -> Result<JsonValue, SendError> {
            let name = nickname.to_string();
            let target = iccid.to_string();
            self.radio
                .with_client(Some(imei), |client| {
                    client
                        .set_profile_nickname(ESIM_SLOT, &target, &name)
                        .map_err(|error| SendError::new("esim_rename_failed", error.to_string()))
                })
                .map_err(|error| SendError::new("esim_rename_failed", error.to_string()))?;
            let readback = self.esim_inventory_after_switch(imei);
            Ok(serde_json::json!({
                "iccid": iccid,
                "nickname": nickname,
                "inventory": readback.inventory,
                "inventory_error": readback.error,
            }))
        }

        /// Take one profile out of service without enabling another.
        ///
        /// Distinct from `switch_esim_profile`, which can only ever move the
        /// card from one profile to another: there was no way to leave a
        /// module with nothing enabled, which is what deleting a profile
        /// requires first.
        fn disable_esim_profile(
            &mut self,
            imei: &str,
            iccid: &str,
        ) -> Result<JsonValue, SendError> {
            Actions::switch_profile(self, Some(imei.to_string()), iccid.to_string(), false)
                .map_err(action_failed)?;
            let readback = self.esim_inventory_after_switch(imei);
            Ok(serde_json::json!({
                "iccid": iccid,
                "enabled": false,
                "inventory": readback.inventory,
                "inventory_error": readback.error,
            }))
        }

        /// Remove one profile from the card.
        ///
        /// 🔴 Irreversible, and the agent adds no guard of its own beyond the
        /// card's: an eUICC refuses to delete the profile it is running on,
        /// and everything else about whether this should happen was decided
        /// before the command was issued.
        fn delete_esim_profile(&mut self, imei: &str, iccid: &str) -> Result<JsonValue, SendError> {
            let target = iccid.to_string();
            self.radio
                .with_client(Some(imei), |client| {
                    client
                        .delete_profile(ESIM_SLOT, &target)
                        .map_err(|error| SendError::new("esim_delete_failed", error.to_string()))
                })
                .map_err(|error| SendError::new("esim_delete_failed", error.to_string()))?;
            let readback = self.esim_inventory_after_switch(imei);
            Ok(serde_json::json!({
                "iccid": iccid,
                "deleted": true,
                "inventory": readback.inventory,
                "inventory_error": readback.error,
            }))
        }

        /// Everything ES10b will say about the chip, on one ISD-R channel.
        ///
        /// Not routed through the panel's `Actions` trait like the profile
        /// list is. That trait is the local web panel's vocabulary, and this
        /// command exists so the same reading can be had from the cloud
        /// console with nobody on the box.
        fn read_esim_info(&mut self, imei: &str) -> Result<JsonValue, SendError> {
            let info = self.radio.with_client(Some(imei), |client| {
                client
                    .read_esim_local_info(ESIM_SLOT)
                    .map_err(|error| SendError::new("esim_info_failed", error.to_string()))
            })?;
            json_details(&esim_info_body(imei, info, unix_ms()))
        }

        fn retrieve_esim_notification(
            &mut self,
            imei: &str,
            sequence_number: i64,
        ) -> Result<JsonValue, SendError> {
            let sequence_number = u64::try_from(sequence_number).map_err(|_| {
                SendError::new(
                    "esim_notification_invalid",
                    format!("sequence number {sequence_number} is negative"),
                )
            })?;
            let pending = self.radio.with_client(Some(imei), |client| {
                client
                    .retrieve_esim_notification(ESIM_SLOT, sequence_number)
                    .map_err(|error| SendError::new("esim_notification_failed", error.to_string()))
            })?;
            json_details(&RetrievedNotificationBody {
                imei: imei.to_string(),
                sequence_number: pending.metadata.sequence_number,
                operations: pending.metadata.operations,
                address: pending.metadata.address,
                iccid: pending.metadata.iccid,
                installation_result: pending.installation_result,
                payload_bytes: pending.payload.len(),
                payload_hex: hex_string(&pending.payload),
                delivered: false,
                delivery_blocked_by: NOTIFICATION_DELIVERY_BLOCKER,
            })
        }

        /// One ES9+ `InitiateAuthentication` against a real SM-DP+.
        ///
        /// The chip is read first and the server second, in that order, so
        /// the challenge the server signs is one this card produced moments
        /// earlier rather than one from a previous session.
        ///
        /// Nothing is written anywhere. This stops at the server's signed
        /// answer: `AuthenticateServer` would put an RSP session on the card,
        /// and delivering a notification would change the state of a real
        /// paid account. Both belong to the download slice.
        fn initiate_esim_authentication(
            &mut self,
            imei: &str,
            smdp_address: Option<&str>,
        ) -> Result<JsonValue, SendError> {
            // Built per call rather than once at start-up. A CI root is an
            // asset with an expiry, and reloading here means installing a new
            // one takes effect without restarting the agent -- which matters
            // because the failure it prevents is the whole fleet losing the
            // ability to download profiles on a date nobody noticed.
            let directory = edge_modem::trust_dir();
            let client = Es9pClient::from_trust_dir(&directory).map_err(|error| {
                SendError::new("esim_trust_anchors_unavailable", error.to_string())
            })?;

            let inputs = self.radio.with_client(Some(imei), |client| {
                client
                    .read_esim_authentication_inputs(ESIM_SLOT)
                    .map_err(|error| {
                        SendError::new("esim_authentication_inputs_failed", error.to_string())
                    })
            })?;

            let (address, source) = match smdp_address {
                Some(address) => (address.to_string(), "request"),
                None => match inputs.addresses.default_dp_address.clone() {
                    Some(address) => (address, "euicc_configured_addresses"),
                    // Deliberately not rootDsAddress. Both bench chips report
                    // testrootsmds.gsma.com, which is GSMA's test discovery
                    // server signed by the SGP.26 test CI -- a production-CI
                    // chip would refuse it, so trying would waste a round trip
                    // and produce a failure that reads like a network fault.
                    None => match inputs.notification_addresses.first() {
                        Some(address) => (address.clone(), "pending_notification"),
                        None => {
                            return Err(SendError::new(
                                "esim_smdp_address_unknown",
                                format!(
                                    "chip has no default SM-DP+ and no pending notification to \
                                     take an address from{}",
                                    inputs
                                        .addresses
                                        .root_ds_address
                                        .as_ref()
                                        .map(|root| format!(
                                            " (its root SM-DS is {root}, which is not an SM-DP+)"
                                        ))
                                        .unwrap_or_default()
                                ),
                            ))
                        }
                    },
                },
            };

            let start = client
                .initiate_authentication(&address, &inputs.challenge, &inputs.info1.raw)
                .map_err(|error| {
                    SendError::new("esim_initiate_authentication_failed", error.to_string())
                })?;

            let chip_ci_keys = inputs.info1.ci_key_ids_for_verification.clone();
            json_details(&EsimAuthenticationBody {
                imei: imei.to_string(),
                eid: inputs.eid,
                smdp_address: start.smdp_address.clone(),
                smdp_address_source: source,
                configured_default_smdp: inputs.addresses.default_dp_address,
                configured_root_smds: inputs.addresses.root_ds_address,
                configured_addresses_error: inputs.addresses_error,
                notification_addresses: inputs.notification_addresses,
                notification_addresses_error: inputs.notification_addresses_error,
                euicc_challenge: hex_string(&inputs.challenge),
                euicc_info1_bytes: inputs.info1.raw.len(),
                sgp22_version: inputs.info1.svn,
                transaction_id: start.transaction_id.clone(),
                server_address: start.server_address.clone(),
                server_challenge: start.server_challenge.clone(),
                echoed_euicc_challenge: start.echoed_euicc_challenge.clone(),
                server_signed1_bytes: start.server_signed1.len(),
                server_signature1_bytes: start.server_signature1.len(),
                euicc_ci_pkid_to_be_used: start.euicc_ci_pkid_to_be_used.clone(),
                // Whether the CI the server picked is one this chip will
                // actually verify against. The two can disagree, and that
                // disagreement is exactly what stops a download later.
                ci_key_accepted_by_chip: chip_ci_keys
                    .iter()
                    .any(|key| key == &start.euicc_ci_pkid_to_be_used),
                chip_ci_key_ids: chip_ci_keys,
                certificate_key_id: start.verification.certificate_key_id.clone(),
                certificate_authority_key_id: start
                    .verification
                    .certificate_authority_key_id
                    .clone(),
                certificate_sha256: start.verification.certificate_sha256.clone(),
                certificate_not_after: start.verification.certificate_not_after.clone(),
                certificate_signed_by_ci: start.verification.certificate_signed_by_ci,
                server_signature_valid: start.verification.server_signature_valid,
                challenge_echoed: start.verification.challenge_echoed,
                trust_anchor_label: start.verification.trust_anchor_label.clone(),
                trust_anchor_key_id: start.verification.trust_anchor_key_id.clone(),
                trust_directory: directory.display().to_string(),
                trust_anchors: client
                    .anchors()
                    .iter()
                    .map(|anchor| TrustAnchorBody {
                        label: anchor.label.clone(),
                        key_id: anchor.key_id.clone(),
                        sha256: anchor.sha256.clone(),
                        not_after: anchor.not_after.clone(),
                    })
                    .collect(),
                negotiated_tls: start.negotiated_tls.clone(),
                admin_protocol: start.admin_protocol.clone(),
                http_status: start.http_status,
                elapsed_ms: start.elapsed_ms,
                profile_downloaded: false,
                stopped_after: AUTHENTICATION_STOP_POINT,
            })
        }

        /// Download one profile from an SM-DP+ and install it on the eUICC.
        ///
        /// The whole exchange happens while this thread holds the module, and
        /// it has to: between `AuthenticateServer` and the last block of the
        /// profile package the card is holding an RSP session, and anything
        /// else that opened a logical channel in the middle would end it.
        ///
        /// Two things this deliberately does not do. It does not enable the
        /// profile — SGP.22 makes install and enable separate operations, and
        /// the module on this bench has exactly one working profile whose
        /// network somebody is using. And it does not deliver the older
        /// notifications the chip has been carrying around; only the one this
        /// download produced goes to the server, because the others describe
        /// profiles nobody asked us to act on.
        fn download_esim_profile(
            &mut self,
            imei: &str,
            activation_code: &str,
            confirmation_code: Option<&str>,
        ) -> Result<JsonValue, SendError> {
            let code = edge_modem::parse_activation_code(activation_code).map_err(|error| {
                SendError::new("esim_activation_code_invalid", error.to_string())
            })?;
            if code.matching_id.is_none() {
                return Err(SendError::new(
                    "esim_activation_code_invalid",
                    "the activation code names no matching id, so the SM-DP+ has no \
                     way to know which order this is",
                ));
            }
            if code.confirmation_code_required && confirmation_code.is_none() {
                return Err(SendError::new(
                    "esim_confirmation_code_required",
                    "the activation code says a confirmation code is required and none \
                     was supplied",
                ));
            }

            let directory = edge_modem::trust_dir();
            let client = Es9pClient::from_trust_dir(&directory).map_err(|error| {
                SendError::new("esim_trust_anchors_unavailable", error.to_string())
            })?;
            let request = edge_modem::DownloadRequest {
                activation_code: &code,
                confirmation_code,
                imei,
            };

            let outcome = self.radio.with_client(Some(imei), |modem| {
                modem
                    .download_esim_profile(ESIM_SLOT, &client, &request)
                    .map_err(|error| SendError::new("esim_download_failed", error.to_string()))
            })?;

            json_details(&download_body(imei, &directory, &client, outcome))
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
            // 时序和判决都在 `rotate_cycle` 里，理由见那里 —— 关键是恢复
            // 那一步**无论如何都要跑**，而那件事只有抽出来才测得到。
            self.radio.with_client(Some(imei), |client| {
                rotate_cycle(|mode| client.set_operating_mode(mode))
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
    /// 关射频、再拉起来。**恢复那一步无论如何都要跑。**
    ///
    /// 🔴 时序本身就是不变量，所以它在这里而不是内联在 `rotate_ip` 里 ——
    /// 内联的话没有任何测试能证明「关失败时 Online 仍然发了出去」，而那正是
    /// 这次要修的东西：原来写的是 `.and_then(...)`，关成功、拉失败就直接短路
    /// 返回，模组停在 LowPower。
    ///
    /// 拉不回来时再试一次：`set_operating_mode(Online)` 是幂等的（已经 Online
    /// 时再设一次无害），而重试的代价和让一根模组永久脱网的代价不在一个量级。
    fn rotate_cycle<E: std::fmt::Display>(
        mut set_mode: impl FnMut(OperatingMode) -> Result<(), E>,
    ) -> Result<(), SendError> {
        let down = set_mode(OperatingMode::LowPower);
        // ⚠️ 这里**不能**有 `?`。提前返回会把模组留在 LowPower —— 脱网、从
        //    机队消失，而唯一能救它的正是同一条 QMI 通道。这批模组经 USB/IP
        //    接入，没人能拔插。`reregister_network` 为同一个不变式写着同一条
        //    注释：「提前返回会把模组留在脱网状态，比它本来要修的故障更糟。」
        let mut up = set_mode(OperatingMode::Online);
        if up.is_err() {
            up = set_mode(OperatingMode::Online);
        }
        rotate_outcome(down, up)
    }

    /// 关射频再拉起来这一对操作，最后该报什么。
    ///
    /// 🔴 **「拉不回来」和「关不下去」是两种完全不同的失败，不能共用一个错误码。**
    ///
    /// - 关不下去：模组没被碰过，屏幕上该说的是「再点一次」。
    /// - 拉不回来：模组**停在 LowPower** —— 脱网、从机队消失，而唯一能救它的
    ///   正是同一条 QMI 通道。这批模组经 USB/IP 接入，没人能拔插。屏幕上该说
    ///   的是完全不同的一句话，而且这一句是紧急的。
    ///
    /// ⚠️ 两步都失败时按**停在 LowPower** 报。关那一步失败可能是超时，而超时
    /// 不代表命令没生效——保守读法是「它可能已经下去了」，因为读错的代价是
    /// 一根没人去救的模组。
    fn rotate_outcome(
        down: Result<(), impl std::fmt::Display>,
        up: Result<(), impl std::fmt::Display>,
    ) -> Result<(), SendError> {
        match (down, up) {
            (_, Err(error)) => Err(SendError::new(
                "rotate_stranded",
                format!("射频关下去了但没能拉回来，模组停在 LowPower：{error}"),
            )),
            (Err(error), Ok(())) => Err(SendError::new("rotate_failed", error.to_string())),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    /// QMI 那一次失败之后，该不该回落到 AT。
    ///
    /// 🔴 **只在「这一根根本没有 QMI 口」时回落。**
    ///
    /// 其他任何失败都是一根**有** QMI 的模组上的真故障。回落等于用一次注定也
    /// 做不成的尝试把原因盖掉——`set_data_network` 的注释写的是同一条规矩：
    /// 「Any other failure is a real fault on a module that does have QMI, and
    /// swallowing it would hide the reason behind a second attempt that cannot
    /// work either.」
    ///
    /// ⚠️ 尤其是 2026-08-25 那次：QMI 模式切换被 **error 60** 拒在半路，模组
    /// 停在 `+CFUN: 7`。那种时候屏幕上必须显示 error 60，而不是显示一条
    /// 「AT 也没成」——后者会把人引到完全错的方向。
    fn radio_falls_back_to_at(reason_code: &str) -> bool {
        reason_code == "modem_not_found"
    }

    /// 没有 QMI 口的模组，开关射频该发哪条 AT。
    ///
    /// 🔴 **绝不能是 `AT+CFUN=1,1`。** 那是**带复位**的形式：模组会重启并重新
    /// 枚举 USB。守卫表把它单列一行，措辞是「也是 +CFUN: 7 唯一量到过的解药，
    /// 但只有一次观测」——那是一条最后手段，不是一个按钮该发的东西。
    ///
    /// 🔴 **也绝不能是 `AT+CFUN=7`。** 守卫表原话：「7 是『进去容易、记录在案
    /// 的出路全部失败』的那个值」。
    ///
    /// 关用 `0` 不用 `4`：守卫表写着 `0/4` 都是立刻脱网、**回程都是同一个口上
    /// 的 `AT+CFUN=1`**，对这里等价，取更常见的那个。回程在同一个口上这件事
    /// 是这条路能做成按钮的前提——关掉射频之后 AT 口还在，开回来的手段没丢。
    fn radio_at_command(online: bool) -> &'static str {
        if online {
            "AT+CFUN=1"
        } else {
            "AT+CFUN=0"
        }
    }

    /// 数据面这一次请求，动手之前要不要先问能力矩阵，问哪一条。
    ///
    /// 🔴 **只在「开」的时候问。** 矩阵说「这个组合不支持数据」是**别去拉起来**
    /// 的理由，不是**拒绝把它关掉**的理由 —— 关不掉比开不起来严重得多，而且
    /// 关数据面本身就是一条恢复路径。这批模组经 USB/IP 接入，没人能物理接触，
    /// 一个「因为不支持所以不给你关」的判决会把人堵在没有出路的地方。
    ///
    /// ⚠️ 接线只有一行（`set_data_network` 里那个 `if let`），宿主机上测不了
    /// ——它要一个真的 `Radio`。这里能钉住的是**策略**：开才问、关不问。
    fn data_capability_gate(enabled: bool) -> Option<edge_core::Operation> {
        enabled.then_some(edge_core::Operation::Data)
    }

    fn json_details<T: serde::Serialize>(value: &T) -> Result<JsonValue, SendError> {
        serde_json::to_value(value)
            .map_err(|error| SendError::new("details_encode_failed", error.to_string()))
    }

    /// `read_esim_info` as the console receives it.
    #[derive(serde::Serialize)]
    struct EsimInfoBody {
        imei: String,
        /// 32 digits identifying the chip. Unchanged by profile switches, which
        /// is what makes it the right key for everything else here.
        eid: String,
        /// This same read in the shape the cloud projects, or `null` when it
        /// cannot be one.
        ///
        /// Carried inside the command result rather than assembled separately
        /// upstream, so the rows the cloud stores and the table the console
        /// draws come from one read of one chip and cannot drift apart.
        inventory: Option<JsonValue>,
        chip: EuiccInfoBody,
        notifications: Vec<NotificationBody>,
        /// Set when the card refused the query rather than having nothing
        /// pending. The two look identical from an empty list.
        notifications_error: Option<String>,
        profiles: Vec<ProfileBody>,
        profiles_error: Option<String>,
    }

    /// One `read_esim_local_info` in the shape the console and the cloud both
    /// receive it.
    ///
    /// Separate from `read_esim_info` because the read needs a modem and this
    /// does not: this is the part that decides what is *said* about a chip, and
    /// a test can only reach it if it stands on its own.
    fn esim_info_body(imei: &str, info: EsimLocalInfo, collected_at: i64) -> EsimInfoBody {
        // Before the reading is taken apart, because it is the reading.
        let inventory = info.inventory_json(imei, collected_at);
        EsimInfoBody {
            imei: imei.to_string(),
            eid: info.eid,
            inventory,
            chip: euicc_info_body(&info.info),
            notifications: info.notifications.iter().map(notification_body).collect(),
            notifications_error: info.notifications_error,
            profiles: info
                .profiles
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
            profiles_error: info.profiles_error,
        }
    }

    /// `switch_esim_profile` as the console receives it.
    ///
    /// It used to answer with nothing at all, which was honest while a switch
    /// had nothing to report. It has something to report now: the chip as it
    /// reads afterwards.
    #[derive(serde::Serialize)]
    struct SwitchEsimBody {
        imei: String,
        target_iccid: String,
        /// The chip as it reads after the switch, or `null` when the read-back
        /// produced nothing the cloud can store.
        inventory: Option<JsonValue>,
        /// Why there is no inventory. The switch itself still succeeded — this
        /// only says the picture of the card afterwards is missing.
        inventory_error: Option<String>,
        /// How many read-backs it took. Reported because nobody has ever timed
        /// how long a REFRESH keeps ISD-R shut on this bench, and a number that
        /// comes back from real switches is worth more than the guess below it.
        readback_attempts: usize,
    }

    /// The outcome of reading a chip back after a switch.
    struct EsimReadback {
        inventory: Option<JsonValue>,
        error: Option<String>,
        attempts: usize,
    }

    /// The seam between what this binary reads off a chip and what the cloud
    /// is able to store. Three crates meet here and only one of them can see
    /// both sides, so this is where the join is checked.
    #[cfg(test)]
    mod esim_inventory_tests {
        use super::*;
        use edge_modem::{EuiccInfo2, Profile};
        use vodoge_contract::EsimInventoryPayload;

        /// The bench eUICC in `867018069514820`, read on 2026-08-25 (T089).
        const BENCH_EID: &str = "89086030202200000026000178339240";
        const WEBBING_ICCID: &str = "89852351225042214201";
        const US_ICCID: &str = "8901240527197122156";
        const BENCH_IMEI: &str = "867018069514820";
        const COLLECTED_AT: i64 = 1_756_000_000_000;

        fn profile(iccid: &str, enabled: bool, nickname: Option<&str>) -> Profile {
            Profile {
                iccid: iccid.to_string(),
                enabled,
                nickname: nickname.map(str::to_string),
                ..Profile::default()
            }
        }

        fn chip(eid: &str, profiles: Vec<Profile>) -> EsimLocalInfo {
            EsimLocalInfo {
                eid: eid.to_string(),
                info: EuiccInfo2::default(),
                notifications: Vec::new(),
                notifications_error: None,
                profiles,
                profiles_error: None,
            }
        }

        /// What this binary puts on the wire has to be exactly what the agent
        /// will accept as a payload -- the two agree by the name of one JSON
        /// key and by the shape underneath it, and nothing else would notice
        /// them drifting apart until `app.esim_profiles` quietly stayed empty.
        #[test]
        fn a_reading_carries_an_inventory_the_contract_accepts() {
            let body = esim_info_body(
                BENCH_IMEI,
                chip(
                    BENCH_EID,
                    vec![
                        profile(WEBBING_ICCID, true, Some("WEBBING")),
                        profile(US_ICCID, false, None),
                    ],
                ),
                COLLECTED_AT,
            );
            let encoded = serde_json::to_value(&body).expect("body json");

            let payload: EsimInventoryPayload =
                serde_json::from_value(encoded["inventory"].clone())
                    .expect("the agent parses this same value");
            assert_eq!(payload.eid, BENCH_EID);
            assert_eq!(payload.modem_imei, BENCH_IMEI);
            assert_eq!(payload.collected_at, COLLECTED_AT);
            assert_eq!(payload.profiles.len(), 2);
            assert_eq!(payload.profiles[0].state, "enabled");
            assert_eq!(payload.profiles[1].iccid, US_ICCID);

            // And the reading the console draws still says the same thing, out
            // of its own fields.
            assert_eq!(encoded["profiles"][0]["enabled"], serde_json::json!(true));
            assert_eq!(
                encoded["profiles"][0]["label"],
                serde_json::json!("WEBBING")
            );
        }

        /// `867018069509705` has no ISD-R, so it never reaches this function at
        /// all. A chip that answered without a usable EID is the case that can:
        /// the reading is still delivered in full, and only the inventory is
        /// absent. The console is where that card gets reported, not here.
        #[test]
        fn a_reading_without_an_inventory_is_still_a_whole_reading() {
            let body = esim_info_body(
                BENCH_IMEI,
                chip("", vec![profile(WEBBING_ICCID, true, None)]),
                COLLECTED_AT,
            );
            let encoded = serde_json::to_value(&body).expect("body json");

            assert_eq!(encoded["inventory"], serde_json::Value::Null);
            assert_eq!(
                encoded["profiles"][0]["iccid"],
                serde_json::json!(WEBBING_ICCID)
            );
            assert_eq!(encoded["imei"], serde_json::json!(BENCH_IMEI));
        }

        /// A read-back that failed must not be reported as a switch that
        /// failed. The profile is already enabled by then, and an operator who
        /// is told otherwise will press the button again.
        #[test]
        fn a_switch_says_separately_whether_it_worked_and_whether_it_could_look() {
            let body = SwitchEsimBody {
                imei: BENCH_IMEI.to_string(),
                target_iccid: US_ICCID.to_string(),
                inventory: None,
                inventory_error: Some("open ISD-R channel: SW 6985".to_string()),
                readback_attempts: ESIM_READBACK_ATTEMPTS,
            };
            let encoded = serde_json::to_value(&body).expect("body json");

            assert_eq!(encoded["inventory"], serde_json::Value::Null);
            assert_eq!(encoded["target_iccid"], serde_json::json!(US_ICCID));
            assert!(encoded["inventory_error"].is_string());
            assert_eq!(encoded["readback_attempts"], serde_json::json!(3));
        }
    }

    /// `GetEUICCInfo2`, every field of it.
    #[derive(serde::Serialize)]
    struct EuiccInfoBody {
        profile_version: Option<String>,
        sgp22_version: Option<String>,
        firmware_version: Option<String>,
        installed_applications: Option<u64>,
        /// What is left to install a profile into, in bytes.
        free_non_volatile_memory: Option<u64>,
        free_volatile_memory: Option<u64>,
        uicc_capabilities: Vec<String>,
        ts102241_version: Option<String>,
        global_platform_version: Option<String>,
        rsp_capabilities: Vec<String>,
        /// The GSMA CI keys this chip will verify an SM-DP+ against. A profile
        /// signed by a CI that is not in this list cannot be downloaded here.
        ci_key_ids_for_verification: Vec<String>,
        ci_key_ids_for_signing: Vec<String>,
        category: Option<u64>,
        forbidden_profile_policy_rules: Vec<String>,
        pp_version: Option<String>,
        sas_accreditation_number: Option<String>,
        /// How many of the sixteen fields the card populated, so a truncated read
        /// is visible as a number rather than as fields quietly missing.
        decoded_fields: usize,
    }

    /// One entry of `ListNotification`.
    #[derive(serde::Serialize)]
    struct NotificationBody {
        sequence_number: u64,
        operations: Vec<String>,
        address: String,
        iccid: Option<String>,
    }

    /// `retrieve_esim_notification` as the console receives it.
    #[derive(serde::Serialize)]
    struct RetrievedNotificationBody {
        imei: String,
        sequence_number: u64,
        operations: Vec<String>,
        address: String,
        iccid: Option<String>,
        installation_result: bool,
        payload_bytes: usize,
        /// The signed notification itself, which is what ES9+ `handleNotification`
        /// has to carry. Kept verbatim: anything re-encoded no longer matches the
        /// eUICC's signature over it.
        payload_hex: String,
        /// Whether the SM-DP+ was told. It was not.
        delivered: bool,
        /// Why not, in one line, so nobody reads a successful fetch as a
        /// successful retry.
        delivery_blocked_by: &'static str,
    }

    /// `initiate_esim_authentication` as the console receives it.
    ///
    /// Long on purpose. This command exists to produce evidence, and evidence
    /// that reduces to "it worked" is not evidence: the point is which server
    /// answered, which CI root vouched for it, which key the chip would have
    /// accepted, and how far the exchange deliberately did not go.
    #[derive(serde::Serialize)]
    struct EsimAuthenticationBody {
        imei: String,
        eid: String,
        /// The SM-DP+ that answered.
        smdp_address: String,
        /// Where that address came from: `request`,
        /// `euicc_configured_addresses` or `pending_notification`.
        smdp_address_source: &'static str,
        configured_default_smdp: Option<String>,
        /// The root discovery server the chip names. Not used as a target:
        /// the bench chips point at GSMA's test SM-DS, which a production-CI
        /// chip cannot authenticate.
        configured_root_smds: Option<String>,
        configured_addresses_error: Option<String>,
        notification_addresses: Vec<String>,
        notification_addresses_error: Option<String>,
        /// The sixteen bytes this chip generated for this exchange.
        euicc_challenge: String,
        euicc_info1_bytes: usize,
        sgp22_version: Option<String>,
        /// What the SM-DP+ calls this session.
        transaction_id: String,
        /// The address inside the server's signed structure.
        server_address: String,
        server_challenge: String,
        /// The chip's challenge as the server echoed it back, signed.
        echoed_euicc_challenge: String,
        server_signed1_bytes: usize,
        server_signature1_bytes: usize,
        /// The CI key the server expects this eUICC to verify with.
        euicc_ci_pkid_to_be_used: String,
        /// Whether that key is one the chip actually lists.
        ci_key_accepted_by_chip: bool,
        chip_ci_key_ids: Vec<String>,
        certificate_key_id: String,
        certificate_authority_key_id: String,
        certificate_sha256: String,
        certificate_not_after: String,
        /// The GSMA CI root's key verified the SM-DP+ certificate.
        certificate_signed_by_ci: bool,
        /// That certificate's key verified `serverSignature1`.
        server_signature_valid: bool,
        /// The echoed challenge is the one this chip produced, so the answer
        /// cannot be a replay of an earlier session.
        challenge_echoed: bool,
        trust_anchor_label: String,
        trust_anchor_key_id: String,
        /// Where the CI roots were read from, so an operator can see which
        /// set was in force rather than assuming.
        trust_directory: String,
        trust_anchors: Vec<TrustAnchorBody>,
        negotiated_tls: Option<String>,
        admin_protocol: Option<String>,
        http_status: u16,
        elapsed_ms: u64,
        /// It was not. Stated rather than implied.
        profile_downloaded: bool,
        stopped_after: &'static str,
    }

    /// One CI root as it was loaded.
    #[derive(serde::Serialize)]
    struct TrustAnchorBody {
        label: String,
        key_id: String,
        sha256: String,
        /// A CI root expires. Rendering the date is what makes a rotation
        /// something someone can plan rather than something that happens.
        not_after: String,
    }

    /// Where this command stops, and why that is a choice.
    const AUTHENTICATION_STOP_POINT: &str =
        "the server's signed answer. AuthenticateServer would open an RSP session on the card \
         and handleNotification would change a real account, so neither runs here";

    /// What still stands between a retrieved notification and a delivered one.
    const NOTIFICATION_DELIVERY_BLOCKER: &str =
        "ES9+ handleNotification needs an HTTPS client and the GSMA CI trust chain, \
         which the edge does not have yet";

    fn euicc_info_body(info: &edge_modem::EuiccInfo2) -> EuiccInfoBody {
        EuiccInfoBody {
            profile_version: info.profile_version.clone(),
            sgp22_version: info.svn.clone(),
            firmware_version: info.firmware_version.clone(),
            installed_applications: info.installed_applications,
            free_non_volatile_memory: info.free_non_volatile_memory,
            free_volatile_memory: info.free_volatile_memory,
            uicc_capabilities: info.uicc_capabilities.clone(),
            ts102241_version: info.ts102241_version.clone(),
            global_platform_version: info.global_platform_version.clone(),
            rsp_capabilities: info.rsp_capabilities.clone(),
            ci_key_ids_for_verification: info.ci_key_ids_for_verification.clone(),
            ci_key_ids_for_signing: info.ci_key_ids_for_signing.clone(),
            category: info.category,
            forbidden_profile_policy_rules: info.forbidden_profile_policy_rules.clone(),
            pp_version: info.pp_version.clone(),
            sas_accreditation_number: info.sas_accreditation_number.clone(),
            decoded_fields: info.populated_fields(),
        }
    }

    fn notification_body(metadata: &edge_modem::NotificationMetadata) -> NotificationBody {
        NotificationBody {
            sequence_number: metadata.sequence_number,
            operations: metadata.operations.clone(),
            address: metadata.address.clone(),
            iccid: metadata.iccid.clone(),
        }
    }

    /// `download_esim_profile` as the console receives it.
    ///
    /// Two snapshots rather than one summary. "A profile was downloaded" is a
    /// claim; a second entry in the profile list, a free-memory figure that
    /// dropped by about the size of the package, and one fewer notification
    /// owed to the SM-DP+ are three independent facts, and they are what an
    /// operator should be reading. The activation code and the matching id
    /// appear nowhere: they are one-time credentials, and a command result is
    /// stored, logged and copied into receipts.
    #[derive(serde::Serialize)]
    struct EsimDownloadBody {
        imei: String,
        eid: String,
        smdp_address: String,
        transaction_id: String,
        /// That the code carried one. Not which one.
        matching_id_supplied: bool,
        confirmation_code_required: bool,

        /// What the SM-DP+ said the profile is, read before anything was
        /// written to the chip.
        profile: Option<ProfileMetadataBody>,
        /// The rules that stopped this download. Empty on the ordinary path.
        refused_policy_rules: Vec<String>,

        before: EuiccSnapshotBody,
        after: Option<EuiccSnapshotBody>,
        /// Bytes of non-volatile memory the install consumed, when both
        /// readings are available.
        free_memory_consumed: Option<i64>,
        profiles_added: Option<i64>,

        /// The `STORE DATA` chain, on real silicon for the first time.
        authenticate_server_blocks: usize,
        prepare_download_blocks: usize,
        bound_profile_package_bytes: usize,
        bound_profile_package_segments: Vec<BppSegmentBody>,
        bound_profile_package_blocks: usize,

        installed: bool,
        /// True only because nothing here ever calls `ES10c.EnableProfile`.
        enabled: bool,
        installation_iccid: Option<String>,
        installation_error: Option<String>,
        failed_bpp_command: Option<String>,

        notification_sequence_number: Option<u64>,
        notification_bytes: usize,
        notification_delivered: bool,
        notification_delivery_error: Option<String>,
        /// The card's own answer to `RemoveNotificationFromList`: 0 is gone.
        notification_removed_code: Option<u64>,
        notifications_pending_before: usize,
        notifications_pending_after: Option<usize>,

        session_cancelled: Option<&'static str>,
        cancel_error: Option<String>,
        stopped_after: Option<String>,

        // The ES9+ session, on the same terms initiate_esim_authentication
        // reports it, so the two results can be compared field by field.
        euicc_challenge: String,
        echoed_euicc_challenge: String,
        server_challenge: String,
        euicc_ci_pkid_to_be_used: String,
        chip_ci_key_ids: Vec<String>,
        ci_key_accepted_by_chip: bool,
        certificate_key_id: String,
        certificate_authority_key_id: String,
        certificate_sha256: String,
        certificate_not_after: String,
        certificate_signed_by_ci: bool,
        server_signature_valid: bool,
        challenge_echoed: bool,
        trust_anchor_label: String,
        trust_anchor_key_id: String,
        trust_directory: String,
        trust_anchors: Vec<TrustAnchorBody>,
        negotiated_tls: Option<String>,
        admin_protocol: Option<String>,
        http: Vec<HttpStepBody>,
    }

    #[derive(serde::Serialize)]
    struct ProfileMetadataBody {
        iccid: Option<String>,
        service_provider_name: Option<String>,
        profile_name: Option<String>,
        class: Option<u8>,
        /// Every rule the SM-DP+ attached, named. `ppr1` forbids disabling the
        /// profile and `ppr2` forbids deleting it, and both are permanent from
        /// the moment it is installed.
        policy_rules: Vec<String>,
    }

    #[derive(serde::Serialize)]
    struct EuiccSnapshotBody {
        free_non_volatile_memory: Option<u64>,
        profiles: Vec<ProfileBody>,
        notifications: Vec<NotificationBody>,
    }

    #[derive(serde::Serialize)]
    struct BppSegmentBody {
        label: String,
        bytes: usize,
        /// How many `STORE DATA` blocks this segment took. Anything above one
        /// is a payload the pre-T030 single-APDU code would have silently
        /// wrapped.
        blocks: usize,
    }

    #[derive(serde::Serialize)]
    struct HttpStepBody {
        step: &'static str,
        http_status: u16,
        elapsed_ms: u64,
    }

    fn snapshot_body(snapshot: &edge_modem::EuiccSnapshot) -> EuiccSnapshotBody {
        EuiccSnapshotBody {
            free_non_volatile_memory: snapshot.free_non_volatile_memory,
            profiles: snapshot
                .profiles
                .iter()
                .map(|profile| ProfileBody {
                    label: profile.label(),
                    iccid: profile.iccid.clone(),
                    enabled: profile.enabled,
                    provider: profile.provider.clone(),
                    name: profile.name.clone(),
                    nickname: profile.nickname.clone(),
                    class: profile.class,
                    isdp_aid: profile.isdp_aid.clone(),
                })
                .collect(),
            notifications: snapshot
                .notifications
                .iter()
                .map(notification_body)
                .collect(),
        }
    }

    fn download_body(
        imei: &str,
        directory: &std::path::Path,
        client: &Es9pClient,
        outcome: edge_modem::DownloadOutcome,
    ) -> EsimDownloadBody {
        let after = outcome.after.as_ref().map(snapshot_body);
        let free_memory_consumed = match (
            outcome.before.free_non_volatile_memory,
            outcome
                .after
                .as_ref()
                .and_then(|snapshot| snapshot.free_non_volatile_memory),
        ) {
            (Some(before), Some(after)) => Some(before as i64 - after as i64),
            _ => None,
        };
        let profiles_added = outcome
            .after
            .as_ref()
            .map(|snapshot| snapshot.profiles.len() as i64 - outcome.before.profiles.len() as i64);
        let installation = outcome.installation.as_ref();
        EsimDownloadBody {
            imei: imei.to_string(),
            eid: outcome.eid.clone(),
            smdp_address: outcome.smdp_address.clone(),
            transaction_id: outcome.transaction_id.clone(),
            matching_id_supplied: outcome.matching_id_present,
            confirmation_code_required: outcome.confirmation_code_required,
            profile: outcome
                .metadata
                .as_ref()
                .map(|metadata| ProfileMetadataBody {
                    iccid: metadata.iccid.clone(),
                    service_provider_name: metadata.service_provider_name.clone(),
                    profile_name: metadata.profile_name.clone(),
                    class: metadata.class,
                    policy_rules: metadata.policy_rules.clone(),
                }),
            refused_policy_rules: outcome.refused_policy_rules.clone(),
            notifications_pending_before: outcome.before.notifications.len(),
            notifications_pending_after: outcome
                .after
                .as_ref()
                .map(|snapshot| snapshot.notifications.len()),
            before: snapshot_body(&outcome.before),
            after,
            free_memory_consumed,
            profiles_added,
            authenticate_server_blocks: outcome.authenticate_server_blocks,
            prepare_download_blocks: outcome.prepare_download_blocks,
            bound_profile_package_bytes: outcome.bpp_bytes,
            bound_profile_package_segments: outcome
                .bpp_segments
                .iter()
                .map(|segment| BppSegmentBody {
                    label: segment.label.clone(),
                    bytes: segment.bytes,
                    blocks: segment.blocks,
                })
                .collect(),
            bound_profile_package_blocks: outcome.bpp_blocks,
            installed: outcome.installed,
            // Stated rather than left to be assumed. Nothing on this path
            // calls EnableProfile, so a downloaded profile sits disabled next
            // to the one that is carrying traffic.
            enabled: false,
            installation_iccid: installation.and_then(|result| result.iccid.clone()),
            installation_error: installation.and_then(|result| result.error_reason.clone()),
            failed_bpp_command: installation.and_then(|result| result.bpp_command.clone()),
            notification_sequence_number: installation.and_then(|result| result.sequence_number),
            notification_bytes: outcome.notification_bytes,
            notification_delivered: outcome.notification_delivered,
            notification_delivery_error: outcome.notification_delivery_error.clone(),
            notification_removed_code: outcome.notification_removed,
            session_cancelled: outcome.session_cancelled,
            cancel_error: outcome.cancel_error.clone(),
            stopped_after: outcome.stopped_after.clone(),
            euicc_challenge: hex_string(&outcome.euicc_challenge),
            echoed_euicc_challenge: outcome.echoed_euicc_challenge.clone(),
            server_challenge: outcome.server_challenge.clone(),
            euicc_ci_pkid_to_be_used: outcome.euicc_ci_pkid_to_be_used.clone(),
            chip_ci_key_ids: outcome.chip_ci_key_ids.clone(),
            ci_key_accepted_by_chip: outcome.ci_key_accepted_by_chip,
            certificate_key_id: outcome.verification.certificate_key_id.clone(),
            certificate_authority_key_id: outcome.verification.certificate_authority_key_id.clone(),
            certificate_sha256: outcome.verification.certificate_sha256.clone(),
            certificate_not_after: outcome.verification.certificate_not_after.clone(),
            certificate_signed_by_ci: outcome.verification.certificate_signed_by_ci,
            server_signature_valid: outcome.verification.server_signature_valid,
            challenge_echoed: outcome.verification.challenge_echoed,
            trust_anchor_label: outcome.verification.trust_anchor_label.clone(),
            trust_anchor_key_id: outcome.verification.trust_anchor_key_id.clone(),
            trust_directory: directory.display().to_string(),
            trust_anchors: client
                .anchors()
                .iter()
                .map(|anchor| TrustAnchorBody {
                    label: anchor.label.clone(),
                    key_id: anchor.key_id.clone(),
                    sha256: anchor.sha256.clone(),
                    not_after: anchor.not_after.clone(),
                })
                .collect(),
            negotiated_tls: outcome.negotiated_tls.clone(),
            admin_protocol: outcome.admin_protocol.clone(),
            http: outcome
                .http
                .iter()
                .map(|step| HttpStepBody {
                    step: step.step,
                    http_status: step.http_status,
                    elapsed_ms: step.elapsed_ms,
                })
                .collect(),
        }
    }

    fn hex_string(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02X}")).collect()
    }

    /// Whether a USSD request may release the session that is already open.
    ///
    /// `AT+CUSD=2` does not cancel "our" request; it releases whatever USSD
    /// session the module is holding. That one fact is the whole difference
    /// between starting a menu and answering one.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum UssdPreempt {
        /// Send `AT+CUSD=2` before the request. A first request wants a known
        /// state, and on that path there is usually no session to release.
        CancelFirst,
        /// Leave any open session alone. A menu selection is an answer *on*
        /// that session, so releasing it is the one thing it must not do.
        KeepSession,
    }

    /// Which preemption a relayed `send_ussd` stage asks for.
    ///
    /// Only `continue` keeps the session. Anything else -- `start`, and any
    /// stage a newer console might send that this build has never heard of --
    /// opens from a known state, because that is the safe reading of a value
    /// we cannot interpret. `cancel` never arrives here: it is a release and
    /// nothing else, and it is routed straight to `Actions::ussd_cancel`.
    fn preempt_for_stage(stage: &str) -> UssdPreempt {
        match stage {
            "continue" => UssdPreempt::KeepSession,
            _ => UssdPreempt::CancelFirst,
        }
    }

    /// The slice of an AT control port a USSD exchange uses.
    ///
    /// It exists so the exchange can be driven by a recording double. The bug
    /// it was extracted for -- a `continue` that opened with `AT+CUSD=2` and
    /// so hung up on the very session it was answering -- is a property of the
    /// *sequence* of commands, and until this trait existed nothing could see
    /// that sequence without a real `/dev/ttyUSB*` and a network that answers.
    /// This bench has the first and has never once had the second.
    trait UssdAtPort {
        fn command(&mut self, command: &str)
            -> Result<edge_modem::AtExchange, edge_modem::AtError>;
        fn wait_for_any_urc(
            &mut self,
            prefixes: &[&str],
            timeout: Duration,
        ) -> Result<Option<String>, edge_modem::AtError>;
    }

    impl UssdAtPort for edge_modem::AtPort {
        fn command(
            &mut self,
            command: &str,
        ) -> Result<edge_modem::AtExchange, edge_modem::AtError> {
            edge_modem::AtPort::command(self, command)
        }

        fn wait_for_any_urc(
            &mut self,
            prefixes: &[&str],
            timeout: Duration,
        ) -> Result<Option<String>, edge_modem::AtError> {
            edge_modem::AtPort::wait_for_any_urc(self, prefixes, timeout)
        }
    }

    /// One USSD request on an already-open port, and the network's answer.
    fn run_ussd_exchange<P: UssdAtPort>(
        port: &mut P,
        code: &str,
        preempt: UssdPreempt,
    ) -> Result<UssdResult, SendError> {
        let started = Instant::now();
        if preempt == UssdPreempt::CancelFirst {
            // Start from a known state. A session left open by an earlier
            // attempt changes how the module answers the next request, and the
            // result is a reply that parses into nothing recognisable. The
            // cancel is best-effort *for a first request*, where there is
            // usually no session to release -- and that qualifier is the whole
            // point, because on a continue the opposite holds: there is always
            // a session then, and releasing it is never harmless. Only the
            // caller knows which of the two this is, which is why the choice
            // arrives as an argument instead of being decided here.
            let _ = port.command(edge_modem::ussd_cancel());
        }
        let exchange = port
            .command(&edge_modem::ussd_request(code))
            .map_err(|error| SendError::new("ussd_failed", error.to_string()))?;
        if !exchange.succeeded() {
            return Err(SendError::new("ussd_rejected", exchange.terminator.clone()));
        }
        // Some networks report inside the command response instead of
        // afterwards, so check what already arrived before waiting for a
        // separate report.
        let inline = exchange
            .lines
            .iter()
            .find_map(|line| edge_modem::parse_ussd_reply(line));
        let reply = match inline {
            Some(reply) => Some(reply),
            None => {
                // The module may answer with a report or reject the session
                // outright; waiting only for the former turns a one-second
                // refusal into a full timeout.
                let line = port
                    .wait_for_any_urc(&["+CUSD:", "+CME ERROR:", "+CMS ERROR:"], USSD_TIMEOUT)
                    .map_err(|error| SendError::new("ussd_wait_failed", error.to_string()))?;
                match line {
                    Some(line) if line.starts_with("+CUSD:") => {
                        let parsed = edge_modem::parse_ussd_reply(&line);
                        // A report the parser cannot place is more useful shown
                        // raw than summarised into a shape it does not fit.
                        match parsed {
                            Some(reply) => Some(reply),
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
        let reply = reply
            .ok_or_else(|| SendError::new("ussd_no_reply", "network did not answer in time"))?;
        Ok(UssdResult {
            code: code.to_string(),
            stage: reply.stage.as_str().to_string(),
            expects_reply: reply.stage.expects_reply(),
            text: reply.text,
            dcs: reply.dcs,
            elapsed_ms: started.elapsed().as_millis() as u64,
        })
    }

    impl RadioPort {
        /// Run one USSD request, saying whether it may release a session that
        /// is already open.
        ///
        /// Separate from `Actions::ussd` on purpose. `Actions` belongs to
        /// `edge-panel`, whose USSD form has no notion of a stage, and the two
        /// callers really do differ: the panel always starts, while the cloud
        /// relay carries the console's stage and sometimes continues.
        fn ussd_staged(
            &self,
            imei: Option<String>,
            code: String,
            preempt: UssdPreempt,
        ) -> Result<UssdResult, PanelError> {
            self.radio
                .with_at_port(imei.as_deref(), |port| {
                    run_ussd_exchange(port, &code, preempt)
                })
                .map_err(|error| PanelError::Action(error.to_string()))
        }
    }

    #[cfg(test)]
    mod ussd_tests {
        use super::*;
        use std::collections::VecDeque;

        /// The one command that releases a USSD session. Spelled out here as a
        /// literal rather than taken from `edge_modem` so the assertions below
        /// are checking the wire, not agreeing with the helper that writes it.
        const RELEASE: &str = "AT+CUSD=2";

        /// An AT port that answers from a script and remembers, in order,
        /// every command it was handed.
        struct RecordingPort {
            issued: Vec<String>,
            reports: VecDeque<String>,
        }

        impl RecordingPort {
            fn answering(reports: &[&str]) -> Self {
                Self {
                    issued: Vec::new(),
                    reports: reports.iter().map(|line| line.to_string()).collect(),
                }
            }
        }

        impl UssdAtPort for RecordingPort {
            fn command(
                &mut self,
                command: &str,
            ) -> Result<edge_modem::AtExchange, edge_modem::AtError> {
                self.issued.push(command.to_string());
                Ok(edge_modem::AtExchange {
                    command: command.to_string(),
                    lines: Vec::new(),
                    terminator: "OK".to_string(),
                    elapsed: Duration::from_millis(1),
                })
            }

            fn wait_for_any_urc(
                &mut self,
                prefixes: &[&str],
                _timeout: Duration,
            ) -> Result<Option<String>, edge_modem::AtError> {
                while let Some(line) = self.reports.pop_front() {
                    if prefixes.iter().any(|prefix| line.starts_with(prefix)) {
                        return Ok(Some(line));
                    }
                }
                Ok(None)
            }
        }

        #[test]
        fn releasing_a_session_is_still_at_cusd_2() {
            assert_eq!(edge_modem::ussd_cancel(), RELEASE);
        }

        /// A first request opens from a known state, and that is still right:
        /// a session left behind by an abandoned attempt changes how the
        /// module answers the next one.
        #[test]
        fn a_start_still_releases_whatever_was_left_open() {
            let mut port = RecordingPort::answering(&["+CUSD: 1,\"1 Balance 2 Plan\",15"]);
            let result = run_ussd_exchange(&mut port, "*100#", UssdPreempt::CancelFirst)
                .expect("the module answered");
            assert_eq!(
                port.issued,
                vec![RELEASE.to_string(), "AT+CUSD=1,\"*100#\",15".to_string()],
            );
            assert!(result.expects_reply);
        }

        /// The bug this exists for. `AT+CUSD=2` releases the session, so
        /// sending it before a menu selection hangs up on the menu, and the
        /// selection then leaves as a fresh request for a USSD code named `2`
        /// -- a chargeable one, and not the item the operator picked.
        #[test]
        fn a_continue_does_not_release_the_session_it_is_answering() {
            let mut port = RecordingPort::answering(&["+CUSD: 0,\"Balance 12.30\",15"]);
            let result = run_ussd_exchange(&mut port, "2", UssdPreempt::KeepSession)
                .expect("the module answered");
            assert_eq!(port.issued, vec!["AT+CUSD=1,\"2\",15".to_string()]);
            assert!(
                !port.issued.iter().any(|command| command == RELEASE),
                "a continue must not release the session: {:?}",
                port.issued,
            );
            assert_eq!(result.text, "Balance 12.30");
            assert!(!result.expects_reply);
        }

        /// A menu that leads to another menu is the case multi-level USSD is
        /// named after: the second selection has to find the session still up.
        #[test]
        fn a_continue_onto_another_menu_still_expects_a_reply() {
            let mut port = RecordingPort::answering(&["+CUSD: 1,\"1 Data 2 Voice\",15"]);
            let result = run_ussd_exchange(&mut port, "2", UssdPreempt::KeepSession)
                .expect("the module answered");
            assert_eq!(port.issued, vec!["AT+CUSD=1,\"2\",15".to_string()]);
            assert_eq!(result.stage, "needs_reply");
            assert!(result.expects_reply);
        }

        /// Only `continue` keeps the session. A stage this build has never
        /// heard of opens from a known state instead, because that is the safe
        /// reading of a value it cannot interpret.
        #[test]
        fn only_continue_keeps_the_session() {
            assert_eq!(preempt_for_stage("continue"), UssdPreempt::KeepSession);
            for stage in ["start", "", "resume", "CONTINUE"] {
                assert_eq!(
                    preempt_for_stage(stage),
                    UssdPreempt::CancelFirst,
                    "stage {stage:?} must open from a known state",
                );
            }
        }
    }

    impl Actions for RadioPort {
        fn rescan_modems(&self) -> Result<RescanResult, PanelError> {
            let ports = visible_control_ports().map_err(PanelError::Action)?;
            self.radio.request_rescan();
            Ok(RescanResult {
                found: ports.len(),
                control_ports: ports
                    .into_iter()
                    .map(|path| path.display().to_string())
                    .collect(),
            })
        }

        /// Adopt a module the agent has actually seen.
        ///
        /// 🔴 The IMEI must belong to something observed. Taking a free-form
        /// IMEI would let an operator adopt hardware that is not there and
        /// then wonder why it is permanently offline -- and it would put a row
        /// in the registry no probe can ever satisfy.
        fn register_modem(
            &self,
            imei: String,
            source: &str,
        ) -> Result<RegistrationResult, PanelError> {
            // 🔴 先把矩阵克隆出来，**然后**才去锁 store。
            //
            // `live_matrix` 那把锁是叶子锁 —— 它只被单独持有，只为把矩阵克隆
            // 出来或写一份新的进去，从不在持有别的锁时去拿（理由写在它创建
            // 处的注释里）。在这里持着 store 再去锁它，就等于亲手引入那条
            // 注释所排除的锁序，而且是一条平时永远不触发、只在
            // `update_capability_matrix` 恰好并发时才死锁的路径。
            let matrix = self.matrix.lock().expect("capability matrix").clone();
            let store = self.store.0.lock().expect("store");
            let seen = store
                .list_local_modem_discoveries()
                .map_err(|error| PanelError::Action(error.to_string()))?;
            let Some(observed) = seen
                .iter()
                .find(|candidate| candidate.imei.as_deref() == Some(imei.as_str()))
            else {
                return Err(PanelError::Action(format!(
                    "{imei} has not been seen by this agent; only an identified module can be adopted"
                )));
            };
            // 纳管的两道闸：支持的（这个 build 驱动得了）＋ 测试过的
            // （这一对在矩阵里有过真实测量）。判定本身在
            // `edge_core::bind_gates`，那里能在本机测；这里只负责把两样输入
            // 凑齐，并且**凑不齐就是拒**。
            let usb = match (
                observed.vendor_id.as_deref(),
                observed.product_id.as_deref(),
            ) {
                (Some(vendor), Some(product)) => edge_core::UsbIdentity::parse(vendor, product),
                _ => None,
            };
            let identified = store
                .list_local_modems()
                .map_err(|error| PanelError::Action(error.to_string()))?
                .into_iter()
                .find(|modem| modem.imei == imei);
            // ⚠️ 这里**没有**像另外三处那样 `.unwrap_or("Generic-International")`。
            // 那个兜底在「报告」和「路由」里说得通；在一道闸上它是失败即放行：
            // 一张还没读出 IMSI 的卡会被当成国际卡，然后拿国际卡的规则过闸。
            // 归属网络读不到就是「这一对还不成立」，而那是暂时的 —— 拒绝的
            // 文案会说下一轮再试。
            let pair = identified.as_ref().and_then(|modem| {
                let (mcc, mnc) = modem.home_mcc.zip(modem.home_mnc)?;
                Some((
                    ModemFamily::from(modem.family.as_str()),
                    CarrierProfile::from(Network::new(mcc, mnc).carrier_profile()),
                ))
            });
            edge_core::bind_gates(strategy_registry(), &matrix, usb, pair).map_err(|refusal| {
                PanelError::Action(format!("{imei} cannot be adopted: {refusal}"))
            })?;

            let already = store
                .is_registered(&imei)
                .map_err(|error| PanelError::Action(error.to_string()))?;
            // 🔴 被追溯执行摘掉的那一根，如果人把它绑回来，履历要跟着回来。
            //
            // 这个仓库用测试钉住了「重复纳管不改写首次纳管的时间和来源」
            // （edge-store/tests/registered_modems.rs）。DELETE + 重新 INSERT
            // 是唯一能绕过那条保证的路径，而追溯执行是第一个会走这条路径的
            // 自动化。一次十分钟就修好的云端手误，不该让六条纳管履历被永久
            // 改写成今天。
            //
            // ⚠️ 只复原**追溯执行**摘的。人手动 unregister 之后再 adopt，
            //    那是一次新的决定，registered_at 就该是今天 ——
            //    所以 `unregister_modem` 不写退休行（那条规则有测试钉着）。
            let retired = store
                .retired_registration(&imei)
                .map_err(|error| PanelError::Action(error.to_string()))?;
            let (registered_at, registered_by) = match &retired {
                Some(row) => (row.registered_at, row.registered_by.clone()),
                None => (unix_ms(), source.to_owned()),
            };
            store
                .register_modem(&edge_store::RegisteredModem {
                    imei: imei.clone(),
                    registered_at,
                    // 🔴 Who adopted it, not where the code runs. Both entry
                    // points share this implementation, and hard-coding
                    // "panel" made a cloud-issued adoption claim to have been
                    // done on the LAN panel -- which is the one question this
                    // column exists to answer.
                    //
                    // 复原的那条走的是同一个字段：一根被自动摘掉又被绑回来的
                    // 模组，「当初是谁纳管的」这个答案没有变过。
                    registered_by,
                    usb_device: observed.usb_device.clone(),
                    // 🔴 真的写进去，不再是 `None`。闸 2 要靠它去查规则，
                    // 而一条 family 为空的纳管记录，事后没有任何办法回答
                    // 「当初是按哪一对放行的」。
                    family: identified.as_ref().map(|modem| modem.family.clone()),
                    note: None,
                })
                .map_err(|error| PanelError::Action(error.to_string()))?;
            if retired.is_some() {
                // 履历已经回到纳管行里，退休记录可以走了。
                //
                // 失败只落日志：那一行留着的后果是面板上多显示一条已经不成立
                // 的「已被自动摘除」，难看但无害；而为它让整个纳管动作失败，
                // 就把一次成功的补救变成了一次失败。
                if let Err(error) = store.forget_retirement(&imei) {
                    log_error(format!("retirement row for {imei} not cleared: {error}"));
                }
            }
            Ok(RegistrationResult {
                imei,
                registered: true,
                changed: !already,
            })
        }

        fn unregister_modem(&self, imei: String) -> Result<RegistrationResult, PanelError> {
            let store = self.store.0.lock().expect("store");
            let changed = store
                .unregister_modem(&imei)
                .map_err(|error| PanelError::Action(error.to_string()))?;
            Ok(RegistrationResult {
                imei,
                registered: false,
                changed,
            })
        }

        fn claim_modem_candidate(
            &self,
            candidate_key: String,
        ) -> Result<CandidateClaimResult, PanelError> {
            let candidate_key = candidate_key.trim().to_string();
            let candidate = edge_modem::at_port_candidates()
                .into_iter()
                .find(|candidate| {
                    candidate.policy == edge_modem::AtProbePolicy::Manual
                        && manual_candidate_key(candidate) == candidate_key
                })
                .ok_or_else(|| {
                    PanelError::Action(
                        "the serial candidate is no longer present; rescan before approving it"
                            .into(),
                    )
                })?;

            let observed = self
                .store
                .0
                .lock()
                .expect("store")
                .list_local_modem_discoveries()
                .map_err(PanelError::Store)?
                .into_iter()
                .any(|discovery| manual_discovery_matches(&discovery, &candidate));
            if !observed {
                return Err(PanelError::Action(
                    "the serial candidate has not been observed by the poller; rescan before approving it"
                        .into(),
                ));
            }

            let profile = ManualModemProfile {
                candidate_key: candidate_key.clone(),
                usb_device: candidate.usb_device.clone(),
                vendor_id: candidate.vendor_id.clone(),
                product_id: candidate.product_id.clone(),
                control_port: candidate.path.display().to_string(),
                approved_at: unix_ms(),
            };
            self.store
                .0
                .lock()
                .expect("store")
                .upsert_manual_modem_profile(&profile)
                .map_err(PanelError::Store)?;
            self.radio.request_rescan();
            Ok(CandidateClaimResult { candidate_key })
        }

        fn send_sms(
            &self,
            to: String,
            body: String,
            imei: Option<String>,
            commission: bool,
        ) -> Result<(), PanelError> {
            // The same three layers the cloud's send goes through. The panel
            // reaches the modem by a different trait, so a check written into
            // only the relay would leave this path able to send on a pairing
            // nobody has measured -- and this path is a browser on the edge
            // machine's LAN, not a more trusted one.
            //
            // `commission` is the one way past it, and it is how a pairing
            // gets into the ledger in the first place: somebody deliberately
            // sends on an unmeasured combination to find out what happens.
            if !commission {
                self.refuse_unsupported(imei.as_deref(), edge_core::Operation::SmsSend)
                    .map_err(|error| PanelError::Action(error.message))?;
            }
            let mut port = RadioPort {
                radio: self.radio.clone(),
                proxies: self.proxies.clone(),
                store: self.store.clone(),
                matrix_authority: self.matrix_authority.clone(),
                matrix: self.matrix.clone(),
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
                matrix_authority: self.matrix_authority.clone(),
                matrix: self.matrix.clone(),
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
            let attempt = self.radio.with_client(imei.as_deref(), |client| {
                client
                    .set_operating_mode(mode)
                    .map_err(|error| SendError::new("radio_failed", error.to_string()))
            });
            // 🔴 **只在「这一根根本没有 QMI 口」时回落到 AT。**
            //
            // 和 `set_data_network` 同一条规矩，那里的注释写得很清楚：其他任何
            // 失败都是一根**有** QMI 的模组上的真故障，吞掉它会把原因藏在一次
            // 注定也做不成的重试后面。
            //
            // 为什么值得加这条回落：EC200U-CN 只说 AT，没有 QMI 口。在此之前
            // 它在面板上**根本没有射频开关**——2026-09-04 它发完一条短信把自己
            // 的 AT 通道挂死时，操作员手上一个恢复动作都没有。
            //
            // ⚠️ AT 这条路在一处上**比 QMI 那条更安全**：`AT+CFUN=0` 之后模组
            // 仍然在总线上、AT 口仍然应答，回程就在同一个口上；而 QMI 的
            // LowPower 在 2026-08-25 有一次被 error 60 拒在半路，把模组停在
            // `+CFUN: 7` 出不来。
            let result = match attempt {
                Err(error) if radio_falls_back_to_at(&error.reason_code) => {
                    self.radio.with_at_port(imei.as_deref(), |port| {
                        port.command(radio_at_command(online))
                            .map(|_| ())
                            .map_err(|error| SendError::new("radio_failed", error.to_string()))
                    })
                }
                other => other,
            };
            result.map_err(|error| PanelError::Action(error.to_string()))
        }

        fn ussd(&self, imei: Option<String>, code: String) -> Result<UssdResult, PanelError> {
            // The panel's USSD form carries no stage, so every request it makes
            // is a first one and opens from a known state. The cloud relay does
            // carry a stage and calls `ussd_staged` directly.
            self.ussd_staged(imei, code, UssdPreempt::CancelFirst)
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
                        access_technology: report.access_technology.map(|value| value.to_string()),
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
            force: bool,
        ) -> Result<AtResult, PanelError> {
            refuse_disruptive_at(&command, force)
                .map_err(|error| PanelError::Action(error.message))?;
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
        start_at_lease(&radio);
        let proxies = Arc::new(ProxyRuntime::new(radio.clone())?);
        // The matrix the cloud last pushed, or the compiled-in one.
        //
        // Read from the store rather than always starting from `builtin()`:
        // the push is not redelivered -- its command is already `succeeded` --
        // so a restart that ignored the stored copy silently reverted the whole
        // fleet to the compiled-in rules, and nothing anywhere said so.
        //
        // A stored document that no longer parses leaves the built-in one
        // standing and says so. A downgrade, or a row written by a build that
        // wrote a shape this one cannot read, must not stop the agent starting.
        let stored_matrix = shared
            .0
            .lock()
            .expect("store")
            .capability_matrix()
            .map_err(|error| error.to_string())?;
        // 这份矩阵敢不敢用来**删**东西。三个分支各自的答案写在下面。
        let matrix_authority = Arc::new(AtomicU8::new(
            edge_core::MatrixAuthority::BuiltinUnparsed.as_u8(),
        ));
        let startup_matrix = match &stored_matrix {
            Some((version, _, document)) => {
                match serde_json::from_str::<serde_json::Value>(document)
                    .ok()
                    .and_then(|value| CapabilityMatrix::from_json_value(&value).ok())
                {
                    Some(matrix) => {
                        log_line(format!(
                            "capability matrix restored from store version={version}"
                        ));
                        matrix_authority.store(
                            edge_core::MatrixAuthority::Stored.as_u8(),
                            Ordering::Relaxed,
                        );
                        matrix
                    }
                    None => {
                        log_error(format!(
                            "stored capability matrix version={version} did not parse; using the built-in one"
                        ));
                        // 🔴 这是一次**读失败**，不是一次「没测过」。
                        //
                        // 到这里为止它只写进了日志，而日志在这台机器上，
                        // 云端看不见。内置矩阵 2026-09-05 之后只剩 3 条 EC20
                        // 规则，所以这一支意味着这台机器对绝大多数「型号 ×
                        // 运营商」的回答都变成了「没测过」—— 追溯执行会因此
                        // 维持现状（见 MatrixAuthority），但云端得知道它为什么
                        // 不动了，否则那就是一台悄悄停止执行的机器。
                        //
                        // Critical：这台机器现在按一份它自己都读不懂的配置在跑。
                        raise_alert(
                            &outbox,
                            edge_core::AlertLevel::Critical,
                            "capability_matrix_unparsed",
                            format!(
                                "stored capability matrix version={version} did not parse; \
                                 running on the built-in one"
                            ),
                            serde_json::json!({
                                "stored_version": version,
                                "builtin_version": CapabilityMatrix::builtin()
                                    .map(|matrix| matrix.version().to_owned())
                                    .unwrap_or_default(),
                            }),
                            unix_ms(),
                        );
                        CapabilityMatrix::builtin().map_err(|error| error.to_string())?
                    }
                }
            }
            None => {
                log_line("no stored capability matrix; using the built-in one".to_string());
                // 从未收到过推送。和上一支同样不允许删东西，但它不是故障 ——
                // 一台刚装好、还没连上云端的机器就是这个状态，不该吵。
                matrix_authority.store(
                    edge_core::MatrixAuthority::BuiltinNoRow.as_u8(),
                    Ordering::Relaxed,
                );
                CapabilityMatrix::builtin().map_err(|error| error.to_string())?
            }
        };
        let live_matrix = Arc::new(Mutex::new(startup_matrix.clone()));
        // 🔴 版本号要用**这个二进制真实的**版本，不是 `CommandExecutor::new`
        //    里那个占位值。更新守卫拿 `running_version()` 判「刷进去的是不是
        //    新的」，而上行的 hello 另走一路报 `env!("CARGO_PKG_VERSION")`
        //    ——两边不同源的话，云端看到的版本和守卫用来判回滚的版本对不上。
        //
        // ⚠️ **自更新（OTA）在这台机器上是不存在的**，这里给的是
        //    `RejectUpdate`：它对任何 `SelfUpdate` 命令一律回
        //    `update_not_configured`。整条链路（下载、校验 sha256、验签、落盘、
        //    握手确认、失败回滚）只有契约层和分发层，没有实现。
        //
        //    因此 `confirm_handshake()` / `rollback_if_handshake_failed()`
        //    现在**故意没有接线**：没有任何东西会被 stage，接上去是一段永远
        //    不执行的代码，比缺口更难发现。要补 OTA 的人从这里开始：先实现一个
        //    真的 `UpdatePort`，用 `with_updater` 换掉下面这个 `RejectUpdate`，
        //    **然后**才把 `confirm_handshake` 接到 Resume 之后。
        //    🔴 在那之前不要接 —— 这批硬件不能拔插，一个刷进去起不来又没有
        //    回滚的版本就是永久变砖。
        let executor = Arc::new(Mutex::new(CommandExecutor::with_updater(
            RadioPort {
                radio: radio.clone(),
                proxies: proxies.clone(),
                store: shared.clone(),
                matrix_authority: matrix_authority.clone(),
                matrix: live_matrix.clone(),
            },
            edge_agent::RejectUpdate::new(env!("CARGO_PKG_VERSION")),
        )));
        // The executor keeps the authoritative copy, so it has to start from
        // the same place `live_matrix` does -- otherwise a restart would route
        // by the built-in rules while reporting the stored version upstream.
        executor
            .lock()
            .expect("executor")
            .restore_matrix(startup_matrix);
        // The capability matrix as it currently stands, republished here every
        // time a command may have replaced it.
        //
        // The executor owns the authoritative copy, but nothing outside the
        // uplink thread may reach in for it: `handle_envelope` holds that mutex
        // for the whole of a command -- an operator scan is 150 seconds -- and
        // underneath it the port locks the store, so a poll pass that waited on
        // the executor while holding the store would deadlock rather than wait.
        //
        // This mutex is therefore a leaf: it is locked on its own, only ever to
        // clone the matrix out or write a new one in, and never while another
        // lock is held. That is what makes it safe regardless of the order
        // anything else takes.
        //
        // Without it, `update_capability_matrix` succeeded and changed nothing
        // the cloud could see: both reporting sites built a fresh
        // `CapabilityMatrix::builtin()`, so the capabilities in DeviceState and
        // the `capability_matrix_version` on Resume stayed at the compiled-in
        // version while the executor routed by the pushed one.
        let panel_actions = Arc::new(RadioPort {
            radio: radio.clone(),
            proxies: proxies.clone(),
            store: shared.clone(),
            matrix_authority: matrix_authority.clone(),
            matrix: live_matrix.clone(),
        });

        // The panel reads this to report cloud vs local, so what it shows is the
        // real uplink rather than a fixed assumption.
        let uplink_online = Arc::new(AtomicBool::new(false));
        // 本次启动**曾经**连上过云端 —— 单调，断线不翻回。
        //
        // 🔴 和 `uplink_online` 是两个问题。追溯执行问的不是「现在通不通」，
        // 而是「云端有没有过机会说话」：冷启动的头几秒里，一台矩阵不对的机器
        // 还没来得及被纠正，此时开始删东西，就是把那几秒变成一个不可逆的窗口。
        //
        // 之后即使断线也不再阻止执行：那时用的是一份**云端真推过**的矩阵
        // （见 MatrixAuthority），陈旧由 30 分钟的隔离期兜着。断线就停止执行
        // 反而会让一台长期离线的机器永远无法自我纠正。
        let uplink_ever_resumed = Arc::new(AtomicBool::new(false));

        let panel_bind = env("VODOGE_EDGE_PANEL", "0.0.0.0:8743");
        let panel_store = shared.clone();
        let panel_online = uplink_online.clone();
        let panel_matrix = live_matrix.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("tokio");
            if let Err(error) = runtime.block_on(serve(
                panel_bind,
                panel_store,
                Some(panel_actions),
                panel_online,
                panel_matrix,
            )) {
                log_error(format!("panel: {error}"));
            }
        });

        let uplink_outbox = outbox.clone();
        let uplink_executor = executor.clone();
        let uplink_matrix = live_matrix.clone();
        let resumed_for_uplink = uplink_ever_resumed.clone();
        std::thread::spawn(move || {
            uplink_loop(
                uplink_outbox,
                uplink_executor,
                uplink_matrix,
                uplink_online,
                resumed_for_uplink,
            )
        });

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
            if let Err(error) = poll_modems(
                &shared,
                &outbox,
                &radio,
                &live_matrix,
                &matrix_authority,
                &uplink_ever_resumed,
                &mut memory,
            ) {
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
            .filter(|p| driven_by_a_strategy(p))
            .collect::<Vec<_>>();
        paths.sort();
        Ok(paths)
    }

    /// The registry used only to ask what hardware this build drives.
    ///
    /// Built once with an empty ledger and kept, because the set of USB
    /// identities a build can drive is a compile-time fact -- the strategies
    /// are `Arc`s of unit structs. Capability *decisions* build their own
    /// registry from the live matrix each time, and must keep doing so: this
    /// one would answer them with a ledger that has measured nothing.
    fn strategy_registry() -> &'static edge_core::StrategyRegistry {
        static REGISTRY: OnceLock<edge_core::StrategyRegistry> = OnceLock::new();
        REGISTRY.get_or_init(|| {
            edge_core::builtin_strategy_registry(edge_core::SupportLedger::default())
                .expect("the shipped strategy registry must build")
        })
    }

    /// The USB identity behind a `cdc-wdm` node, read from sysfs.
    ///
    /// `/sys/class/usbmisc/<name>/device` is the USB *interface*; the vendor
    /// and product live on its parent, the device. Walking up one level is the
    /// whole of it, and a node whose parent cannot be read is treated as
    /// unknown rather than assumed to be ours.
    fn usb_identity_of(path: &Path) -> Option<edge_core::UsbIdentity> {
        let name = path.file_name()?.to_str()?;
        let interface = std::fs::canonicalize(
            PathBuf::from("/sys/class/usbmisc")
                .join(name)
                .join("device"),
        )
        .ok()?;
        let device = interface.parent()?;
        let read = |field: &str| -> Option<String> {
            std::fs::read_to_string(device.join(field))
                .ok()
                .map(|value| value.trim().to_owned())
        };
        edge_core::UsbIdentity::parse(&read("idVendor")?, &read("idProduct")?)
    }

    /// 🔴 Whether any strategy in this build drives the hardware behind a node.
    ///
    /// The gate that decides what the agent opens at all. Before it existed the
    /// enumerator probed every `cdc-wdm` on the box, and on this bench that
    /// meant two Qualcomm MSM8916 sticks nothing here can drive: they answered
    /// enough to be listed, never enough to be identified, re-enumerated every
    /// few minutes for hours, and filled the candidate list with rows no
    /// operator could act on.
    ///
    /// A node whose identity cannot be read is **refused**, not admitted. The
    /// alternative fails open, and failing open here is how the gate quietly
    /// stops being a gate.
    fn driven_by_a_strategy(path: &Path) -> bool {
        let Some(identity) = usb_identity_of(path) else {
            log_line(format!(
                "skipping {}: its USB identity could not be read",
                path.display()
            ));
            return false;
        };
        if strategy_registry().drives(identity) {
            return true;
        }
        log_line(format!(
            "skipping {} ({identity}): no strategy in this build drives it",
            path.display()
        ));
        false
    }

    /// Every endpoint the agent can currently use to identify a modem. QMI
    /// and serial ports are both returned: a new module without `cdc-wdm`
    /// should still be observable by a rescan receipt before it is fully
    /// manageable.
    fn visible_control_ports() -> Result<Vec<PathBuf>, String> {
        let mut ports = cdc_wdm_paths()?;
        // Include manual-only serial candidates in the acknowledgement too.
        // The receipt is an inventory of what the kernel exposed, not a claim
        // that it was safe to send an AT command to every listed port.
        ports.extend(
            edge_modem::at_port_candidates()
                .into_iter()
                .map(|candidate| candidate.path),
        );
        ports.sort();
        ports.dedup();
        Ok(ports)
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
        /// Previous `/proc/net/dev` totals and when they were taken, so
        /// throughput is a rate over the interval rather than a counter that
        /// only ever grows.
        net: Option<(NetTotals, Instant)>,
    }

    /// Received and transmitted bytes summed across the host's own interfaces.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct NetTotals {
        rx: u64,
        tx: u64,
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
        live_matrix: &Arc<Mutex<CapabilityMatrix>>,
        matrix_authority: &Arc<AtomicU8>,
        uplink_ever_resumed: &Arc<AtomicBool>,
        memory: &mut PollMemory,
    ) -> Result<(), String> {
        let now = unix_ms();
        let qmi_paths = cdc_wdm_paths()?;
        let mut snapshots: Vec<ModemSnapshot> = Vec::new();
        let qmi_usb: std::collections::BTreeSet<String> = qmi_paths
            .iter()
            .filter_map(|path| edge_modem::usb_device_of_qmi(path))
            .collect();
        // The same gate the QMI enumerator uses, for the same reason: a serial
        // endpoint on hardware no strategy drives is a candidate no operator
        // can adopt. `Manual` policy already stops the agent writing to it,
        // but the row was still shown, and a list of rows that cannot be acted
        // on is what made the panel unreadable on this bench.
        //
        // A candidate with no USB identity at all is kept: platform-attached
        // serial has none, and refusing it here would drop hardware this gate
        // was never about.
        let serial_candidates: Vec<_> = edge_modem::at_port_candidates()
            .into_iter()
            .filter(candidate_is_driven)
            .collect();
        let automatic_serial_usb: std::collections::BTreeSet<String> = serial_candidates
            .iter()
            .filter(|candidate| candidate.policy == edge_modem::AtProbePolicy::Automatic)
            .filter_map(|candidate| candidate.usb_device.clone())
            .collect();
        let (approved_manual_ports, approved_manual_keys) =
            approved_manual_serial_candidates(shared, &serial_candidates);

        // Preserve a newly visible serial endpoint even when the background
        // worker has insufficient evidence to write AT to it. Do not list the
        // PPP/diagnostic siblings of a modem that already has a QMI or safe AT
        // control endpoint: those are not independent devices.
        for candidate in serial_candidates
            .iter()
            .filter(|candidate| candidate.policy == edge_modem::AtProbePolicy::Manual)
        {
            let has_known_sibling = candidate
                .usb_device
                .as_ref()
                .is_some_and(|usb| qmi_usb.contains(usb) || automatic_serial_usb.contains(usb));
            if !has_known_sibling {
                let candidate_key = manual_candidate_key(candidate);
                record_manual_serial_candidate(
                    shared,
                    candidate,
                    approved_manual_keys.contains(&candidate_key),
                    now,
                );
            }
        }
        // USB devices already accounted for over QMI. A module that answers
        // there is also listed by `at_control_ports`, and without this it
        // would be reported twice under one IMEI -- once managed, once not.
        let mut claimed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

        for path in &qmi_paths {
            match probe_one(path, shared, outbox, radio) {
                Ok(snapshot) => {
                    if let Some(usb) = edge_modem::usb_device_of_qmi(path) {
                        claimed.insert(usb);
                    }
                    // 🔴 Identifying a module is not adopting it. An operator
                    // has to choose, on the panel or from the cloud, and until
                    // they do this is a candidate: shown, never acted on, and
                    // gone from the list when it is unplugged.
                    //
                    // Kept out of `snapshots` as well as out of the inventory,
                    // because `snapshots` is what `DeviceState` carries -- an
                    // unadopted module reaching the cloud would have the
                    // console create a row for it, which is the same accretion
                    // one layer up.
                    if !is_managed(shared, &snapshot.imei) {
                        log_line(format!(
                            "poll {} imei={} identified, not managed",
                            path.display(),
                            snapshot.imei
                        ));
                        record_discovery(
                            shared,
                            DiscoveryTransport::Qmi,
                            path,
                            DiscoveryState::Found,
                            Some(&snapshot.imei),
                            "identified and awaiting adoption",
                            now,
                        );
                        continue;
                    }
                    log_line(format!("poll {} imei={} ok", path.display(), snapshot.imei));
                    record_discovery(
                        shared,
                        DiscoveryTransport::Qmi,
                        path,
                        DiscoveryState::Manageable,
                        Some(&snapshot.imei),
                        "QMI identity probe succeeded",
                        now,
                    );
                    snapshots.push(snapshot);
                }
                // Deliberately not claiming the USB device here. A module
                // whose QMI node is present but unusable is exactly what the
                // AT pass below is for, and skipping it would keep the
                // failure to the one log line it has always been.
                Err(error) => {
                    log_error(format!("poll {} FAIL {error}", path.display()));
                    // The bench's own long-running example: /dev/cdc-wdm1 has
                    // answered POLLERR every poll for hours with nothing
                    // upstream aware of it. The port goes in the context
                    // rather than the code so the throttle still groups them.
                    raise_alert(
                        outbox,
                        edge_core::AlertLevel::Error,
                        "qmi_poll_failed",
                        format!("{}: {error}", path.display()),
                        serde_json::json!({ "port": path.display().to_string() }),
                        now,
                    );
                    record_discovery(
                        shared,
                        DiscoveryTransport::Qmi,
                        path,
                        DiscoveryState::ProbeFailed,
                        None,
                        error,
                        now,
                    );
                }
            }
        }

        // Second enumeration, over serial rather than QMI.
        //
        // The agent indexed modules by `/dev/cdc-wdm*` alone, so a stick in a
        // usbnet mode that exposes no QMI node simply left the fleet, leaving
        // one `poll FAIL` line behind if it left anything at all. That is the
        // shape of the usbnet incident on this bench, and it is also what a
        // brand new module looks like before anybody has set it up.
        // 🔴 从**已过滤**的候选派生，不是 `at_control_ports()`。
        //
        // 那个函数是同一个选择器套在这台机器上的**全部**候选上，而下面这个
        // 循环会真的打开每一个返回值并往里写 AT。`edge_core::strategies` 里
        // 那条注释说的正是这种硬件——两根高通 MSM8916 棒子，能被枚举、
        // 永远认不出，把候选列表刷满几个小时——它的结尾是
        // 「Nothing drives them, so **nothing should open them**」。
        //
        // QMI 那半边早就在开之前过闸了（`driven_by_a_strategy`）。这半边没有，
        // 而这半边才是会往陌生串口写字节的那一半。
        //
        // ⚠️ 手工批准的口不受这一闸约束，这是对的：运维明确点过头，
        //    而候选过滤本来就是为「没人点过头的东西别碰」而设的。
        let at_paths = at_paths_to_probe(&serial_candidates, approved_manual_ports);
        for at_path in at_paths {
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
                    upsert_at_only_local_modem(shared, &snapshot, &at_path, now)?;
                    // Same rule as the QMI pass: identified is not adopted,
                    // and an unadopted module stays out of `DeviceState` so
                    // the cloud does not create a row the operator never asked
                    // for.
                    if !is_managed(shared, &snapshot.imei) {
                        record_discovery(
                            shared,
                            DiscoveryTransport::At,
                            &at_path,
                            DiscoveryState::Found,
                            Some(&snapshot.imei),
                            "identified over AT and awaiting adoption",
                            now,
                        );
                        continue;
                    }
                    record_discovery(
                        shared,
                        DiscoveryTransport::At,
                        &at_path,
                        DiscoveryState::AtOnly,
                        Some(&snapshot.imei),
                        "AT identified the modem; QMI-managed actions are unavailable",
                        now,
                    );
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
                        // Same rule: a silent port whose last occupant was
                        // never adopted is a candidate that went quiet, not a
                        // managed module that went missing.
                        Some((imei, seen)) if is_managed(shared, &imei) => {
                            log_error(format!(
                                "poll {} silent, last held imei={imei}",
                                at_path.display()
                            ));
                            snapshots.push(absent_snapshot(&imei, &seen, "unknown"));
                            claimed.extend(usb.clone());
                        }
                        // 🔴 The arm the guard above makes necessary. A module
                        // this process identified but nobody adopted has gone
                        // quiet: worth recording, never worth reporting. Its
                        // USB device is still claimed so the port is not then
                        // re-examined as if nothing were known about it.
                        Some((imei, _)) => {
                            log_line(format!(
                                "poll {} silent, last held unadopted imei={imei}",
                                at_path.display()
                            ));
                            record_discovery(
                                shared,
                                DiscoveryTransport::At,
                                &at_path,
                                DiscoveryState::Found,
                                Some(&imei),
                                "identified on an earlier pass and awaiting adoption",
                                now,
                            );
                            claimed.extend(usb.clone());
                        }
                        None => {
                            log_error(format!("poll {} silent, unidentified", at_path.display()));
                            record_discovery(
                                shared,
                                DiscoveryTransport::At,
                                &at_path,
                                DiscoveryState::ProbeFailed,
                                None,
                                "AT+CGSN did not return a usable IMEI",
                                now,
                            );
                        }
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
            // 🔴 Managed only. `memory.seen` remembers every module this
            // process has identified, adopted or not, so reporting all of them
            // as absent would send unadopted hardware to the cloud by the back
            // door -- as an offline row, which is worse than a live one:
            // nothing will ever update it again.
            let missing: Vec<(String, SeenModem)> = memory
                .seen
                .iter()
                .filter(|(imei, _)| !present.contains(*imei))
                .filter(|(imei, _)| is_managed(shared, imei))
                .map(|(imei, seen)| (imei.clone(), seen.clone()))
                .collect();
            for (imei, seen) in missing {
                log_error(format!("poll imei={imei} absent from both enumerations"));
                // A module that was in the inventory and is now in neither
                // enumeration: unplugged, or its USB endpoint has gone. Either
                // way nothing else says so.
                raise_alert(
                    outbox,
                    edge_core::AlertLevel::Warning,
                    "modem_absent",
                    format!("modem {imei} is in neither enumeration"),
                    serde_json::json!({ "imei": imei }),
                    now,
                );
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
        fill_msisdn(shared, radio, &mut snapshots);
        fill_apn_contexts(shared, radio, &mut snapshots);
        // Modules the QMI sweep never reached. Their store fills up and stops
        // accepting messages with nothing upstream aware of it, which is how
        // China Telecom's reply sat unread on this bench with the agent
        // reporting the stick as healthy.
        for snapshot in &snapshots {
            if snapshot.manageable {
                continue;
            }
            match sweep_inbox_over_at(shared, outbox, radio, &snapshot.imei, now) {
                Ok(0) => {}
                Ok(carried) => log_line(format!(
                    "collected {carried} sms over AT from {}",
                    snapshot.imei
                )),
                // Never fatal to the pass: a module that would not answer its
                // store is still a module whose state belongs upstream.
                Err(error) => log_line(format!("at inbox {}: {error}", snapshot.imei)),
            }
        }
        // Cloned out under its own lock and then used, rather than held across
        // the enqueue: see the note where `live_matrix` is created.
        let matrix = live_matrix.lock().expect("capability matrix").clone();
        // Read here rather than inside: the state builder takes no store, and
        // a failed read must not stop a state report that is otherwise good.
        // Drop sightings of endpoints nothing has seen for a day. The key is
        // derived from USB topology, so a module that comes back on a
        // different bus path is a new row rather than an update -- and without
        // this the list grows by one per re-plug and never shrinks.
        {
            let store = shared.0.lock().expect("store");
            let cutoff = now - DISCOVERY_RETENTION_MS;
            match store.forget_stale_discoveries(cutoff) {
                Ok(0) => {}
                Ok(removed) => log_line(format!("discoveries pruned: {removed}")),
                Err(error) => log_error(format!("discoveries not pruned: {error}")),
            }
        }
        // 🔴 `Err => None`，不是 `Err => Vec::new()`。
        //
        // 空的候选列表是一句**真话**（这台机器上没有待批准的 endpoint）；
        // 读失败**不是**。云端已经把这两件事分开了：`0050` 的投影在
        // `NOT (NEW.payload ? 'discoveries')` 时直接返回，而注释写明了理由
        // ——「reading its silence as \"nothing is plugged in\" would clear a
        // list somebody is looking at」。撒谎的是这一半。
        //
        // 这和正下方 `managed` 的写法是同一条规则，也和它同一个来历：
        // `managed_imeis` 那次，一次短暂的存储读失败取消了整台设备的纳管。
        let discoveries = match shared
            .0
            .lock()
            .expect("store")
            .list_local_modem_discoveries()
        {
            Ok(rows) => Some(rows),
            Err(error) => {
                log_error(format!("discoveries not read: {error}"));
                None
            }
        };
        // 追溯执行：已纳管的模组现在还过不过得了那两道闸。
        //
        // 放在这里而不是 `managed` 之后，是为了让同一趟上报的 `managed_imeis`
        // 已经是执行**之后**的真值 —— 否则云端会先收到一份仍然列着它的名单，
        // 下一趟才更正，中间那段时间里控制台和边缘对「谁被管着」的答案不一致。
        //
        // `matrix` 在这里已经克隆好了，而且是在本函数**所有** store 锁之前
        // 克隆的，所以复用它不会产生 store→matrix 这条锁序边。
        enforce_registration(
            shared,
            outbox,
            &matrix,
            edge_core::MatrixAuthority::from_u8(matrix_authority.load(Ordering::Relaxed)),
            uplink_ever_resumed.load(Ordering::Relaxed),
            discoveries.as_deref(),
            now,
        );

        // Read separately from the snapshots: the registry is the authority on
        // what is managed, and a module adopted but never yet seen has no
        // snapshot to be inferred from.
        let managed: Option<Vec<String>> = match shared.0.lock().expect("store").registered_modems()
        {
            Ok(rows) => Some(rows.into_iter().map(|row| row.imei).collect()),
            Err(error) => {
                log_error(format!("registry not read: {error}"));
                None
            }
        };
        enqueue_device_state(
            outbox,
            &matrix,
            &snapshots,
            &host,
            discoveries.as_deref(),
            managed.as_deref(),
            now,
        )?;
        if qmi_paths.is_empty() && snapshots.is_empty() {
            return Err("no /dev/cdc-wdm* and no AT control port answered".into());
        }
        Ok(())
    }

    /// Whether this module is one the agent has been told to manage.
    ///
    /// 🔴 The gate that separates "seen" from "managed". A probe that
    /// identifies a module no longer makes it part of the inventory: an
    /// operator has to have adopted it, on the panel or from the cloud.
    ///
    /// Unregistered modules are recorded as candidates instead -- visible,
    /// adoptable, and gone from the list when they are unplugged. That is the
    /// whole point: `local_modems` used to accumulate every stick that had
    /// ever been plugged in, and there was no way to tell one somebody chose
    /// from one that happened to be there once.
    ///
    /// A store that cannot be read answers **false**. Managing a module the
    /// agent cannot confirm was adopted is the error worth avoiding; the cost
    /// of the other direction is a poll that does nothing for one cycle.
    fn is_managed(shared: &Arc<SharedStore>, imei: &str) -> bool {
        let store = shared.0.lock().expect("store");
        match store.is_registered(imei) {
            Ok(registered) => registered,
            Err(error) => {
                log_error(format!("registry unreadable for {imei}: {error}"));
                false
            }
        }
    }

    /// Persist the inventory row for a module that only answered over AT.
    /// It is deliberately kept separate from `probe_one`: AT-only is useful
    /// evidence but it must not claim that QMI-only actions are safe.
    fn upsert_at_only_local_modem(
        shared: &Arc<SharedStore>,
        snapshot: &ModemSnapshot,
        at_path: &Path,
        now: i64,
    ) -> Result<(), String> {
        // Same gate as the QMI path: identified is not adopted.
        if !is_managed(shared, &snapshot.imei) {
            return Ok(());
        }
        let store = shared.0.lock().expect("store");
        store
            .upsert_local_modem(&LocalModem {
                imei: snapshot.imei.clone(),
                family: snapshot.family.clone(),
                firmware: snapshot.firmware.clone(),
                msisdn: snapshot.msisdn.clone(),
                msisdn_iccid: snapshot.msisdn.as_ref().and(snapshot.iccid.clone()),
                apn_contexts: snapshot.apn_contexts.clone(),
                iccid: snapshot.iccid.clone(),
                state: snapshot.state.to_string(),
                last_seen: Some(now),
                mcc: snapshot.serving.as_ref().map(|network| network.mcc),
                mnc: snapshot.serving.as_ref().map(|network| network.mnc),
                home_mcc: snapshot.home.as_ref().map(|network| network.mcc),
                home_mnc: snapshot.home.as_ref().map(|network| network.mnc),
                imsi: snapshot.imsi.clone(),
                discovery: snapshot.discovery.wire().to_string(),
                manageable: snapshot.manageable,
                control_port: Some(at_path.display().to_string()),
            })
            .map_err(|error| error.to_string())
    }

    /// Retain an endpoint-level discovery result so the panel can show a
    /// real hardware problem before the module has supplied an IMEI.
    /// How an endpoint was reached when it was recorded.
    ///
    /// Deliberately a wider set than [`Discovery`], which says how a *modem*
    /// answered. `Serial` is an endpoint that has produced no IMEI and is
    /// therefore not modem inventory at all.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DiscoveryTransport {
        Qmi,
        At,
        Serial,
    }

    impl DiscoveryTransport {
        fn wire(self) -> &'static str {
            match self {
                Self::Qmi => "qmi",
                Self::At => "at",
                Self::Serial => "serial",
            }
        }
    }

    /// What the last observation of one endpoint established.
    ///
    /// This is the whole vocabulary. It is an enum because the panel had come
    /// to defend against fourteen spellings -- `managed`, `failed`, `error`,
    /// `unavailable`, `silent`, `unidentified`, `unsupported`, `pending` and
    /// more -- of which nine were never written by anything. An untyped string
    /// crossing that boundary is what let the two vocabularies drift apart
    /// without either side being wrong about anything it could check.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DiscoveryState {
        /// QMI answered. Everything the agent can do is available.
        Manageable,
        /// A transport was tried and the module did not identify itself.
        ProbeFailed,
        /// AT answered but QMI did not: identity is known, QMI-only actions
        /// are out of reach.
        AtOnly,
        /// A modem-shaped serial endpoint that nobody has approved for
        /// probing. Recorded, never written to.
        Found,
        /// Approved by an operator; the next poll will try an identity probe.
        Claimed,
    }

    impl DiscoveryState {
        fn wire(self) -> &'static str {
            match self {
                Self::Manageable => "manageable",
                Self::ProbeFailed => "probe_failed",
                Self::AtOnly => "at_only",
                Self::Found => "found",
                Self::Claimed => "claimed",
            }
        }
    }

    fn record_discovery(
        shared: &Arc<SharedStore>,
        transport: DiscoveryTransport,
        control_port: &Path,
        state: DiscoveryState,
        imei: Option<&str>,
        detail: impl Into<String>,
        now: i64,
    ) {
        let usb_device = match transport {
            DiscoveryTransport::Qmi => edge_modem::usb_device_of_qmi(control_port),
            DiscoveryTransport::At => edge_modem::usb_device_of_at(control_port),
            // Serial rows are written by `record_manual_serial_candidate`,
            // which has the live candidate and so already knows its USB
            // device. Nothing reaches here with it.
            DiscoveryTransport::Serial => None,
        };
        let identity = usb_device.as_deref().and_then(edge_modem::usb_identity);
        let path = control_port.display().to_string();
        let transport = transport.wire();
        let candidate_key = match usb_device.as_deref() {
            Some(usb) => format!("{transport}:usb:{usb}"),
            None => format!("{transport}:port:{path}"),
        };
        let result = shared
            .0
            .lock()
            .expect("store")
            .upsert_local_modem_discovery(&LocalModemDiscovery {
                candidate_key,
                usb_device,
                transport: transport.to_string(),
                control_port: path,
                vendor_id: identity.as_ref().map(|identity| identity.vendor.clone()),
                product_id: identity.as_ref().map(|identity| identity.product.clone()),
                state: state.wire().to_string(),
                imei: imei.map(str::to_string),
                detail: detail.into(),
                last_seen: now,
            });
        if let Err(error) = result {
            log_error(format!("discovery result not recorded: {error}"));
        }
    }

    /// Show a modem-shaped serial endpoint that did not meet the conservative
    /// automatic-probe policy. Until an operator approves it, it remains
    /// deliberately unprobed: a USB serial adapter can use the same tty
    /// naming convention, and the panel should make that uncertainty visible
    /// rather than turning it into AT traffic.
    fn record_manual_serial_candidate(
        shared: &Arc<SharedStore>,
        candidate: &edge_modem::AtPortCandidate,
        approved: bool,
        now: i64,
    ) {
        let path = candidate.path.display().to_string();
        let candidate_key = manual_candidate_key(candidate);
        let mut facts = vec![format!(
            "{:?} serial endpoint was not automatically probed",
            candidate.kind
        )];
        if let Some(interface) = candidate.interface.as_deref() {
            facts.push(format!("interface {interface}"));
        }
        if let Some(label) = candidate.interface_label.as_deref() {
            facts.push(format!("label {label}"));
        }
        if let Some(driver) = candidate.driver.as_deref() {
            facts.push(format!("driver {driver}"));
        }
        if approved {
            facts.push(
                "explicitly approved; the next poll will attempt an AT identity probe".into(),
            );
        } else {
            facts.push("needs an explicit modem profile before an AT identity probe".into());
        }
        let result = shared
            .0
            .lock()
            .expect("store")
            .upsert_local_modem_discovery(&LocalModemDiscovery {
                candidate_key,
                usb_device: candidate.usb_device.clone(),
                transport: DiscoveryTransport::Serial.wire().into(),
                control_port: path,
                vendor_id: candidate.vendor_id.clone(),
                product_id: candidate.product_id.clone(),
                state: if approved {
                    DiscoveryState::Claimed.wire()
                } else {
                    DiscoveryState::Found.wire()
                }
                .into(),
                imei: None,
                detail: facts.join("; "),
                last_seen: now,
            });
        if let Err(error) = result {
            log_error(format!("manual serial candidate not recorded: {error}"));
        }
    }

    /// The key is a current, physical observation rather than a user-entered
    /// path. A USB device can expose several serial functions, so the port is
    /// part of the key as well as the topology: one candidate must never
    /// overwrite an unrelated sibling merely because they share a stick.
    fn manual_candidate_key(candidate: &edge_modem::AtPortCandidate) -> String {
        let path = candidate.path.display();
        let transport = DiscoveryTransport::Serial.wire();
        match candidate.usb_device.as_deref() {
            Some(usb) => format!("{transport}:usb:{usb}:port:{path}"),
            None => format!("{transport}:port:{path}"),
        }
    }

    /// Return only manual candidates that are still exactly the endpoints an
    /// operator approved. The stored approval is evidence, not a substitute
    /// for live topology: a re-enumerated USB device needs fresh approval.
    fn approved_manual_serial_candidates(
        shared: &Arc<SharedStore>,
        candidates: &[edge_modem::AtPortCandidate],
    ) -> (Vec<PathBuf>, std::collections::BTreeSet<String>) {
        let profiles = match shared.0.lock().expect("store").list_manual_modem_profiles() {
            Ok(profiles) => profiles,
            Err(error) => {
                log_error(format!("manual modem approvals not read: {error}"));
                return (Vec::new(), std::collections::BTreeSet::new());
            }
        };
        let mut paths = Vec::new();
        let mut keys = std::collections::BTreeSet::new();
        for candidate in candidates
            .iter()
            .filter(|candidate| candidate.policy == edge_modem::AtProbePolicy::Manual)
        {
            if profiles
                .iter()
                .any(|profile| manual_profile_matches(profile, candidate))
            {
                paths.push(candidate.path.clone());
                keys.insert(manual_candidate_key(candidate));
            }
        }
        (paths, keys)
    }

    fn manual_profile_matches(
        profile: &ManualModemProfile,
        candidate: &edge_modem::AtPortCandidate,
    ) -> bool {
        profile.candidate_key == manual_candidate_key(candidate)
            && profile.usb_device == candidate.usb_device
            && profile.vendor_id == candidate.vendor_id
            && profile.product_id == candidate.product_id
            && profile.control_port == candidate.path.display().to_string()
    }

    fn manual_discovery_matches(
        discovery: &LocalModemDiscovery,
        candidate: &edge_modem::AtPortCandidate,
    ) -> bool {
        discovery.transport == DiscoveryTransport::Serial.wire()
            && discovery.state == DiscoveryState::Found.wire()
            && discovery.candidate_key == manual_candidate_key(candidate)
            && discovery.usb_device == candidate.usb_device
            && discovery.vendor_id == candidate.vendor_id
            && discovery.product_id == candidate.product_id
            && discovery.control_port == candidate.path.display().to_string()
    }

    #[cfg(test)]
    mod manual_claim_tests {
        use super::*;

        fn candidate() -> edge_modem::AtPortCandidate {
            edge_modem::AtPortCandidate {
                path: PathBuf::from("/dev/ttyUSB8"),
                kind: edge_modem::AtPortKind::Usb,
                usb_device: Some("2-4.2".into()),
                interface: Some("1.3".into()),
                interface_label: None,
                driver: Some("option".into()),
                vendor_id: Some("2c7c".into()),
                product_id: Some("0901".into()),
                policy: edge_modem::AtProbePolicy::Manual,
            }
        }

        fn profile(candidate: &edge_modem::AtPortCandidate) -> ManualModemProfile {
            ManualModemProfile {
                candidate_key: manual_candidate_key(candidate),
                usb_device: candidate.usb_device.clone(),
                vendor_id: candidate.vendor_id.clone(),
                product_id: candidate.product_id.clone(),
                control_port: candidate.path.display().to_string(),
                approved_at: 1,
            }
        }

        #[test]
        fn approval_requires_the_same_live_topology_and_port() {
            let candidate = candidate();
            let profile = profile(&candidate);
            assert!(manual_profile_matches(&profile, &candidate));

            let moved = edge_modem::AtPortCandidate {
                path: PathBuf::from("/dev/ttyUSB9"),
                ..candidate
            };
            assert!(
                !manual_profile_matches(&profile, &moved),
                "a recycled tty node must need fresh approval"
            );
        }

        #[test]
        fn only_a_raw_found_discovery_can_be_claimed() {
            let candidate = candidate();
            let found = LocalModemDiscovery {
                candidate_key: manual_candidate_key(&candidate),
                usb_device: candidate.usb_device.clone(),
                transport: DiscoveryTransport::Serial.wire().into(),
                control_port: candidate.path.display().to_string(),
                vendor_id: candidate.vendor_id.clone(),
                product_id: candidate.product_id.clone(),
                state: DiscoveryState::Found.wire().into(),
                imei: None,
                detail: String::new(),
                last_seen: 1,
            };
            assert!(manual_discovery_matches(&found, &candidate));
            assert!(
                !manual_discovery_matches(
                    &LocalModemDiscovery {
                        state: DiscoveryState::Claimed.wire().into(),
                        ..found
                    },
                    &candidate,
                ),
                "a repeated request cannot re-claim an already approved endpoint"
            );
        }
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
    fn remember_usb_site(shared: &Arc<SharedStore>, imei: &str, usb: Option<&str>, now: i64) {
        let Some(usb) = usb else { return };
        // Read now rather than assumed: the pair is what a recorded position
        // is checked against later, and recording a remembered value would
        // make that check compare the record with itself.
        let Some(identity) = edge_modem::usb_identity(usb) else {
            return;
        };
        if let Err(error) =
            shared
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
            log_error(format!(
                "usb position for imei={imei} not recorded: {error}"
            ));
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
            // Identity that belongs to the hardware rather than to this pass.
            // A module that has stopped answering still has the firmware it
            // had; the projection keeps the last non-null anyway, and sending
            // None here would be a reading rather than an absence.
            firmware: None,
            msisdn: None,
            control_port: None,
            apn_contexts: None,
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
        let _busy = radio.arbiter.acquire(edge_modem::ModemPriority::Normal);
        let mut port = edge_modem::AtPort::open_with_timeout(
            at_path,
            AT_PROBE_TIMEOUT.max(Duration::from_secs(2)),
        )
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
        // Same derivation as the QMI path, and the same source for the one
        // thing an IMSI does not carry: where its MNC ends.
        let ef_ad = read_ef_ad_over_at(&mut port);
        let home = at_home_network(imsi.as_deref(), &ef_ad, &at_path.display().to_string());
        // Same derivation as the QMI path, and for the same reason: the model
        // alone does not key the matrix. `AT+CGMM` answers "EC20F" where the
        // matrix is keyed on "EC20", so the raw reply used to arrive upstream
        // as its own family and `ModemFamily::from` -- an exact match -- turned
        // it into `Other("EC20F")`. The stick then took the matrix fallback and
        // reported every capability as `probe`, while the same hardware
        // answering over QMI got the measured EC20 rules. Both sources go to
        // `detect`, which is what reconciles the two paths.
        let model = at_identity_line(&mut port, "AT+CGMM").unwrap_or_default();
        let revision = at_identity_line(&mut port, "AT+CGMR").unwrap_or_default();
        let family = at_family(&model, &revision);
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
            firmware: Some(revision.clone()).filter(|value| !value.is_empty()),
            // Free here: the port is already open and the command is one more
            // round trip on it.
            msisdn: at_identity_line(&mut port, "AT+CNUM")
                .and_then(|line| edge_modem::parse_cnum(&[line])),
            control_port: Some(at_path.display().to_string()),
            // Free here, like the number: the port is open and this is one
            // more round trip on it.
            apn_contexts: read_apn_contexts(&mut port),
        })
    }

    /// Refuse an AT command that reaches disruptive state, unless the caller
    /// said `force`.
    ///
    /// One implementation for both entry points. The cloud relay and the LAN
    /// panel reach the modem through different traits, and a check written
    /// into only one of them would be a console the other way round: the panel
    /// is on the edge machine's LAN, so it is not the less exposed of the two.
    ///
    /// The refusal names the classification rather than saying "no", because
    /// the operator's next move is either to re-send with `force` or to
    /// discover they meant a different command.
    fn refuse_disruptive_at(command: &str, force: bool) -> Result<(), SendError> {
        if force {
            return Ok(());
        }
        match edge_core::classify_at_command(command).disruptive() {
            None => Ok(()),
            Some(kind) => Err(SendError::new(
                format!("at_{}_refused", kind.wire()),
                format!(
                    "{command:?} {} and was not sent; re-send with force to mean it",
                    kind.reason()
                ),
            )),
        }
    }

    /// Fill in each module's own number, reading it only when it is not
    /// already known for the card that is in the slot.
    ///
    /// Deliberately outside the probe. The QMI probe holds the modem arbiter
    /// for its whole run, and reading `AT+CNUM` needs that same arbiter for
    /// the module's serial port, so asking for it in there would wait on a
    /// lock this thread is holding.
    ///
    /// Read once per card rather than once per poll: the number cannot change
    /// while the same ICCID is in the same module, and this runs every eight
    /// seconds. `msisdn_iccid` is what makes "already known" answerable --
    /// on an eUICC a profile switch changes the ICCID under a module that has
    /// not moved, and a number carried across that boundary would be shown
    /// against a card it does not belong to.
    ///
    /// Every failure here is silent by design: a card that carries no number
    /// is the common case, not a fault, and a module that would not answer
    /// gets asked again next time.
    fn fill_msisdn(shared: &Arc<SharedStore>, radio: &Radio, snapshots: &mut [ModemSnapshot]) {
        let known = match shared.0.lock().expect("store").list_local_modems() {
            Ok(modems) => modems,
            Err(error) => {
                log_error(format!("msisdn cache not read: {error}"));
                return;
            }
        };
        for snapshot in snapshots.iter_mut() {
            if snapshot.msisdn.is_some() {
                continue;
            }
            // The AT probe already asked on the port it had open, so a `None`
            // there is an answer rather than an omission. Asking again here
            // would be a second round trip every eight seconds for a card
            // that has already said it has no number.
            if snapshot.discovery == Discovery::At {
                continue;
            }
            let stored = known.iter().find(|modem| modem.imei == snapshot.imei);
            if let Some(stored) = stored {
                // Same card as when it was read, so the stored answer stands
                // -- including a stored `None`, which is a card that has
                // already been asked and had nothing to say.
                if stored.msisdn_iccid.is_some() && stored.msisdn_iccid == snapshot.iccid {
                    snapshot.msisdn = stored.msisdn.clone();
                    continue;
                }
            }
            let read = radio.with_at_port(Some(&snapshot.imei), |port| {
                Ok(port
                    .command("AT+CNUM")
                    .ok()
                    .filter(edge_modem::AtExchange::succeeded)
                    .and_then(|exchange| edge_modem::parse_cnum(&exchange.lines)))
            });
            match read {
                Ok(number) => {
                    snapshot.msisdn = number.clone();
                    // Written even when the answer was nothing: that is the
                    // fact that keeps the next poll from asking again.
                    if let Err(error) = shared.0.lock().expect("store").set_modem_msisdn(
                        &snapshot.imei,
                        number.as_deref(),
                        snapshot.iccid.as_deref(),
                    ) {
                        log_error(format!("msisdn not recorded: {error}"));
                    }
                }
                Err(error) => {
                    log_line(format!("msisdn for {} unavailable: {error}", snapshot.imei))
                }
            }
        }
    }

    /// The module's packet data profiles, as JSON, or `None` if it would not
    /// say.
    ///
    /// Serialised here rather than carried as a struct because it is stored,
    /// sent and displayed as a block and nothing queries inside it.
    fn read_apn_contexts(port: &mut edge_modem::AtPort) -> Option<String> {
        let exchange = port
            .command("AT+CGDCONT?")
            .ok()
            .filter(edge_modem::AtExchange::succeeded)?;
        let mut contexts = edge_core::parse_cgdcont(&exchange.lines);
        // Credentials arrive one context at a time: `+QICSGP` has no form that
        // lists them all, so this is one exchange per row. It runs once per
        // card rather than once per poll -- `fill_apn_contexts` caches the
        // whole blob against the ICCID.
        //
        // `+CGAUTH` would be the standard place to read these and is not used:
        // measured 2026-08-30, an EC20 answers `ERROR` to `AT+CGAUTH=?` while
        // both bench families answer `AT+QICSGP`. See edge-core/src/apn.rs.
        //
        // A module that refuses `+QICSGP` keeps the contexts it did report.
        // The APN is the useful half and it is already in hand; dropping the
        // lot because the credential read failed would trade a whole answer
        // for half of one.
        for context in contexts.iter_mut() {
            let Some(answer) = port
                .command(&format!("AT+QICSGP={}", context.cid))
                .ok()
                .filter(edge_modem::AtExchange::succeeded)
            else {
                continue;
            };
            if let Some(credentials) = edge_core::parse_qicsgp(&answer.lines) {
                edge_core::merge_credentials(context, &credentials);
            }
        }
        // An empty answer is still an answer: a module holding no contexts is
        // a real state, and recording it as "not read" would leave an operator
        // unable to tell it from an agent that never asked.
        serde_json::to_string(&contexts).ok()
    }

    /// Collect a module's stored messages over AT.
    ///
    /// For modules the QMI sweep cannot reach: the EC200U series exposes no
    /// `cdc-wdm`, so a message that arrives on one is delivered, stored, and
    /// invisible. Proved on this bench -- China Telecom's reply to a balance
    /// query sat unread in module storage with nothing able to read it.
    ///
    /// 🔴 **The orchestration here is a second copy of the QMI collector's,
    /// and that is a deliberate, temporary choice rather than an oversight.**
    /// Every primitive is shared -- `decode_deliver`, `fragment_fingerprint`,
    /// `seen_before`, `assemble`, `enqueue_sms`, the ingest ledger -- because
    /// those are where a second implementation would drift. What is duplicated
    /// is the sequencing around them, and it was not extracted because the QMI
    /// path is load-bearing for three sticks, has no test over its
    /// orchestration, and could only have been refactored against a type
    /// check. Consolidating the two is worth doing with a test in front of it.
    ///
    /// The two rules that matter are restated rather than assumed, because
    /// getting either wrong loses messages:
    ///
    /// * A fragment whose siblings have not arrived stays on the module. The
    ///   next pass completes it; deleting it loses half a message for good.
    /// * A message our books already hold is deleted anyway. The store is
    ///   small and a full one stops accepting new messages, so a slot we have
    ///   already carried away must not be left occupying it.
    fn sweep_inbox_over_at(
        shared: &Arc<SharedStore>,
        outbox: &Arc<Mutex<DurableOutbox>>,
        radio: &Radio,
        imei: &str,
        now: i64,
    ) -> Result<usize, String> {
        let stored = radio
            .with_at_port(Some(imei), |port| {
                edge_modem::list_over_at(port)
                    .map_err(|error| SendError::new("at_list_failed", error.to_string()))
            })
            .map_err(|error| error.message)?;

        // Only what arrived. `AT+CMGL=4` asks for everything, and a store
        // holding this module's own sent messages would otherwise have them
        // decoded as deliveries and carried upstream as if somebody had sent
        // them to us.
        let received: Vec<_> = stored.into_iter().filter(|row| row.is_received()).collect();
        if received.is_empty() {
            return Ok(0);
        }

        let mut fragments: Vec<edge_core::InboundFragment> = Vec::with_capacity(received.len());
        for (slot, row) in received.iter().enumerate() {
            let decoded = edge_core::decode_deliver(&row.pdu);
            log_line(format!(
                "sms(at) from={} dcs={} encoding={} bytes={} udh={}",
                decoded.peer,
                decoded
                    .dcs
                    .map(|dcs| format!("{dcs:#04x}"))
                    .unwrap_or_else(|| "none".into()),
                decoded.encoding,
                row.pdu.len(),
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
            fragments.push(edge_core::InboundFragment {
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

        let ingested = {
            let store = shared.0.lock().expect("store");
            let mut counts: BTreeMap<String, u32> = BTreeMap::new();
            for fragment in &fragments {
                if counts.contains_key(&fragment.fingerprint) {
                    continue;
                }
                let copies = store
                    .ingested_sms_copies(imei, &fragment.fingerprint)
                    .map_err(|e| e.to_string())?;
                if copies > 0 {
                    counts.insert(fragment.fingerprint.clone(), copies);
                }
            }
            counts
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>()
        };
        let seen = edge_modem::seen_before(
            &fragments
                .iter()
                .map(|fragment| fragment.fingerprint.clone())
                .collect::<Vec<_>>(),
            &ingested,
        );

        // The decision, shared with the QMI collector. Both rules that lose
        // messages when they are broken live in there and are tested there.
        let settlement = edge_core::settle_inbound(fragments, &seen, now);
        if settlement.pending > 0 {
            log_line(format!(
                "{} sms(at) fragment(s) awaiting the rest, left on the module",
                settlement.pending
            ));
        }

        let mut stored_fingerprints: Vec<String> = Vec::new();
        let mut carried = 0usize;
        for settled in &settlement.ready {
            let message = &settled.message;
            if !message.missing.is_empty() {
                log_error(format!(
                    "sms(at) from={} released with part(s) {:?} of {} never delivered",
                    message.sender, message.missing, message.parts
                ));
            }
            let local = LocalMessage {
                seq: (carried as u64) + (now as u64 % 1_000_000) * 1000,
                peer: message.sender.clone(),
                body: message.body.clone(),
                bearer: "cellular".into(),
                direction: "inbound".into(),
                received_at: now,
                modem_imei: Some(imei.to_string()),
            };
            shared
                .0
                .lock()
                .expect("store")
                .insert_local_message(&local)
                .map_err(|e| e.to_string())?;
            enqueue_sms(
                outbox,
                imei,
                &message.sender,
                &message.body,
                settled.encoding,
                now,
            )?;
            carried += 1;
            stored_fingerprints.extend(settled.fingerprints.iter().cloned());
        }

        if !stored_fingerprints.is_empty() {
            let store = shared.0.lock().expect("store");
            store
                .record_ingested_sms(imei, &stored_fingerprints, now)
                .map_err(|e| e.to_string())?;
            store
                .prune_ingested_sms(imei, SMS_LEDGER_KEEP)
                .map_err(|e| e.to_string())?;
        }

        // Last, and only after the stores above committed.
        let deletable = settlement.deletable();
        if !deletable.is_empty() {
            let _ = radio.with_at_port(Some(imei), |port| {
                for slot in &deletable {
                    if let Some(row) = received.get(*slot) {
                        let _ = edge_modem::delete_over_at(port, row.index);
                    }
                }
                Ok(())
            });
        }
        Ok(carried)
    }

    /// Fill in the packet data profiles for modules whose probe did not read
    /// them.
    ///
    /// Same shape and the same reasons as `fill_msisdn`: the QMI probe holds
    /// the arbiter, `AT+CGDCONT?` needs it, and the table only changes when
    /// something writes to it. Re-read when the card changes, because a
    /// different profile on an eUICC can arrive with a different operator
    /// default.
    fn fill_apn_contexts(
        shared: &Arc<SharedStore>,
        radio: &Radio,
        snapshots: &mut [ModemSnapshot],
    ) {
        let known = match shared.0.lock().expect("store").list_local_modems() {
            Ok(modems) => modems,
            Err(error) => {
                log_error(format!("apn cache not read: {error}"));
                return;
            }
        };
        for snapshot in snapshots.iter_mut() {
            if snapshot.apn_contexts.is_some() {
                continue;
            }
            let stored = known.iter().find(|modem| modem.imei == snapshot.imei);
            if let Some(stored) = stored {
                // Keyed on the card for the same reason the number is: a
                // profile switch changes the ICCID under a module that has not
                // moved, and the operator default can change with it.
                if stored.apn_contexts.is_some() && stored.msisdn_iccid == snapshot.iccid {
                    snapshot.apn_contexts = stored.apn_contexts.clone();
                    continue;
                }
            }
            match radio.with_at_port(Some(&snapshot.imei), |port| Ok(read_apn_contexts(port))) {
                // Distinguished from the error below because they mean
                // different things and looked identical in the log: an error
                // is "no port to ask on", this is "the port answered and the
                // module would not list its contexts".
                Ok(None) => log_line(format!(
                    "apn contexts for {} not listed by the module",
                    snapshot.imei
                )),
                Ok(contexts) => snapshot.apn_contexts = contexts,
                Err(error) => log_line(format!(
                    "apn contexts for {} unavailable: {error}",
                    snapshot.imei
                )),
            }
        }
    }

    /// One identifying AT value, trimmed.
    ///
    /// `None` covers all three ways this can fail to produce something worth
    /// keying on -- the port was lost, the module rejected the command, or it
    /// answered `OK` with no content -- because none of them is different to a
    /// caller deciding what the hardware is.
    fn at_identity_line(port: &mut edge_modem::AtPort, command: &str) -> Option<String> {
        port.command(command)
            .ok()
            .filter(edge_modem::AtExchange::succeeded)
            .and_then(|exchange| exchange.lines.first().map(|line| line.trim().to_string()))
            .filter(|value| !value.is_empty())
    }

    /// The canonical family name for a module identified over AT.
    ///
    /// The naming rule itself lives in `edge-core` so both transports share
    /// one copy of it and it stays testable off Linux. What belongs here is
    /// the log: an unrecognised family is an honest answer but a useless one,
    /// and without the strings that produced it there is no way to find out
    /// which pattern is missing.
    fn at_family(model: &str, revision: &str) -> String {
        let name = ModemFamily::detect_name(model, revision);
        if name == ModemFamily::UNKNOWN {
            log_error(format!(
                "family unreadable over AT at+cgmm={model:?} at+cgmr={revision:?}"
            ));
        } else if matches!(ModemFamily::from(name.as_str()), ModemFamily::Other(_)) {
            log_error(format!(
                "family unrecognised over AT model={model:?} revision={revision:?}"
            ));
        }
        name
    }

    /// What to assume when the card would not say how long its MNC is.
    ///
    /// Two is what this agent assumed unconditionally until `EF_AD` was read,
    /// and it is right for every card on the bench -- but it is an assumption,
    /// so it is only ever reached with a log line naming the card that forced
    /// it. A silent fallback here does not blank the home network, it fills it
    /// with a wrong one.
    const FALLBACK_MNC_DIGITS: usize = 2;

    /// The home network as the AT-only probe derives it.
    ///
    /// `AT+CIMI` gives the IMSI and `+CRSM` gives `EF_AD`; both come off the
    /// card, neither is configured here. That is what makes the console's
    /// operator name a card reading rather than a claim of ours.
    fn at_home_network(imsi: Option<&str>, ef_ad: &[String], source: &str) -> Option<Network> {
        let bytes = parse_crsm_binary(ef_ad);
        Network::from_imsi(imsi?, mnc_digits_or_fallback(bytes, source))
    }

    /// The home network as the QMI probe derives it. Same rule, same decoder;
    /// only the transport for `EF_AD` differs.
    fn qmi_home_network(
        imsi: Option<&str>,
        ef_ad: Result<Vec<u8>, String>,
        source: &str,
    ) -> Option<Network> {
        Network::from_imsi(imsi?, mnc_digits_or_fallback(ef_ad, source))
    }

    fn mnc_digits_or_fallback(ef_ad: Result<Vec<u8>, String>, source: &str) -> usize {
        let digits = ef_ad.and_then(|bytes| {
            // The bytes go in the message: an EF_AD this decoder rejects is
            // the one thing that cannot be re-read from the log later.
            Network::mnc_digits_from_ef_ad(&bytes)
                .map_err(|error| format!("{error} ({})", edge_modem::hex_upper(&bytes)))
        });
        match digits {
            Ok(digits) => digits,
            Err(error) => {
                log_error(format!(
                    "EF_AD {source}: {error}; assuming a {FALLBACK_MNC_DIGITS}-digit MNC"
                ));
                FALLBACK_MNC_DIGITS
            }
        }
    }

    /// `EF_AD` over the AT port, for a module with no QMI interface.
    ///
    /// `+CRSM` is restricted access to the file the module's own USIM
    /// application already has selected: one command on the basic channel,
    /// no logical channel opened, nothing left selected afterwards. The path
    /// argument is deliberately absent -- all three bench modules answer
    /// `+CME ERROR: 23` to `AT+CRSM=176,28589,0,0,4,,"7FFF"` and answer
    /// `+CRSM: 144,0,"00000002"` without it.
    fn read_ef_ad_over_at(port: &mut edge_modem::AtPort) -> Vec<String> {
        let command = format!("AT+CRSM=176,{EF_AD_FILE_ID},0,0,{EF_AD_READ_BYTES}");
        port.command(&command)
            .ok()
            .filter(edge_modem::AtExchange::succeeded)
            .map(|exchange| exchange.lines)
            .unwrap_or_default()
    }

    /// `EF_AD` is `6FAD`, and `+CRSM` names files in decimal. The QMI path
    /// reaches the same file through `edge_modem`'s own constant; this is the
    /// AT spelling of it, not a second opinion about which file to read.
    const EF_AD_FILE_ID: u16 = 0x6fad;

    /// Four bytes is all that is wanted: byte 4 carries the MNC length and
    /// what follows it is for services this agent does not read. Asking for
    /// the whole file would need its length first, which is a second command.
    const EF_AD_READ_BYTES: u8 = 4;

    /// `+CRSM: <sw1>,<sw2>,"<hex>"`.
    ///
    /// `sw1` is decimal, so a card that answered normally says `144`. `91xx`
    /// is accepted too: it means the read succeeded and a proactive command
    /// is waiting, and rejecting it would drop a perfectly good `EF_AD` on a
    /// card that happens to run a SIM toolkit applet.
    fn parse_crsm_binary(lines: &[String]) -> Result<Vec<u8>, String> {
        let line = lines
            .iter()
            .find(|line| line.starts_with("+CRSM:"))
            .ok_or_else(|| format!("no +CRSM line in {lines:?}"))?;
        let body = line.trim_start_matches("+CRSM:").trim();
        let mut fields = body.splitn(3, ',');
        let sw1: u8 = fields
            .next()
            .and_then(|field| field.trim().parse().ok())
            .ok_or_else(|| format!("no SW1 in {line:?}"))?;
        let sw2: u8 = fields
            .next()
            .and_then(|field| field.trim().parse().ok())
            .ok_or_else(|| format!("no SW2 in {line:?}"))?;
        if !(sw1 == 0x90 && sw2 == 0x00) && sw1 != 0x91 {
            return Err(format!("card answered SW {sw1:02x}{sw2:02x}"));
        }
        let hex = fields
            .next()
            .map(|field| field.trim().trim_matches('"'))
            .filter(|field| !field.is_empty())
            .ok_or_else(|| format!("no data in {line:?}"))?;
        edge_modem::decode_hex(hex).ok_or_else(|| format!("{hex:?} is not hex"))
    }

    #[cfg(test)]
    mod home_network_tests {
        use super::*;

        /// The US profile this product exists to run. Both probes must slice
        /// its IMSI where `EF_AD` says, not at a fixed two digits: `310-26`
        /// is not an operator, it is what `310260…` looks like after the
        /// wrong cut, and it reaches the console as a bare string and the
        /// ePDG FQDN as `mnc026`.
        #[test]
        fn the_qmi_probe_reads_a_three_digit_mnc_off_the_card() {
            let home = qmi_home_network(
                Some("310260123456789"),
                Ok(vec![0x00, 0x00, 0x00, 0x03]),
                "/dev/cdc-wdm0",
            );
            assert_eq!(home.map(Network::numeric), Some("310-260".to_string()));
        }

        #[test]
        fn the_at_only_probe_reads_a_three_digit_mnc_off_the_card() {
            let home = at_home_network(
                Some("310260123456789"),
                &["+CRSM: 144,0,\"00000003\"".to_string()],
                "/dev/ttyUSB2",
            );
            assert_eq!(home.map(Network::numeric), Some("310-260".to_string()));
        }

        /// The three cards on the bench, with the `EF_AD` each one actually
        /// answered on 2026-08-24 -- `00 00 00 02` over QMI READ TRANSPARENT
        /// and `+CRSM: 144,0,"00000002"` over AT, on all three. Their home
        /// networks are what the cloud shows today and must not move.
        #[test]
        fn the_bench_cards_report_the_same_home_network_as_before() {
            let bench = [
                ("454006395021420", "454-00"),
                ("460026303803275", "460-02"),
                ("454003063217957", "454-00"),
            ];
            for (imsi, expected) in bench {
                let over_qmi =
                    qmi_home_network(Some(imsi), Ok(vec![0x00, 0x00, 0x00, 0x02]), "bench");
                assert_eq!(over_qmi.map(Network::numeric), Some(expected.to_string()));
                let over_at = at_home_network(
                    Some(imsi),
                    &["+CRSM: 144,0,\"00000002\"".to_string()],
                    "bench",
                );
                assert_eq!(over_at.map(Network::numeric), Some(expected.to_string()));
            }
        }

        /// A card that will not say keeps today's behaviour rather than
        /// guessing something new, on both transports.
        #[test]
        fn a_card_that_will_not_state_its_mnc_length_falls_back_to_two() {
            assert_eq!(
                qmi_home_network(Some("460026303803275"), Err("no card".into()), "bench")
                    .map(Network::numeric),
                Some("460-02".to_string())
            );
            // Three bytes: an older card that never states the length.
            assert_eq!(
                qmi_home_network(Some("460026303803275"), Ok(vec![0x00, 0x00, 0x00]), "bench")
                    .map(Network::numeric),
                Some("460-02".to_string())
            );
            // `+CME ERROR: 23`, which is what the bench modules answer when
            // `+CRSM` is given a path argument: no `+CRSM:` line at all.
            assert_eq!(
                at_home_network(Some("460026303803275"), &[], "bench").map(Network::numeric),
                Some("460-02".to_string())
            );
        }

        /// `+CRSM` reports the status word in decimal, and a failed read
        /// still comes back on an `OK` line. Reading `6A82` as data would
        /// hand the decoder two bytes of status word as an `EF_AD`.
        #[test]
        fn a_crsm_answer_that_is_not_a_successful_read_is_rejected() {
            assert!(parse_crsm_binary(&["+CRSM: 106,130".to_string()]).is_err());
            assert!(parse_crsm_binary(&["+CRSM: 148,4,\"\"".to_string()]).is_err());
            assert!(parse_crsm_binary(&["OK".to_string()]).is_err());
            assert!(parse_crsm_binary(&["+CRSM: 144,0,\"00zz0002\"".to_string()]).is_err());
            assert_eq!(
                parse_crsm_binary(&["+CRSM: 144,0,\"00000002\"".to_string()]),
                Ok(vec![0x00, 0x00, 0x00, 0x02])
            );
            // `91xx`: read succeeded, a proactive command is waiting.
            assert_eq!(
                parse_crsm_binary(&["+CRSM: 145,32,\"00000003\"".to_string()]),
                Ok(vec![0x00, 0x00, 0x00, 0x03])
            );
        }

        /// The command is the one that was sampled on all three modules.
        /// Adding the path argument makes them answer `+CME ERROR: 23`.
        #[test]
        fn the_crsm_read_is_the_command_the_bench_answered() {
            assert_eq!(
                format!("AT+CRSM=176,{EF_AD_FILE_ID},0,0,{EF_AD_READ_BYTES}"),
                "AT+CRSM=176,28589,0,0,4"
            );
        }
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

        let net_sample = std::fs::read_to_string("/proc/net/dev")
            .ok()
            .map(|text| parse_proc_net_dev(&text));
        let now = Instant::now();
        let (net_rx_bytes_per_sec, net_tx_bytes_per_sec) = match (memory.net, net_sample) {
            (Some((previous, at)), Some(current)) => {
                let seconds = now.duration_since(at).as_secs_f64();
                if seconds > 0.0 {
                    (
                        Some(((current.rx.saturating_sub(previous.rx)) as f64 / seconds) as u64),
                        Some(((current.tx.saturating_sub(previous.tx)) as f64 / seconds) as u64),
                    )
                } else {
                    (None, None)
                }
            }
            _ => (None, None),
        };
        if let Some(current) = net_sample {
            memory.net = Some((current, now));
        }

        let disk = disk_usage(Path::new(&env("VODOGE_EDGE_DATA", "/var/lib/vodoge-edge")));

        HostStats {
            public_ip,
            cpu_percent,
            memory_used_bytes: memory_reading
                .map(|(total, available)| total.saturating_sub(available)),
            memory_total_bytes: memory_reading.map(|(total, _)| total),
            disk_used_bytes: disk.map(|(total, available)| total.saturating_sub(available)),
            disk_total_bytes: disk.map(|(total, _)| total),
            net_rx_bytes_per_sec,
            net_tx_bytes_per_sec,
            cpu_model: read_cpu_model(),
            kernel: read_trimmed_file("/proc/sys/kernel/osrelease"),
            hostname: read_trimmed_file("/proc/sys/kernel/hostname"),
        }
    }

    /// One line per interface; the first two counter columns are received and
    /// the ninth is transmitted.
    ///
    /// Loopback and the modules' own `wwan` interfaces are left out. This
    /// number is meant to answer "is the box's link to the world busy", and
    /// counting traffic the agent sends to hardware sitting inside the same
    /// machine would answer a different question with the same figure.
    fn parse_proc_net_dev(text: &str) -> NetTotals {
        let mut totals = NetTotals::default();
        for line in text.lines() {
            let Some((name, counters)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            if name == "lo" || name.starts_with("wwan") || name.starts_with("veth") {
                continue;
            }
            let fields: Vec<u64> = counters
                .split_whitespace()
                .map(|field| field.parse().unwrap_or(0))
                .collect();
            if fields.len() < 9 {
                continue;
            }
            totals.rx = totals.rx.saturating_add(fields[0]);
            totals.tx = totals.tx.saturating_add(fields[8]);
        }
        totals
    }

    /// Total and available bytes of the filesystem holding `path`.
    ///
    /// Available rather than free: the difference is the root reserve, and
    /// reporting free space the agent cannot actually use would say a disk is
    /// fine right up to the point where writes start failing.
    fn disk_usage(path: &Path) -> Option<(u64, u64)> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let raw = CString::new(path.as_os_str().as_bytes()).ok()?;
        // SAFETY: `raw` is a valid NUL-terminated path and `stats` is a
        // correctly sized, zeroed target that statvfs only writes into.
        let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(raw.as_ptr(), &mut stats) } != 0 {
            return None;
        }
        let block = stats.f_frsize as u64;
        Some((
            block.saturating_mul(stats.f_blocks as u64),
            block.saturating_mul(stats.f_bavail as u64),
        ))
    }

    fn read_trimmed_file(path: &str) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()
            .map(|text| text.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    fn read_cpu_model() -> Option<String> {
        let text = std::fs::read_to_string("/proc/cpuinfo").ok()?;
        text.lines()
            .find(|line| line.starts_with("model name"))
            .and_then(|line| line.split_once(':'))
            .map(|(_, value)| value.trim().to_string())
            .filter(|value| !value.is_empty())
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
        candidate
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|address| address.to_string())
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
        let _busy = radio.arbiter.acquire(edge_modem::ModemPriority::Normal);
        let device = CdcWdmDevice::open(path).map_err(|e| e.to_string())?;
        let mut client = QmiClient::new(device);
        client.sync().map_err(|e| e.to_string())?;
        let serials = client.get_serial_numbers().map_err(|e| e.to_string())?;
        let imei = serials
            .imei
            .clone()
            .ok_or_else(|| "missing IMEI".to_string())?;
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
        // MCC is always the first three digits. How many of the rest are the
        // MNC is a property of the card, not of this fleet, so it is read
        // from the card too -- see `qmi_home_network`.
        let ef_ad = client.read_ef_ad().map_err(|error| error.to_string());
        let home = qmi_home_network(imsi.as_deref(), ef_ad, &path.display().to_string());
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
        // The inventory row is written only for a module somebody adopted.
        // Probing is how identity is learned, and it happens before adoption
        // by necessity -- you cannot adopt an IMEI you have not read -- so the
        // gate belongs here rather than earlier.
        if is_managed(shared, &imei) {
            let store = shared.0.lock().expect("store");
            store
                .upsert_local_modem(&LocalModem {
                    imei: imei.clone(),
                    family: family_name.clone(),
                    firmware: Some(revision.clone()).filter(|value| !value.is_empty()),
                    // Filled by `fill_msisdn` after the arbiter is free, so
                    // nothing is written for it here.
                    msisdn: None,
                    msisdn_iccid: None,
                    // Filled by `fill_apn_contexts` after the arbiter is free.
                    apn_contexts: None,
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
                    discovery: Discovery::Qmi.wire().to_string(),
                    manageable: true,
                    control_port: Some(path.display().to_string()),
                })
                .map_err(|e| e.to_string())?;
        }

        // One window of slots read directly, on top of the listing. Windows
        // are aligned so a rotation covers the store exactly, with no slot
        // read twice before every other slot has been read once.
        let sweep_window =
            SMS_SWEEP_CURSOR.fetch_add(1, Ordering::Relaxed) % (SMS_SWEEP_LIMIT / SMS_SWEEP_WINDOW);
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
        let mut fragments: Vec<edge_core::InboundFragment> = Vec::with_capacity(pass.inbound.len());
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
            fragments.push(edge_core::InboundFragment {
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
            counts
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>()
        };
        let seen = edge_modem::seen_before(
            &fragments
                .iter()
                .map(|fragment| fragment.fingerprint.clone())
                .collect::<Vec<_>>(),
            &ingested,
        );

        // The decision, shared with the AT collector in `sweep_inbox_over_at`.
        // Both rules that lose messages when they are broken live in
        // `edge_core::settle_inbound` and are tested there rather than in
        // either transport.
        let settlement = edge_core::settle_inbound(fragments, &seen, now);

        // Rows our books already account for. A previous pass stored them and
        // the delete that should have followed did not take -- or somebody
        // read them out from under us. Storing them again would show the
        // operator the same message twice, so the slot is cleared instead.
        if !settlement.already_ours.is_empty() {
            log_line(format!(
                "{} sms already stored, clearing the modem's copy",
                settlement.already_ours.len()
            ));
            let settled: Vec<_> = settlement
                .already_ours
                .iter()
                .filter_map(|slot| pass.inbound.get(*slot).cloned())
                .collect();
            let _ = delete_inbound(&mut client, &settled);
        }

        // A fragment whose siblings have not arrived stays on the modem, so
        // the next pass can complete it. Deleting it would lose half a message
        // permanently, which is worse than reading it twice.
        if settlement.pending > 0 {
            log_line(format!(
                "{} sms fragment(s) awaiting the rest, left on the modem",
                settlement.pending
            ));
        }

        let mut stored_fingerprints: Vec<String> = Vec::new();
        let mut stored: Vec<edge_modem::CollectedMessage> = Vec::new();
        for (index, settled) in settlement.ready.iter().enumerate() {
            let message = &settled.message;
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
            enqueue_sms(
                outbox,
                &imei,
                &message.sender,
                &message.body,
                settled.encoding,
                now,
            )?;
            stored_fingerprints.extend(settled.fingerprints.iter().cloned());
            stored.extend(
                settled
                    .slots
                    .iter()
                    .filter_map(|slot| pass.inbound.get(*slot).cloned()),
            );
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
            // Already read above to decide the family, and previously thrown
            // away with it.
            firmware: Some(revision.clone()).filter(|value| !value.is_empty()),
            // Filled in after the probe by `fill_msisdn`: reading it needs the
            // module's AT port, which this function cannot take because it is
            // already holding the arbiter.
            msisdn: None,
            control_port: Some(path.display().to_string()),
            // Filled by `fill_apn_contexts` after the probe, for the same
            // reason the number is: reading them needs the module's AT port,
            // which this function is already holding the arbiter against.
            apn_contexts: None,
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
        /// Firmware revision as the module reports it. Both probes already
        /// read this to decide the family; it used to be discarded, so the
        /// only way to learn which build was on a stick was to ask for a
        /// diagnostic report and read the answer by hand.
        firmware: Option<String>,
        /// The card's own number, where the card carries one. Often absent:
        /// plenty of operators never write it, so `None` means the card did
        /// not say rather than that there is no number.
        msisdn: Option<String>,
        /// The kernel node this module is driven through.
        control_port: Option<String>,
        /// Packet data profiles, as JSON. `None` means not read this pass --
        /// they are cached and re-read only when the card changes.
        apn_contexts: Option<String>,
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
        /// The filesystem holding the agent's own databases, not every mount.
        /// That is the one whose exhaustion stops the outbox committing.
        disk_used_bytes: Option<u64>,
        disk_total_bytes: Option<u64>,
        /// Averaged over the interval between two polls, like `cpu_percent`,
        /// rather than being the since-boot counter `/proc/net/dev` holds.
        net_rx_bytes_per_sec: Option<u64>,
        net_tx_bytes_per_sec: Option<u64>,
        cpu_model: Option<String>,
        kernel: Option<String>,
        hostname: Option<String>,
    }

    /// How long a candidate sighting outlives its last observation.
    ///
    /// A day: long enough that a module unplugged overnight is still listed in
    /// the morning with an honest `last_seen`, short enough that a week of
    /// re-plugs does not leave a list that is mostly archaeology.
    const DISCOVERY_RETENTION_MS: i64 = 24 * 60 * 60 * 1000;

    /// The DeviceState payload for one poll pass.
    ///
    /// Separated from the enqueue so the shape can be asserted without a
    /// durable outbox on disk -- the rules below are about what is in the
    /// map, and every one of them had been unexercised.
    ///
    /// 🔴 An empty `modems` is reported, not swallowed. It used to return
    /// early, because `DeviceStatePayload.modems` carried `minItems: 1` and
    /// there was nothing honest to invent. The cost was not silence about
    /// modems -- it was silence about **everything**: `discoveries` and
    /// `managed_imeis` ride in the same envelope, so a box whose only hardware
    /// was a serial candidate awaiting approval reported nothing at all and
    /// was invisible from the cloud. The schema now says `minItems: 0`, and an
    /// empty list is the honest report it always was.
    fn device_state_payload(
        matrix: &CapabilityMatrix,
        modems: &[ModemSnapshot],
        host: &HostStats,
        discoveries: Option<&[edge_store::LocalModemDiscovery]>,
        managed: Option<&[String]>,
        now: i64,
    ) -> serde_json::Value {
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
            let resolved = matrix.query(&ModemFamily::from(modem.family.as_str()), &carrier);
            let capability = resolved.capability.clone();
            // Whether the matrix had anything to say about this pair at all.
            // The panel has shown this since it existed; the cloud could not
            // tell "characterised as probe" from "never heard of it", and
            // those are the two states a ledger entry is written between.
            let capability_origin = match resolved.origin {
                CapabilityOrigin::Rule => "rule",
                CapabilityOrigin::Fallback => "fallback",
            };
            let carrier_profile = carrier.as_str().to_string();
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
                // Read by both identity probes and previously discarded with
                // the family they were used to detect.
                "firmware": modem.firmware,
                "msisdn": modem.msisdn,
                // Physical topology. The cloud cannot see the edge machine's
                // /dev or sysfs, so without these an operator diagnosing a
                // silent stick has to ask somebody with a shell on the box.
                "control_port": modem.control_port,
                "usb_device": modem.usb,
                // The module's own profile table. Which context carries data
                // is a row on the module rather than a property of the card,
                // and this is the only way the cloud can see it.
                "apn_contexts": modem.apn_contexts.as_deref()
                    .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok()),
                "capability": {
                    "sms_mo": capability.sms_mo.wire(),
                    "sms_mt": capability.sms_mt.wire(),
                    "matrix_version": matrix.version(),
                    "carrier_profile": carrier_profile,
                    "origin": capability_origin
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
                "disk_used_bytes": host.disk_used_bytes,
                "disk_total_bytes": host.disk_total_bytes,
                "net_rx_bytes_per_sec": host.net_rx_bytes_per_sec,
                "net_tx_bytes_per_sec": host.net_tx_bytes_per_sec,
                "cpu_model": host.cpu_model,
                "kernel": host.kernel,
                "hostname": host.hostname,
            },
            // Everything this agent manages, including what it cannot find
            // right now. Sent so the cloud can retire a row for a module
            // nobody manages any more: the edge simply stops reporting one,
            // and without this the row sits at its last observation for ever,
            // which reads as a healthy module that went quiet.
        });
        // 🔴 Inserted only when the registry was actually read, and `json!`
        // is why this is not a field above: `Option::None` there serialises as
        // `null`, and the contract types this as an array -- a failed read
        // would produce an envelope the cloud rejects outright.
        //
        // The distinction matters beyond validity. An empty list is a real
        // state (nothing adopted) and the cloud acts on it by retiring every
        // row; sending one because a store read failed would unmanage the
        // whole device on a transient error.
        let mut payload = payload;
        // What the agent has seen and not written to. The panel could always
        // list these and claim one; until they travelled, an operator working
        // from the cloud could not tell that a stick had been plugged in at
        // all.
        //
        // 🔴 Inserted only when the store was actually read, for the same
        // reason `managed_imeis` below is -- and against the same cloud rule.
        // `0050`'s projection replaces the whole list from this key, so an
        // empty array retires every candidate row for this device. Sending one
        // because a store read failed would clear a list an operator is
        // looking at, on a transient error.
        if let (Some(discoveries), Some(map)) = (discoveries, payload.as_object_mut()) {
            map.insert(
                "discoveries".into(),
                serde_json::json!(discoveries
                    .iter()
                    .map(|candidate| serde_json::json!({
                        "candidate_key": candidate.candidate_key,
                        "usb_device": candidate.usb_device,
                        "transport": candidate.transport,
                        "control_port": candidate.control_port,
                        "vendor_id": candidate.vendor_id,
                        "product_id": candidate.product_id,
                        "state": candidate.state,
                        "imei": candidate.imei,
                        "detail": candidate.detail,
                        "last_seen": candidate.last_seen,
                    }))
                    .collect::<Vec<_>>()),
            );
        }
        if let (Some(managed), Some(map)) = (managed, payload.as_object_mut()) {
            map.insert("managed_imeis".into(), serde_json::json!(managed));
        }
        payload
    }

    /// 追溯执行敢做到哪一步。
    ///
    /// 🔴 默认 `Mark`：这个特性上线时**一行都不删**，只标记并告警。
    ///
    /// 这是整套设计里唯一让「自动做破坏」保有退路的地方。机队上先跑几周
    /// 只标记模式，看 `retro_quarantined` 的误报率；误报为零之后，再逐台
    /// 打开 `VODOGE_RETRO_ENFORCE=unbind`。而那一步是可逆的 ——
    /// 改环境变量重启即可。
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum EnforceMode {
        Mark,
        Unbind,
    }

    fn enforce_mode() -> EnforceMode {
        enforce_mode_from(&env("VODOGE_RETRO_ENFORCE", "mark"))
    }

    /// 🔴 只有逐字的 `unbind` 才开。拼错、留空、写 `true`、写 `UNBIND`
    /// —— 全都落到 `Mark`。
    ///
    /// 一个会因为拼错而**打开**破坏性行为的开关，比没有开关更糟：
    /// 运维以为自己写的是「关」，而它开着。所以这里既不做大小写归一，
    /// 也不接受任何同义词 —— 只有一个字符串通往删除。
    fn enforce_mode_from(value: &str) -> EnforceMode {
        match value.trim() {
            "unbind" => EnforceMode::Unbind,
            _ => EnforceMode::Mark,
        }
    }

    /// 一趟追溯执行要做的全部动作。
    #[derive(Debug, Default)]
    struct EnforcementPlan {
        /// 闸又过了，清掉标记。
        keep: Vec<String>,
        /// 判不了，维持现状。
        hold: Vec<(String, edge_core::HoldReason)>,
        /// 真判定，隔离期未满。
        quarantine: Vec<(String, edge_core::BindRefusal, i64, u32)>,
        /// 真判定，隔离期满。
        unbind: Vec<(String, edge_core::BindRefusal)>,
    }

    /// 把三张表拼成每根模组的证据。
    ///
    /// ⚠️ 每一个 `None` 都表示「读不到」，不表示「没有」——
    /// `enforce_one` 依赖这个约定。
    fn build_evidence(
        registered: &[edge_store::RegisteredModem],
        gates: &std::collections::BTreeMap<String, edge_store::GateFailure>,
        observed: &[edge_store::LocalModem],
        discoveries: &[edge_store::LocalModemDiscovery],
        now: i64,
    ) -> Vec<edge_core::GateEvidence> {
        registered
            .iter()
            .map(|row| {
                let seen = observed.iter().find(|modem| modem.imei == row.imei);
                let discovery = discoveries
                    .iter()
                    .find(|candidate| candidate.imei.as_deref() == Some(row.imei.as_str()));
                let gate = gates.get(&row.imei);
                edge_core::GateEvidence {
                    imei: row.imei.clone(),
                    adopted_family: row
                        .family
                        .as_deref()
                        .map(|name| ModemFamily::from(name)),
                    observed_family: seen.map(|modem| ModemFamily::from(modem.family.as_str())),
                    // 归属网络读不到就是 None —— 这里**没有**
                    // `.unwrap_or("Generic-International")`，理由和
                    // `register_modem` 里那处一样：那个兜底在报告和路由里
                    // 说得通，在一道闸上它意味着一张还没读出 IMSI 的卡会被
                    // 当成国际卡去过闸。
                    carrier: seen.and_then(|modem| {
                        let (mcc, mnc) = modem.home_mcc.zip(modem.home_mnc)?;
                        Some(CarrierProfile::from(
                            Network::new(mcc, mnc).carrier_profile(),
                        ))
                    }),
                    usb: discovery.and_then(|candidate| {
                        match (
                            candidate.vendor_id.as_deref(),
                            candidate.product_id.as_deref(),
                        ) {
                            (Some(vendor), Some(product)) => {
                                edge_core::UsbIdentity::parse(vendor, product)
                            }
                            _ => None,
                        }
                    }),
                    observation_age_ms: seen
                        .and_then(|modem| modem.last_seen)
                        .map(|seen| now.saturating_sub(seen).max(0)),
                    failing_since_ms: gate.map(|gate| gate.since),
                    failing_passes: gate.map(|gate| gate.passes).unwrap_or(0),
                }
            })
            .collect()
    }

    /// 读不到隔离标记的那几根，这一趟**不判**，改成 Hold。
    ///
    /// 🔴 这不是洁癖。把「读不到标记」和「没有标记」混起来会开出一整类
    /// 零宽限删除：读不到时若照常判定，得到 `Keep` 的那一根不会被清标记
    /// （调用方以为它本来就没有），库里旧的 `gate_failed_since` 原封不动地
    /// 活下来；下一次真判定用 `COALESCE` 接上那个旧起点，隔离期当场就是满的
    /// —— 一次瞬时的 SQLITE_BUSY 就能把 30 分钟的宽限变成 0。
    ///
    /// 第一版代码的注释写着「这一趟就不判它」，而代码照判不误。
    /// 这个函数是让那句注释变成真的。
    fn split_unreadable(
        registered: &[edge_store::RegisteredModem],
        unreadable: &[String],
    ) -> (
        Vec<edge_store::RegisteredModem>,
        Vec<(String, edge_core::HoldReason)>,
    ) {
        let mut judged = Vec::with_capacity(registered.len());
        let mut holds = Vec::new();
        for row in registered {
            if unreadable.iter().any(|imei| imei == &row.imei) {
                // 照样要出现在告警里 —— 静默消失的那几根恰好是最需要
                // 有人看一眼的。
                holds.push((
                    row.imei.clone(),
                    edge_core::HoldReason::GateStateUnreadable,
                ));
            } else {
                judged.push(row.clone());
            }
        }
        (judged, holds)
    }

    /// 这一趟要打开并写 AT 的那组串口。
    ///
    /// 🔴 从**已过滤**的候选派生，不是 `edge_modem::at_control_ports()`。
    ///
    /// 那个函数是同一个选择器套在这台机器上的**全部**候选上，而调用方会真的
    /// 打开每一个返回值并往里写 AT。`edge_core::strategies` 里那条注释说的
    /// 正是这种硬件 —— 两根高通 MSM8916 棒子，能被枚举、永远认不出，
    /// 把候选列表刷满几个小时，在日志里和真故障分不开 —— 它的结尾是
    /// 「Nothing drives them, so **nothing should open them**」。
    ///
    /// QMI 那半边早就在开之前过闸了（`driven_by_a_strategy`）。这半边没有，
    /// 而这半边才是会往陌生串口写字节的那一半。
    ///
    /// ⚠️ 手工批准的口**不**受这一闸约束，这是对的：运维明确点过头，
    ///    而这道闸本来就是为「没人点过头的东西别碰」而设的。
    fn at_paths_to_probe(
        candidates: &[edge_modem::AtPortCandidate],
        approved_manual: Vec<PathBuf>,
    ) -> Vec<PathBuf> {
        let driven: Vec<_> = candidates
            .iter()
            .filter(|candidate| candidate_is_driven(candidate))
            .cloned()
            .collect();
        let mut paths = edge_modem::select_control_ports(driven);
        paths.extend(approved_manual);
        paths.sort();
        paths.dedup();
        paths
    }

    /// 这个串口候选，本 build 有没有策略驱动它背后的硬件。
    ///
    /// 判据只看 USB 标识，因为那是开口之前唯一能知道的东西。
    ///
    /// ⚠️ **没有** USB 标识的一律保留，这是有意的，不是漏网：
    /// 平台直挂的高速串口本来就没有 vid/pid，在这里拒掉它会丢掉这道闸从来
    /// 就不针对的硬件。同理，vid/pid 存在却解析不出十六进制的也保留 ——
    /// 那是 sysfs 给了个不认识的形状，不是「这块硬件我们不支持」。
    ///
    /// 🔴 和 `bind_gates` 的 `UnreadableUsbIdentity` 方向相反，而两边都对：
    /// 那里在决定**要不要纳管**，证据不足就拒；这里在决定**要不要看一眼**，
    /// 证据不足就看。看一眼的代价是一次 AT 探测，拒绝的代价是一块插着的
    /// 硬件永远不出现在候选列表里。
    fn candidate_is_driven(candidate: &edge_modem::AtPortCandidate) -> bool {
        match (
            candidate.vendor_id.as_deref(),
            candidate.product_id.as_deref(),
        ) {
            (Some(vendor), Some(product)) => match edge_core::UsbIdentity::parse(vendor, product) {
                Some(identity) => strategy_registry().drives(identity),
                None => true,
            },
            _ => true,
        }
    }

    #[cfg(test)]
    mod serial_gate_tests {
        use super::candidate_is_driven;
        use edge_modem::{AtPortCandidate, AtPortKind, AtProbePolicy};
        use std::path::PathBuf;

        fn candidate(path: &str, usb: &str, vid: Option<&str>, pid: Option<&str>) -> AtPortCandidate {
            AtPortCandidate {
                path: PathBuf::from(path),
                kind: AtPortKind::Usb,
                usb_device: Some(usb.to_owned()),
                interface: Some("1.2".into()),
                interface_label: None,
                driver: Some("option".into()),
                vendor_id: vid.map(str::to_owned),
                product_id: pid.map(str::to_owned),
                policy: AtProbePolicy::Automatic,
            }
        }

        /// 🔴 没有策略驱动的硬件，一个口都不该被打开。
        ///
        /// `edge_core::strategies` 里那条注释说的正是这种：两根高通 MSM8916
        /// 棒子，能被枚举、永远认不出，把候选列表刷满几个小时，
        /// 在日志里和真故障分不开。它的结尾是「Nothing drives them,
        /// so nothing should open them」。
        #[test]
        fn hardware_no_strategy_drives_is_never_opened() {
            assert!(!candidate_is_driven(&candidate(
                "/dev/ttyUSB9",
                "1-1.5",
                Some("05c6"),
                Some("90b4")
            )));
        }

        /// 阴性对照：台架上真在跑的两种硬件都要通过。
        ///
        /// 没有它，上面那条可以靠「永远返回 false」通过 —— 而那会让整台机器
        /// 的 AT 枚举当场停摆，包括只走 AT 的那根 EC200U。
        #[test]
        fn the_hardware_on_this_bench_still_gets_opened() {
            for (vid, pid, what) in [
                ("2c7c", "0125", "EC20 / EC25-CN / EG25-G"),
                ("2c7c", "0901", "EC200U-CN"),
            ] {
                assert!(
                    candidate_is_driven(&candidate("/dev/ttyUSB0", "1-1.2", Some(vid), Some(pid))),
                    "{what} 被挡在外面了"
                );
            }
        }

        /// ⚠️ 没有 USB 标识的一律保留 —— 平台直挂的高速串口本来就没有
        /// vid/pid，在这里拒掉它会丢掉这道闸从来就不针对的硬件。
        #[test]
        fn a_port_with_no_usb_identity_is_kept() {
            let mut platform = candidate("/dev/ttyHS0", "-", None, None);
            platform.usb_device = None;
            platform.kind = AtPortKind::HighSpeed;
            assert!(candidate_is_driven(&platform));
        }

        /// vid/pid 在、但解析不出十六进制的也保留：那是 sysfs 给了个不认识的
        /// 形状，不是「这块硬件我们不支持」。
        ///
        /// 🔴 和 `bind_gates` 的 `UnreadableUsbIdentity` 方向相反，而两边都对：
        /// 那里在决定要不要**纳管**，证据不足就拒；这里在决定要不要**看一眼**，
        /// 证据不足就看。看一眼的代价是一次 AT 探测；拒绝的代价是一块插着的
        /// 硬件永远不出现在候选列表里。
        #[test]
        fn an_unparseable_identity_is_kept_not_refused() {
            assert!(candidate_is_driven(&candidate(
                "/dev/ttyUSB1",
                "1-1.3",
                Some("zzzz"),
                Some("0125")
            )));
        }

        /// 🔴 会被打开的那组路径里，不该有未被驱动的口。
        ///
        /// 这条钉的是真正的行为改动。此前 `at_paths` 取的是
        /// `at_control_ports()` —— 同一个选择器套在**全部**候选上 ——
        /// 于是那根高通棒子每 8 秒被打开并写一次 AT。
        #[test]
        fn the_ports_that_get_opened_exclude_undriven_hardware() {
            let all = vec![
                candidate("/dev/ttyUSB0", "1-1.2", Some("2c7c"), Some("0125")),
                candidate("/dev/ttyUSB9", "1-1.5", Some("05c6"), Some("90b4")),
            ];
            // 前提：不过滤的话这两个口都会被打开。前提不成立，
            // 下面那句就不是在测过滤。
            assert_eq!(edge_modem::select_control_ports(all.clone()).len(), 2);

            assert_eq!(
                super::at_paths_to_probe(&all, Vec::new()),
                vec![PathBuf::from("/dev/ttyUSB0")]
            );
        }

        /// ⚠️ 手工批准的口不受这一闸约束 —— 运维明确点过头了。
        ///
        /// 没有这条，上面那条可以靠「把手工批准的也一起过滤掉」通过，
        /// 而那会让「批准」这个按钮变成一个不起作用的按钮。
        #[test]
        fn an_operator_approved_port_is_probed_even_if_nothing_drives_it() {
            let undriven = vec![candidate("/dev/ttyUSB9", "1-1.5", Some("05c6"), Some("90b4"))];
            let approved = vec![PathBuf::from("/dev/ttyUSB9")];
            assert_eq!(
                super::at_paths_to_probe(&undriven, approved),
                vec![PathBuf::from("/dev/ttyUSB9")],
                "运维批准过的口被自动过滤挡住了，那个按钮就成了摆设"
            );
        }
    }

    /// 纯判定，不碰 store。
    fn plan_enforcement(
        matrix: &CapabilityMatrix,
        authority: edge_core::MatrixAuthority,
        uplink_ever_resumed: bool,
        evidence: &[edge_core::GateEvidence],
        now: i64,
    ) -> EnforcementPlan {
        let mut plan = EnforcementPlan::default();
        for item in evidence {
            match edge_core::enforce_one(
                strategy_registry(),
                matrix,
                authority,
                uplink_ever_resumed,
                item,
                now,
            ) {
                edge_core::Enforcement::Keep => plan.keep.push(item.imei.clone()),
                edge_core::Enforcement::Hold(reason) => {
                    plan.hold.push((item.imei.clone(), reason))
                }
                edge_core::Enforcement::Quarantine {
                    refusal,
                    elapsed_ms,
                    passes,
                } => plan
                    .quarantine
                    .push((item.imei.clone(), refusal, elapsed_ms, passes)),
                edge_core::Enforcement::Unbind(refusal) => {
                    plan.unbind.push((item.imei.clone(), refusal))
                }
            }
        }
        plan
    }

    /// 一条告警里最多列几根模组。
    ///
    /// 契约把 context 里的数组封在 64。超了就截断并置 `truncated` ——
    /// 被云端拒收整封信意味着这条告警彻底消失，比截断严重得多。
    const ALERT_MODEM_CAP: usize = 64;

    fn modem_array(entries: Vec<serde_json::Value>) -> (serde_json::Value, bool) {
        let truncated = entries.len() > ALERT_MODEM_CAP;
        let kept: Vec<_> = entries.into_iter().take(ALERT_MODEM_CAP).collect();
        (serde_json::json!(kept), truncated)
    }

    /// 已纳管的模组现在还过不过得了那两道闸。
    ///
    /// 🔴 唯一的失败模式是**删掉不该删的行**，所以每一次读失败都走
    /// 「整趟作废 + 告警」，而不是「当成空的继续」。判定本身在
    /// `edge_core::retro`，那里能在本机测。
    ///
    /// 落点是 `poll_modems` 的尾部，理由有三条：
    ///   ① 只有它同时拿得到 store、outbox 和矩阵；
    ///   ② 矩阵在这里已经被克隆好了，而且是在**所有 store 锁之前**克隆的，
    ///      所以复用它就不会产生 store→matrix 这条锁序边（见 `live_matrix`
    ///      创建处那段「叶子锁」注释）；
    ///   ③ 它就是观测发生的地方，`last_seen` 在这一刻最新鲜。
    fn enforce_registration(
        shared: &Arc<SharedStore>,
        outbox: &Arc<Mutex<DurableOutbox>>,
        matrix: &CapabilityMatrix,
        authority: edge_core::MatrixAuthority,
        uplink_ever_resumed: bool,
        discoveries: Option<&[edge_store::LocalModemDiscovery]>,
        now: i64,
    ) {
        // 候选列表读不到 → 整趟作废。
        //
        // 不是谨慎过头：USB 标识全部来自这张表，把「读不到」当成空表，
        // 等于让每一根已纳管模组的闸 1 证据同时消失。
        let Some(discoveries) = discoveries else {
            raise_alert(
                outbox,
                edge_core::AlertLevel::Error,
                "retro_inputs_unreadable",
                "candidate list unreadable; registration gates not evaluated this pass",
                serde_json::json!({ "reason": "discoveries" }),
                now,
            );
            return;
        };

        let mode = enforce_mode();
        let matrix_version = matrix.version().to_owned();

        // 收集 → 判定 → 执行，全部在**同一次** store 锁内。
        //
        // 这样面板和云端的 `register_modem`（用的是同一把 mutex）无法与本趟
        // 交错，判定与执行之间的时序问题从根上不存在 —— 不需要在 DELETE 上
        // 加任何 compare-and-swap 谓词。
        let plan = {
            let mut store = shared.0.lock().expect("store");
            let registered = match store.registered_modems() {
                Ok(rows) => rows,
                Err(error) => {
                    log_error(format!("registry not read: {error}"));
                    raise_alert(
                        outbox,
                        edge_core::AlertLevel::Error,
                        "retro_inputs_unreadable",
                        format!("registry unreadable: {error}"),
                        serde_json::json!({ "reason": "registry" }),
                        now,
                    );
                    return;
                }
            };
            if registered.is_empty() {
                return;
            }
            let observed = match store.list_local_modems() {
                Ok(rows) => rows,
                Err(error) => {
                    log_error(format!("inventory not read: {error}"));
                    raise_alert(
                        outbox,
                        edge_core::AlertLevel::Error,
                        "retro_inputs_unreadable",
                        format!("inventory unreadable: {error}"),
                        serde_json::json!({ "reason": "inventory" }),
                        now,
                    );
                    return;
                }
            };
            let mut gates = std::collections::BTreeMap::new();
            let mut unreadable: Vec<String> = Vec::new();
            for row in &registered {
                match store.gate_failure(&row.imei) {
                    Ok(Some(gate)) => {
                        gates.insert(row.imei.clone(), gate);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        // 🔴 「读不到」单独记，**不**和「没有标记」混在一起。
                        //
                        // 混起来会开出一整类零宽限删除：读不到时若照常判定，
                        // 得到 Keep 就不会去清库里那条标记（调用方以为它不
                        // 存在），旧的 gate_failed_since 原封不动地活下来；
                        // 下一次真判定用 COALESCE 接上那个旧起点，隔离期当场
                        // 就是满的。
                        //
                        // 这段代码此前的注释写着「这一趟就不判它」——
                        // 而代码照判不误。现在它真的不判了。
                        log_error(format!("gate state not read for {}: {error}", row.imei));
                        unreadable.push(row.imei.clone());
                    }
                }
            }

            let (judged, unreadable_holds) = split_unreadable(&registered, &unreadable);
            let evidence = build_evidence(&judged, &gates, &observed, discoveries, now);
            let mut plan = plan_enforcement(matrix, authority, uplink_ever_resumed, &evidence, now);
            plan.hold.extend(unreadable_holds);

            // 执行。
            for imei in &plan.keep {
                // 无条件清，不看 `gates` 里有没有。
                //
                // 省下的那次 UPDATE 换来的是上面说的那类零宽限删除：只要
                // 「库里有标记」和「本进程知道有标记」出现过一次分歧，
                // 清除就会被跳过。一次幂等的 UPDATE 便宜得多。
                if let Err(error) = store.clear_gate_failure(imei) {
                    // 🔴 这是唯一一次往「更容易删」方向偏的写失败：自愈没成功，
                    // 而倒计时还在走。它必须有告警，不能只落日志。
                    log_error(format!("gate mark not cleared for {imei}: {error}"));
                    raise_alert(
                        outbox,
                        edge_core::AlertLevel::Error,
                        "retro_mark_not_cleared",
                        format!("{imei} passed the gates again but its countdown could not be cleared"),
                        serde_json::json!({ "imei": imei, "error": error.to_string() }),
                        now,
                    );
                }
            }
            // 🔴 隔离和越线的都要记标记。
            //
            // 倒计时是「这个状态持续了多久」的**记录**，与本机敢不敢删无关。
            // 只给隔离期内的记，会让 mark 模式下越线的那些停在越线那一刻的
            // 值上；等哪天切到 unbind，第一趟就到期 —— 隔离期实际为零。
            for (imei, refusal) in plan
                .quarantine
                .iter()
                .map(|(imei, refusal, _, _)| (imei, refusal))
                .chain(plan.unbind.iter().map(|(imei, refusal)| (imei, refusal)))
            {
                if let Err(error) = store.mark_gate_failure(imei, refusal.wire(), now) {
                    // 倒计时没推进就等于这一趟没发生 —— 往安全的方向偏。
                    log_error(format!("gate mark not written for {imei}: {error}"));
                }
            }
            let mut retired = Vec::new();
            if mode == EnforceMode::Unbind {
                for (imei, refusal) in &plan.unbind {
                    let Some(row) = registered.iter().find(|row| &row.imei == imei) else {
                        continue;
                    };
                    let record = edge_store::Retirement {
                        imei: imei.clone(),
                        registered_at: row.registered_at,
                        registered_by: row.registered_by.clone(),
                        family: row.family.clone(),
                        usb_device: row.usb_device.clone(),
                        retired_at: now,
                        reason: refusal.wire().to_owned(),
                        detail: Some(refusal.to_string()),
                        matrix_version: Some(matrix_version.clone()),
                    };
                    // 🔴 先写日志再删。告警可能入不了队（outbox 满、磁盘坏），
                    // 而那正是最需要留下痕迹的时刻。
                    log_error(format!(
                        "retiring {imei}: {} (matrix {matrix_version})",
                        refusal
                    ));
                    match store.retire_modem(&record) {
                        Ok(true) => retired.push((imei.clone(), refusal.clone())),
                        Ok(false) => log_error(format!("{imei} was already gone; not retired")),
                        // 没删成就不能说删了 —— 它不进告警的批次。
                        Err(error) => log_error(format!("{imei} not retired: {error}")),
                    }
                }
            }
            // 🔴 返回的是**判定**（plan.unbind），不是**结果**（retired）。
            //
            // 此前这里把 retired 塞回 plan.unbind，于是 mark 模式下 retired
            // 恒为空，越过隔离期的模组就从所有告警里彻底消失了 ——
            // 而「先跑几周只标记、看误报率」看到的正好是一个假的零：
            // 它要度量的那个人群，恰恰是唯一不产生告警的那一群。
            (plan, retired)
        };

        emit_plan_alerts(
            &plan.0,
            &plan.1,
            authority,
            &matrix_version,
            mode,
            |(level, code, message, context, throttling)| match throttling {
                Throttling::Throttled => raise_alert(outbox, level, code, message, context, now),
                Throttling::Bypass => {
                    raise_alert_unthrottled(outbox, level, code, message, context, now)
                }
            },
        );
    }

    /// 一趟一条，不是一根一条。
    ///
    /// 🔴 现有的 `modem_absent` 是逐根 `raise_alert`，共用一个常量 code。
    /// 后果被低估了：掉线是持续状态，所以抢到发送名额的永远是同一根，
    /// 其余几根的身份在 `Suppress` 分支里当场蒸发 —— 那个分支是 `return`，
    /// payload 连构造都不构造。这里不照抄那九行。
    /// 一条告警：级别、code、正文、context，以及**过不过节流**。
    type PlannedAlert = (
        edge_core::AlertLevel,
        &'static str,
        String,
        serde_json::Value,
        Throttling,
    );

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Throttling {
        Throttled,
        /// 只给「一次性、且总量天然有界」的 code。见 `raise_alert_unthrottled`。
        Bypass,
    }

    /// 这一趟该发哪几条告警。
    ///
    /// 副作用做成注入的 sink，和 `rotate_cycle` 一样 —— 于是「mark 模式下
    /// 越线的模组会不会有告警」这种问题可以在本机断言，不需要一个真的 outbox。
    /// 这个特性的试运行期完全依赖那条告警，而它此前恰好是缺的。
    ///
    /// 🔴 一趟一条，不是一根一条。现有的 `modem_absent` 是逐根 `raise_alert`
    /// 共用一个常量 code，而掉线是持续状态，所以抢到发送名额的永远是排序
    /// 最小的那一根，其余几根的身份在 `Suppress` 分支里当场蒸发 ——
    /// 那个分支是 `return`，payload 连构造都不构造。这里不照抄那九行。
    fn emit_plan_alerts(
        plan: &EnforcementPlan,
        retired: &[(String, edge_core::BindRefusal)],
        authority: edge_core::MatrixAuthority,
        matrix_version: &str,
        mode: EnforceMode,
        mut sink: impl FnMut(PlannedAlert),
    ) {
        if !plan.hold.is_empty() {
            // 判据整体不可信（回落到内置矩阵、uplink 没连上过）单独成一条：
            // 那是一台机器的状态，不是几根模组各自的问题。
            // 🔴 两个 systemic 原因要**分别**报，不能合成一条。
            //
            // 第一版把它们都塞进 `retro_matrix_not_authoritative`，
            // context 里写 `authority.wire()`。冷启动那几趟的实际输出是
            // 「矩阵不权威」配上 `authority: "stored"` —— 文案和字段
            // 自相矛盾，而读它的人多半是在半夜排查为什么执行停了。
            //
            // 而且这两件事的下一步完全不同：矩阵不权威要去看这台机器的
            // 矩阵是哪来的；uplink 没连上过要去看网络和证书。
            let uplink_cold = plan
                .hold
                .iter()
                .any(|(_, reason)| matches!(reason, edge_core::HoldReason::UplinkNeverResumed));
            let matrix_weak = plan.hold.iter().any(|(_, reason)| {
                matches!(reason, edge_core::HoldReason::MatrixNotAuthoritative(_))
            });
            if uplink_cold {
                sink((
                    edge_core::AlertLevel::Warning,
                    "retro_uplink_never_resumed",
                    "registration gates not evaluated: this agent has not reached the cloud since it started"
                        .to_owned(),
                    serde_json::json!({
                        "matrix_version": matrix_version,
                        "held": plan.hold.len(),
                    }),
                    Throttling::Throttled,
                ));
            } else if matrix_weak {
                sink((
                    edge_core::AlertLevel::Warning,
                    "retro_matrix_not_authoritative",
                    "registration gates not evaluated: the running matrix is not authoritative"
                        .to_owned(),
                    serde_json::json!({
                        "authority": authority.wire(),
                        "matrix_version": matrix_version,
                        "held": plan.hold.len(),
                    }),
                    Throttling::Throttled,
                ));
            } else {
                let (modems, truncated) = modem_array(
                    plan.hold
                        .iter()
                        .map(|(imei, reason)| {
                            serde_json::json!({ "imei": imei, "hold": reason.wire() })
                        })
                        .collect(),
                );
                sink((
                    edge_core::AlertLevel::Warning,
                    "retro_hold",
                    format!("{} adopted modules could not be evaluated", plan.hold.len()),
                    serde_json::json!({
                        "count": plan.hold.len(),
                        "modems": modems,
                        "truncated": truncated,
                    }),
                    Throttling::Throttled,
                ));
            }
        }

        if !plan.quarantine.is_empty() {
            let (modems, truncated) = modem_array(
                plan.quarantine
                    .iter()
                    .map(|(imei, refusal, elapsed, passes)| {
                        serde_json::json!({
                            "imei": imei,
                            "refusal": refusal.wire(),
                            "elapsed_ms": elapsed,
                            "passes": passes,
                        })
                    })
                    .collect(),
            );
            sink((
                edge_core::AlertLevel::Error,
                "retro_quarantined",
                format!(
                    "{} adopted modules no longer pass the registration gates",
                    plan.quarantine.len()
                ),
                serde_json::json!({
                    "count": plan.quarantine.len(),
                    "modems": modems,
                    "matrix_version": matrix_version,
                    "truncated": truncated,
                }),
                Throttling::Throttled,
            ));
        }

        // 🔴 mark 模式下越过隔离期的那些，必须自己有一条告警。
        //
        // 它们不在 `quarantine` 里（已经越线了），也不在 `retired` 里
        // （本机不删）。少了这一条，试运行期看到的是一个**假的零**——
        // 「先跑几周看误报率」要度量的正是这群，而它们恰好一声不响。
        //
        // 走节流：这是一个持续状态，每一趟都会复发，节流对它是对的。
        if mode == EnforceMode::Mark && !plan.unbind.is_empty() {
            let (modems, truncated) = modem_array(
                plan.unbind
                    .iter()
                    .map(|(imei, refusal)| {
                        serde_json::json!({ "imei": imei, "refusal": refusal.wire() })
                    })
                    .collect(),
            );
            sink((
                edge_core::AlertLevel::Critical,
                "retro_would_unbind",
                format!(
                    "{} adopted modules would be retired if this agent were enforcing",
                    plan.unbind.len()
                ),
                serde_json::json!({
                    "count": plan.unbind.len(),
                    "modems": modems,
                    "matrix_version": matrix_version,
                    "truncated": truncated,
                }),
                Throttling::Throttled,
            ));
        }

        if !retired.is_empty() {
            let (modems, truncated) = modem_array(
                retired
                    .iter()
                    .map(|(imei, refusal)| {
                        serde_json::json!({ "imei": imei, "refusal": refusal.wire() })
                    })
                    .collect(),
            );
            // 🔴 不过节流。解绑是一次性的：删掉那一行之后下一趟不会再看它
            // 第二眼，所以被压掉的这条**永远不会被补发**。
            sink((
                edge_core::AlertLevel::Critical,
                "retro_unbound",
                format!(
                    "{} adopted modules were retired by the registration gates",
                    retired.len()
                ),
                serde_json::json!({
                    "count": retired.len(),
                    "modems": modems,
                    "matrix_version": matrix_version,
                    "truncated": truncated,
                }),
                Throttling::Bypass,
            ));
        }
    }

    #[cfg(test)]
    mod retro_tests {
        use super::{
            build_evidence, emit_plan_alerts, enforce_mode_from, split_unreadable, EnforceMode,
            EnforcementPlan, PlannedAlert, Throttling,
        };

        /// 🔴 只有一个字符串通往删除。
        #[test]
        fn only_the_exact_word_opens_the_destructive_mode() {
            assert_eq!(enforce_mode_from("unbind"), EnforceMode::Unbind);
            assert_eq!(enforce_mode_from("  unbind  "), EnforceMode::Unbind);
            for other in ["mark", "", "true", "1", "yes", "UNBIND", "Unbind", "unbin", "unbind!"] {
                assert_eq!(
                    enforce_mode_from(other),
                    EnforceMode::Mark,
                    "{other:?} 打开了破坏性模式"
                );
            }
        }

        fn registered(imei: &str, family: Option<&str>) -> edge_store::RegisteredModem {
            edge_store::RegisteredModem {
                imei: imei.into(),
                registered_at: 1,
                registered_by: "panel".into(),
                usb_device: None,
                family: family.map(str::to_owned),
                note: None,
            }
        }

        fn observed(imei: &str, home: Option<(u16, u16)>, last_seen: Option<i64>) -> edge_store::LocalModem {
            edge_store::LocalModem {
                imei: imei.into(),
                family: "EC20".into(),
                firmware: None,
                msisdn: None,
                msisdn_iccid: None,
                apn_contexts: None,
                iccid: None,
                state: "registered".into(),
                last_seen,
                mcc: None,
                mnc: None,
                home_mcc: home.map(|(mcc, _)| mcc),
                home_mnc: home.map(|(_, mnc)| mnc),
                imsi: None,
                discovery: "qmi".into(),
                manageable: true,
                control_port: None,
            }
        }

        fn candidate(imei: &str, vendor: Option<&str>, product: Option<&str>) -> edge_store::LocalModemDiscovery {
            edge_store::LocalModemDiscovery {
                candidate_key: "k".into(),
                usb_device: None,
                transport: "qmi".into(),
                control_port: "/dev/cdc-wdm0".into(),
                vendor_id: vendor.map(str::to_owned),
                product_id: product.map(str::to_owned),
                state: "manageable".into(),
                imei: Some(imei.into()),
                detail: String::new(),
                last_seen: 1,
            }
        }

        fn gates() -> std::collections::BTreeMap<String, edge_store::GateFailure> {
            std::collections::BTreeMap::new()
        }

        /// 🔴 一根纳管了但本轮没被观测到的模组，证据里全是 `None` ——
        /// 不是「零值」，也不是任何看起来合理的默认。
        #[test]
        fn a_registration_with_no_observation_yields_no_evidence() {
            let evidence = build_evidence(
                &[registered("1", Some("EC20"))],
                &gates(),
                &[],
                &[],
                1_000,
            );
            let item = &evidence[0];
            assert!(item.observed_family.is_none());
            assert!(item.carrier.is_none());
            assert!(item.usb.is_none());
            assert!(item.observation_age_ms.is_none(), "没观测过不该有年龄");
        }

        /// 🔴 归属网络只读到一半 → `carrier` 是 `None`，**不是**
        /// Generic-International。
        ///
        /// 另外三处 `.unwrap_or("Generic-International")` 在报告和路由里说得
        /// 通；在一道闸上它意味着一张还没读出 IMSI 的卡被当成国际卡去过闸，
        /// 而国际卡那一对在矩阵里是有规则的。
        #[test]
        fn a_half_read_home_network_is_not_silently_international() {
            for home in [None, Some((460u16, 0u16))] {
                let mut row = observed("1", home, Some(900));
                if home.is_some() {
                    row.home_mnc = None; // 只读到 mcc
                }
                let evidence = build_evidence(
                    &[registered("1", Some("EC20"))],
                    &gates(),
                    &[row],
                    &[],
                    1_000,
                );
                assert!(
                    evidence[0].carrier.is_none(),
                    "归属网络没读全却给出了一个运营商"
                );
            }
        }

        /// USB 标识缺一半就是读不到 —— 不能只凭 vendor 猜。
        #[test]
        fn half_a_usb_identity_is_no_identity() {
            for (vendor, product) in [(Some("2c7c"), None), (None, Some("0125")), (None, None)] {
                let evidence = build_evidence(
                    &[registered("1", Some("EC20"))],
                    &gates(),
                    &[observed("1", Some((460, 2)), Some(900))],
                    &[candidate("1", vendor, product)],
                    1_000,
                );
                assert!(evidence[0].usb.is_none(), "{vendor:?}/{product:?} 拼出了一个标识");
            }
            // 阴性对照：两半都在就要认出来。
            let evidence = build_evidence(
                &[registered("1", Some("EC20"))],
                &gates(),
                &[observed("1", Some((460, 2)), Some(900))],
                &[candidate("1", Some("2c7c"), Some("0125"))],
                1_000,
            );
            assert_eq!(
                evidence[0].usb,
                Some(edge_core::UsbIdentity::new(0x2c7c, 0x0125))
            );
        }

        fn refusal() -> edge_core::BindRefusal {
            edge_core::BindRefusal::NeverMeasured {
                family: edge_core::ModemFamily::EC25_CN,
                carrier: edge_core::CarrierProfile::CN_UNICOM,
            }
        }

        fn alerts(
            plan: &EnforcementPlan,
            retired: &[(String, edge_core::BindRefusal)],
            mode: EnforceMode,
        ) -> Vec<PlannedAlert> {
            alerts_with(plan, retired, mode, edge_core::MatrixAuthority::Stored)
        }

        /// ⚠️ authority 要能传进来。写死成 Stored 的话，那条「矩阵不权威」的
        /// 断言就会去断言一个**生产里不可能出现**的组合（hold 原因说
        /// BuiltinNoRow，context 里却是 stored），而断言不可能的值是坏味道：
        /// 它会在真值变了的时候照样通过。
        fn alerts_with(
            plan: &EnforcementPlan,
            retired: &[(String, edge_core::BindRefusal)],
            mode: EnforceMode,
            authority: edge_core::MatrixAuthority,
        ) -> Vec<PlannedAlert> {
            let mut out = Vec::new();
            emit_plan_alerts(
                plan,
                retired,
                authority,
                "2026-09-01T03:32:24Z",
                mode,
                |a| out.push(a),
            );
            out
        }

        fn codes(alerts: &[PlannedAlert]) -> Vec<&'static str> {
            alerts.iter().map(|a| a.1).collect()
        }

        /// 🔴 读不到隔离标记的那一根，这一趟不参与判定。
        ///
        /// 混起来会开出一整类零宽限删除：读不到时若照常判定，得到 Keep 的
        /// 那一根不会被清标记（调用方以为它本来就没有），库里旧的
        /// gate_failed_since 原封不动地活下来；下一次真判定用 COALESCE 接上
        /// 那个旧起点，隔离期当场满 —— 一次瞬时 SQLITE_BUSY 就把 30 分钟的
        /// 宽限变成 0。
        #[test]
        fn a_modem_whose_mark_could_not_be_read_is_not_judged() {
            let rows = vec![registered("1", Some("EC20")), registered("2", Some("EC20"))];
            let (judged, holds) = split_unreadable(&rows, &["2".to_string()]);
            assert_eq!(judged.len(), 1);
            assert_eq!(judged[0].imei, "1");
            assert_eq!(
                holds,
                vec![("2".to_string(), edge_core::HoldReason::GateStateUnreadable)],
                "读不到标记的那根既没被判、也没进 hold —— 它会静默消失"
            );
        }

        /// 阴性对照：都读得到时一根都不该被挡在判定之外。
        ///
        /// 没有这条，上面那条可以靠「永远不判任何东西」通过，
        /// 而那是一个看起来开着的关闭。
        #[test]
        fn nothing_is_held_back_when_every_mark_was_readable() {
            let rows = vec![registered("1", Some("EC20")), registered("2", Some("EC20"))];
            let (judged, holds) = split_unreadable(&rows, &[]);
            assert_eq!(judged.len(), 2);
            assert!(holds.is_empty());
        }

        /// 🔴 mark 模式下越过隔离期的模组，必须有一条自己的告警。
        ///
        /// 它们不在 quarantine 里（越线了），也不在 retired 里（本机不删）。
        /// 少了这一条，「先跑几周只标记、看误报率」看到的是一个**假的零**——
        /// 要度量的正是这群，而它们恰好一声不响。
        ///
        /// 第一版实现就是这样：把 retired 塞回 plan.unbind 再发告警，
        /// 于是 mark 模式下 retired 恒为空，这群人彻底消失。而 mark 模式
        /// 是整套设计里唯一让「自动做破坏」保有退路的地方。
        #[test]
        fn mark_mode_still_announces_what_it_would_have_deleted() {
            let plan = EnforcementPlan {
                unbind: vec![("868019060490134".into(), refusal())],
                ..Default::default()
            };
            let emitted = alerts(&plan, &[], EnforceMode::Mark);
            assert!(
                codes(&emitted).contains(&"retro_would_unbind"),
                "mark 模式下越线的模组没有任何告警：{:?}",
                codes(&emitted)
            );
            assert_eq!(emitted[0].0, edge_core::AlertLevel::Critical);
        }

        /// 但 mark 模式**不能**说它删了 —— 它一行都没删。
        #[test]
        fn mark_mode_never_claims_a_delete() {
            let plan = EnforcementPlan {
                unbind: vec![("1".into(), refusal())],
                ..Default::default()
            };
            assert!(!codes(&alerts(&plan, &[], EnforceMode::Mark)).contains(&"retro_unbound"));
        }

        /// 🔴 告警说的是**真的删掉了的那些**，不是判定。
        ///
        /// 判定为删、而 retire_modem 写失败的那一根不能出现在 retro_unbound
        /// 里：没删就不能说删了，否则云端会退休一行边缘还在管的记录。
        #[test]
        fn a_failed_retire_is_not_announced_as_a_delete() {
            let plan = EnforcementPlan {
                unbind: vec![("1".into(), refusal()), ("2".into(), refusal())],
                ..Default::default()
            };
            let retired = vec![("1".to_string(), refusal())];
            let emitted = alerts(&plan, &retired, EnforceMode::Unbind);
            let unbound = emitted
                .iter()
                .find(|a| a.1 == "retro_unbound")
                .expect("有这条");
            assert_eq!(unbound.3["count"], 1, "把没删成的那根也算进去了");
        }

        /// 只有 retro_unbound 绕过节流。
        ///
        /// 解绑是一次性的：删掉那一行之后下一趟不会再看它第二眼，被压掉的
        /// 那条永远不会被补发。其余几条都是持续状态，节流对它们是对的 ——
        /// 让它们也绕过，一台持续 Hold 的机器会每一趟发一条。
        #[test]
        fn only_the_one_shot_alert_bypasses_the_throttle() {
            let plan = EnforcementPlan {
                hold: vec![("1".into(), edge_core::HoldReason::NeverObserved)],
                quarantine: vec![("2".into(), refusal(), 0, 1)],
                unbind: vec![("3".into(), refusal())],
                ..Default::default()
            };
            let retired = vec![("3".to_string(), refusal())];
            for (_, code, _, _, throttling) in alerts(&plan, &retired, EnforceMode::Unbind) {
                let expected = if code == "retro_unbound" {
                    Throttling::Bypass
                } else {
                    Throttling::Throttled
                };
                assert_eq!(throttling, expected, "{code} 的节流选择不对");
            }
        }

        /// 判据整体不可信是**一台机器**的状态，不是几根模组各自的问题。
        /// 混进 retro_hold 会让运维去逐根排查，而该修的是这台机器的矩阵。
        #[test]
        fn a_systemic_hold_is_reported_as_one_machine_level_fault() {
            let plan = EnforcementPlan {
                hold: vec![
                    (
                        "1".into(),
                        edge_core::HoldReason::MatrixNotAuthoritative(
                            edge_core::MatrixAuthority::BuiltinNoRow,
                        ),
                    ),
                    ("2".into(), edge_core::HoldReason::NeverObserved),
                ],
                ..Default::default()
            };
            assert_eq!(
                codes(&alerts(&plan, &[], EnforceMode::Mark)),
                vec!["retro_matrix_not_authoritative"]
            );
        }

        /// 🔴 冷启动那一支不能报成「矩阵不权威」。
        ///
        /// 第一版把两个 systemic 原因合成一条，于是冷启动的实际输出是
        /// 「矩阵不权威」配上 `authority: "stored"` —— 文案和字段自相矛盾。
        /// 两件事的下一步也完全不同：一个去看矩阵哪来的，一个去看网络和证书。
        #[test]
        fn a_cold_uplink_is_not_reported_as_a_bad_matrix() {
            let plan = EnforcementPlan {
                hold: vec![("1".into(), edge_core::HoldReason::UplinkNeverResumed)],
                ..Default::default()
            };
            let emitted = alerts(&plan, &[], EnforceMode::Mark);
            assert_eq!(codes(&emitted), vec!["retro_uplink_never_resumed"]);
            assert!(
                emitted[0].3.get("authority").is_none(),
                "冷启动那条不该带 authority —— 它和矩阵权威性无关"
            );
        }

        /// 阴性对照：真的是矩阵不权威时，照旧报那一条，并带上 authority。
        #[test]
        fn a_weak_matrix_is_still_reported_with_its_authority() {
            let plan = EnforcementPlan {
                hold: vec![(
                    "1".into(),
                    edge_core::HoldReason::MatrixNotAuthoritative(
                        edge_core::MatrixAuthority::BuiltinNoRow,
                    ),
                )],
                ..Default::default()
            };
            let emitted = alerts_with(
                &plan,
                &[],
                EnforceMode::Mark,
                edge_core::MatrixAuthority::BuiltinNoRow,
            );
            assert_eq!(codes(&emitted), vec!["retro_matrix_not_authoritative"]);
            assert_eq!(
                emitted[0].3["authority"], "builtin_no_row",
                "context 里的 authority 必须是真的那一个，否则运维会去查错方向"
            );
        }

        /// 一趟一条，不是一根一条 —— 但身份不能丢。
        #[test]
        fn one_alert_per_pass_not_per_modem() {
            let plan = EnforcementPlan {
                hold: (0..30)
                    .map(|i| (format!("{i}"), edge_core::HoldReason::NeverObserved))
                    .collect(),
                ..Default::default()
            };
            let emitted = alerts(&plan, &[], EnforceMode::Mark);
            assert_eq!(emitted.len(), 1, "30 根发了 {} 条", emitted.len());
            assert_eq!(emitted[0].3["count"], 30);
        }

        /// 超过契约上限就截断并说明，而不是让整封信被云端拒收。
        #[test]
        fn an_oversized_list_is_truncated_rather_than_lost() {
            let plan = EnforcementPlan {
                hold: (0..200)
                    .map(|i| (format!("{i}"), edge_core::HoldReason::NeverObserved))
                    .collect(),
                ..Default::default()
            };
            let emitted = alerts(&plan, &[], EnforceMode::Mark);
            assert_eq!(emitted[0].3["truncated"], true);
            assert_eq!(emitted[0].3["modems"].as_array().unwrap().len(), 64);
            assert_eq!(emitted[0].3["count"], 200, "计数要说真话，即使列表被截断");
        }

        /// 观测年龄不会是负数 —— 时钟往回跳时，一行「来自未来」的观测
        /// 不该看起来格外新鲜从而绕过新鲜度关口。
        #[test]
        fn an_observation_from_the_future_is_not_extra_fresh() {
            let evidence = build_evidence(
                &[registered("1", Some("EC20"))],
                &gates(),
                &[observed("1", Some((460, 2)), Some(9_000))],
                &[],
                1_000,
            );
            assert_eq!(evidence[0].observation_age_ms, Some(0));
        }
    }

    fn enqueue_device_state(
        outbox: &Arc<Mutex<DurableOutbox>>,
        matrix: &CapabilityMatrix,
        modems: &[ModemSnapshot],
        host: &HostStats,
        discoveries: Option<&[edge_store::LocalModemDiscovery]>,
        managed: Option<&[String]>,
        now: i64,
    ) -> Result<(), String> {
        let payload = device_state_payload(matrix, modems, host, discoveries, managed, now);
        append_kind(outbox, "DeviceState", payload)
    }

    #[cfg(test)]
    mod device_state_tests {
        use super::{device_state_payload, HostStats};
        use edge_core::CapabilityMatrix;

        fn matrix() -> CapabilityMatrix {
            CapabilityMatrix::builtin().expect("built-in matrix")
        }

        fn candidate() -> edge_store::LocalModemDiscovery {
            edge_store::LocalModemDiscovery {
                candidate_key: "1-1.3:1.0".into(),
                usb_device: Some("1-1.3".into()),
                // 这个值在 2026-09-05 之前是契约禁止的，尽管边缘端一直会写它。
                transport: "serial".into(),
                control_port: "/dev/ttyUSB4".into(),
                vendor_id: Some("2c7c".into()),
                product_id: Some("0901".into()),
                state: "found".into(),
                imei: None,
                detail: String::new(),
                last_seen: 1,
            }
        }

        /// 🔴 一台没有已识别模组、只有一个待批准候选的机器，必须在云端可见。
        ///
        /// 这是去掉那个提前返回的**全部理由**。此前 modems 为空就整封不发，
        /// 而 discoveries 和 managed_imeis 搭的是同一封信 —— 于是这台机器
        /// 在云端完全不存在，运维连「有根棒插上了」都看不到。
        #[test]
        fn a_pass_with_no_modems_still_carries_its_candidates() {
            let payload = device_state_payload(
                &matrix(),
                &[],
                &HostStats::default(),
                Some(&[candidate()]),
                None,
                7,
            );
            let map = payload.as_object().expect("payload is a map");
            assert_eq!(
                map["modems"].as_array().map(Vec::len),
                Some(0),
                "modems 要是空数组，不是 null —— 契约把它类型化为数组"
            );
            let seen = map["discoveries"].as_array().expect("discoveries is an array");
            assert_eq!(seen.len(), 1, "候选没跟着走，这封信就白发了");
            assert_eq!(seen[0]["transport"], "serial");
        }

        /// 缺席 ≠ 空。
        ///
        /// 读注册表失败时 `managed` 是 `None`，这个键必须**根本不出现**：
        /// 云端的 `app.apply_managed_modems` 把缺席读作「agent 没说」而直接
        /// 返回，把空数组读作「一个都没纳管」并退休掉所有行。一次短暂的存储
        /// 读错因此会取消整台设备的纳管 —— 这不是假设，是发生过的事故。
        #[test]
        fn a_failed_registry_read_omits_the_key_entirely() {
            let payload = device_state_payload(
                &matrix(),
                &[],
                &HostStats::default(),
                Some(&[]),
                None,
                7,
            );
            assert!(
                !payload.as_object().expect("map").contains_key("managed_imeis"),
                "读不到注册表时写出这个键，等于替 agent 说了它没说过的话"
            );
        }

        /// 而空数组是一句**真话**，要照发。
        ///
        /// 阴性对照：没有它，上面那条测试可以靠「永远不写这个键」通过。
        #[test]
        fn an_empty_registry_is_a_statement_and_is_sent() {
            let payload = device_state_payload(
                &matrix(),
                &[],
                &HostStats::default(),
                Some(&[]),
                Some(&[]),
                7,
            );
            let map = payload.as_object().expect("map");
            assert!(map.contains_key("managed_imeis"), "「一个都没纳管」是真话，不该被吞掉");
            assert_eq!(map["managed_imeis"].as_array().map(Vec::len), Some(0));
        }

        /// 🔴 候选列表读不到时，这个键必须**根本不出现**。
        ///
        /// 和 managed_imeis 是同一条规则，而且云端已经把它实现好了：
        /// 0050 的投影在 `NOT (NEW.payload ? 'discoveries')` 时直接返回，
        /// 注释写明「reading its silence as \"nothing is plugged in\" would
        /// clear a list somebody is looking at」。而这条投影是**整表替换**
        /// ——一个捏造的空数组会退休掉这台设备下的每一行候选。
        ///
        /// 也就是说：云端等这半边说真话已经等了很久，是边缘这半在撒谎。
        #[test]
        fn an_unreadable_candidate_list_omits_the_key_entirely() {
            let payload = device_state_payload(
                &matrix(),
                &[],
                &HostStats::default(),
                None,
                None,
                7,
            );
            assert!(
                !payload.as_object().expect("map").contains_key("discoveries"),
                "读不到就写空数组，云端会把运维正在看的候选列表整张清掉"
            );
        }

        /// 阴性对照：真的一个候选都没有，是一句真话，要照发。
        #[test]
        fn an_empty_candidate_list_is_a_statement_and_is_sent() {
            let payload = device_state_payload(
                &matrix(),
                &[],
                &HostStats::default(),
                Some(&[]),
                None,
                7,
            );
            let map = payload.as_object().expect("map");
            assert!(map.contains_key("discoveries"), "「一个候选都没有」是真话");
            assert_eq!(map["discoveries"].as_array().map(Vec::len), Some(0));
        }

        /// 找不到的模组也要出现在名单里 —— 名单是注册表，不是本轮观测。
        #[test]
        fn the_managed_list_is_the_registry_not_this_pass() {
            let payload = device_state_payload(
                &matrix(),
                &[],
                &HostStats::default(),
                Some(&[]),
                Some(&["868019060490134".to_string()]),
                7,
            );
            let listed = payload["managed_imeis"].as_array().expect("array");
            assert_eq!(listed.len(), 1, "本轮一根都没看见，但注册表里有一根");
            assert_eq!(listed[0], "868019060490134");
        }
    }

    /// The alert throttle this process announces through.
    ///
    /// Process-global for the same reason `LogRing` is: raising an alert is
    /// ambient, and threading a handle through every call site that can fail
    /// would change a dozen signatures to carry something none of them are
    /// about.
    fn alert_throttle() -> &'static Mutex<edge_core::AlertThrottle> {
        static THROTTLE: OnceLock<Mutex<edge_core::AlertThrottle>> = OnceLock::new();
        THROTTLE
            .get_or_init(|| Mutex::new(edge_core::AlertThrottle::new(edge_core::DEFAULT_WINDOW_MS)))
    }

    /// Tell the cloud something is wrong, at most once per window per code.
    ///
    /// 🔴 `code` must be a constant. It is what the throttle groups by, so a
    /// code with a port or an IMEI interpolated into it makes every occurrence
    /// a distinct fault and defeats the throttle entirely -- which is the
    /// failure this whole path exists to avoid. Anything that varies belongs
    /// in `context`.
    ///
    /// Failure to enqueue is logged and swallowed: an alert that cannot be
    /// sent must not take down the thing that was trying to report a problem.
    fn raise_alert(
        outbox: &Arc<Mutex<DurableOutbox>>,
        level: edge_core::AlertLevel,
        code: &'static str,
        message: impl Into<String>,
        context: serde_json::Value,
        now: i64,
    ) {
        let decision = {
            let mut throttle = alert_throttle().lock().expect("alert throttle");
            throttle.consider(code, now)
        };
        let repeats = match decision {
            edge_core::Decision::Suppress => return,
            edge_core::Decision::Send => 0,
            edge_core::Decision::Repeat { repeats } => repeats,
        };
        emit_alert(outbox, level, code, message, context, now, repeats);
    }

    /// 不过节流地发一条告警。
    ///
    /// 🔴 只给「**一次性**、且总量天然有界」的 code 用。加新调用点之前，
    /// 先证明这两条。
    ///
    /// 节流的前提是「同一个故障会在循环里反复出现」，所以压掉几条不损失信息
    /// ——下一次出现会把 `repeats` 带出来。追溯执行的解绑**不满足这个前提**：
    /// 删掉那一行之后 `registered_modems()` 不再返回它，下一趟根本不会再看它
    /// 第二眼，所以被压掉的那条**永远不会被补发**。
    ///
    /// 而且 `AlertThrottle::consider` 只按 code 分组。真实的压制场景很具体：
    /// 一根已纳管模组被拔掉，discovery 行被剪掉，于是每 8 秒产生一次
    /// `retro_hold`；这时另一根因为矩阵推送真的被解绑 —— 如果共用一个 code，
    /// 那条 Critical 会被这条 Warning 压住 15 分钟，然后永久消失。
    /// 所以两件事既分成不同的 code，最响的那个还要绕开节流。
    ///
    /// 量是有界的：一个 IMEI 一生最多被追溯解绑一次，总量不超过曾被纳管的
    /// 物理模组数，而重新纳管是人的动作。
    fn raise_alert_unthrottled(
        outbox: &Arc<Mutex<DurableOutbox>>,
        level: edge_core::AlertLevel,
        code: &'static str,
        message: impl Into<String>,
        context: serde_json::Value,
        now: i64,
    ) {
        emit_alert(outbox, level, code, message, context, now, 0);
    }

    /// 两条路径共用的落地部分。
    fn emit_alert(
        outbox: &Arc<Mutex<DurableOutbox>>,
        level: edge_core::AlertLevel,
        code: &'static str,
        message: impl Into<String>,
        context: serde_json::Value,
        now: i64,
        repeats: u32,
    ) {
        let mut context = context;
        if repeats > 0 {
            if let Some(map) = context.as_object_mut() {
                // The number that says "still broken" rather than "broke
                // again": how many occurrences were held back since the last
                // time this code was announced.
                map.insert("repeats".into(), serde_json::json!(repeats));
            }
        }
        let message: String = message.into();
        let payload = serde_json::json!({
            "level": level.wire(),
            "code": code,
            // The contract caps this at 1024 and requires at least one
            // character. Truncating here beats having the cloud reject the
            // envelope and lose the alert entirely.
            "message": if message.is_empty() {
                code.to_string()
            } else {
                message.chars().take(1024).collect::<String>()
            },
            "occurred_at": now,
            "context": context,
        });
        if let Err(error) = append_kind(outbox, "Alert", payload) {
            log_error(format!("alert {code} not enqueued: {error}"));
        }
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
        live_matrix: Arc<Mutex<CapabilityMatrix>>,
        online: Arc<AtomicBool>,
        ever_resumed: Arc<AtomicBool>,
    ) {
        let url = env("VODOGE_UPLINK_URL", "wss://43.108.53.126:444/v1/edge");
        let cert_dir = env("VODOGE_EDGE_CERTS", "/etc/vodoge-edge");
        loop {
            let result = uplink_once(
                &url,
                &cert_dir,
                &outbox,
                &executor,
                &live_matrix,
                &online,
                &ever_resumed,
            );
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
        live_matrix: &Arc<Mutex<CapabilityMatrix>>,
        online: &Arc<AtomicBool>,
        ever_resumed: &Arc<AtomicBool>,
    ) -> Result<(), String> {
        let tls = load_tls(Path::new(cert_dir))?;
        let mut socket = Socket::connect(url, tls).map_err(|e| e.to_string())?;
        // Read before the outbox is locked, so the matrix mutex is never held
        // underneath another one. It reports what this agent is actually
        // routing by, which after an `update_capability_matrix` is no longer
        // the version compiled into the binary.
        let matrix_version = live_matrix
            .lock()
            .expect("capability matrix")
            .version()
            .to_string();
        let snapshot = {
            let box_ = outbox.lock().expect("outbox");
            ResumeSnapshot {
                last_assigned_seq: box_.last_allocated(),
                last_acked_seq: box_.committed_through(),
                lowest_retained_seq: box_.lowest_retained_seq(),
                pending_gap_ids: box_.pending_gap_ids(),
                capability_matrix_version: matrix_version,
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
        // 单调：一旦为真就不再翻回。见它创建处的注释。
        ever_resumed.store(true, Ordering::Relaxed);
        loop {
            match socket.recv_envelope() {
                Ok(envelope) => {
                    let inbound = worker
                        .on_inbound(&mut socket, envelope, Instant::now())
                        .map_err(|e| e.to_string())?;
                    if let Inbound::CommandDeliver(deliver) = inbound {
                        if let Err(error) =
                            handle_command(&deliver, executor, live_matrix, &mut socket, outbox)
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
        live_matrix: &Arc<Mutex<CapabilityMatrix>>,
        socket: &mut Socket,
        outbox: &Arc<Mutex<DurableOutbox>>,
    ) -> Result<(), String> {
        let now = unix_ms();
        // Read the matrix back out under the same lock that may have just
        // replaced it, then publish it below. Cloning on every command rather
        // than only on `update_capability_matrix` keeps this from having to
        // know which kinds can change it -- the matrix is a dozen rules and
        // commands are rare.
        let (outcome, matrix) = {
            let mut running = executor.lock().expect("executor");
            let outcome = running
                .handle_envelope(envelope, now)
                .map_err(|error| error.to_string())?;
            let matrix = running.matrix().clone();
            (outcome, matrix)
        };
        *live_matrix.lock().expect("capability matrix") = matrix;
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
        let envelope_id =
            EnvelopeId::new(outcome.result.cmd_id.clone()).map_err(|e| e.to_string())?;
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
        if let Some(inventory) = &outcome.inventory {
            if let Err(error) = send_esim_inventory(inventory, socket, outbox, now) {
                // Logged, never fatal, and never a reason to fail the command.
                // The command result is what the operator is waiting on and it
                // has already been sequenced; losing the inventory costs a
                // stale projection until the next read, which is a smaller
                // harm than an error on an action that worked.
                log_error(format!("esim inventory: {error}"));
            }
        }
        Ok(())
    }

    /// Sequence and send one `EsimInventory` envelope.
    ///
    /// Its own envelope id, deliberately not the `cmd_id`: that id already
    /// belongs to this command's `CommandResult`, and reusing it would collide
    /// in the outbox, hand this payload the result's sequence number, and drop
    /// one of the two on the floor.
    fn send_esim_inventory(
        payload: &EsimInventoryPayload,
        socket: &mut Socket,
        outbox: &Arc<Mutex<DurableOutbox>>,
        now: i64,
    ) -> Result<(), String> {
        let bytes = serde_json::to_vec(payload).map_err(|e| e.to_string())?;
        let id = uuid::Uuid::new_v4().to_string();
        let envelope_id = EnvelopeId::new(id.clone()).map_err(|e| e.to_string())?;
        let (sequence, _) = outbox
            .lock()
            .expect("outbox")
            .append(
                envelope_id,
                "EsimInventory",
                bytes,
                RetentionClass::Protected,
            )
            .map_err(|e| e.to_string())?;
        socket
            .send_envelope(&Envelope {
                v: PROTOCOL_VERSION,
                kind: MessageKind::EsimInventory,
                id,
                ts: now,
                device_id: DEVICE_ID.into(),
                seq: Some(sequence),
                trace_id: None,
                payload: serde_json::to_value(payload).map_err(|e| e.to_string())?,
            })
            .map_err(|e| e.to_string())?;
        println!(
            "esim inventory {} profiles={} seq={sequence}",
            payload.eid,
            payload.profiles.len()
        );
        Ok(())
    }

    fn load_tls(dir: &Path) -> Result<std::sync::Arc<rustls::ClientConfig>, String> {
        let mut ca = BufReader::new(File::open(dir.join("ca.crt")).map_err(|e| e.to_string())?);
        let mut device =
            BufReader::new(File::open(dir.join("device.crt")).map_err(|e| e.to_string())?);
        let mut key =
            BufReader::new(File::open(dir.join("device.key")).map_err(|e| e.to_string())?);
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
        client_config(roots, chain, rustls::pki_types::PrivateKeyDer::Pkcs8(key))
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
    mod radio_at_tests {
        use super::radio_at_command;

        /// 🔴 **不许出现带复位的形式。**
        ///
        /// `AT+CFUN=1,1` 会让模组重启并重新枚举 USB。守卫表把它单列一行、
        /// 措辞是「只有一次观测」的最后手段——一个按钮不该发这种东西。
        /// `AT+CFUN=7` 同理：进去容易，记录在案的出路全部失败过。
        #[test]
        fn the_radio_toggle_never_sends_the_resetting_form() {
            for online in [true, false] {
                let cmd = radio_at_command(online);
                assert!(!cmd.contains(','), "带逗号就是带复位的形式：{cmd}");
                assert!(!cmd.contains('7'), "7 是那个出不来的值：{cmd}");
            }
        }

        /// 🔴 只有「根本没有 QMI 口」才回落，别的失败要原样报出来。
        #[test]
        fn only_a_missing_qmi_port_falls_back_to_at() {
            assert!(
                super::radio_falls_back_to_at("modem_not_found"),
                "AT-only 的模组必须能走 AT 那条路"
            );
            for real_fault in ["radio_failed", "modem_open_failed", "qmi_error_60"] {
                assert!(
                    !super::radio_falls_back_to_at(real_fault),
                    "{real_fault} 是一根**有** QMI 的模组上的真故障 —— \
                     回落会用一次注定也做不成的尝试把原因盖掉，\
                     而 2026-08-25 那次屏幕上必须显示的正是 error 60 本身"
                );
            }
        }

        /// 关得掉，也开得回来——而且回程就在同一个口上。
        #[test]
        fn both_directions_exist_and_are_different() {
            assert_eq!(radio_at_command(false), "AT+CFUN=0");
            assert_eq!(radio_at_command(true), "AT+CFUN=1");
            assert_ne!(
                radio_at_command(true),
                radio_at_command(false),
                "开和关发同一条命令 —— 那个按钮会变成单向的"
            );
        }
    }

    #[cfg(test)]
    mod capability_gate_tests {
        use super::data_capability_gate;

        /// 🔴 开数据面要过矩阵；以前这条路一次都不问。
        #[test]
        fn bringing_data_up_has_to_clear_the_matrix_first() {
            assert_eq!(
                data_capability_gate(true),
                Some(edge_core::Operation::Data),
                "开数据面必须先问矩阵——否则云端改矩阵去关某批模组的数据面，改完没有任何效果"
            );
        }

        /// 🔴 关数据面**不问**。「不支持」是别拉起来的理由，不是不许关的理由。
        #[test]
        fn taking_data_down_is_never_refused_for_being_unsupported() {
            assert_eq!(
                data_capability_gate(false),
                None,
                "关数据面是恢复路径 —— 拿「不支持」拦住它，会把人堵在没有出路的地方"
            );
        }
    }

    #[cfg(test)]
    mod rotate_tests {
        use super::{rotate_cycle, rotate_outcome, OperatingMode, SendError};

        fn code(result: Result<(), SendError>) -> String {
            match result {
                Ok(()) => "ok".to_string(),
                Err(error) => error.reason_code.clone(),
            }
        }

        /// 🔴 拉不回来必须有自己的错误码——操作员的下一步完全不同。
        #[test]
        fn a_radio_that_will_not_come_back_up_is_its_own_failure() {
            assert_eq!(
                code(rotate_outcome(
                    Ok::<(), String>(()),
                    Err("timeout".to_string())
                )),
                "rotate_stranded",
                "关下去了拉不回来 —— 模组停在 LowPower，没人能拔插"
            );
            assert_eq!(
                code(rotate_outcome(
                    Err("busy".to_string()),
                    Ok::<(), String>(())
                )),
                "rotate_failed",
                "根本没关下去 —— 模组没被碰过，重试即可"
            );
            assert_eq!(
                code(rotate_outcome(Ok::<(), String>(()), Ok::<(), String>(()))),
                "ok"
            );
        }

        /// ⚠️ 两步都失败时按**停在 LowPower** 报：关那步的失败可能是超时，
        /// 而超时不代表命令没生效。读错的代价是一根没人去救的模组。
        #[test]
        fn when_both_steps_fail_it_reports_the_dangerous_reading() {
            assert_eq!(
                code(rotate_outcome(
                    Err("timeout".to_string()),
                    Err("timeout".to_string())
                )),
                "rotate_stranded"
            );
        }

        /// 🔴 **关失败时，Online 仍然要发出去。**
        ///
        /// 这条是这次修改的核心。原来写的是 `.and_then(...)`，短路之后 Online
        /// 根本不发，模组停在 LowPower。纯判决函数证明不了这件事——必须看
        /// 「到底发了哪几条命令」。
        #[test]
        fn the_radio_is_always_brought_back_up_even_if_taking_it_down_failed() {
            let mut sent = Vec::new();
            let _ = rotate_cycle(|mode| {
                sent.push(mode);
                Err::<(), String>("busy".to_string())
            });
            assert!(
                sent.contains(&OperatingMode::Online),
                "关失败之后没发 Online —— 模组会停在 LowPower：{sent:?}"
            );
        }

        /// 拉不回来要再试一次。幂等，而代价不对等。
        #[test]
        fn a_radio_that_fails_to_come_back_is_asked_a_second_time() {
            let mut sent = Vec::new();
            let _ = rotate_cycle(|mode| {
                sent.push(mode);
                if mode == OperatingMode::Online {
                    Err::<(), String>("timeout".to_string())
                } else {
                    Ok(())
                }
            });
            assert_eq!(
                sent.iter().filter(|m| **m == OperatingMode::Online).count(),
                2,
                "只试了一次就放弃：{sent:?}"
            );
        }

        /// 一切正常时不多发命令——重试只在失败时发生。
        #[test]
        fn a_clean_cycle_sends_exactly_two_commands() {
            let mut sent = Vec::new();
            let out = rotate_cycle(|mode| {
                sent.push(mode);
                Ok::<(), String>(())
            });
            assert!(out.is_ok());
            assert_eq!(
                sent,
                vec![OperatingMode::LowPower, OperatingMode::Online],
                "正常路径上不该有多余的命令"
            );
        }

        /// 报出来的话里要带上拉不回来的原因，否则屏幕上只剩一个错误码。
        #[test]
        fn the_stranded_message_carries_why_it_could_not_come_back() {
            let Err(error) = rotate_outcome(Ok::<(), String>(()), Err("qmi timeout".to_string()))
            else {
                panic!("应该是错的");
            };
            assert!(
                error.message.contains("qmi timeout"),
                "少了原因就没法判断该不该立刻再下一条命令：{}",
                error.message
            );
        }
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

        /// The whole vocabulary the panel has to understand, written down once.
        ///
        /// It had drifted the other way: the panel carried fourteen state
        /// spellings and four possible names for the detail field, of which
        /// nine and three respectively were never produced by anything here.
        /// Neither side could catch that on its own, because a string that is
        /// never sent is indistinguishable from one that is merely rare.
        #[test]
        fn the_discovery_vocabulary_is_these_five_states_and_three_transports() {
            let states = [
                DiscoveryState::Manageable,
                DiscoveryState::ProbeFailed,
                DiscoveryState::AtOnly,
                DiscoveryState::Found,
                DiscoveryState::Claimed,
            ];
            assert_eq!(
                states.map(DiscoveryState::wire),
                ["manageable", "probe_failed", "at_only", "found", "claimed"],
            );

            let transports = [
                DiscoveryTransport::Qmi,
                DiscoveryTransport::At,
                DiscoveryTransport::Serial,
            ];
            assert_eq!(
                transports.map(DiscoveryTransport::wire),
                ["qmi", "at", "serial"]
            );

            // A serial endpoint's transport has to agree with the prefix its
            // candidate key is built from, or an approval never matches the
            // discovery it was granted against.
            assert!(manual_candidate_key(&edge_modem::AtPortCandidate {
                path: PathBuf::from("/dev/ttyUSB8"),
                kind: edge_modem::AtPortKind::Usb,
                usb_device: Some("2-4.2".into()),
                interface: None,
                interface_label: None,
                driver: None,
                vendor_id: None,
                product_id: None,
                policy: edge_modem::AtProbePolicy::Manual,
            })
            .starts_with(DiscoveryTransport::Serial.wire()));
        }

        /// The AT probe stored its raw `AT+CGMM` reply, so one physical stick
        /// was `EC20` over QMI and `Other("EC20F")` over AT -- taking the
        /// probe-everything matrix fallback on the second path only, with
        /// nothing in the log to say so.
        ///
        /// The naming rule itself is specified and exercised in `edge-core`
        /// (`family_detect_tests`), where it runs on any machine. What this
        /// pins is that the AT path still defers to it rather than growing a
        /// second copy that can drift back.
        #[test]
        fn the_at_path_reports_the_canonical_family_not_the_raw_reply() {
            assert_eq!(at_family("EC20F", ""), ModemFamily::EC20.as_str());
            assert_eq!(at_family("", ""), ModemFamily::UNKNOWN);
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
                error
                    .message
                    .contains("refusing to reset a module that is answering"),
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
