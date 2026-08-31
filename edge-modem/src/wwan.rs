//! Turning an established packet session into a network interface.
//!
//! QMI starting a session gets an address from the network; it does not put
//! that address on anything. The `wwan` device stays `DOWN` with no address
//! until somebody configures it, which is why this bench had four registered
//! modules, an APN table, and no data path at all.
//!
//! # Which interface belongs to which modem
//!
//! A `cdc-wdm` control node and its `wwan` data interface are two functions of
//! one USB interface, so sysfs already relates them:
//!
//! ```text
//! /sys/class/usbmisc/cdc-wdm1/device/net/wwan1
//! ```
//!
//! Walking that is the only mapping that survives re-enumeration. Pairing them
//! by ordinal -- `cdc-wdm1` with `wwan1` -- is the tempting shortcut and it is
//! wrong: the numbers are assigned independently, and on a bench where modules
//! come and go over USB/IP they drift apart. Configuring the wrong interface
//! puts one module's address on another module's link.
//!
//! # Why the default route does not go in the main table
//!
//! 🔴 A modem's default route must never land in the main routing table. This
//! box has four modules and one uplink of its own, and `ip route add default`
//! in the main table is refused with `RTNETLINK answers: File exists` when the
//! box already has one -- which is how this was found, on 2026-08-31. The
//! refusal is the good outcome: had it succeeded it would have moved the
//! box's own traffic onto a modem, and the SSH session configuring it with it.
//!
//! So each interface gets its own table and a rule that sends traffic sourced
//! from its address there. Four modules then have four working defaults at
//! once, which is what a box that exists to egress through a chosen module
//! needs -- one shared default could only ever serve one of them.
//!
//! # `raw_ip`
//!
//! `qmi_wwan` defaults to an Ethernet framing the modules do not speak. The
//! driver exposes a `raw_ip` toggle, and 🔴 **it can only be written while the
//! interface is down** -- the write returns `EBUSY` otherwise, and an
//! interface configured in the wrong mode passes no traffic while looking
//! entirely healthy.

use std::path::{Path, PathBuf};

/// Where the data plane's shell-outs are described rather than run.
///
/// Built as data so the order can be asserted. The order is not incidental:
/// the address has to be flushed before the mode changes, the mode has to
/// change while the link is down, and the route cannot be added before the
/// address it goes out of exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Step {
    pub program: &'static str,
    pub args: Vec<String>,
    /// Whether a failure is expected and may be ignored.
    ///
    /// The deletes are: removing a rule that is not there, or flushing a table
    /// that is already empty, both fail and both mean the state is already
    /// what was wanted. Treating those as faults would make every first run
    /// report an error it had just corrected.
    pub tolerant: bool,
}

impl Step {
    fn ip(args: &[&str]) -> Self {
        Self {
            program: "ip",
            args: args.iter().map(|value| (*value).to_owned()).collect(),
            tolerant: false,
        }
    }

    /// A step whose failure means "already so".
    fn optional(args: &[&str]) -> Self {
        Self {
            tolerant: true,
            ..Self::ip(args)
        }
    }
}

/// The `wwan` interface that shares a USB interface with this control node.
///
/// `control` is a path like `/dev/cdc-wdm1`; only its file name is used.
/// `root` is the sysfs mount, injectable so the walk can be tested against a
/// tree on disk rather than against whatever hardware the test host has.
pub fn interface_for(root: &Path, control: &Path) -> Option<String> {
    let node = control.file_name()?.to_str()?;
    let net = root.join("class/usbmisc").join(node).join("device/net");
    let mut names: Vec<String> = std::fs::read_dir(net)
        .ok()?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .collect();
    // Sorted so a module that somehow exposes two data interfaces produces the
    // same answer every time rather than whichever the directory listed first.
    names.sort();
    names.into_iter().next()
}

/// Path of the driver's framing toggle for an interface.
pub fn raw_ip_path(root: &Path, interface: &str) -> PathBuf {
    root.join("class/net").join(interface).join("qmi/raw_ip")
}

/// The steps that take an interface from wherever it is to carrying `settings`.
///
/// Split from running them so the sequence is a value: the ordering rules in
/// this module's header are asserted in tests rather than described in a
/// comment above an imperative block.
pub fn bring_up(interface: &str, settings: &Ipv4View) -> Vec<Step> {
    let mut steps = vec![
        // Down first: `raw_ip` refuses to change on a live interface, and an
        // address left over from a previous session would survive the flush
        // order otherwise.
        Step::ip(&["link", "set", interface, "down"]),
        Step::optional(&["addr", "flush", "dev", interface]),
    ];
    steps.push(Step::ip(&["link", "set", interface, "up"]));
    steps.push(Step::ip(&[
        "addr",
        "add",
        &format!("{}/{}", settings.address, settings.prefix),
        "dev",
        interface,
    ]));
    if let Some(mtu) = settings.mtu {
        steps.push(Step::ip(&["link", "set", interface, "mtu", &mtu.to_string()]));
    }
    if let Some(gateway) = &settings.gateway {
        let table = table_for(interface).to_string();
        // Onlink: the gateway a mobile network hands back is routinely outside
        // the prefix it also hands back, and without this `ip` refuses the
        // route as unreachable. That refusal is the last step of a session
        // that otherwise came up perfectly.
        steps.push(Step::ip(&[
            "route", "add", "default", "via", gateway, "dev", interface, "onlink",
            "table", &table,
        ]));
        // Deleted first so a re-run does not stack duplicate rules; a missing
        // rule makes the delete fail, which the caller ignores for this step.
        steps.push(Step::optional(&[
            "rule", "del", "from", &settings.address, "lookup", &table,
        ]));
        steps.push(Step::ip(&[
            "rule", "add", "from", &settings.address, "lookup", &table,
        ]));
    }
    steps
}

/// The routing table this interface's default route lives in.
///
/// Derived from the trailing digits of the name so the tables are legible in
/// `ip rule` output -- `wwan0` is 100, `wwan1` is 101 -- and stable for as
/// long as the name is. A name with no number falls back to the base, which
/// collides only among unnumbered interfaces, and this driver names them all.
pub fn table_for(interface: &str) -> u32 {
    const BASE: u32 = 100;
    let digits: String = interface
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    BASE + digits.parse::<u32>().unwrap_or(0)
}

/// The steps that undo `bring_up`, for a session that has ended.
pub fn tear_down(interface: &str, address: Option<&str>) -> Vec<Step> {
    let table = table_for(interface).to_string();
    let mut steps = Vec::new();
    if let Some(address) = address {
        // The rule goes before the address it matches on: a rule left behind
        // pointing at an empty table black-holes anything that later gets the
        // same address, which on this bench is the next session on the same
        // module.
        steps.push(Step::optional(&["rule", "del", "from", address, "lookup", &table]));
    }
    steps.push(Step::optional(&["route", "flush", "table", &table]));
    steps.push(Step::ip(&["addr", "flush", "dev", interface]));
    steps.push(Step::ip(&["link", "set", interface, "down"]));
    steps
}

/// What `bring_up` needs, decoupled from the QMI parser's own type so this
/// module can be tested without building a QMI response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4View {
    pub address: String,
    pub prefix: u8,
    pub gateway: Option<String>,
    pub mtu: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let ordinal = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "vodoge-wwan-{name}-{}-{ordinal}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("root");
        root
    }

    /// 🔴 The mapping that must not be done by ordinal. `cdc-wdm1` here owns
    /// `wwan3`, which is the case a "same number" shortcut gets wrong -- and
    /// getting it wrong puts one module's address on another module's link.
    #[test]
    fn the_interface_is_found_through_sysfs_not_by_matching_numbers() {
        let root = scratch("mapping");
        let net = root.join("class/usbmisc/cdc-wdm1/device/net/wwan3");
        std::fs::create_dir_all(&net).expect("tree");
        assert_eq!(
            interface_for(&root, Path::new("/dev/cdc-wdm1")),
            Some("wwan3".to_owned())
        );
    }

    /// A control node with no data interface behind it is not an error to
    /// report loudly: plenty of modules expose one, and the caller's answer is
    /// "no data plane here" either way.
    #[test]
    fn a_node_with_no_data_interface_maps_to_nothing() {
        let root = scratch("bare");
        std::fs::create_dir_all(root.join("class/usbmisc/cdc-wdm0/device")).expect("tree");
        assert_eq!(interface_for(&root, Path::new("/dev/cdc-wdm0")), None);
        assert_eq!(interface_for(&root, Path::new("/dev/cdc-wdm9")), None);
    }

    /// 🔴 The ordering rules, as assertions. `raw_ip` cannot be written to a
    /// live interface, so the link goes down before anything else; the address
    /// cannot be added before the link is up; the route cannot be added before
    /// the address exists.
    #[test]
    fn the_sequence_puts_the_link_down_before_it_configures_anything() {
        let steps = bring_up(
            "wwan0",
            &Ipv4View {
                address: "10.115.32.7".into(),
                prefix: 30,
                gateway: Some("10.115.32.8".into()),
                mtu: Some(1500),
            },
        );
        let rendered: Vec<String> = steps
            .iter()
            .map(|step| format!("{} {}", step.program, step.args.join(" ")))
            .collect();
        assert_eq!(rendered[0], "ip link set wwan0 down");
        assert_eq!(rendered[1], "ip addr flush dev wwan0");
        let up = rendered.iter().position(|line| line == "ip link set wwan0 up");
        let addr = rendered
            .iter()
            .position(|line| line.starts_with("ip addr add"));
        let route = rendered
            .iter()
            .position(|line| line.starts_with("ip route add"));
        assert!(up < addr, "an address was added to a down interface");
        assert!(addr < route, "a route was added before its source address");
    }

    /// 🔴 The default route goes in the interface's own table, never the main
    /// one. Measured 2026-08-31: `ip route add default ... ` in the main table
    /// is refused `File exists` on a box that already has a default -- and the
    /// refusal is the good outcome, because succeeding would have moved the
    /// box's own traffic, and the session configuring it, onto a modem.
    #[test]
    fn the_default_route_never_lands_in_the_main_table() {
        let steps = bring_up(
            "wwan0",
            &Ipv4View {
                address: "10.115.32.7".into(),
                prefix: 30,
                gateway: Some("10.64.64.64".into()),
                mtu: None,
            },
        );
        let route = steps
            .iter()
            .find(|step| step.args.first().map(String::as_str) == Some("route"))
            .expect("a default route");
        let table = route
            .args
            .iter()
            .position(|arg| arg == "table")
            .expect("the route must name a table");
        assert_eq!(route.args[table + 1], "100", "wwan0's table is 100");
        assert!(
            steps.iter().any(|step| step.args.first().map(String::as_str) == Some("rule")
                && step.args.contains(&"add".to_owned())),
            "a table with no rule pointing at it routes nothing"
        );
    }

    /// Four modules, four tables, four simultaneous defaults. One shared table
    /// could only ever serve one of them, which is not what a box that egresses
    /// through a chosen module can do.
    #[test]
    fn each_interface_gets_its_own_table() {
        assert_eq!(table_for("wwan0"), 100);
        assert_eq!(table_for("wwan3"), 103);
        assert_ne!(table_for("wwan0"), table_for("wwan1"));
        // No trailing number is the only collision, and this driver numbers
        // every interface it creates.
        assert_eq!(table_for("wwan"), 100);
    }

    /// 🔴 `onlink`, because a mobile network routinely hands back a gateway
    /// outside the prefix it hands back with it. Without it `ip` refuses the
    /// route and a session that came up perfectly carries nothing.
    #[test]
    fn the_default_route_is_onlink() {
        let steps = bring_up(
            "wwan0",
            &Ipv4View {
                address: "10.115.32.7".into(),
                prefix: 30,
                gateway: Some("10.64.64.64".into()),
                mtu: None,
            },
        );
        let route = steps
            .iter()
            .find(|step| step.args.first().map(String::as_str) == Some("route"))
            .expect("a default route");
        assert!(
            route.args.iter().any(|arg| arg == "onlink"),
            "the gateway is outside the prefix here and this route would be refused: {route:?}"
        );
    }

    /// A session with no gateway still gets its address. Reporting an address
    /// and no route is a fault an operator can see; refusing to configure
    /// anything hides it.
    #[test]
    fn an_absent_gateway_does_not_stop_the_address() {
        let steps = bring_up(
            "wwan0",
            &Ipv4View {
                address: "10.115.32.7".into(),
                prefix: 30,
                gateway: None,
                mtu: None,
            },
        );
        assert!(steps.iter().any(|step| step.args.contains(&"add".to_owned())));
        assert!(
            !steps
                .iter()
                .any(|step| step.args.first().map(String::as_str) == Some("route")),
            "a route was invented for a session that named no gateway"
        );
    }

    #[test]
    fn tearing_down_removes_the_rule_before_the_address_it_matches() {
        let steps = tear_down("wwan0", Some("10.115.32.7"));
        let rendered: Vec<String> = steps
            .iter()
            .map(|step| format!("{} {}", step.program, step.args.join(" ")))
            .collect();
        let rule = rendered.iter().position(|line| line.starts_with("ip rule del"));
        let addr = rendered.iter().position(|line| line.starts_with("ip addr flush"));
        assert!(rule < addr, "a rule left pointing at an empty table black-holes the next session");
        assert!(rendered.iter().any(|line| line.starts_with("ip route flush table")));
    }
}
