use std::cell::Cell;
use std::time::Duration;

use edge_core::{
    arbitrate, Bearer, Plmn, RegistrationEvidence, RegistrationSourceKind, SendPlan,
};
use edge_modem::{
    collect_inbound, delete_inbound, discover, send_with_plan, with_restore, DiscoveredModem,
    FakeEnumerator, FakeModem, MessageTag, ModemPort, PortError, TransportKind, UnsupportedPort,
    StorageType,
};

#[test]
fn mixed_list_does_not_read_or_delete_mo() {
    let mut modem = FakeModem::new("867018069509705", "EC20");
    modem.push_sms(1, MessageTag::MoSent, b"sent");
    modem.push_sms(2, MessageTag::MtUnread, b"hello");
    modem.push_sms(3, MessageTag::MoUnsent, b"draft");

    let pass = collect_inbound(&mut modem).expect("collect");
    assert_eq!(pass.inbound.len(), 1);
    assert_eq!(pass.inbound[0].index, 2);
    assert_eq!(pass.skipped_mo.len(), 2);
    assert_eq!(modem.reads(), &[(StorageType::Uim, 2)]);

    delete_inbound(&mut modem, &pass.inbound).expect("delete inbound only");
    assert_eq!(modem.deletes(), &[(StorageType::Uim, 2)]);
}

/// A modem that keeps received messages in its own memory rather than on the
/// SIM. These EC20s do exactly that, and a reader that looked only at the SIM
/// reported an empty inbox while five messages sat on the device.
#[test]
fn messages_in_the_modems_own_memory_are_collected() {
    let mut modem = FakeModem::new("867018069509705", "EC20");
    modem.push_sms_in(StorageType::Nv, 1, MessageTag::MtUnread, b"from the network");

    let pass = collect_inbound(&mut modem).expect("collect");
    assert_eq!(pass.inbound.len(), 1, "a message on the device was missed");
    assert_eq!(pass.inbound[0].storage, StorageType::Nv);
    assert_eq!(modem.reads(), &[(StorageType::Nv, 1)]);

    // And the delete has to target the same store: index 1 on the SIM is a
    // different message entirely.
    delete_inbound(&mut modem, &pass.inbound).expect("delete");
    assert_eq!(modem.deletes(), &[(StorageType::Nv, 1)]);
}

/// The same index in two stores is two messages, and both must survive the
/// round trip intact.
#[test]
fn the_same_index_in_two_stores_is_two_messages() {
    let mut modem = FakeModem::new("867018069509705", "EC20");
    modem.push_sms_in(StorageType::Uim, 1, MessageTag::MtUnread, b"on the sim");
    modem.push_sms_in(StorageType::Nv, 1, MessageTag::MtUnread, b"on the device");

    let pass = collect_inbound(&mut modem).expect("collect");
    assert_eq!(pass.inbound.len(), 2);
    let bodies: Vec<&[u8]> = pass.inbound.iter().map(|m| m.raw.pdu.as_slice()).collect();
    assert!(bodies.contains(&b"on the sim".as_slice()));
    assert!(bodies.contains(&b"on the device".as_slice()));
}

#[test]
fn serving_system_searching_with_cell_is_camped() {
    let mut modem = FakeModem::new("862547055142811", "EC20");
    modem.evidence = vec![
        RegistrationEvidence::serving_system(false, None),
        RegistrationEvidence::cell_location(Some(Plmn::new("460", "01")), Some(4_945_529)),
    ];
    let verdict = arbitrate(&modem.registration_evidence().expect("evidence"));
    assert!(verdict.registered);
    assert!(!verdict.recovery_allowed);
    assert_eq!(
        verdict.trusted_source,
        Some(RegistrationSourceKind::CellLocation)
    );
}

#[test]
fn restore_runs_with_its_own_budget_after_body_fails() {
    let mut restored_with = None;
    let result: Result<(), &'static str> = with_restore(
        || Ok(()),
        |budget| {
            restored_with = Some(budget);
            Ok(())
        },
        Duration::from_secs(30),
        || Err("body cancelled"),
    );
    assert_eq!(result, Err("body cancelled"));
    assert_eq!(restored_with, Some(Duration::from_secs(30)));
}

#[test]
fn restore_still_runs_when_disrupt_succeeds_and_body_ok() {
    let radio_on = Cell::new(true);
    let result = with_restore(
        || {
            radio_on.set(false);
            Ok::<(), &'static str>(())
        },
        |_| {
            radio_on.set(true);
            Ok(())
        },
        Duration::from_millis(50),
        || Ok("did work"),
    );
    assert_eq!(result, Ok("did work"));
    assert!(radio_on.get());
}

#[test]
fn discovery_stops_at_the_first_non_empty_step() {
    let enumerator = FakeEnumerator {
        qmi: vec![DiscoveredModem {
            kind: TransportKind::Qmi,
            path: "/dev/cdc-wdm0".into(),
            net_iface: Some("wwan0".into()),
        }],
        mbim: vec![DiscoveredModem {
            kind: TransportKind::Mbim,
            path: "/dev/cdc-wdm-mbim".into(),
            net_iface: None,
        }],
        at: vec![DiscoveredModem {
            kind: TransportKind::At,
            path: "/dev/ttyUSB2".into(),
            net_iface: None,
        }],
    };
    let found = discover(&enumerator);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].kind, TransportKind::Qmi);
}

#[test]
fn discovery_falls_back_to_vid_at() {
    let enumerator = FakeEnumerator {
        at: vec![DiscoveredModem {
            kind: TransportKind::At,
            path: "/dev/ttyUSB2".into(),
            net_iface: None,
        }],
        ..FakeEnumerator::default()
    };
    let found = discover(&enumerator);
    assert_eq!(found[0].kind, TransportKind::At);
}

#[test]
fn send_plan_uses_fallback_when_primary_fails() {
    let mut modem = FakeModem::new("867018069509705", "EC20");
    modem.fail_on(Bearer::Cellular);
    let plan = SendPlan::with_reason(
        Some(Bearer::Cellular),
        Some(Bearer::Ims),
        "intl vertical: cellular then IMS",
    );
    let outcome = send_with_plan(&mut modem, &plan, b"pdu").expect("fallback send");
    assert!(outcome.fallback_used);
    assert_eq!(outcome.used, Bearer::Ims);
    assert_eq!(
        modem.sent(),
        &[(Bearer::Ims, b"pdu".to_vec())]
    );
}

#[test]
fn send_plan_without_a_bearer_does_not_touch_the_modem() {
    let mut modem = FakeModem::new("867018069509705", "EC20");
    let plan = SendPlan::unavailable("no_cdma_fallback_and_no_ct_volte_mbn");
    let error = send_with_plan(&mut modem, &plan, b"pdu").expect_err("no send");
    assert!(modem.sent().is_empty());
    assert!(error.to_string().contains("no_cdma_fallback_and_no_ct_volte_mbn"));
}

/// Every stub transport refuses every call in the trait, with the error that
/// names a missing implementation rather than a missing device.
///
/// This used to check one `imei()` per stub, which left the other eight calls
/// free to answer `Ok` -- and one of them did: `sweep_slots` took the trait
/// default and returned `Ok(vec![])`, an empty success no caller could tell
/// from a real sweep that found nothing. Naming every call is the point: half
/// an implementation is what this has to turn red on.
#[test]
fn at_mbim_pcsc_stubs_exist_and_are_unsupported() {
    for (kind, mut port) in [
        (TransportKind::At, UnsupportedPort::at()),
        (TransportKind::Mbim, UnsupportedPort::mbim()),
        (TransportKind::Pcsc, UnsupportedPort::pcsc()),
    ] {
        let refused = PortError::Unsupported(kind);
        assert_eq!(port.transport_kind(), kind, "a stub named the wrong transport");
        assert_eq!(port.imei().unwrap_err(), refused);
        assert_eq!(port.firmware().unwrap_err(), refused);
        assert_eq!(port.registration_evidence().unwrap_err(), refused);
        assert_eq!(port.list_sms().unwrap_err(), refused);
        assert_eq!(
            port.sweep_slots(0, 16).unwrap_err(),
            refused,
            "an empty sweep reads as 'nothing in those slots', not 'no such transport'"
        );
        assert_eq!(port.read_sms(StorageType::Uim, 1).unwrap_err(), refused);
        assert_eq!(port.delete_sms(StorageType::Uim, 1).unwrap_err(), refused);
        assert_eq!(port.send_pdu(b"pdu").unwrap_err(), refused);
        assert_eq!(port.send_on(Bearer::Ims, b"pdu").unwrap_err(), refused);
    }
}

/// The PC/SC failure has to read as "this build has no PC/SC", because the
/// other reading -- "no reader found" -- sends whoever hits it off to plug in
/// hardware, and `goal.md:161` says nobody can reach that hardware to plug
/// anything into. That is the same reason the stub stays a stub: T052
/// (2026-08-25) decided against writing a path no one could ever run. See
/// `docs/goals/vodoge-vowifi-call/notes/T052-pcsc-reader.md`.
#[test]
fn the_pcsc_stub_blames_the_build_not_a_missing_reader() {
    let message = UnsupportedPort::pcsc().imei().unwrap_err().to_string();
    assert!(message.contains("pcsc"), "does not say which transport: {message}");
    assert!(
        message.contains("not implemented"),
        "does not name a missing implementation: {message}"
    );
    assert!(
        message.contains("no device was contacted"),
        "leaves 'no reader is plugged in' open as a reading: {message}"
    );
}
