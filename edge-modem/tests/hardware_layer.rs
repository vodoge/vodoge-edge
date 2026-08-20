use std::cell::Cell;
use std::time::Duration;

use edge_core::{arbitrate, Plmn, RegistrationEvidence, RegistrationSourceKind};
use edge_modem::{
    collect_inbound, delete_inbound, discover, with_restore, DiscoveredModem, FakeEnumerator,
    FakeModem, MessageTag, ModemPort, TransportKind, UnsupportedPort,
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
    assert_eq!(modem.reads(), &[2]);

    delete_inbound(&mut modem, &pass.inbound).expect("delete inbound only");
    assert_eq!(modem.deletes(), &[2]);
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
fn at_mbim_pcsc_stubs_exist_and_are_unsupported() {
    for mut port in [UnsupportedPort::at(), UnsupportedPort::mbim(), UnsupportedPort::pcsc()] {
        assert!(port.imei().is_err());
    }
}
