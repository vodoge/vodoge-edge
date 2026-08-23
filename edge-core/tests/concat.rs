use edge_core::{assemble, decode_deliver, ConcatPart, FRAGMENT_GRACE_MS};

const HOUR_MS: i64 = 3_600_000;

fn part(sender: &str, ref_id: u16, total: u8, seq: u8, body: &str, at: i64) -> ConcatPart {
    ConcatPart {
        sender: sender.into(),
        ref_id,
        total,
        seq,
        body: body.into(),
        received_at: Some(at),
    }
}

#[test]
fn concatenates_fragments_in_order() {
    let parts = [
        part("+86100", 7, 2, 2, "world", 1_000),
        part("+86100", 7, 2, 1, "hello", 1_000),
    ];
    let (done, pending) = assemble(&parts, 2_000, FRAGMENT_GRACE_MS);
    assert!(pending.is_empty());
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].body, "helloworld");
    assert_eq!(done[0].parts, 2);
    assert_eq!(done[0].sources, vec![1, 0]);
    assert!(done[0].missing.is_empty());
}

#[test]
fn keeps_incomplete_groups_pending() {
    let parts = [part("+86100", 1, 3, 1, "a", 1_000)];
    let (done, pending) = assemble(&parts, 2_000, FRAGMENT_GRACE_MS);
    assert!(done.is_empty());
    assert_eq!(pending, vec![0]);
}

/// The bench fault, in miniature.
///
/// The service centre delivered one two-fragment message twice. Every sequence
/// number is present, so the message is whole -- twice over. Asking for exactly
/// `total` fragments called that incomplete, and because incomplete means "do
/// not delete", the copies stayed on the modem and were re-read every poll for
/// a day.
#[test]
fn a_message_delivered_twice_yields_two_messages_and_nothing_pending() {
    let parts = [
        part("10086", 0xc3, 2, 1, "first-", 1_000),
        part("10086", 0xc3, 2, 2, "half", 1_000),
        part("10086", 0xc3, 2, 1, "first-", 9_000),
        part("10086", 0xc3, 2, 2, "half", 9_000),
    ];
    let (done, pending) = assemble(&parts, 10_000, FRAGMENT_GRACE_MS);
    assert!(pending.is_empty(), "a whole message must not be pending");
    assert_eq!(done.len(), 2);
    assert_eq!(done[0].body, "first-half");
    assert_eq!(done[1].body, "first-half");
    // Oldest delivery first, and every stored row named so the caller can
    // clear all four off the modem.
    assert_eq!(done[0].sources, vec![0, 1]);
    assert_eq!(done[1].sources, vec![2, 3]);
}

/// An eight-bit reference wraps. Two different messages from one sender can
/// carry the same one, and fragments must not be crossed between them.
#[test]
fn a_reused_reference_pairs_fragments_by_arrival_order() {
    let parts = [
        part("10086", 0x07, 2, 2, "-later", 50_000),
        part("10086", 0x07, 2, 1, "earlier", 1_000),
        part("10086", 0x07, 2, 2, "-earlier", 1_000),
        part("10086", 0x07, 2, 1, "later", 50_000),
    ];
    let (done, pending) = assemble(&parts, 60_000, FRAGMENT_GRACE_MS);
    assert!(pending.is_empty());
    assert_eq!(done.len(), 2);
    assert_eq!(done[0].body, "earlier-earlier");
    assert_eq!(done[1].body, "later-later");
}

/// Uneven counts: the second fragment arrived twice, the first only once. One
/// whole message comes out and the spare stays put -- deleting it would throw
/// away half of whatever it belongs to.
#[test]
fn a_spare_fragment_stays_on_the_modem() {
    let parts = [
        part("10086", 0x14, 2, 1, "one", 1_000),
        part("10086", 0x14, 2, 2, "two", 1_000),
        part("10086", 0x14, 2, 2, "two", 2_000),
    ];
    let (done, pending) = assemble(&parts, 3_000, FRAGMENT_GRACE_MS);
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].sources, vec![0, 1]);
    assert_eq!(pending, vec![2]);
}

#[test]
fn an_orphan_is_released_once_the_grace_period_is_up() {
    let parts = [part("10086", 0x90, 2, 1, "half a message", 1_000)];

    let (done, pending) = assemble(&parts, 1_000 + FRAGMENT_GRACE_MS, FRAGMENT_GRACE_MS);
    assert!(done.is_empty(), "still inside the grace period");
    assert_eq!(pending, vec![0]);

    let (done, pending) = assemble(&parts, 1_001 + FRAGMENT_GRACE_MS, FRAGMENT_GRACE_MS);
    assert!(pending.is_empty(), "the store must be reclaimable");
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].missing, vec![2]);
    assert_eq!(done[0].sources, vec![0]);
    assert_eq!(done[0].body, "half a message[missing part 2 of 2]");
}

#[test]
fn a_fragment_with_no_timestamp_is_never_released_early() {
    let parts = [ConcatPart {
        sender: "10086".into(),
        ref_id: 0x90,
        total: 2,
        seq: 1,
        body: "half".into(),
        received_at: None,
    }];
    let (done, pending) = assemble(&parts, 400 * FRAGMENT_GRACE_MS, FRAGMENT_GRACE_MS);
    assert!(done.is_empty());
    assert_eq!(pending, vec![0]);
}

/// Every SMS-DELIVER that sat on the China Mobile SIM (ICCID
/// 8986003031401770106) on 2026-08-24, read off it with `AT+CPMS="SM"` and
/// `AT+CMGL=4` while the agent was stopped. Nine rows, re-read every eight
/// seconds all day, never stored and never deleted.
///
/// Reference 0xc3 is a four-fragment message the service centre delivered
/// twice, at 01:04:33 and again at 01:12:14 (+08:00) -- eight rows, every
/// sequence number present twice. Reference 0x90 is fragment 1 of 2 of a
/// message whose other half never arrived.
///
/// SIM order, which is neither arrival order nor fragment order.
const SIM_ROWS: [&str; 9] = [
    // index 4: ref 0xc3 1/4, 01:12:14
    "0891683108301145F86405A10180F60008628042102141238C050003C3040130104E1A52A167E58BE230115C0A656C76845BA26237FF0C60A8597DFF0160A853EF4EE576F463A556DE590D5E8F53F78FDB884C4E1A52A167E595F44E0E529E7406003A003100300031002E67E58BE24F59989D000A003100300032002E67E58BE25B9E65F68BDD8D39000A003100300033002E67E58BE2538653F28BDD8D39000A00310030",
    // index 5: ref 0x90 1/2, 01:03:31 -- the orphan
    "0891683108301145F86405A10180F60008628042103013238C05000390020160A8597DFF0160A853EF4EE576F463A556DE590D5E8F53F78FDB884C4E1A52A167E58BE24E0E529E7406FF1A0020621676F463A570B951FB002000680074007400700073003A002F002F00640078002E00310030003000380036002E0063006E002F006400740063007A0030003100205145503CFF0870B951FB94FE63A56B635E386D888017",
    // index 6: ref 0xc3 4/4, 01:12:14
    "0891683108301145F86405A10180F60008628042102141235E050003C3040467E5770B002870B951FB63A56B635E386D8880176D4191CF002930026BCF54684E095145503C4F4E81F3003800386298FF0C652F630100330030514353CA4EE54E0B5C0F989D5145503C300230104E2D56FD79FB52A83011",
    // index 7: ref 0xc3 3/4, 01:12:14
    "0891683108301145F86405A10180F60008628042102141238C050003C304030041004E6D4191CF000A003100360032002E67E58BE2534F8BAE6B3E000A0020767B5F554E2D56FD79FB52A80041005000508FDB884C4E1A52A167E58BE24E0E529E7406FF0C70B951FB00680074007400700073003A002F002F00640078002E00310030003000380036002E0063006E002F0041002F006B007800580063004200677ACB5373",
    // index 8: ref 0xc3 2/4, 01:12:14
    "0891683108301145F86405A10180F60008628042102141238C050003C304020034002E67E58BE25145503C7F348D398BB05F55000A003100300035002E67E58BE28D265355000A003100300036002E8BDD8D398D265355000A003100300037002E8D2662374F59989D63D09192000A003100300038002E004100498C46670D52A1000A003100300039002E67E58BE259579910000A003100360031002E67E58BE20057004C",
    // index 23: ref 0xc3 2/4, 01:04:33
    "0891683108301145F86405A10180F60008628042104033238C050003C304020034002E67E58BE25145503C7F348D398BB05F55000A003100300035002E67E58BE28D265355000A003100300036002E8BDD8D398D265355000A003100300037002E8D2662374F59989D63D09192000A003100300038002E004100498C46670D52A1000A003100300039002E67E58BE259579910000A003100360031002E67E58BE20057004C",
    // index 24: ref 0xc3 1/4, 01:04:33
    "0891683108301145F86405A10180F60008628042104033238C050003C3040130104E1A52A167E58BE230115C0A656C76845BA26237FF0C60A8597DFF0160A853EF4EE576F463A556DE590D5E8F53F78FDB884C4E1A52A167E595F44E0E529E7406003A003100300031002E67E58BE24F59989D000A003100300032002E67E58BE25B9E65F68BDD8D39000A003100300033002E67E58BE2538653F28BDD8D39000A00310030",
    // index 25: ref 0xc3 4/4, 01:04:33
    "0891683108301145F86405A10180F60008628042104033235E050003C3040467E5770B002870B951FB63A56B635E386D8880176D4191CF002930026BCF54684E095145503C4F4E81F3003800386298FF0C652F630100330030514353CA4EE54E0B5C0F989D5145503C300230104E2D56FD79FB52A83011",
    // index 26: ref 0xc3 3/4, 01:04:33
    "0891683108301145F86405A10180F60008628042104033238C050003C304030041004E6D4191CF000A003100360032002E67E58BE2534F8BAE6B3E000A0020767B5F554E2D56FD79FB52A80041005000508FDB884C4E1A52A167E58BE24E0E529E7406FF0C70B951FB00680074007400700073003A002F002F00640078002E00310030003000380036002E0063006E002F0041002F006B007800580063004200677ACB5373",
];

/// 2026-08-23 17:20:00 UTC -- eight minutes after the later delivery.
const JUST_AFTER: i64 = 1_787_505_600_000;

fn sim_fragments() -> Vec<ConcatPart> {
    SIM_ROWS
        .iter()
        .map(|row| {
            let pdu = unhex(row);
            let decoded = decode_deliver(&pdu);
            let (ref_id, total, seq) = decoded.concat.expect("every row carries a UDH");
            ConcatPart {
                sender: decoded.peer,
                ref_id,
                total,
                seq,
                body: decoded.body,
                received_at: decoded.received_at,
            }
        })
        .collect()
}

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn the_sim_rows_decode_to_the_headers_they_were_read_with() {
    let parts = sim_fragments();
    let seen: Vec<(u16, u8, u8)> = parts
        .iter()
        .map(|part| (part.ref_id, part.total, part.seq))
        .collect();
    assert_eq!(
        seen,
        vec![
            (0xc3, 4, 1),
            (0x90, 2, 1),
            (0xc3, 4, 4),
            (0xc3, 4, 3),
            (0xc3, 4, 2),
            (0xc3, 4, 2),
            (0xc3, 4, 1),
            (0xc3, 4, 4),
            (0xc3, 4, 3),
        ]
    );
    assert!(parts.iter().all(|part| part.sender == "10086"));
    // 01:12:14 and 01:04:33 at +08:00.
    assert_eq!(parts[0].received_at, Some(1_787_505_134_000));
    assert_eq!(parts[5].received_at, Some(1_787_504_673_000));
    assert_eq!(parts[1].received_at, Some(1_787_504_611_000));
}

#[test]
fn the_sim_rows_assemble_into_the_two_messages_that_are_whole() {
    let parts = sim_fragments();
    let (done, pending) = assemble(&parts, JUST_AFTER, FRAGMENT_GRACE_MS);

    assert_eq!(done.len(), 2, "both deliveries of 0xc3 are complete");
    assert_eq!(pending, vec![1], "only the orphaned 0x90 fragment is left");

    // Oldest delivery first: the 01:04:33 copy, then the 01:12:14 one.
    assert_eq!(done[0].sources, vec![6, 5, 8, 7]);
    assert_eq!(done[1].sources, vec![0, 4, 3, 2]);
    for message in &done {
        assert_eq!(message.parts, 4);
        assert!(message.missing.is_empty());
        assert_eq!(message.sender, "10086");
    }
    assert_eq!(done[0].body, done[1].body, "same text, delivered twice");

    // Two strings that exist in no single fragment: "104." is split across the
    // boundary between fragments 1 and 2 ("...10" then "4."), and "WLAN"
    // across 2 and 3 ("...WL" then "AN..."). Either one is proof the fragments
    // were joined, in the right order, with nothing dropped between them --
    // an assertion no fragment can satisfy on its own.
    let body = &done[0].body;
    assert!(body.contains("104."), "fragments 1 and 2 not joined: {body}");
    assert!(body.contains("WLAN"), "fragments 2 and 3 not joined: {body}");
    assert!(body.contains("https://dx.10086.cn/A/kxXcB"));
    let first = body.find("101.").expect("fragment 1");
    let second = body.find("105.").expect("fragment 2");
    let third = body.find("https://").expect("fragment 3");
    assert!(first < second && second < third, "out of order: {body}");
}

#[test]
fn the_orphaned_sim_fragment_is_released_a_day_later() {
    let parts = sim_fragments();
    let (done, pending) = assemble(
        &parts,
        JUST_AFTER + FRAGMENT_GRACE_MS + HOUR_MS,
        FRAGMENT_GRACE_MS,
    );
    assert!(pending.is_empty(), "the SIM must become reclaimable");
    assert_eq!(done.len(), 3);
    let released = done
        .iter()
        .find(|message| !message.missing.is_empty())
        .expect("the orphan");
    assert_eq!(released.missing, vec![2]);
    assert_eq!(released.sources, vec![1]);
    assert!(released.body.contains("https://dx.10086.cn/dtcz01"));
    assert!(released.body.ends_with("[missing part 2 of 2]"));
}
