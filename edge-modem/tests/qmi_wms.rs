use edge_modem::{
    parse_list_messages, retain_mobile_terminated, ListedMessage, MessageMode, MessageTag,
    QmiClient, QmiResponse, QmiTransport, ServiceId, SessionError, StorageType, LIST_MESSAGES,
};

struct FakeWms {
    wms_client: u8,
}

impl QmiTransport for FakeWms {
    fn transact(&mut self, request: &[u8]) -> Result<Vec<u8>, SessionError> {
        let service = request[4];
        let client = request[5];
        let (transaction, message) = decode_header(request);
        let payload = match (service, message) {
            (0x00, 0x0027) => success_result_tlv(),
            (0x00, 0x0022) => allocation_payload(ServiceId::WMS.as_u8(), self.wms_client),
            (0x05, 0x0031) => mixed_list_payload(),
            (0x05, 0x0022) => raw_read_payload(),
            (0x05, 0x0020) => {
                let mut payload = success_result_tlv();
                payload.extend_from_slice(&[0x01, 0x02, 0x00, 97, 0x00]);
                payload
            }
            (0x05, 0x0024) => success_result_tlv(),
            _ => {
                return Err(SessionError::transport(format!(
                    "unexpected service=0x{service:02x} message=0x{message:04x} client=0x{client:02x}"
                )))
            }
        };
        Ok(response_frame(service, client, transaction, message, &payload))
    }
}

#[test]
fn list_parser_keeps_returned_tags_not_the_request_filter() {
    let frame = response_frame(
        ServiceId::WMS.as_u8(),
        0x06,
        1,
        LIST_MESSAGES.as_u16(),
        &mixed_list_payload(),
    );
    let response = QmiResponse::decode(&frame).expect("list frame");
    let listed = parse_list_messages(&response, StorageType::Nv).expect("parse list");
    assert_eq!(
        listed,
        vec![
            ListedMessage {
                index: 1,
                tag: MessageTag::MoSent,
                storage: StorageType::Nv,
            },
            ListedMessage {
                index: 2,
                tag: MessageTag::MtUnread,
                storage: StorageType::Nv,
            },
            ListedMessage {
                index: 3,
                tag: MessageTag::MoUnsent,
                storage: StorageType::Nv,
            },
        ]
    );
    assert_eq!(
        retain_mobile_terminated(&listed),
        vec![ListedMessage {
            index: 2,
            tag: MessageTag::MtUnread,
            storage: StorageType::Nv,
        }]
    );
}

#[test]
fn session_lists_reads_sends_and_deletes_sms() {
    let mut client = QmiClient::new(FakeWms { wms_client: 0x06 });
    client.sync().expect("sync");

    let listed = client
        .list_sms(StorageType::Uim, MessageTag::MtUnread, MessageMode::Gw)
        .expect("list");
    assert_eq!(retain_mobile_terminated(&listed).len(), 1);

    let message = client
        .read_sms(StorageType::Uim, 2, MessageMode::Gw)
        .expect("read");
    assert_eq!(message.tag, Some(MessageTag::MtUnread));
    assert_eq!(message.pdu, b"pdu");

    let message_id = client.send_sms(0x06, b"\x00\x01").expect("send");
    assert_eq!(message_id, Some(97));

    client
        .delete_sms(StorageType::Uim, 2, MessageMode::Gw)
        .expect("delete");
}

fn mixed_list_payload() -> Vec<u8> {
    let mut payload = success_result_tlv();
    let mut list = Vec::new();
    list.extend_from_slice(&3u32.to_le_bytes());
    list.extend_from_slice(&1u32.to_le_bytes());
    list.push(MessageTag::MoSent.as_u8());
    list.extend_from_slice(&2u32.to_le_bytes());
    list.push(MessageTag::MtUnread.as_u8());
    list.extend_from_slice(&3u32.to_le_bytes());
    list.push(MessageTag::MoUnsent.as_u8());
    payload.push(0x01);
    payload.extend_from_slice(&(list.len() as u16).to_le_bytes());
    payload.extend_from_slice(&list);
    payload
}

fn raw_read_payload() -> Vec<u8> {
    let mut payload = success_result_tlv();
    let mut value = vec![MessageTag::MtUnread.as_u8(), 0x06];
    value.extend_from_slice(&(b"pdu".len() as u16).to_le_bytes());
    value.extend_from_slice(b"pdu");
    payload.push(0x01);
    payload.extend_from_slice(&(value.len() as u16).to_le_bytes());
    payload.extend_from_slice(&value);
    payload
}

fn success_result_tlv() -> Vec<u8> {
    vec![0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]
}

fn allocation_payload(service: u8, client: u8) -> Vec<u8> {
    let mut payload = success_result_tlv();
    payload.extend_from_slice(&[0x01, 0x02, 0x00, service, client]);
    payload
}

fn decode_header(request: &[u8]) -> (u16, u16) {
    let service = request[4];
    if service == ServiceId::CONTROL.as_u8() {
        (
            request[7] as u16,
            u16::from_le_bytes([request[8], request[9]]),
        )
    } else {
        (
            u16::from_le_bytes([request[7], request[8]]),
            u16::from_le_bytes([request[9], request[10]]),
        )
    }
}

fn response_frame(
    service: u8,
    client: u8,
    transaction: u16,
    message: u16,
    payload: &[u8],
) -> Vec<u8> {
    let is_control = service == ServiceId::CONTROL.as_u8();
    let qmi_header_length = if is_control { 6 } else { 7 };
    let qmux_length = 5 + qmi_header_length + payload.len();
    let mut frame = Vec::with_capacity(qmux_length + 1);
    frame.push(0x01);
    frame.extend_from_slice(&(qmux_length as u16).to_le_bytes());
    frame.push(0x80);
    frame.push(service);
    frame.push(client);
    frame.push(if is_control { 0x01 } else { 0x02 });
    if is_control {
        frame.push(transaction as u8);
    } else {
        frame.extend_from_slice(&transaction.to_le_bytes());
    }
    frame.extend_from_slice(&message.to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// A modem that answers the list-tag argument the way the bench EC20s
/// actually do.
///
/// The collector used to ask for `MtUnread` alone, on the strength of a
/// comment claiming the tag was ignored. On 2026-08-23 one `AT+CMGR` flipped a
/// stored message to `REC READ` and the next five collection passes returned
/// nothing, while `AT+CPMS?` still counted it in the store: the message was
/// unreachable for good and its slot was held for good.
struct TaggedStore {
    wms_client: u8,
    rows: Vec<(StorageType, u32, MessageTag)>,
    /// False for a modem that really does ignore the tag and answers every
    /// query with its whole store.
    honours_tag: bool,
    asked: std::rc::Rc<std::cell::RefCell<Vec<(u8, u8)>>>,
}

impl QmiTransport for TaggedStore {
    fn transact(&mut self, request: &[u8]) -> Result<Vec<u8>, SessionError> {
        let service = request[4];
        let client = request[5];
        let (transaction, message) = decode_header(request);
        let payload = match (service, message) {
            (0x00, 0x0027) => success_result_tlv(),
            (0x00, 0x0022) => allocation_payload(ServiceId::WMS.as_u8(), self.wms_client),
            (0x05, 0x0031) => {
                let storage = request_tlv(request, 0x01).expect("storage tlv")[0];
                let tag = request_tlv(request, 0x11).expect("tag tlv")[0];
                self.asked.borrow_mut().push((storage, tag));
                let honours = self.honours_tag;
                let rows: Vec<(u32, MessageTag)> = self
                    .rows
                    .iter()
                    .filter(|(row_storage, _, row_tag)| {
                        row_storage.as_u8() == storage && (!honours || row_tag.as_u8() == tag)
                    })
                    .map(|(_, index, row_tag)| (*index, *row_tag))
                    .collect();
                list_payload(&rows)
            }
            (0x05, 0x0022) => raw_read_payload(),
            (0x05, 0x0024) => success_result_tlv(),
            _ => {
                return Err(SessionError::transport(format!(
                    "unexpected service=0x{service:02x} message=0x{message:04x} client=0x{client:02x}"
                )))
            }
        };
        Ok(response_frame(service, client, transaction, message, &payload))
    }
}

fn bench_store(honours_tag: bool) -> (QmiClient<TaggedStore>, std::rc::Rc<std::cell::RefCell<Vec<(u8, u8)>>>) {
    let asked = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut client = QmiClient::new(TaggedStore {
        wms_client: 0x06,
        rows: vec![
            // The message somebody's AT+CMGR turned into REC READ.
            (StorageType::Nv, 1, MessageTag::MtRead),
            (StorageType::Nv, 2, MessageTag::MtUnread),
        ],
        honours_tag,
        asked: std::rc::Rc::clone(&asked),
    });
    client.sync().expect("sync");
    (client, asked)
}

/// The defect this file exists to keep out: a message that was marked read is
/// still a message the operator never saw, and it is still occupying a slot in
/// a store that holds fifty.
#[test]
fn a_message_someone_marked_read_is_still_collected() {
    let (mut client, _) = bench_store(true);
    let listed = edge_modem::ModemPort::list_sms(&mut client).expect("list");
    let indexes: Vec<u32> = listed.iter().map(|message| message.index).collect();
    assert!(
        indexes.contains(&1),
        "a read message must still be listed, got {listed:?}"
    );
    assert!(indexes.contains(&2), "got {listed:?}");
}

/// Both stores are still asked, and both tags are asked of each: a store the
/// modem cannot list must not stop the other from being read.
#[test]
fn every_store_is_asked_for_read_and_unread() {
    let (mut client, asked) = bench_store(true);
    edge_modem::ModemPort::list_sms(&mut client).expect("list");
    let asked = asked.borrow().clone();
    for storage in [StorageType::Uim, StorageType::Nv] {
        for tag in [MessageTag::MtRead, MessageTag::MtUnread] {
            assert!(
                asked.contains(&(storage.as_u8(), tag.as_u8())),
                "{storage:?}/{tag:?} was never asked for: {asked:?}"
            );
        }
    }
}

/// A modem that genuinely ignores the tag answers both queries with the same
/// rows. Listing each of them would read and store one message twice.
#[test]
fn a_modem_that_ignores_the_tag_does_not_yield_duplicates() {
    let (mut client, _) = bench_store(false);
    let listed = edge_modem::ModemPort::list_sms(&mut client).expect("list");
    let mut seen: Vec<(StorageType, u32)> = listed
        .iter()
        .map(|message| (message.storage, message.index))
        .collect();
    let before = seen.len();
    seen.sort();
    seen.dedup();
    assert_eq!(before, seen.len(), "one row listed twice: {listed:?}");
    assert_eq!(seen.len(), 2, "got {listed:?}");
}

/// TLV value of one type out of a request frame.
fn request_tlv(request: &[u8], wanted: u8) -> Option<Vec<u8>> {
    let mut offset = 13;
    while offset + 3 <= request.len() {
        let kind = request[offset];
        let length = u16::from_le_bytes([request[offset + 1], request[offset + 2]]) as usize;
        let start = offset + 3;
        if start + length > request.len() {
            return None;
        }
        if kind == wanted {
            return Some(request[start..start + length].to_vec());
        }
        offset = start + length;
    }
    None
}

/// A `LIST_MESSAGES` response holding the given rows. An empty store answers
/// without the list TLV at all, which is what these modules do.
fn list_payload(rows: &[(u32, MessageTag)]) -> Vec<u8> {
    let mut payload = success_result_tlv();
    if rows.is_empty() {
        return payload;
    }
    let mut list = Vec::new();
    list.extend_from_slice(&(rows.len() as u32).to_le_bytes());
    for (index, tag) in rows {
        list.extend_from_slice(&index.to_le_bytes());
        list.push(tag.as_u8());
    }
    payload.push(0x01);
    payload.extend_from_slice(&(list.len() as u16).to_le_bytes());
    payload.extend_from_slice(&list);
    payload
}
