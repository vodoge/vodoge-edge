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
    let listed = parse_list_messages(&response).expect("parse list");
    assert_eq!(
        listed,
        vec![
            ListedMessage {
                index: 1,
                tag: MessageTag::MoSent,
            },
            ListedMessage {
                index: 2,
                tag: MessageTag::MtUnread,
            },
            ListedMessage {
                index: 3,
                tag: MessageTag::MoUnsent,
            },
        ]
    );
    assert_eq!(
        retain_mobile_terminated(&listed),
        vec![ListedMessage {
            index: 2,
            tag: MessageTag::MtUnread,
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
