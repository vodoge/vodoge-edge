use edge_modem::{
    parse_eid, ApduResponse, QmiClient, QmiTransport, ServiceId, SessionError, GET_EID_APDU,
    ISD_R_AID,
};

struct FakeUim {
    uim_client: u8,
}

impl QmiTransport for FakeUim {
    fn transact(&mut self, request: &[u8]) -> Result<Vec<u8>, SessionError> {
        let service = request[4];
        let client = request[5];
        let (transaction, message) = decode_header(request);
        let payload = match (service, message) {
            (0x00, 0x0027) => success_result_tlv(),
            (0x00, 0x0022) => allocation_payload(ServiceId::UIM.as_u8(), self.uim_client),
            (0x0b, 0x0042) => {
                let mut payload = success_result_tlv();
                payload.extend_from_slice(&[0x10, 0x01, 0x00, 0x01]);
                payload
            }
            (0x0b, 0x003b) => apdu_payload(request),
            (0x0b, 0x003f) => success_result_tlv(),
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
fn parse_eid_accepts_tag_5a() {
    let mut data = vec![0x5a, 0x10];
    data.extend_from_slice(&eid_bytes());
    let rapdu = ApduResponse {
        data,
        sw1: 0x90,
        sw2: 0x00,
    };
    assert_eq!(parse_eid(&rapdu).expect("eid"), expected_eid());
}

#[test]
fn session_opens_isd_r_and_reads_eid() {
    let mut client = QmiClient::new(FakeUim { uim_client: 0x08 });
    client.sync().expect("sync");
    let channel = client
        .open_logical_channel(1, ISD_R_AID)
        .expect("open ISD-R");
    assert_eq!(channel, 1);
    let eid = client.read_eid(1).expect("read EID");
    assert_eq!(eid, expected_eid());
    assert_eq!(eid.len(), 32);
}

fn apdu_payload(request: &[u8]) -> Vec<u8> {
    let rapdu = if request.windows(GET_EID_APDU.len()).any(|window| window == GET_EID_APDU)
    {
        let mut rapdu = vec![0x5a, 0x10];
        rapdu.extend_from_slice(&eid_bytes());
        rapdu.extend_from_slice(&[0x90, 0x00]);
        rapdu
    } else {
        vec![0x90, 0x00]
    };
    wrap_apdu(&rapdu)
}

fn wrap_apdu(rapdu: &[u8]) -> Vec<u8> {
    let mut payload = success_result_tlv();
    let mut value = (rapdu.len() as u16).to_le_bytes().to_vec();
    value.extend_from_slice(rapdu);
    payload.push(0x10);
    payload.extend_from_slice(&(value.len() as u16).to_le_bytes());
    payload.extend_from_slice(&value);
    payload
}

fn eid_bytes() -> [u8; 16] {
    [
        0x89, 0x04, 0x90, 0x32, 0x00, 0x40, 0x08, 0x88, 0x26, 0x00, 0x04, 0x61, 0x58, 0x12, 0x34,
        0x56,
    ]
}

fn expected_eid() -> &'static str {
    "89049032004008882600046158123456"
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
