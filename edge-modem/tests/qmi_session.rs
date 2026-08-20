use edge_modem::{
    ClientAllocationRequest, OperatingMode, QmiClient, QmiTransport, ServiceId, SessionError,
    CTL_SYNC, GET_DEVICE_REV_ID, GET_DEVICE_SERIAL_NUMBERS, GET_MANUFACTURER, GET_MODEL_ID,
    GET_OPERATING_MODE, SET_OPERATING_MODE,
};

struct FakeModem {
    dms_client: u8,
}

impl QmiTransport for FakeModem {
    fn transact(&mut self, request: &[u8]) -> Result<Vec<u8>, SessionError> {
        if request.len() < 10 || request[0] != 0x01 {
            return Err(SessionError::transport("truncated QMUX request"));
        }

        let service = request[4];
        let client = request[5];
        let (transaction, message) = if service == ServiceId::CONTROL.as_u8() {
            (
                request[7] as u16,
                u16::from_le_bytes([request[8], request[9]]),
            )
        } else {
            (
                u16::from_le_bytes([request[7], request[8]]),
                u16::from_le_bytes([request[9], request[10]]),
            )
        };

        let payload = match (service, message) {
            (0x00, 0x0027) => success_result_tlv(),
            (0x00, 0x0022) => allocation_payload(ServiceId::DMS.as_u8(), self.dms_client),
            (0x02, 0x0025) => serial_payload(),
            (0x02, 0x0023) => string_payload(0x01, b"EC20CEAR02A13M4G"),
            (0x02, 0x0022) => string_payload(0x01, b"EC20-CE"),
            (0x02, 0x0021) => string_payload(0x01, b"Quectel"),
            (0x02, 0x002d) => {
                let mut payload = success_result_tlv();
                payload.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]);
                payload
            }
            (0x02, 0x002e) => success_result_tlv(),
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
fn session_syncs_and_allocates_a_dms_client() {
    let mut client = QmiClient::new(FakeModem { dms_client: 0x04 });
    client.sync().expect("CTL sync succeeds");
    let assignment = client.allocate(ServiceId::DMS).expect("DMS client allocated");
    assert_eq!(assignment.service(), ServiceId::DMS);
    assert_eq!(assignment.client_id().as_u8(), 0x04);
    assert_eq!(client.client_for(ServiceId::DMS).unwrap().as_u8(), 0x04);
}

#[test]
fn session_reads_imei_revision_and_operating_mode() {
    let mut client = QmiClient::new(FakeModem { dms_client: 0x04 });
    client.sync().expect("CTL sync succeeds");

    let serials = client.get_serial_numbers().expect("serial numbers");
    assert_eq!(serials.imei.as_deref(), Some("860000000000001"));
    assert_eq!(client.get_revision().expect("revision").device_rev_id, "EC20CEAR02A13M4G");
    assert_eq!(client.get_model().expect("model"), "EC20-CE");
    assert_eq!(client.get_manufacturer().expect("manufacturer"), "Quectel");
    assert_eq!(
        client.get_operating_mode().expect("operating mode"),
        OperatingMode::Online
    );
    client
        .set_operating_mode(OperatingMode::LowPower)
        .expect("set operating mode");
}

#[test]
fn dms_message_ids_match_libqmi() {
    assert_eq!(CTL_SYNC.as_u16(), 0x0027);
    assert_eq!(ClientAllocationRequest::MESSAGE_ID.as_u16(), 0x0022);
    assert_eq!(GET_MANUFACTURER.as_u16(), 0x0021);
    assert_eq!(GET_MODEL_ID.as_u16(), 0x0022);
    assert_eq!(GET_DEVICE_REV_ID.as_u16(), 0x0023);
    assert_eq!(GET_DEVICE_SERIAL_NUMBERS.as_u16(), 0x0025);
    assert_eq!(GET_OPERATING_MODE.as_u16(), 0x002d);
    assert_eq!(SET_OPERATING_MODE.as_u16(), 0x002e);
}

fn success_result_tlv() -> Vec<u8> {
    vec![0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]
}

fn allocation_payload(service: u8, client: u8) -> Vec<u8> {
    let mut payload = success_result_tlv();
    payload.extend_from_slice(&[0x01, 0x02, 0x00, service, client]);
    payload
}

fn serial_payload() -> Vec<u8> {
    let mut payload = success_result_tlv();
    payload.extend_from_slice(&[0x11, 0x0f, 0x00]);
    payload.extend_from_slice(b"860000000000001");
    payload
}

fn string_payload(kind: u8, value: &[u8]) -> Vec<u8> {
    let mut payload = success_result_tlv();
    payload.push(kind);
    payload.extend_from_slice(&(value.len() as u16).to_le_bytes());
    payload.extend_from_slice(value);
    payload
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
