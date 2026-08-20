use edge_modem::{
    parse_cell_location, parse_serving_system, NasRegistrationState, QmiClient, QmiResponse,
    QmiTransport, ServiceId, SessionError, GET_CELL_LOCATION_INFO, GET_SERVING_SYSTEM,
};

struct FakeNas {
    nas_client: u8,
}

impl QmiTransport for FakeNas {
    fn transact(&mut self, request: &[u8]) -> Result<Vec<u8>, SessionError> {
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
            (0x00, 0x0022) => {
                let mut payload = success_result_tlv();
                payload.extend_from_slice(&[0x01, 0x02, 0x00, ServiceId::NAS.as_u8(), self.nas_client]);
                payload
            }
            (0x03, 0x0024) => serving_system_searching(),
            (0x03, 0x0043) => lte_cell_location(),
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
fn serving_system_searching_has_empty_plmn() {
    let frame = response_frame(
        ServiceId::NAS.as_u8(),
        0x05,
        1,
        GET_SERVING_SYSTEM.as_u16(),
        &serving_system_searching(),
    );
    let response = QmiResponse::decode(&frame).expect("serving system frame");
    let serving = parse_serving_system(&response).expect("parse serving system");
    assert_eq!(serving.registration_state, NasRegistrationState::Searching);
    assert!(!serving.ps_attached);
    assert_eq!(serving.mcc, None);
    assert_eq!(serving.mnc, None);
    assert_eq!(serving.radio_interface, None);
}

#[test]
fn lte_cell_location_has_plmn_tac_and_global_cell_id() {
    let frame = response_frame(
        ServiceId::NAS.as_u8(),
        0x05,
        1,
        GET_CELL_LOCATION_INFO.as_u16(),
        &lte_cell_location(),
    );
    let response = QmiResponse::decode(&frame).expect("cell location frame");
    let info = parse_cell_location(&response).expect("parse cell location");
    let lte = info.lte.expect("LTE TLV");
    assert_eq!(lte.mcc, "460");
    assert_eq!(lte.mnc, "11");
    assert_eq!(lte.tac, 6401);
    assert_eq!(lte.global_cell_id, 4_945_521);
    assert_eq!(lte.earfcn, 1506);
    assert!(lte.is_complete());
}

#[test]
fn session_reads_the_section_4_2_hardware_contradiction() {
    let mut client = QmiClient::new(FakeNas { nas_client: 0x05 });
    client.sync().expect("sync");
    let serving = client.get_serving_system().expect("serving system");
    let cell = client.get_cell_location().expect("cell location");

    assert_eq!(serving.registration_state, NasRegistrationState::Searching);
    assert_eq!(serving.mcc, None);
    let lte = cell.lte.expect("LTE");
    assert!(lte.is_complete());
}

fn success_result_tlv() -> Vec<u8> {
    vec![0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]
}

fn serving_system_searching() -> Vec<u8> {
    let mut payload = success_result_tlv();
    // TLV 0x01: registration=searching, CS unknown, PS detached, network unknown, 0 radios.
    payload.extend_from_slice(&[0x01, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]);
    payload
}

fn lte_cell_location() -> Vec<u8> {
    let mut payload = success_result_tlv();
    let mut value = vec![0x00]; // not idle
    value.extend_from_slice(&[0x64, 0xf0, 0x11]); // 460 / 11
    value.extend_from_slice(&6401u16.to_le_bytes());
    value.extend_from_slice(&4_945_521u32.to_le_bytes());
    value.extend_from_slice(&1506u16.to_le_bytes());
    value.extend_from_slice(&0u16.to_le_bytes()); // serving cell id
    value.extend_from_slice(&[0, 0, 0, 0]); // idle thresholds
    payload.push(0x13);
    payload.extend_from_slice(&(value.len() as u16).to_le_bytes());
    payload.extend_from_slice(&value);
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
