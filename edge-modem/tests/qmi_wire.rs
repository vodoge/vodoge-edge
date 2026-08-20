use edge_modem::{
    AllocationError, ClientAllocationRequest, ClientAssignment, ClientId, ClientRegistry,
    CorrelationError,
    MessageId, PendingTransactions, QmiRequest, QmiResponse, ServiceId, Tlv, TransactionId,
    WireError,
};

#[test]
fn service_request_encodes_qmux_and_two_byte_transaction() {
    let request = QmiRequest::from_tlvs(
        ServiceId::UIM,
        ClientId::allocated(0x07).expect("nonzero client ID"),
        TransactionId::new(0x1234),
        MessageId::new(0x002f),
        &[Tlv::new(0x10, vec![0xaa]).expect("short TLV")],
    )
    .expect("valid service request");

    assert_eq!(
        request.encode(),
        vec![
            0x01, 0x10, 0x00, 0x00, 0x0b, 0x07, 0x00, 0x34, 0x12, 0x2f, 0x00, 0x04,
            0x00, 0x10, 0x01, 0x00, 0xaa,
        ]
    );
}

#[test]
fn control_client_allocation_uses_the_one_byte_transaction_header() {
    let allocation = ClientAllocationRequest::new(ServiceId::UIM, TransactionId::new(0x7f))
        .expect("control transaction fits in one byte");
    let request = allocation
        .to_qmi_request()
        .expect("allocation request encodes");

    assert_eq!(
        request.encode(),
        vec![
            0x01, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x22, 0x00, 0x04, 0x00,
            0x01, 0x01, 0x00, 0x0b,
        ]
    );
    assert!(matches!(
        ClientAllocationRequest::new(ServiceId::UIM, TransactionId::new(0x0100)),
        Err(AllocationError::Wire(WireError::ControlTransactionOutOfRange { .. }))
    ));
}

#[test]
fn response_decode_preserves_qmi_metadata_and_tlvs() {
    let frame = response_frame(
        ServiceId::UIM.as_u8(),
        0x07,
        0x1234,
        0x002f,
        &success_result_tlv(),
    );

    let response = QmiResponse::decode(&frame).expect("valid service response");
    assert_eq!(response.service(), ServiceId::UIM);
    assert_eq!(response.client_id().as_u8(), 0x07);
    assert_eq!(response.transaction(), TransactionId::new(0x1234));
    assert_eq!(response.message_id(), MessageId::new(0x002f));
    assert_eq!(response.tlvs().expect("validated on decode")[0].kind, 0x02);
}

#[test]
fn decoder_rejects_malformed_frames_before_correlation() {
    assert!(matches!(
        QmiResponse::decode(&[0x01, 0x00]),
        Err(WireError::FrameTooShort { .. })
    ));

    let valid = response_frame(
        ServiceId::UIM.as_u8(),
        0x07,
        0x1234,
        0x002f,
        &success_result_tlv(),
    );

    let mut wrong_marker = valid.clone();
    wrong_marker[0] = 0x02;
    assert!(matches!(
        QmiResponse::decode(&wrong_marker),
        Err(WireError::InvalidInterfaceType { actual: 0x02 })
    ));

    let mut wrong_qmux_length = valid.clone();
    wrong_qmux_length[1] = wrong_qmux_length[1].saturating_sub(1);
    assert!(matches!(
        QmiResponse::decode(&wrong_qmux_length),
        Err(WireError::QmuxLengthMismatch { .. })
    ));

    let mut wrong_direction = valid.clone();
    wrong_direction[3] = 0x00;
    assert!(matches!(
        QmiResponse::decode(&wrong_direction),
        Err(WireError::UnexpectedQmuxControlFlag { .. })
    ));

    let mut zero_service_client = valid.clone();
    zero_service_client[5] = 0x00;
    assert!(matches!(
        QmiResponse::decode(&zero_service_client),
        Err(WireError::ServiceRequiresAllocatedClient { .. })
    ));

    let mut request_kind = valid.clone();
    request_kind[6] = 0x00;
    assert!(matches!(
        QmiResponse::decode(&request_kind),
        Err(WireError::UnexpectedMessageKind { .. })
    ));

    let mut wrong_payload_length = valid.clone();
    wrong_payload_length[11] = wrong_payload_length[11].saturating_add(1);
    assert!(matches!(
        QmiResponse::decode(&wrong_payload_length),
        Err(WireError::PayloadLengthMismatch { .. })
    ));

    let truncated_tlv = response_frame(
        ServiceId::UIM.as_u8(),
        0x07,
        1,
        0x002f,
        &[0x02, 0x04, 0x00, 0x00],
    );
    assert!(matches!(
        QmiResponse::decode(&truncated_tlv),
        Err(WireError::TruncatedTlvValue { .. })
    ));
}

#[test]
fn request_builder_rejects_invalid_service_client_pairs_and_raw_tlv_data() {
    assert!(matches!(
        ClientAssignment::new(ServiceId::CONTROL, ClientId::CONTROL),
        Err(WireError::ControlServiceCannotHaveAssignment)
    ));
    assert!(matches!(
        QmiRequest::new(
            ServiceId::UIM,
            ClientId::CONTROL,
            TransactionId::new(1),
            MessageId::new(1),
            Vec::new(),
        ),
        Err(WireError::ServiceRequiresAllocatedClient { .. })
    ));
    assert!(matches!(
        QmiRequest::new(
            ServiceId::CONTROL,
            ClientId::allocated(1).expect("nonzero client"),
            TransactionId::new(1),
            MessageId::new(1),
            Vec::new(),
        ),
        Err(WireError::ControlServiceRequiresControlClient { .. })
    ));
    assert!(matches!(
        QmiRequest::new(
            ServiceId::CONTROL,
            ClientId::CONTROL,
            TransactionId::new(0x0100),
            MessageId::new(1),
            Vec::new(),
        ),
        Err(WireError::ControlTransactionOutOfRange { .. })
    ));
    assert!(matches!(
        QmiRequest::new(
            ServiceId::UIM,
            ClientId::allocated(1).expect("nonzero client"),
            TransactionId::new(1),
            MessageId::new(1),
            vec![0x01, 0x02],
        ),
        Err(WireError::TruncatedTlvHeader { .. })
    ));
}

#[test]
fn client_allocation_response_installs_a_service_client_and_builds_release() {
    let allocation = ClientAllocationRequest::new(ServiceId::UIM, TransactionId::new(0x33))
        .expect("valid allocation request");
    let request = allocation
        .to_qmi_request()
        .expect("allocation request encodes");
    let response = QmiResponse::decode(&response_frame(
        ServiceId::CONTROL.as_u8(),
        0x00,
        0x33,
        ClientAllocationRequest::MESSAGE_ID.as_u16(),
        &[
            0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
            ServiceId::UIM.as_u8(), 0x09,
        ],
    ))
    .expect("well-formed allocation response");

    let mut pending = PendingTransactions::default();
    pending.register(&request).expect("register allocation request");
    pending.resolve(&response).expect("correlate allocation response");

    let assignment = allocation.accept(&response).expect("allocation succeeds");
    assert_eq!(assignment.service(), ServiceId::UIM);
    assert_eq!(assignment.client_id().as_u8(), 0x09);

    let mut registry = ClientRegistry::default();
    registry.install(assignment).expect("install once");
    assert_eq!(registry.client_for(ServiceId::UIM), Some(assignment.client_id()));
    assert!(registry.install(assignment).is_err());
    assert_eq!(
        registry
            .release(ServiceId::UIM)
            .expect("remove installed assignment"),
        assignment
    );

    let release = assignment
        .release_request(TransactionId::new(0x34))
        .expect("release request encodes");
    assert_eq!(release.message_id(), MessageId::new(0x0023));
    assert_eq!(release.tlvs().expect("release TLV")[0].value, vec![0x0b, 0x09]);
}

#[test]
fn client_allocation_rejects_a_mismatched_or_zero_client_response() {
    let allocation = ClientAllocationRequest::new(ServiceId::UIM, TransactionId::new(0x33))
        .expect("valid allocation request");

    let wrong_service = QmiResponse::decode(&response_frame(
        ServiceId::CONTROL.as_u8(),
        0x00,
        0x33,
        ClientAllocationRequest::MESSAGE_ID.as_u16(),
        &[
            0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
            ServiceId::DMS.as_u8(), 0x09,
        ],
    ))
    .expect("well-formed response with wrong allocated service");
    assert!(matches!(
        allocation.accept(&wrong_service),
        Err(AllocationError::ServiceMismatch { .. })
    ));

    let zero_client = QmiResponse::decode(&response_frame(
        ServiceId::CONTROL.as_u8(),
        0x00,
        0x33,
        ClientAllocationRequest::MESSAGE_ID.as_u16(),
        &[
            0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
            ServiceId::UIM.as_u8(), 0x00,
        ],
    ))
    .expect("well-formed response with invalid client ID");
    assert!(matches!(
        allocation.accept(&zero_client),
        Err(AllocationError::Wire(WireError::ZeroClientId))
    ));
}

#[test]
fn transaction_matching_is_client_scoped_and_does_not_drop_mismatches() {
    let first = request(ServiceId::UIM, 0x01, 0x0042, 0x002f);
    let second = request(ServiceId::UIM, 0x02, 0x0042, 0x002f);
    let duplicate_transaction = request(ServiceId::UIM, 0x01, 0x0042, 0x0030);
    let mut pending = PendingTransactions::default();

    pending.register(&first).expect("first transaction");
    pending.register(&second).expect("same ID is valid for another client");
    assert!(matches!(
        pending.register(&duplicate_transaction),
        Err(CorrelationError::DuplicateTransaction(_))
    ));

    let wrong_message = QmiResponse::decode(&response_frame(
        ServiceId::UIM.as_u8(),
        0x01,
        0x0042,
        0x0030,
        &success_result_tlv(),
    ))
    .expect("well-formed mismatched response");
    assert!(matches!(
        pending.resolve(&wrong_message),
        Err(CorrelationError::MessageMismatch { .. })
    ));
    assert_eq!(pending.len(), 2, "mismatched response must remain pending");

    let first_response = QmiResponse::decode(&response_frame(
        ServiceId::UIM.as_u8(),
        0x01,
        0x0042,
        0x002f,
        &success_result_tlv(),
    ))
    .expect("first response");
    let second_response = QmiResponse::decode(&response_frame(
        ServiceId::UIM.as_u8(),
        0x02,
        0x0042,
        0x002f,
        &success_result_tlv(),
    ))
    .expect("second response");

    assert_eq!(
        pending.resolve(&first_response).expect("first correlation").key,
        first.transaction_key()
    );
    assert_eq!(
        pending.resolve(&second_response).expect("second correlation").key,
        second.transaction_key()
    );
    assert!(pending.is_empty());
}

fn request(service: ServiceId, client: u8, transaction: u16, message: u16) -> QmiRequest {
    QmiRequest::new(
        service,
        ClientId::allocated(client).expect("nonzero client"),
        TransactionId::new(transaction),
        MessageId::new(message),
        Vec::new(),
    )
    .expect("valid request")
}

fn success_result_tlv() -> Vec<u8> {
    vec![0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]
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
