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

use std::{cell::RefCell, rc::Rc};

/// What a fake eUICC was asked to do.
///
/// Shared with the test rather than reached through the client, so the same
/// assertions can be pointed at an unmodified copy of the old implementation.
#[derive(Default)]
struct EuiccLog {
    opens: usize,
    closes: usize,
    get_responses: usize,
    /// Every command APDU, in order. `GET RESPONSE` is not one.
    commands: Vec<Vec<u8>>,
}

/// An eUICC that answers ES10 commands the way the ones on the bench do.
///
/// It hands data over in `61xx` rounds of at most 256 bytes and counts the
/// logical channels it was asked to open, which are the two things the
/// transport used to get wrong.
struct FakeEuicc {
    uim_client: u8,
    log: Rc<RefCell<EuiccLog>>,
    /// What is left of the current answer.
    outstanding: Vec<u8>,
    /// Commands to refuse, by their ES10 tag.
    refuse: Vec<[u8; 2]>,
    /// How many challenges have been handed out.
    ///
    /// A real chip generates a fresh random per call. A fake that returned a
    /// constant would let a cached implementation pass, so this one changes
    /// its answer every time and the test asserts on the difference.
    challenges: u8,
}

impl FakeEuicc {
    fn new() -> (Self, Rc<RefCell<EuiccLog>>) {
        Self::refusing(Vec::new())
    }

    fn refusing(refuse: Vec<[u8; 2]>) -> (Self, Rc<RefCell<EuiccLog>>) {
        let log = Rc::new(RefCell::new(EuiccLog::default()));
        (
            Self {
                uim_client: 0x08,
                log: Rc::clone(&log),
                outstanding: Vec::new(),
                refuse,
                challenges: 0,
            },
            log,
        )
    }

    fn answer_for(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        let tag = [*payload.first()?, *payload.get(1)?];
        if self.refuse.contains(&tag) {
            return None;
        }
        if tag == [0xbf, 0x2e] {
            self.challenges = self.challenges.wrapping_add(1);
            let mut answer = from_hex(CHALLENGE_RESPONSE);
            *answer.last_mut()? = self.challenges;
            return Some(answer);
        }
        let hex = match tag {
            [0xbf, 0x3e] => EID_RESPONSE,
            [0xbf, 0x22] => INFO2_RESPONSE,
            [0xbf, 0x20] => INFO1_RESPONSE,
            [0xbf, 0x3c] => CONFIGURED_ADDRESSES_RESPONSE,
            [0xbf, 0x28] => LIST_NOTIFICATION_RESPONSE,
            [0xbf, 0x2d] => PROFILES_RESPONSE,
            [0xbf, 0x2b] => PENDING_RESPONSE,
            _ => return None,
        };
        Some(from_hex(hex))
    }
}

impl QmiTransport for FakeEuicc {
    fn transact(&mut self, request: &[u8]) -> Result<Vec<u8>, SessionError> {
        let service = request[4];
        let client = request[5];
        let (transaction, message) = decode_header(request);
        let payload = match (service, message) {
            (0x00, 0x0027) => success_result_tlv(),
            (0x00, 0x0022) => allocation_payload(ServiceId::UIM.as_u8(), self.uim_client),
            (0x0b, 0x0042) => {
                self.log.borrow_mut().opens += 1;
                let mut payload = success_result_tlv();
                payload.extend_from_slice(&[0x10, 0x01, 0x00, 0x01]);
                payload
            }
            (0x0b, 0x003f) => {
                self.log.borrow_mut().closes += 1;
                success_result_tlv()
            }
            (0x0b, 0x003b) => {
                let apdu = apdu_from(request);
                let rapdu = if apdu.len() >= 2 && apdu[1] == 0xc0 {
                    // GET RESPONSE. Le zero means 256, which is what the card
                    // on the bench asks for on every round but the last.
                    self.log.borrow_mut().get_responses += 1;
                    let wanted = match apdu.get(4).copied() {
                        Some(0) | None => 256,
                        Some(le) => usize::from(le),
                    };
                    let take = wanted.min(self.outstanding.len());
                    let mut chunk: Vec<u8> = self.outstanding.drain(..take).collect();
                    chunk.extend_from_slice(&remaining_status(self.outstanding.len()));
                    chunk
                } else {
                    self.log.borrow_mut().commands.push(apdu.clone());
                    match self.answer_for(apdu.get(5..).unwrap_or_default()) {
                        Some(answer) => {
                            self.outstanding = answer;
                            remaining_status(self.outstanding.len()).to_vec()
                        }
                        // 6A88: referenced data not found, which is what a
                        // card answers to a command it does not implement.
                        None => vec![0x6a, 0x88],
                    }
                };
                wrap_apdu(&rapdu)
            }
            _ => {
                return Err(SessionError::transport(format!(
                    "unexpected service=0x{service:02x} message=0x{message:04x} client=0x{client:02x}"
                )))
            }
        };
        Ok(response_frame(service, client, transaction, message, &payload))
    }
}

/// `61 xx` while bytes remain, `90 00` once they do not. `61 00` means 256.
fn remaining_status(remaining: usize) -> [u8; 2] {
    if remaining == 0 {
        [0x90, 0x00]
    } else if remaining >= 256 {
        [0x61, 0x00]
    } else {
        [0x61, remaining as u8]
    }
}

/// Pull the command APDU out of a `UIM SEND APDU` request.
fn apdu_from(request: &[u8]) -> Vec<u8> {
    let mut cursor = 13;
    while cursor + 3 <= request.len() {
        let kind = request[cursor];
        let length = usize::from(u16::from_le_bytes([request[cursor + 1], request[cursor + 2]]));
        let value = &request[cursor + 3..cursor + 3 + length];
        if kind == 0x02 {
            let declared = usize::from(u16::from_le_bytes([value[0], value[1]]));
            return value[2..2 + declared].to_vec();
        }
        cursor += 3 + length;
    }
    Vec::new()
}

fn from_hex(hex: &str) -> Vec<u8> {
    let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex"))
        .collect()
}

/// Captured from 867018069514820 with AT+CGLA on its ISD-R channel.
const EID_RESPONSE: &str = "BF3E125A1089086030202200000026000178339240";
/// `GetEUICCChallenge` from the same chip. The last byte is overwritten per
/// call so a cached answer cannot pass for a fresh one.
const CHALLENGE_RESPONSE: &str = "BF2E1280108BCF1BE4ADA9C98AF062987330056103";
/// `GetEUICCInfo1`: three fields, and the CI keys the chip verifies with.
const INFO1_RESPONSE: &str = "BF20358203020202A916041481370F5125D0B1D408D4C3B232E6D25E795BEBFB\
                              AA16041481370F5125D0B1D408D4C3B232E6D25E795BEBFB";
/// `GetEuiccConfiguredAddresses`: no default SM-DP+, only GSMA's *test* root
/// discovery server. Both bench chips answer exactly this, which is why an
/// address has to come from somewhere else before ES9+ can start.
const CONFIGURED_ADDRESSES_RESPONSE: &str =
    "BF3C17811574657374726F6F74736D64732E67736D612E636F6D";
const INFO2_RESPONSE: &str = "BF227E8103020301820302020283030402008 40D8101008204000279D083020B\
                              898505077F3E1F808603090200870302030088020490A916041481370F5125D0B1\
                              D408D4C3B232E6D25E795BEBFBAA16041481370F5125D0B1D408D4C3B232E6D25E7\
                              95BEBFB8B01009902064004030100000C0D45442D5A492D55502D30383236";
const LIST_NOTIFICATION_RESPONSE: &str = "BF2881E7A081E4\
    BF2F36800100810207800C217762672E70726F642E6F6E64656D616E64636F6E6E65637469766974792E636F6D\
    5A0A98583215220524122410\
    BF2F36800101810204100C217762672E70726F642E6F6E64656D616E64636F6E6E65637469766974792E636F6D\
    5A0A98583215220524122410\
    BF2F36800102810207800C217762672E70726F642E6F6E64656D616E64636F6E6E65637469766974792E636F6D\
    5A0A98583215220524122410\
    BF2F36800103810206400C217762672E70726F642E6F6E64656D616E64636F6E6E65637469766974792E636F6D\
    5A0A98583215220524122410";

/// The profile list off the same chip, long-form lengths and policy rules.
const PROFILES_RESPONSE: &str = "BF2D81B0A081ADE381AA5A0A98583215220524122410\
    4F10A0000005591010FFFFFFFF89000012009F70010191055361696C79920757454242494E47950102\
    BF7672E224E116C1149880246500BFD50F1415AF56C705A94E2BB2015AE30ADB080000000000000001\
    E224E116C114A8F000988F2C44FA897427E1A740FDE2FF545C19E30ADB080000000000000001\
    E224E116C1148204F3D96D0061D88FBD97FC8CE041E9494D6B9BE30ADB080000000000000001";

/// The pending notification list off the same chip: 3333 bytes, which the card
/// only hands over in fourteen `GET RESPONSE` rounds. Duplicated from the
/// decoder's own tests on purpose: this file exercises the transport that
/// fetches it, and a shortened copy would stop testing the rounds.
const PENDING_RESPONSE: &str = "BF2B820D00A0820CFCBF3781C2BF277C8010F2E53202F2314318B9D0EBD1D11EF87EBF2F36800100810207800C217762\
        672E70726F642E6F6E64656D616E64636F6E6E65637469766974792E636F6D5A0A98583215220524122410060E2B0601\
        040181F80201815C646502A21FA01D4F10A0000005591010FFFFFFFF890000120004093007A00530038001005F37402F\
        1D7FC2943917ECBD4C49E10161AB3E9490E53A6D247231BE974AF2E12068F25A9EDDEE897A744635BD27D1E195932C92\
        10669BB4E179706A0E3F0B4636DA94308205B4BF2F36800101810204100C217762672E70726F642E6F6E64656D616E64\
        636F6E6E65637469766974792E636F6D5A0A985832152205241224105F3740A0622EE3E090975C91D0B3A5F2605350B2\
        448B375A5B0F4D3476689C28F6D38D065B1113FC6759C4A9DC8CBC22F357496BF2C89BB7FEC6208BF2BF2C13C1E4FF30\
        820239308201E0A00302010202110089086030202200000026000178339201300A06082A8648CE3D0403023079310B30\
        0906035504061302434E31283026060355040A131F45617374636F6D706561636520546563686E6F6C6F677920436F2E\
        2C4C746431153013060355040B130C45617374636F6D7065616365312930270603550403132045617374636F6D706561\
        63652E45554D2E436F6E73756D65722E5A68756861693020170D3236303631333032353835305A180F39393939313233\
        313233353935395A305531283026060355040A131F45617374636F6D706561636520546563686E6F6C6F677920436F2E\
        2C4C74643129302706035504051320383930383630333032303232303030303030323630303031373833333932343030\
        59301306072A8648CE3D020106082A8648CE3D030107034200049D9BFE5A4A1E21F2EFE6525C7B36217C81F38216AD51\
        8B96584FFCB6940E0E461B15668B04363C8C4ECBD470D7FA283BC3A22EE1715969F9348D029946DA2958A36B3069301F\
        0603551D230418301680143A6B2CA4585D9C95C5947ABDD3BB1B0169ACEF72301D0603551D0E0416041499B0EB0F926C\
        0835A94EA4F7987D989DD3611617300E0603551D0F0101FF04040302078030170603551D200101FF040D300B30090607\
        67811201020101300A06082A8648CE3D04030203470030440220170673F6215275E7F1D2829B72567D3607D427B651BF\
        CE6D718F84D8725C247A02204A6DEA07F07F346D3972ADEB730268F2C01DBF2984BE8DAD1CC47682064C468C308202F7\
        3082029EA00302010202105986939CF376FDD1013E8F1529307748300A06082A8648CE3D040302304431183016060355\
        040A130F47534D204173736F63696174696F6E312830260603550403131F47534D204173736F63696174696F6E202D20\
        5253503220526F6F7420434931301E170D3139313132313030303030305A170D3439313132303233353935395A307931\
        0B300906035504061302434E31283026060355040A131F45617374636F6D706561636520546563686E6F6C6F67792043\
        6F2E2C4C746431153013060355040B130C45617374636F6D7065616365312930270603550403132045617374636F6D70\
        656163652E45554D2E436F6E73756D65722E5A68756861693059301306072A8648CE3D020106082A8648CE3D03010703\
        4200042FB0E6C5292E90321B0F1C69E88D5C3CF8C0E5F79E5C6F2C588552A74AB894AA0B4414B349F4616CDDE9629DCA\
        F955B7C39712EEAF46101AF686D44F8B2DFC07A382013B30820137301D0603551D0E041604143A6B2CA4585D9C95C594\
        7ABDD3BB1B0169ACEF7230120603551D130101FF040830060101FF02010030170603551D200101FF040D300B30090607\
        67811201020102304D0603551D1F044630443042A040A03E863C687474703A2F2F67736D612D63726C2E73796D617574\
        682E636F6D2F6F66666C696E6563612F67736D612D727370322D726F6F742D6369312E63726C300E0603551D0F0101FF\
        04040302010630510603551D1E0101FF04473045A0433041A43F303D31283026060355040A131F45617374636F6D7065\
        61636520546563686E6F6C6F677920436F2E2C4C74643111300F06035504051308383930383630333030160603551D11\
        040F300D880B2B06010401838A1D010202301F0603551D2304183016801481370F5125D0B1D408D4C3B232E6D25E795B\
        EBFB300A06082A8648CE3D040302034700304402203C5FD987D7CABB5172489647A8563016BE05DE44B06CE285A2D679\
        0BCDF408CA02202272886D929FC9434153068C8BE3521BC371E9101A18A56E9BAA7DD936592A1EBF3781C2BF277C8010\
        7F8AEDA1660948A98CCD5E819455C192BF2F36800102810207800C217762672E70726F642E6F6E64656D616E64636F6E\
        6E65637469766974792E636F6D5A0A98583215220524122410060E2B0601040181F80201815C646502A21FA01D4F10A0\
        000005591010FFFFFFFF890000120004093007A00530038001005F37408FF2164785CEB8FE92AAAB080FECE43ECA9A21\
        2C862CD6F943527CDBB7322BC6C04107FB78E21B7823D6DFD94CFAC61865899E169CCBAFD8D49D237C13CA266D308205\
        B4BF2F36800103810206400C217762672E70726F642E6F6E64656D616E64636F6E6E65637469766974792E636F6D5A0A\
        985832152205241224105F3740DD508DB2942F3340ED121BD3B3AF4FE28303A56CBE40B19D8BB5453E9991CB56E7A12C\
        D6BC48677BF25C05B9051010E70F19D8B2B0E3077B1B55D47A749B8D0830820239308201E0A003020102021100890860\
        30202200000026000178339201300A06082A8648CE3D0403023079310B300906035504061302434E3128302606035504\
        0A131F45617374636F6D706561636520546563686E6F6C6F677920436F2E2C4C746431153013060355040B130C456173\
        74636F6D7065616365312930270603550403132045617374636F6D70656163652E45554D2E436F6E73756D65722E5A68\
        756861693020170D3236303631333032353835305A180F39393939313233313233353935395A30553128302606035504\
        0A131F45617374636F6D706561636520546563686E6F6C6F677920436F2E2C4C74643129302706035504051320383930\
        38363033303230323230303030303032363030303137383333393234303059301306072A8648CE3D020106082A8648CE\
        3D030107034200049D9BFE5A4A1E21F2EFE6525C7B36217C81F38216AD518B96584FFCB6940E0E461B15668B04363C8C\
        4ECBD470D7FA283BC3A22EE1715969F9348D029946DA2958A36B3069301F0603551D230418301680143A6B2CA4585D9C\
        95C5947ABDD3BB1B0169ACEF72301D0603551D0E0416041499B0EB0F926C0835A94EA4F7987D989DD3611617300E0603\
        551D0F0101FF04040302078030170603551D200101FF040D300B3009060767811201020101300A06082A8648CE3D0403\
        0203470030440220170673F6215275E7F1D2829B72567D3607D427B651BFCE6D718F84D8725C247A02204A6DEA07F07F\
        346D3972ADEB730268F2C01DBF2984BE8DAD1CC47682064C468C308202F73082029EA00302010202105986939CF376FD\
        D1013E8F1529307748300A06082A8648CE3D040302304431183016060355040A130F47534D204173736F63696174696F\
        6E312830260603550403131F47534D204173736F63696174696F6E202D205253503220526F6F7420434931301E170D31\
        39313132313030303030305A170D3439313132303233353935395A3079310B300906035504061302434E312830260603\
        55040A131F45617374636F6D706561636520546563686E6F6C6F677920436F2E2C4C746431153013060355040B130C45\
        617374636F6D7065616365312930270603550403132045617374636F6D70656163652E45554D2E436F6E73756D65722E\
        5A68756861693059301306072A8648CE3D020106082A8648CE3D030107034200042FB0E6C5292E90321B0F1C69E88D5C\
        3CF8C0E5F79E5C6F2C588552A74AB894AA0B4414B349F4616CDDE9629DCAF955B7C39712EEAF46101AF686D44F8B2DFC\
        07A382013B30820137301D0603551D0E041604143A6B2CA4585D9C95C5947ABDD3BB1B0169ACEF7230120603551D1301\
        01FF040830060101FF02010030170603551D200101FF040D300B3009060767811201020102304D0603551D1F04463044\
        3042A040A03E863C687474703A2F2F67736D612D63726C2E73796D617574682E636F6D2F6F66666C696E6563612F6773\
        6D612D727370322D726F6F742D6369312E63726C300E0603551D0F0101FF04040302010630510603551D1E0101FF0447\
        3045A0433041A43F303D31283026060355040A131F45617374636F6D706561636520546563686E6F6C6F677920436F2E\
        2C4C74643111300F06035504051308383930383630333030160603551D11040F300D880B2B06010401838A1D01020230\
        1F0603551D2304183016801481370F5125D0B1D408D4C3B232E6D25E795BEBFB300A06082A8648CE3D04030203470030\
        4402203C5FD987D7CABB5172489647A8563016BE05DE44B06CE285A2D6790BCDF408CA02202272886D929FC943415306\
        8C8BE3521BC371E9101A18A56E9BAA7DD936592A1E";

/// One channel for the whole read.
///
/// The implementation this replaced opened and closed the ISD-R around every
/// single APDU, so the same four commands cost four channels. That is not only
/// wasteful: a stateful sequence cannot survive it at all, and every open is
/// another chance to leak one.
#[test]
fn reading_a_chip_opens_one_logical_channel() {
    let (transport, log) = FakeEuicc::new();
    let mut client = QmiClient::new(transport);
    client.sync().expect("sync");
    let info = client.read_esim_local_info(1).expect("local info");

    assert_eq!(info.eid, "89086030202200000026000178339240");
    assert_eq!(info.info.populated_fields(), 16);
    assert_eq!(info.notifications.len(), 4);
    assert_eq!(info.profiles.len(), 1);
    assert_eq!(info.notifications_error, None);
    assert_eq!(info.profiles_error, None);

    let log = log.borrow();
    assert_eq!(log.opens, 1, "one ISD-R channel for the whole read");
    assert_eq!(log.closes, 1, "and it is closed again");
    // GetEUICCData, GetEUICCInfo2, ListNotification, GetProfilesInfo.
    assert_eq!(log.commands.len(), 4);
    assert!(log.commands.iter().all(|apdu| apdu[1] == 0xe2));
}

/// The answer the single-round implementation truncated.
///
/// `RetrieveNotificationsList` on the bench chip is 3333 bytes and arrives in
/// fourteen `GET RESPONSE` rounds. Asking once yields 256 bytes: a prefix that
/// still looks like BER-TLV, so the failure showed up as a parse error rather
/// than as a short read.
#[test]
fn an_answer_that_needs_many_get_responses_arrives_whole() {
    let (transport, log) = FakeEuicc::new();
    let mut client = QmiClient::new(transport);
    client.sync().expect("sync");
    let notification = client
        .retrieve_esim_notification(1, 3)
        .expect("notification 3");

    assert_eq!(notification.metadata.sequence_number, 3);
    assert_eq!(notification.metadata.operations, vec!["enable"]);
    assert_eq!(
        notification.metadata.address,
        "wbg.prod.ondemandconnectivity.com"
    );
    assert!(!notification.installation_result);
    assert!(notification.payload.len() > 1000);

    let log = log.borrow();
    assert_eq!(log.get_responses, 14, "fourteen continuations");
    assert_eq!(log.opens, 1);
    assert_eq!(log.closes, 1);
}

/// Two commands on one channel, the second of which the card answers in more
/// than one round.
#[test]
fn a_sequence_on_one_channel_collects_every_round() {
    let (transport, log) = FakeEuicc::new();
    let mut client = QmiClient::new(transport);
    client.sync().expect("sync");
    {
        let mut session = client.isdr_session(1).expect("session");
        let answer = session
            .execute(&edge_modem::list_notification_payload())
            .expect("list");
        assert_eq!(answer.len(), 235, "one round is enough for this one");
        let pending = session.retrieve_notifications().expect("pending");
        assert_eq!(pending.len(), 4, "and fourteen are needed for this one");
    }
    let log = log.borrow();
    assert!(
        log.get_responses >= 2,
        "the card asked to be read again, got {} rounds",
        log.get_responses
    );
    assert_eq!(log.opens, 1);
    assert_eq!(log.closes, 1, "dropping the session closes the channel");
}

/// A command that fails mid-sequence must not leave the channel open.
///
/// This is the case a caller cannot be trusted with: the `?` returns and the
/// close never runs. An eUICC has only a few channels, and after enough of
/// these every profile operation fails to open one.
#[test]
fn a_failed_command_still_closes_the_channel() {
    let (transport, log) = FakeEuicc::refusing(vec![[0xbf, 0x22]]);
    let mut client = QmiClient::new(transport);
    client.sync().expect("sync");

    let error = client.read_esim_local_info(1).expect_err("info2 refused");
    assert!(
        error.to_string().contains("6a88"),
        "the card's own status word survives: {error}"
    );

    let log = log.borrow();
    assert_eq!(log.opens, 1);
    assert_eq!(log.closes, 1, "closed on the error path too");
}

/// Everything an ES9+ session needs, gathered on one channel.
///
/// The challenge and the CI key list have to come from the same card, so they
/// are read inside one ISD-R session rather than through separate calls that
/// could each land on a different chip.
#[test]
fn reading_the_authentication_inputs_opens_one_logical_channel() {
    let (transport, log) = FakeEuicc::new();
    let mut client = QmiClient::new(transport);
    client.sync().expect("sync");
    let inputs = client
        .read_esim_authentication_inputs(1)
        .expect("authentication inputs");

    assert_eq!(inputs.eid, "89086030202200000026000178339240");
    assert_eq!(inputs.challenge.len(), 16);
    assert_eq!(inputs.info1.svn.as_deref(), Some("2.2.2"));
    assert_eq!(
        inputs.info1.ci_key_ids_for_verification,
        vec!["81370F5125D0B1D408D4C3B232E6D25E795BEBFB"]
    );
    // The whole BF20 TLV, which is what ES9+ carries base64 encoded. Fifty-six
    // bytes: three of header and the fifty-three the card declared.
    assert_eq!(inputs.info1.raw.len(), 56);
    assert_eq!(&inputs.info1.raw[..2], &[0xbf, 0x20]);

    // No default SM-DP+ on this chip, so the address has to come from the
    // pending notifications instead.
    assert_eq!(inputs.addresses.default_dp_address, None);
    assert_eq!(
        inputs.addresses.root_ds_address.as_deref(),
        Some("testrootsmds.gsma.com")
    );
    assert_eq!(
        inputs.notification_addresses,
        vec!["wbg.prod.ondemandconnectivity.com"],
        "four notifications, one distinct address"
    );

    let log = log.borrow();
    assert_eq!(log.opens, 1, "one ISD-R channel for the whole read");
    assert_eq!(log.closes, 1);
    // GetEUICCData, GetEUICCChallenge, GetEUICCInfo1,
    // GetEuiccConfiguredAddresses, ListNotification.
    assert_eq!(log.commands.len(), 5);
}

/// Two reads, two different challenges.
///
/// The whole evidential value of an ES9+ round trip rests on the challenge
/// being generated by the card at the moment of asking. A cached one would
/// make a replayed server answer verify perfectly.
#[test]
fn every_challenge_is_a_new_one() {
    let (transport, _log) = FakeEuicc::new();
    let mut client = QmiClient::new(transport);
    client.sync().expect("sync");
    let first = client
        .read_esim_authentication_inputs(1)
        .expect("first")
        .challenge;
    let second = client
        .read_esim_authentication_inputs(1)
        .expect("second")
        .challenge;
    assert_ne!(first, second, "the chip was asked twice, not cached once");
}

/// A chip that refuses `GetEuiccConfiguredAddresses` is still usable.
///
/// The addresses are one of two ways to learn where to go, and neither is
/// mandatory, so a refusal is recorded next to the read rather than failing
/// it. The notification addresses still arrive.
#[test]
fn a_refused_address_query_does_not_fail_the_read() {
    let (transport, log) = FakeEuicc::refusing(vec![[0xbf, 0x3c]]);
    let mut client = QmiClient::new(transport);
    client.sync().expect("sync");
    let inputs = client
        .read_esim_authentication_inputs(1)
        .expect("authentication inputs");
    assert!(inputs.addresses_error.is_some(), "the refusal is reported");
    assert_eq!(inputs.addresses.default_dp_address, None);
    assert_eq!(
        inputs.notification_addresses,
        vec!["wbg.prod.ondemandconnectivity.com"]
    );
    assert_eq!(log.borrow().closes, 1);
}

/// A chip with no challenge has nothing to authenticate with.
#[test]
fn a_refused_challenge_fails_the_read_and_closes_the_channel() {
    let (transport, log) = FakeEuicc::refusing(vec![[0xbf, 0x2e]]);
    let mut client = QmiClient::new(transport);
    client.sync().expect("sync");
    assert!(client.read_esim_authentication_inputs(1).is_err());
    let log = log.borrow();
    assert_eq!(log.opens, 1);
    assert_eq!(log.closes, 1);
}

/// A card that is not an eUICC is a refusal, not a silent empty answer.
///
/// 867018069509705 on the bench is one: `AT+CCHO` on the ISD-R AID returns
/// ERROR because there is no ISD-R on that card at all.
#[test]
fn a_card_that_answers_nothing_is_reported_not_hidden() {
    let (transport, log) = FakeEuicc::refusing(vec![[0xbf, 0x3e]]);
    let mut client = QmiClient::new(transport);
    client.sync().expect("sync");
    assert!(client.read_esim_local_info(1).is_err());
    assert_eq!(log.borrow().closes, 1);
}
