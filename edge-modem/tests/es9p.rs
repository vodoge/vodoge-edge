//! ES9+ against captures from a production SM-DP+.
//!
//! Every fixture here came off the wire on 2026-08-24 from
//! `wbg.prod.ondemandconnectivity.com`, the SM-DP+ named by the pending
//! notifications on the eUICC in module 867018069514820. Nothing in this file
//! was produced by the code it tests, which is the point: a signature these
//! tests can verify is a signature Thales produced with a key we do not have,
//! and a test that agreed with our own encoder would not be able to tell a
//! correct implementation from a consistently wrong one.

use std::path::PathBuf;

use edge_modem::{
    hash_confirmation_code, initiate_authentication_request, load_trust_anchors,
    parse_activation_code, parse_initiate_authentication, verify_server_credentials,
    AuthenticationStart, Es9pClient, Es9pError, HttpResponse, TrustAnchor,
};

/// GSM Association - RSP2 Root CI1.
///
/// Source: the certificate chain `wbg.prod.ondemandconnectivity.com:443`
/// presents, which is where an LPA would learn it from too. Serial
/// `6e68567a77a0ee7c85ee183963dfaa7a`, valid 2017-02-22 to 2052-02-21,
/// SHA-256 `5e3e91fd...80a56bb3`. Its subject key identifier is
/// `81370F51...795BEBFB`, the same value both bench eUICCs report in
/// `euiccCiPKIdListForVerification`.
const CI_ROOT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIICSTCCAe+gAwIBAgIQbmhWeneg7nyF7hg5Y9+qejAKBggqhkjOPQQDAjBEMRgw
FgYDVQQKEw9HU00gQXNzb2NpYXRpb24xKDAmBgNVBAMTH0dTTSBBc3NvY2lhdGlv
biAtIFJTUDIgUm9vdCBDSTEwIBcNMTcwMjIyMDAwMDAwWhgPMjA1MjAyMjEyMzU5
NTlaMEQxGDAWBgNVBAoTD0dTTSBBc3NvY2lhdGlvbjEoMCYGA1UEAxMfR1NNIEFz
c29jaWF0aW9uIC0gUlNQMiBSb290IENJMTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABJ1qutL0HCMX52GJ6/jeibsAqZfULWj/X10p/Min6seZN+hf5llovbCNuB2n
unLz+O8UD0SUCBUVo8e6n9X1TuajgcAwgb0wDgYDVR0PAQH/BAQDAgEGMA8GA1Ud
EwEB/wQFMAMBAf8wEwYDVR0RBAwwCogIKwYBBAGC6WAwFwYDVR0gAQH/BA0wCzAJ
BgdngRIBAgEAME0GA1UdHwRGMEQwQqBAoD6GPGh0dHA6Ly9nc21hLWNybC5zeW1h
dXRoLmNvbS9vZmZsaW5lY2EvZ3NtYS1yc3AyLXJvb3QtY2kxLmNybDAdBgNVHQ4E
FgQUgTcPUSXQsdQI1MOyMubSXnlb6/swCgYIKoZIzj0EAwIDSAAwRQIgIJdYsOMF
WziPK7l8nh5mu0qiRiVf25oa9ullG/OIASwCIQDqCmDrYf+GziHXBOiwJwnBaeBO
aFsiLzIEOaUuZwdNUw==
-----END CERTIFICATE-----
";

/// The TLS certificate the same host presents.
///
/// Here as a *wrong* anchor rather than as an unused one: it is a real
/// certificate from the real chain, issued by the same CI, and it still must
/// not satisfy a request whose signing certificate names the root. Anything
/// that accepts it is matching on "came from Thales" rather than on the key.
const TLS_LEAF_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDNjCCAtygAwIBAgIQTt4YDAV4XhZ+ELoObFfFjTAKBggqhkjOPQQDAjBEMRgw
FgYDVQQKEw9HU00gQXNzb2NpYXRpb24xKDAmBgNVBAMTH0dTTSBBc3NvY2lhdGlv
biAtIFJTUDIgUm9vdCBDSTEwHhcNMjUwOTI0MDAwMDAwWhcNMjYxMDIzMjM1OTU5
WjBtMQswCQYDVQQGEwJGUjESMBAGA1UEBwwJTGEgQ2lvdGF0MRIwEAYDVQQKDAlU
SEFMRVMgU0ExDDAKBgNVBAsMA0RJUzEoMCYGA1UEAwwfKi5wcm9kLm9uZGVtYW5k
Y29ubmVjdGl2aXR5LmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPaTGoS/
9obsppIhOKizb/yraqEVoYtl795mMtxLIQKhxu8zQw/VJZqLb1To/2PeDp+z8Ohw
K+uoy/ET3TfnKFqjggGFMIIBgTAUBgNVHSAEDTALMAkGB2eBEgECAQMwTgYDVR0f
BEcwRTBDoEGgP4Y9IGh0dHA6Ly9nc21hLWNybC5zeW1hdXRoLmNvbS9vZmZsaW5l
Y2EvZ3NtYS1yc3AyLXJvb3QtY2kxLmNybDAgBgNVHSUBAf8EFjAUBggrBgEFBQcD
AQYIKwYBBQUHAwIwDgYDVR0PAQH/BAQDAgeAMIGmBgNVHREEgZ4wgZuCHyoucHJv
ZC5vbmRlbWFuZGNvbm5lY3Rpdml0eS5jb22CIyouZ2NwLXByb2Qub25kZW1hbmRj
b25uZWN0aXZpdHkuY29tgicqLnByb2QuY2xhc3NpYy5vbmRlbWFuZGNvbm5lY3Rp
dml0eS5jb22CGioucHJvZC5pZHMtb2RjLmdlbWFsdG8uY29tiA4rBgEEAYH4AgGB
XGRlAjAdBgNVHQ4EFgQUghEvyy+Q2tXjX+vTyJGQ1FNNNKkwHwYDVR0jBBgwFoAU
gTcPUSXQsdQI1MOyMubSXnlb6/swCgYIKoZIzj0EAwIDSAAwRQIhAKpzl/NY//mc
leJjEItQs+leIN2L5+spEaOoDLTOsfHHAiAYk4UJx+QkAVOxWySuC2kgFL01AmL9
QJVworhOlUcpVw==
-----END CERTIFICATE-----
";

/// One `initiateAuthentication` answer, verbatim.
const REAL_ANSWER: &str = r#"{"header":{"functionExecutionStatus":{"status":"Executed-Success"}},"transactionId":"E4F6996D64A543FC8A7F6F8F97F9428D","serverSigned1":"MFmAEOT2mW1kpUP8in9vj5f5Qo2BEIvPG+StqcmK8GKYczAFYQODIXdiZy5wcm9kLm9uZGVtYW5kY29ubmVjdGl2aXR5LmNvbYQQCYL4eTemxWslVpxWjkxNaA==","serverSignature1":"XzdA8EmYdfIP++1JKTy42NednT5S1wB3nGZl3hK64fGTSRgaqLMJBhZG7G0FE8S5pVS+BSFa1Rpl/1ZJl64RmhF4HA==","euiccCiPKIdToBeUsed":"BBSBNw9RJdCx1AjUw7Iy5tJeeVvr+w==","serverCertificate":"MIICcjCCAhmgAwIBAgIQDQkGG+/yt1Jc3R89c4zfAjAKBggqhkjOPQQDAjBEMRgwFgYDVQQKEw9HU00gQXNzb2NpYXRpb24xKDAmBgNVBAMTH0dTTSBBc3NvY2lhdGlvbiAtIFJTUDIgUm9vdCBDSTEwHhcNMjQwOTI2MDAwMDAwWhcNMjcwOTI1MjM1OTU5WjBaMQswCQYDVQQGEwJGUjESMBAGA1UEBwwJTGEgQ2lvdGF0MRIwEAYDVQQKDAlUSEFMRVMgU0ExDDAKBgNVBAsMA0RJUzEVMBMGA1UEAwwMVEhBTEVTIFNNRFBQMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVXJO33aaLakOC6U1kuYIfnOMfgUZ9ONU2iwiHRvGXlRbv8QklQm/N2oWfBYfgOKmKJ+8zc126Bku5GXkiUzb7qOB1jCB0zAZBgNVHREEEjAQiA4rBgEEAYH4AgGBXGRlAjAXBgNVHSABAf8EDTALMAkGB2eBEgECAQQwTQYDVR0fBEYwRDBCoECgPoY8aHR0cDovL2dzbWEtY3JsLnN5bWF1dGguY29tL29mZmxpbmVjYS9nc21hLXJzcDItcm9vdC1jaTEuY3JsMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUJfcJs3NsC9oy1qlKMb3kfLEqJaowHwYDVR0jBBgwFoAUgTcPUSXQsdQI1MOyMubSXnlb6/swCgYIKoZIzj0EAwIDRwAwRAIgGW0my9crsVnzGmxCEEQtUqIFZubVgWGLzyxtu4lfe18CIAyWe1Es5pV85+TSauK+7rnSowkd6/NN4+OoclLbt15a"}"#;

/// The challenge `GetEUICCChallenge` produced for that exchange.
const SENT_CHALLENGE: &str = "8BCF1BE4ADA9C98AF062987330056103";
const SMDP_HOST: &str = "wbg.prod.ondemandconnectivity.com";
const CI_KEY_ID: &str = "81370F5125D0B1D408D4C3B232E6D25E795BEBFB";

#[test]
fn a_trust_directory_reports_what_it_holds() {
    let dir = temp_dir("anchors");
    write(&dir, "gsma-rsp2-root-ci1.pem", CI_ROOT_PEM);
    let anchors = load_trust_anchors(&dir).expect("load");
    assert_eq!(anchors.len(), 1);
    let anchor = &anchors[0];
    assert_eq!(anchor.label, "gsma-rsp2-root-ci1.pem");
    assert_eq!(anchor.key_id, CI_KEY_ID);
    assert_eq!(
        anchor.sha256,
        "5e3e91fd454327c3af5d32a7a73bbc59fe43aa7d85fd32d5db44423f80a56bb3"
    );
    // A CI root has an expiry, and it is the reason this is a file rather
    // than a constant. Rendering it is what makes the rotation visible.
    assert_eq!(anchor.not_after, "20520221235959Z");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_trust_directory_with_nothing_in_it_is_refused() {
    let dir = temp_dir("empty");
    match load_trust_anchors(&dir) {
        Err(Es9pError::NoTrustAnchors { .. }) => {}
        other => panic!("expected NoTrustAnchors, got {other:?}"),
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_client_refuses_to_exist_without_a_trust_anchor() {
    // There is no "skip verification" path, so an empty anchor set has to be
    // an error at construction rather than a client that trusts everything.
    match Es9pClient::new(Vec::new()) {
        Err(Es9pError::NoTrustAnchors { .. }) => {}
        other => panic!("expected NoTrustAnchors, got {:?}", other.err()),
    }
}

#[test]
fn a_production_answer_decodes_into_its_signed_fields() {
    let start = parse_initiate_authentication(REAL_ANSWER.as_bytes()).expect("parse");
    assert_eq!(start.transaction_id, "E4F6996D64A543FC8A7F6F8F97F9428D");
    // The echoed challenge comes out of the signed structure, not out of the
    // JSON, so this is also a check that ServerSigned1 was decoded.
    assert_eq!(start.echoed_euicc_challenge, SENT_CHALLENGE);
    assert_eq!(start.server_address, SMDP_HOST);
    assert_eq!(start.server_challenge, "0982F87937A6C56B25569C568E4C4D68");
    // Reported without its DER OCTET STRING wrapper so it can be compared
    // straight against what GetEUICCInfo1 lists.
    assert_eq!(start.euicc_ci_pkid_to_be_used, CI_KEY_ID);
    assert_eq!(start.server_signed1.len(), 91);
    assert_eq!(start.server_certificate.len(), 630);
}

#[test]
fn a_production_answer_verifies_against_the_gsma_ci_root() {
    let anchors = anchors_from(&[("gsma-rsp2-root-ci1.pem", CI_ROOT_PEM)]);
    let start = parse_initiate_authentication(REAL_ANSWER.as_bytes()).expect("parse");
    let verified = verify_server_credentials(&start, SMDP_HOST, &challenge(), &anchors)
        .expect("verify");
    assert!(verified.certificate_signed_by_ci);
    assert!(verified.server_signature_valid);
    assert!(verified.challenge_echoed);
    assert_eq!(verified.trust_anchor_label, "gsma-rsp2-root-ci1.pem");
    assert_eq!(verified.trust_anchor_key_id, CI_KEY_ID);
    assert_eq!(verified.certificate_authority_key_id, CI_KEY_ID);
    assert_eq!(
        verified.certificate_key_id,
        "25F709B3736C0BDA32D6A94A31BDE47CB12A25AA"
    );
    assert_eq!(
        verified.certificate_sha256,
        "7f93b55b56a9da4e29bc4d4118f698a3dd8d5354b28f936734e7fa0efd8ea9b5"
    );
    assert_eq!(verified.certificate_not_after, "270925235959Z");
}

#[test]
fn the_right_root_is_picked_out_of_several() {
    let anchors = anchors_from(&[
        ("aaa-tls-leaf.pem", TLS_LEAF_PEM),
        ("gsma-rsp2-root-ci1.pem", CI_ROOT_PEM),
    ]);
    let start = parse_initiate_authentication(REAL_ANSWER.as_bytes()).expect("parse");
    let verified =
        verify_server_credentials(&start, SMDP_HOST, &challenge(), &anchors).expect("verify");
    // Sorted first alphabetically, so a chain that matched on order rather
    // than on key identifier would have picked the wrong one.
    assert_eq!(verified.trust_anchor_label, "gsma-rsp2-root-ci1.pem");
}

#[test]
fn a_certificate_from_an_authority_we_do_not_hold_is_refused() {
    let anchors = anchors_from(&[("tls-leaf.pem", TLS_LEAF_PEM)]);
    let start = parse_initiate_authentication(REAL_ANSWER.as_bytes()).expect("parse");
    match verify_server_credentials(&start, SMDP_HOST, &challenge(), &anchors) {
        Err(Es9pError::UntrustedCertificateAuthority { authority_key_id }) => {
            assert_eq!(authority_key_id, CI_KEY_ID);
        }
        other => panic!("expected UntrustedCertificateAuthority, got {other:?}"),
    }
}

#[test]
fn a_changed_byte_in_the_signed_structure_fails_the_signature() {
    let anchors = anchors_from(&[("gsma-rsp2-root-ci1.pem", CI_ROOT_PEM)]);
    let mut start = parse_initiate_authentication(REAL_ANSWER.as_bytes()).expect("parse");
    // Last byte of the server's own challenge. Everything else still lines
    // up, including the echoed eUICC challenge, so only the signature can
    // catch this.
    let last = start.server_signed1.len() - 1;
    start.server_signed1[last] ^= 0x01;
    assert_eq!(
        verify_server_credentials(&start, SMDP_HOST, &challenge(), &anchors),
        Err(Es9pError::ServerSignatureInvalid)
    );
}

#[test]
fn a_changed_byte_in_the_certificate_fails_the_ci_signature() {
    let anchors = anchors_from(&[("gsma-rsp2-root-ci1.pem", CI_ROOT_PEM)]);
    let mut start = parse_initiate_authentication(REAL_ANSWER.as_bytes()).expect("parse");
    // Inside the validity dates, which is in the signed part of the
    // certificate and not in anything else this code reads.
    start.server_certificate[80] ^= 0x01;
    assert_eq!(
        verify_server_credentials(&start, SMDP_HOST, &challenge(), &anchors),
        Err(Es9pError::CertificateSignatureInvalid)
    );
}

#[test]
fn an_answer_to_someone_elses_challenge_is_refused() {
    let anchors = anchors_from(&[("gsma-rsp2-root-ci1.pem", CI_ROOT_PEM)]);
    let start = parse_initiate_authentication(REAL_ANSWER.as_bytes()).expect("parse");
    // A perfectly valid, correctly signed answer -- from an earlier session.
    // This is the only check that ties the exchange to the card in the slot
    // right now, so it has to be fatal rather than a warning.
    let other = [0u8; 16];
    match verify_server_credentials(&start, SMDP_HOST, &other, &anchors) {
        Err(Es9pError::ChallengeMismatch { sent, echoed }) => {
            assert_eq!(sent, "00000000000000000000000000000000");
            assert_eq!(echoed, SENT_CHALLENGE);
        }
        other => panic!("expected ChallengeMismatch, got {other:?}"),
    }
}

#[test]
fn an_answer_signed_for_another_address_is_refused() {
    let anchors = anchors_from(&[("gsma-rsp2-root-ci1.pem", CI_ROOT_PEM)]);
    let start = parse_initiate_authentication(REAL_ANSWER.as_bytes()).expect("parse");
    match verify_server_credentials(&start, "csl.prod.ondemandconnectivity.com", &challenge(), &anchors)
    {
        Err(Es9pError::AddressMismatch { asked, signed }) => {
            assert_eq!(asked, "csl.prod.ondemandconnectivity.com");
            assert_eq!(signed, SMDP_HOST);
        }
        other => panic!("expected AddressMismatch, got {other:?}"),
    }
}

#[test]
fn a_refusal_carries_the_codes_the_server_sent() {
    let body = br#"{"header":{"functionExecutionStatus":{"status":"Failed","statusCodeData":{"subjectCode":"8.1.1","reasonCode":"3.9","message":"unknown eUICC"}}}}"#;
    match parse_initiate_authentication(body) {
        Err(Es9pError::FunctionFailed {
            status,
            subject_code,
            reason_code,
            message,
        }) => {
            assert_eq!(status, "Failed");
            assert_eq!(subject_code.as_deref(), Some("8.1.1"));
            assert_eq!(reason_code.as_deref(), Some("3.9"));
            assert_eq!(message.as_deref(), Some("unknown eUICC"));
        }
        other => panic!("expected FunctionFailed, got {other:?}"),
    }
}

#[test]
fn the_request_carries_base64_of_exactly_what_the_chip_produced() {
    // Both fields are what the eUICC emitted, base64 of the bytes and nothing
    // re-encoded: euiccInfo1 travels as the whole BF20 TLV.
    let info1 = hex_bytes(
        "BF20358203020202A916041481370F5125D0B1D408D4C3B232E6D25E795BEBFB\
         AA16041481370F5125D0B1D408D4C3B232E6D25E795BEBFB",
    );
    let body = initiate_authentication_request(SMDP_HOST, &challenge(), &info1);
    assert_eq!(
        body,
        "{\"euiccChallenge\":\"i88b5K2pyYrwYphzMAVhAw==\",\
         \"euiccInfo1\":\"vyA1ggMCAgKpFgQUgTcPUSXQsdQI1MOyMubSXnlb6/uqFgQUgTcPUSXQsdQI1MOyMubSXnlb6/s=\",\
         \"smdpAddress\":\"wbg.prod.ondemandconnectivity.com\"}"
    );
}

#[test]
fn a_content_length_answer_is_cut_where_it_says() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Admin-Protocol: gsma/rsp/v2.2.0\r\nContent-Length: 2\r\n\r\n{}trailing";
    let response = HttpResponse::parse(raw).expect("parse");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"{}");
    assert_eq!(
        response.header("x-admin-protocol").as_deref(),
        Some("gsma/rsp/v2.2.0")
    );
}

#[test]
fn a_chunked_answer_is_reassembled() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"a\":\r\n2\r\n1}\r\n0\r\n\r\n";
    let response = HttpResponse::parse(raw).expect("parse");
    assert_eq!(response.body, b"{\"a\":1}");
}

#[test]
fn a_body_shorter_than_its_content_length_is_an_error() {
    // Truncated JSON that still parses as an object is how a half-read answer
    // becomes a wrong answer, so the length is checked before the parser sees
    // it.
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n{}";
    match HttpResponse::parse(raw) {
        Err(Es9pError::MalformedHttp { .. }) => {}
        other => panic!("expected MalformedHttp, got {other:?}"),
    }
}

fn challenge() -> Vec<u8> {
    hex_bytes(SENT_CHALLENGE)
}

fn hex_bytes(text: &str) -> Vec<u8> {
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
        .collect()
}

fn anchors_from(files: &[(&str, &str)]) -> Vec<TrustAnchor> {
    let dir = temp_dir(&format!("anchors-{}", files.len()));
    for (name, pem) in files {
        write(&dir, name, pem);
    }
    let anchors = load_trust_anchors(&dir).expect("load anchors");
    std::fs::remove_dir_all(&dir).ok();
    anchors
}

/// Distinguishes two directories asked for in the same nanosecond.
///
/// 🔴 The clock alone was not enough, and the way it failed was ugly. `tag` is
/// derived from the *number* of anchor files, so several tests ask for
/// `anchors-1`; the test binary runs them on threads in one process, so the
/// pid matches too; and `SystemTime` on macOS repeats often enough that two of
/// them landed in one directory. The anchors one test wrote were then loaded
/// by another, and
/// `a_certificate_from_an_authority_we_do_not_hold_is_refused` found the CI
/// root it is supposed to be missing and passed the verification it exists to
/// refuse. Intermittently: three runs in five were green.
static NEXT_TEMP_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let unique = NEXT_TEMP_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("t032-{tag}-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn write(dir: &PathBuf, name: &str, contents: &str) {
    std::fs::write(dir.join(name), contents).expect("write anchor");
}

/// Keeps the unused-import warning honest: `AuthenticationStart` is part of
/// the surface these tests exercise through `parse_initiate_authentication`.
#[allow(dead_code)]
fn _shape(_: AuthenticationStart) {}

// ---------------------------------------------------------------------------
// Activation codes.
//
// The one input to a download that comes from a human, and a one-time
// credential: an activation code that this reads wrongly is not a retry, it is
// an order somebody has to have reissued.
// ---------------------------------------------------------------------------

#[test]
fn a_qr_code_activation_string_is_read_field_by_field() {
    let code = parse_activation_code("LPA:1$smdp.example.com$QQ111-22222-33333-44444")
        .expect("activation code");
    assert_eq!(code.smdp_address, "smdp.example.com");
    assert_eq!(code.matching_id.as_deref(), Some("QQ111-22222-33333-44444"));
    assert_eq!(code.object_identifier, None);
    assert!(!code.confirmation_code_required);
}

/// The prefix is what a scanner emits and what a person retyping leaves off.
#[test]
fn the_lpa_prefix_is_optional() {
    let with = parse_activation_code("LPA:1$smdp.example.com$AAAA").expect("with");
    let without = parse_activation_code("1$smdp.example.com$AAAA").expect("without");
    assert_eq!(with, without);
}

#[test]
fn the_optional_fields_are_read_when_they_are_there() {
    let code = parse_activation_code("LPA:1$smdp.example.com$AAAA$1.3.6.1.4.1.31746$1")
        .expect("activation code");
    assert_eq!(code.object_identifier.as_deref(), Some("1.3.6.1.4.1.31746"));
    assert!(code.confirmation_code_required);
}

/// An empty fourth field with the flag after it is legal and common.
#[test]
fn an_empty_object_identifier_still_leaves_the_flag_readable() {
    let code = parse_activation_code("1$smdp.example.com$AAAA$$1").expect("activation code");
    assert_eq!(code.object_identifier, None);
    assert!(code.confirmation_code_required);
}

/// A version this LPA cannot carry out is refused rather than assumed to be
/// version 1. Guessing here consumes an activation code with a client that
/// then cannot finish.
#[test]
fn an_unknown_activation_code_version_is_refused() {
    assert!(matches!(
        parse_activation_code("LPA:2$smdp.example.com$AAAA"),
        Err(Es9pError::MalformedActivationCode { .. })
    ));
    assert!(matches!(
        parse_activation_code("LPA:1$smdp.example.com"),
        Err(Es9pError::MalformedActivationCode { .. })
    ));
    assert!(matches!(
        parse_activation_code("LPA:1$notahostname$AAAA"),
        Err(Es9pError::MalformedActivationCode { .. })
    ));
}

/// SGP.22: `hashCc = SHA256(SHA256(CC) || transactionId)`.
///
/// Two hashes, not one, and the transaction id is appended to the digest
/// rather than to the code. Getting that wrong produces a `PrepareDownload`
/// the card refuses with a signature error, which reads like a broken
/// certificate chain rather than like a mistyped confirmation code.
///
/// The expected value was computed outside this crate, with Python's
/// `hashlib`, so the test cannot pass by agreeing with the same library the
/// implementation uses.
#[test]
fn the_confirmation_code_hash_binds_the_code_to_the_transaction() {
    let transaction = hex_bytes("AABBCCDD");
    assert_eq!(
        hash_confirmation_code("12345678", &transaction).to_vec(),
        hex_bytes("fd5db44a3d887ca68a8c0ddb95617936bea5530dec7ab87c241feb0b8c4565bb")
    );
    // The digest of the code on its own is a different value, which is the
    // mistake the two-round definition exists to rule out.
    assert_ne!(
        hash_confirmation_code("12345678", &transaction).to_vec(),
        hex_bytes("ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f")
    );
    // And a different transaction gives a different hash, so the binding is
    // real rather than decorative.
    assert_ne!(
        hash_confirmation_code("12345678", &transaction),
        hash_confirmation_code("12345678", &hex_bytes("AABBCCDE"))
    );
}
