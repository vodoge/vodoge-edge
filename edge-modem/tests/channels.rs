use edge_modem::LogicalChannels;

#[test]
fn release_all_except_esim_keeps_the_isd_r_channel() {
    let mut channels = LogicalChannels::default();
    channels.open(1);
    channels.set_esim(2);
    channels.open(3);

    let closed = channels.release_all_except_esim();
    assert_eq!(closed, vec![1, 3]);
    assert!(channels.is_open(2));
    assert!(!channels.is_open(1));
    assert_eq!(channels.esim(), Some(2));
}
