use edge_core::{assemble, ConcatPart};

#[test]
fn concatenates_fragments_in_order() {
    let parts = [
        ConcatPart {
            sender: "+86100".into(),
            ref_id: 7,
            total: 2,
            seq: 2,
            body: "world".into(),
        },
        ConcatPart {
            sender: "+86100".into(),
            ref_id: 7,
            total: 2,
            seq: 1,
            body: "hello".into(),
        },
    ];
    let (done, pending) = assemble(&parts);
    assert!(pending.is_empty());
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].body, "helloworld");
    assert_eq!(done[0].parts, 2);
}

#[test]
fn keeps_incomplete_groups_pending() {
    let parts = [ConcatPart {
        sender: "+86100".into(),
        ref_id: 1,
        total: 3,
        seq: 1,
        body: "a".into(),
    }];
    let (done, pending) = assemble(&parts);
    assert!(done.is_empty());
    assert_eq!(pending.len(), 1);
}
