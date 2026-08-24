module github.com/yuanshuai1122/vodoge-edge/vowifi

go 1.26.3

// The IKEv2/ESP stack is consumed from the read-only local mirror of
// github.com/boa-z/vowifi-go. T040/T041 forbid editing anything under
// vendor-mirror/, and `go build -overlay` is forbidden too: an overlay makes the
// compiled artifact disagree with the source tree while the mirror hash check
// still passes, which turns "not one byte changed" from a true statement about
// the binary into a false one. The mirror is designed for injection instead --
// see docs/goals/vodoge-vowifi-call/notes/T041-injection-seams.md -- so it is
// wired in unmodified, by path, exactly like voice/go.mod does.
replace github.com/boa-z/vowifi-go => ../../vendor-mirror/vowifi-go-1e9c6e6

require github.com/boa-z/vowifi-go v0.0.0-00010101000000-000000000000

require golang.org/x/sys v0.46.0 // indirect
