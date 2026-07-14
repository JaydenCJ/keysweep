// Tests for the top-level dispatch: which detector handles which bytes,
// and that unrelated files yield nothing.
package parse

import (
	"testing"

	"github.com/JaydenCJ/keysweep/internal/testkeys"
)

func TestIrrelevantFilesYieldNothing(t *testing.T) {
	if fs := File(nil); fs != nil {
		t.Fatalf("empty: got %+v", fs)
	}
	if fs := File([]byte("just a README\nwith words about keys and certificates\n")); len(fs) != 0 {
		t.Fatalf("plain text: got %+v", fs)
	}
	noise := make([]byte, 512)
	for i := range noise {
		noise[i] = byte(i * 7)
	}
	if fs := File(noise); len(fs) != 0 {
		t.Fatalf("binary noise: got %+v", fs)
	}
}

func TestEveryCommittedFixtureIsHandledWithoutPanic(t *testing.T) {
	// Regression net: every fixture must run through File cleanly; the
	// ones that are real material must produce at least one finding.
	expectFindings := map[string]bool{
		"embedded.env": true, "bundle.p12": true, "keystore.jks": true,
		"keystore.jceks": true, "cert_leaf.der": true,
		"rsa2048_pkcs8.der": true, "rsa2048_pkcs8_enc.der": true,
	}
	for _, name := range testkeys.Names() {
		fs := File(testkeys.Read(name))
		isPEMish := len(fs) > 0
		if expectFindings[name] && !isPEMish {
			t.Errorf("%s: expected findings, got none", name)
		}
		_ = fs
	}
}

func TestDispatchPrefersPEMOverDERWhenBothPlausible(t *testing.T) {
	// A PEM file whose leading bytes could sniff as text containing 0x30
	// must go down the PEM path — check via the line number being set.
	f := one(t, testkeys.Read("rsa2048_pkcs8.pem"))
	if f.Line != 1 || f.Format != "pkcs8-pem" {
		t.Fatalf("got %+v", f)
	}
}
