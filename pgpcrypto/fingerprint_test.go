package pgpcrypto

import (
	"strings"
	"testing"
)

func TestFullFingerprintFromArmoredPublicKeyMatchesShortForm(t *testing.T) {
	kp, err := GenerateIdentityKeypair("carol@example.com", "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	full, err := FullFingerprintFromArmoredPublicKey(kp.PublicKeyArmored)
	if err != nil {
		t.Fatalf("FullFingerprintFromArmoredPublicKey: %v", err)
	}
	if len(full) != 40 {
		t.Fatalf("full fingerprint length = %d, want 40 (got %q)", len(full), full)
	}

	short, err := FingerprintFromArmoredPublicKey(kp.PublicKeyArmored)
	if err != nil {
		t.Fatalf("FingerprintFromArmoredPublicKey: %v", err)
	}
	wantShort := full[len(full)-8:]
	wantShort = wantShort[:4] + "-" + wantShort[4:]
	if short != wantShort {
		t.Fatalf("short fingerprint %q is not the last 8 hex chars of full fingerprint %q (want %q)", short, full, wantShort)
	}

	// Deterministic: same key, same fingerprint every call.
	full2, err := FullFingerprintFromArmoredPublicKey(kp.PublicKeyArmored)
	if err != nil {
		t.Fatalf("FullFingerprintFromArmoredPublicKey (2nd call): %v", err)
	}
	if full != full2 {
		t.Fatalf("fingerprint not deterministic: %q != %q", full, full2)
	}

	if strings.ToUpper(full) != full {
		t.Fatalf("expected uppercase hex, got %q", full)
	}
}

func TestFullFingerprintFromArmoredPublicKeyRejectsGarbage(t *testing.T) {
	if _, err := FullFingerprintFromArmoredPublicKey("not a key"); err == nil {
		t.Fatal("expected error for garbage input, got nil")
	}
}
