package pgpcrypto

import "testing"

func TestIdentityKeypairWithPassphraseRoundTrip(t *testing.T) {
	kp, err := GenerateIdentityKeypair("alice@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	groupKeyHex, encryptedGroupKey, err := GenerateEncryptedGroupKey(kp.PublicKeyArmored)
	if err != nil {
		t.Fatalf("generate encrypted group key: %v", err)
	}

	// Zła passphrase musi się nie udać.
	if _, err := DecryptArmoredMessageWithPassphrase(encryptedGroupKey, kp.PrivateKeyArmored, "wrong"); err == nil {
		t.Fatalf("expected error with wrong passphrase, got nil")
	}

	got, err := DecryptArmoredMessageWithPassphrase(encryptedGroupKey, kp.PrivateKeyArmored, "correct horse battery staple")
	if err != nil {
		t.Fatalf("decrypt with correct passphrase: %v", err)
	}
	if got != groupKeyHex {
		t.Fatalf("group key mismatch: got %q want %q", got, groupKeyHex)
	}
}

func TestIdentityKeypairWithoutPassphrase(t *testing.T) {
	kp, err := GenerateIdentityKeypair("bob@example.com", "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	_, encryptedGroupKey, err := GenerateEncryptedGroupKey(kp.PublicKeyArmored)
	if err != nil {
		t.Fatalf("generate encrypted group key: %v", err)
	}
	if _, err := DecryptArmoredMessageWithKey(encryptedGroupKey, kp.PrivateKeyArmored); err != nil {
		t.Fatalf("decrypt plaintext key: %v", err)
	}
}
