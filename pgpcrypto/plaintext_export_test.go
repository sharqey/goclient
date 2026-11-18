package pgpcrypto

import "testing"

// TestPlaintextPrivateKeyArmored_Protected — device-linkiem wolno wysyłać
// wyłącznie plaintext klucze (CLIENT_SPEC.md "Device linking"); to sprawdza,
// że klucz chroniony passphrase da się odblokować i użyć BEZ tej passphrase
// po re-serializacji, dokładnie tak jak zrobiłby to odbiorca (device B).
func TestPlaintextPrivateKeyArmored_Protected(t *testing.T) {
	kp, err := GenerateIdentityKeypair("alice@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	groupKeyHex, encryptedGroupKey, err := GenerateEncryptedGroupKey(kp.PublicKeyArmored)
	if err != nil {
		t.Fatalf("generate encrypted group key: %v", err)
	}

	if _, err := PlaintextPrivateKeyArmored(kp.PrivateKeyArmored, "wrong"); err == nil {
		t.Fatalf("expected error with wrong passphrase, got nil")
	}

	plaintextKey, err := PlaintextPrivateKeyArmored(kp.PrivateKeyArmored, "correct horse battery staple")
	if err != nil {
		t.Fatalf("export plaintext: %v", err)
	}

	// Odbiorca (device B) nie zna passphrase — DecryptArmoredMessageWithKey
	// (bez passphrase) musi zadziałać na wyeksportowanym kluczu.
	got, err := DecryptArmoredMessageWithKey(encryptedGroupKey, plaintextKey)
	if err != nil {
		t.Fatalf("decrypt with plaintext-exported key: %v", err)
	}
	if got != groupKeyHex {
		t.Fatalf("group key mismatch: got %q want %q", got, groupKeyHex)
	}
}

func TestPlaintextPrivateKeyArmored_AlreadyPlaintext(t *testing.T) {
	kp, err := GenerateIdentityKeypair("bob@example.com", "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	_, encryptedGroupKey, err := GenerateEncryptedGroupKey(kp.PublicKeyArmored)
	if err != nil {
		t.Fatalf("generate encrypted group key: %v", err)
	}

	plaintextKey, err := PlaintextPrivateKeyArmored(kp.PrivateKeyArmored, "")
	if err != nil {
		t.Fatalf("export plaintext: %v", err)
	}
	if _, err := DecryptArmoredMessageWithKey(encryptedGroupKey, plaintextKey); err != nil {
		t.Fatalf("decrypt with round-tripped key: %v", err)
	}
}
