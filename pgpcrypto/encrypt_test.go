package pgpcrypto

import "testing"

func TestEncryptDecryptWithGroupKeyRoundTrip(t *testing.T) {
	kp, err := GenerateIdentityKeypair("carol@example.com", "")
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	_, encryptedGroupKey, err := GenerateEncryptedGroupKey(kp.PublicKeyArmored)
	if err != nil {
		t.Fatalf("generate group key: %v", err)
	}

	plaintext := `{"password":"hunter2","totp_secret":"","notes":""}`
	ciphertext, groupEncryptedSecretKey, err := EncryptWithGroupKey(plaintext, encryptedGroupKey, kp.PrivateKeyArmored)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	got, err := DecryptWithGroupKey(ciphertext, groupEncryptedSecretKey, encryptedGroupKey, kp.PrivateKeyArmored)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != plaintext {
		t.Fatalf("mismatch: got %q want %q", got, plaintext)
	}
}

// TASK-018 (password-manager-flutter) runda 5: Private nie ma group_key —
// EncryptOwnerSecret/DecryptDirectSecret muszą interoperować tak samo jak
// EncryptWithGroupKey/DecryptWithGroupKey wyżej.
func TestEncryptOwnerSecretDecryptDirectSecretRoundTrip(t *testing.T) {
	kp, err := GenerateIdentityKeypair("dave@example.com", "")
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	plaintext := `{"password":"hunter2","totp_secret":"","notes":""}`
	ciphertext, ownerEncryptedSecretKey, err := EncryptOwnerSecret(plaintext, kp.PublicKeyArmored)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	got, err := DecryptDirectSecret(ciphertext, ownerEncryptedSecretKey, kp.PrivateKeyArmored, "")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != plaintext {
		t.Fatalf("mismatch: got %q want %q", got, plaintext)
	}
}

// Ten sam plaintext/klucz -> różny ciphertext/owner_encrypted_secret_key za
// każdym razem (losowy IV, losowy secret_key per wywołanie) — semantic
// security AES-GCM.
func TestEncryptOwnerSecret_NeverReusesKeyOrIV(t *testing.T) {
	kp, err := GenerateIdentityKeypair("erin@example.com", "")
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	plaintext := `{"password":"same","totp_secret":"","notes":""}`

	c1, k1, err := EncryptOwnerSecret(plaintext, kp.PublicKeyArmored)
	if err != nil {
		t.Fatalf("encrypt 1: %v", err)
	}
	c2, k2, err := EncryptOwnerSecret(plaintext, kp.PublicKeyArmored)
	if err != nil {
		t.Fatalf("encrypt 2: %v", err)
	}
	if c1 == c2 || k1 == k2 {
		t.Fatalf("expected different ciphertext/key per call, got identical output")
	}
}

// Rewrapper: klucz grupy przepakowany z klucza A na klucz B otwiera się
// kluczem B (klucze gałęzi dla nowego członka).
func TestRewrapperRoundTrip(t *testing.T) {
	a, err := GenerateIdentityKeypair("a@example.com", "")
	if err != nil {
		t.Fatalf("generate a: %v", err)
	}
	b, err := GenerateIdentityKeypair("b@example.com", "")
	if err != nil {
		t.Fatalf("generate b: %v", err)
	}
	rw, err := NewRewrapper(a.PrivateKeyArmored, b.PublicKeyArmored)
	if err != nil {
		t.Fatalf("new rewrapper: %v", err)
	}
	for i := 0; i < 3; i++ {
		groupKeyHex, forA, err := GenerateEncryptedGroupKey(a.PublicKeyArmored)
		if err != nil {
			t.Fatalf("generate group key: %v", err)
		}
		forB, err := rw.Rewrap(forA)
		if err != nil {
			t.Fatalf("rewrap: %v", err)
		}
		got, err := DecryptArmoredMessageWithKey(forB, b.PrivateKeyArmored)
		if err != nil {
			t.Fatalf("decrypt as b: %v", err)
		}
		if got != groupKeyHex {
			t.Fatalf("mismatch: got %q want %q", got, groupKeyHex)
		}
	}
}
