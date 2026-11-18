package pgpcrypto

import (
	"encoding/json"
	"os"
	"testing"
)

// group-key-vector.json — kopia tasks/crypto-test-vectors.json z repo
// password-manager (źródło prawdy, tu duplikowany świadomie jako dane, nie
// kod, żeby ten test był samodzielny). MUSI przejść zarówno ta
// implementacja Go, jak i przyszły port na Dart (Flutter) — patrz
// TASK-002-full-client.md, sekcja "Flutter". Fixture jest stały, NIE
// regenerować losowo — ma łapać regresje w tej implementacji, nie tylko
// potwierdzać że kod się zgadza sam ze sobą.
type vector struct {
	PrivateKeyArmored       string `json:"private_key_armored"`
	Plaintext               string `json:"plaintext"`
	EncryptedGroupKey       string `json:"encrypted_group_key"`
	GroupEncryptedSecretKey string `json:"group_encrypted_secret_key"`
	Ciphertext              string `json:"ciphertext"`
}

func TestDecryptWithGroupKey_FixedVector(t *testing.T) {
	b, err := os.ReadFile("testdata/group-key-vector.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v vector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}

	got, err := DecryptWithGroupKey(v.Ciphertext, v.GroupEncryptedSecretKey, v.EncryptedGroupKey, v.PrivateKeyArmored)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != v.Plaintext {
		t.Fatalf("plaintext mismatch:\n got:  %q\n want: %q", got, v.Plaintext)
	}
}
