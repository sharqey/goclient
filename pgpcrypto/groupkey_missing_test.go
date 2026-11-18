package pgpcrypto

import (
	"errors"
	"testing"
)

// Pusty klucz grupy (nikt go nie udostępnił) daje czytelny ErrNoGroupKey
// zamiast "armor decode: EOF" — BUGS.md 2026-09-12.
func TestEmptyGroupKeyGivesErrNoGroupKey(t *testing.T) {
	if _, err := DecryptWithGroupKey("ct", "gesk", "", "priv"); !errors.Is(err, ErrNoGroupKey) {
		t.Fatalf("decrypt: want ErrNoGroupKey, got %v", err)
	}
	if _, _, err := EncryptWithGroupKey("pt", "  \n", "priv"); !errors.Is(err, ErrNoGroupKey) {
		t.Fatalf("encrypt: want ErrNoGroupKey, got %v", err)
	}
}
