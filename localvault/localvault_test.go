package localvault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sharqey/goclient/pgpcrypto"
)

func TestCreateUnlockAddListDecrypt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")

	v, err := Create(path, "My Vault", "correct horse battery staple")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if v.VaultName() != "My Vault" {
		t.Fatalf("VaultName = %q, want %q", v.VaultName(), "My Vault")
	}

	_, err = v.AddSecret("account", "GitHub", "alice", "https://github.com", "", true, []byte(`{"password":"hunter2","totp_secret":"JBSWY3DPEHPK3PXP","notes":"work"}`))
	if err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	// Reopen from disk — simulates app restart, żeby upewnić się że save()
	// faktycznie napisał kompletny, poprawny plik.
	reopened, err := Unlock(path, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	secrets, err := reopened.ListSecrets()
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("ListSecrets len = %d, want 1", len(secrets))
	}
	got := secrets[0]
	if got.Title != "GitHub" || got.Username != "alice" || !got.HasTOTP {
		t.Fatalf("unexpected secret metadata: %+v", got)
	}

	meta, plaintext, err := reopened.DecryptSecret(got.ID)
	if err != nil {
		t.Fatalf("DecryptSecret: %v", err)
	}
	if meta.Title != "GitHub" {
		t.Fatalf("meta.Title = %q, want GitHub", meta.Title)
	}
	want := `{"password":"hunter2","totp_secret":"JBSWY3DPEHPK3PXP","notes":"work"}`
	if string(plaintext) != want {
		t.Fatalf("plaintext = %q, want %q", plaintext, want)
	}

	if err := reopened.UpdateSecret(got.ID, "GitHub Personal", "alice", "https://github.com", "", true, []byte(`{"password":"newpass","totp_secret":"JBSWY3DPEHPK3PXP","notes":"work"}`)); err != nil {
		t.Fatalf("UpdateSecret: %v", err)
	}
	_, plaintext2, err := reopened.DecryptSecret(got.ID)
	if err != nil {
		t.Fatalf("DecryptSecret after update: %v", err)
	}
	if string(plaintext2) != `{"password":"newpass","totp_secret":"JBSWY3DPEHPK3PXP","notes":"work"}` {
		t.Fatalf("plaintext after update = %q", plaintext2)
	}
	updated, ok, err := reopened.SecretByID(got.ID)
	if err != nil {
		t.Fatalf("SecretByID: %v", err)
	}
	if !ok {
		t.Fatalf("SecretByID: not found")
	}
	if updated.Title != "GitHub Personal" {
		t.Fatalf("Title after update = %q", updated.Title)
	}
}

// TestLegacyFormatMigration — a format_version 1 file (plaintext title/
// username/url/vault_name, content-only ciphertext, dokładnie jak przed
// 2026-09-08) musi się otworzyć i zostać uaktualniony BEZPOŚREDNIO do
// format_version 3 w locie (task 012 — pomija pośredni zapis w kształcie 2),
// bez utraty danych.
func TestLegacyFormatMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sharqey")
	masterPassword := "correct horse battery staple"

	v, err := Create(path, "Legacy Vault", masterPassword)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	added, err := v.AddSecret("account", "GitHub", "alice", "https://github.com", "", true, []byte(`{"password":"hunter2"}`))
	if err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	// Ręcznie "postarz" plik do kształtu format_version 1: jawne metadane
	// obok ciphertextu treści (bez metadanych w środku), jawne vault_name —
	// symuluje plik zapisany PRZED tą zmianą formatu.
	contentOnlyCiphertext, wrappedKey, err := encryptRaw(v.groupKey, `{"password":"hunter2"}`)
	if err != nil {
		t.Fatalf("encryptRaw: %v", err)
	}
	legacy := struct {
		FormatVersion       int    `json:"format_version"`
		VaultName           string `json:"vault_name"`
		Identity            identity
		GroupKeySelfWrapped string `json:"group_key_self_wrapped"`
		Secrets             []struct {
			ID                      string `json:"id"`
			Type                    string `json:"type"`
			Title                   string `json:"title"`
			Username                string `json:"username"`
			URL                     string `json:"url"`
			HasTOTP                 bool   `json:"has_totp"`
			Ciphertext              string `json:"ciphertext"`
			GroupEncryptedSecretKey string `json:"group_encrypted_secret_key"`
		} `json:"secrets"`
	}{
		FormatVersion: 1,
		VaultName:     "Legacy Vault",
		Identity: identity{
			PublicKeyArmored:  v.f.Recipients[0].PublicKeyArmored,
			PrivateKeyArmored: v.f.Recipients[0].PrivateKeyArmored,
		},
		GroupKeySelfWrapped: v.f.Recipients[0].WrappedGroupKey,
	}
	legacy.Secrets = append(legacy.Secrets, struct {
		ID                      string `json:"id"`
		Type                    string `json:"type"`
		Title                   string `json:"title"`
		Username                string `json:"username"`
		URL                     string `json:"url"`
		HasTOTP                 bool   `json:"has_totp"`
		Ciphertext              string `json:"ciphertext"`
		GroupEncryptedSecretKey string `json:"group_encrypted_secret_key"`
	}{
		ID: added.ID, Type: "account", Title: "GitHub", Username: "alice", URL: "https://github.com",
		HasTOTP: true, Ciphertext: contentOnlyCiphertext, GroupEncryptedSecretKey: wrappedKey,
	})
	b, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy fixture: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write legacy fixture: %v", err)
	}

	migrated, err := Unlock(path, masterPassword)
	if err != nil {
		t.Fatalf("Unlock (legacy migration): %v", err)
	}
	if migrated.VaultName() != "Legacy Vault" {
		t.Fatalf("VaultName after migration = %q, want %q", migrated.VaultName(), "Legacy Vault")
	}
	secrets, err := migrated.ListSecrets()
	if err != nil {
		t.Fatalf("ListSecrets after migration: %v", err)
	}
	if len(secrets) != 1 || secrets[0].Title != "GitHub" || secrets[0].Username != "alice" || !secrets[0].HasTOTP {
		t.Fatalf("unexpected migrated secret: %+v", secrets)
	}
	_, plaintext, err := migrated.DecryptSecret(added.ID)
	if err != nil {
		t.Fatalf("DecryptSecret after migration: %v", err)
	}
	if string(plaintext) != `{"password":"hunter2"}` {
		t.Fatalf("plaintext after migration = %q", plaintext)
	}

	// Plik na dysku musi być teraz w formacie 3: title jawny ("GitHub"), ale
	// vault_name i reszta metadanych sekretu (username/url) nadal zaszyfrowane
	// — re-otwórz z pliku od zera, poza pamięcią z tego testu.
	reopenedAgain, err := Unlock(path, masterPassword)
	if err != nil {
		t.Fatalf("Unlock (post-migration reopen): %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migrated file: %v", err)
	}
	var onDisk file
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatalf("unmarshal migrated file: %v", err)
	}
	if onDisk.FormatVersion != FormatVersionRecipients {
		t.Fatalf("format_version on disk = %d, want %d", onDisk.FormatVersion, FormatVersionRecipients)
	}
	if len(onDisk.Secrets) != 1 || onDisk.Secrets[0].Title != "GitHub" {
		t.Fatalf("secret title on disk not plaintext: %+v", onDisk.Secrets)
	}
	if strings.Contains(string(raw), "alice") || strings.Contains(string(raw), "Legacy Vault") {
		t.Fatalf("migrated file on disk still contains plaintext non-title metadata: %s", raw)
	}
	if reopenedAgain.VaultName() != "Legacy Vault" {
		t.Fatalf("VaultName after reopen = %q", reopenedAgain.VaultName())
	}
}

// TestV2ToV3Migration — a hand-built format_version 2 file (WSZYSTKO poza id
// zaszyfrowane, łącznie z title wewnątrz koperty) musi się otworzyć i zostać
// zmigrowany do format_version 3: title trafia jawnie do secretRecord, a
// koperta przestaje go zawierać — bez utraty innych danych.
func TestV2ToV3Migration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v2.sharqey")
	masterPassword := "correct horse battery staple"

	v, err := Create(path, "V2 Vault", masterPassword)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Ręcznie zbuduj kopertę w kształcie format_version 2 — title WEWNĄTRZ
	// koperty, obok reszty metadanych, dokładnie jak przed tym taskiem.
	type envelopeV2 struct {
		Type     string `json:"type"`
		Title    string `json:"title"`
		Username string `json:"username"`
		URL      string `json:"url"`
		HasTOTP  bool   `json:"has_totp"`
		Content  string `json:"content"`
	}
	envBytes, err := json.Marshal(envelopeV2{
		Type: "account", Title: "GitHub", Username: "alice", URL: "https://github.com",
		HasTOTP: true, Content: `{"password":"hunter2"}`,
	})
	if err != nil {
		t.Fatalf("marshal v2 envelope: %v", err)
	}
	ciphertext, wrappedKey, err := encryptRaw(v.groupKey, string(envBytes))
	if err != nil {
		t.Fatalf("encryptRaw: %v", err)
	}

	v.f.Secrets = append(v.f.Secrets, secretRecord{
		ID: "secret-1", Ciphertext: ciphertext, GroupEncryptedSecretKey: wrappedKey,
	})
	// Ręcznie "postarz" recipienta do kształtu format_version < 4 (LegacyIdentity/
	// LegacyGroupKeySelfWrapped zamiast Recipients) — symuluje plik zapisany
	// przed taskiem 067.
	v.f.LegacyIdentity = identity{
		PublicKeyArmored:  v.f.Recipients[0].PublicKeyArmored,
		PrivateKeyArmored: v.f.Recipients[0].PrivateKeyArmored,
	}
	v.f.LegacyGroupKeySelfWrapped = v.f.Recipients[0].WrappedGroupKey
	v.f.Recipients = nil
	v.f.FormatVersion = 2
	if err := v.save(); err != nil {
		t.Fatalf("save v2 fixture: %v", err)
	}

	// Sanity: on disk, the envelope carries "title" and secretRecord.Title
	// (top-level, unindented from the envelope) is empty/absent.
	rawBefore, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read v2 fixture: %v", err)
	}
	var v2OnDisk file
	if err := json.Unmarshal(rawBefore, &v2OnDisk); err != nil {
		t.Fatalf("unmarshal v2 fixture: %v", err)
	}
	if v2OnDisk.Secrets[0].Title != "" {
		t.Fatalf("v2 fixture unexpectedly has plaintext title on record: %+v", v2OnDisk.Secrets[0])
	}

	migrated, err := Unlock(path, masterPassword)
	if err != nil {
		t.Fatalf("Unlock (v2->v3 migration): %v", err)
	}
	if migrated.VaultName() != "V2 Vault" {
		t.Fatalf("VaultName after migration = %q, want %q", migrated.VaultName(), "V2 Vault")
	}

	secrets, err := migrated.ListSecrets()
	if err != nil {
		t.Fatalf("ListSecrets after migration: %v", err)
	}
	if len(secrets) != 1 || secrets[0].Title != "GitHub" || secrets[0].Username != "alice" || !secrets[0].HasTOTP {
		t.Fatalf("unexpected migrated secret: %+v", secrets)
	}
	_, plaintext, err := migrated.DecryptSecret("secret-1")
	if err != nil {
		t.Fatalf("DecryptSecret after migration: %v", err)
	}
	if string(plaintext) != `{"password":"hunter2"}` {
		t.Fatalf("plaintext after migration = %q", plaintext)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migrated file: %v", err)
	}
	var onDisk file
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatalf("unmarshal migrated file: %v", err)
	}
	if onDisk.FormatVersion != FormatVersionRecipients {
		t.Fatalf("format_version on disk = %d, want %d", onDisk.FormatVersion, FormatVersionRecipients)
	}
	if len(onDisk.Secrets) != 1 || onDisk.Secrets[0].Title != "GitHub" {
		t.Fatalf("secret title on disk not plaintext after v2->v3 migration: %+v", onDisk.Secrets)
	}
	if strings.Contains(string(raw), "alice") || strings.Contains(string(raw), "hunter2") {
		t.Fatalf("migrated file on disk still contains plaintext non-title data: %s", raw)
	}

	// Decrypt the migrated ciphertext directly and confirm the envelope no
	// longer carries "title" at all.
	migratedPlaintextEnvelope, err := decryptRaw(migrated.groupKey, onDisk.Secrets[0].Ciphertext, onDisk.Secrets[0].GroupEncryptedSecretKey)
	if err != nil {
		t.Fatalf("decryptRaw migrated envelope: %v", err)
	}
	if strings.Contains(migratedPlaintextEnvelope, "title") {
		t.Fatalf("migrated envelope still contains title: %s", migratedPlaintextEnvelope)
	}
}

// TestCreateProducesSingleSelfRecipient — task 067: Create() musi budować
// dokładnie jeden recipient IsSelf:true (kształt format_version 4), zamiast
// dawnego identity/group_key_self_wrapped.
func TestCreateProducesSingleSelfRecipient(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")
	v, err := Create(path, "My Vault", "pw")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if v.f.FormatVersion != FormatVersionRecipients {
		t.Fatalf("FormatVersion = %d, want %d", v.f.FormatVersion, FormatVersionRecipients)
	}
	if len(v.f.Recipients) != 1 {
		t.Fatalf("Recipients len = %d, want 1", len(v.f.Recipients))
	}
	rec := v.f.Recipients[0]
	if !rec.IsSelf {
		t.Fatal("recipient IsSelf = false, want true")
	}
	if rec.PrivateKeyArmored == "" || rec.PublicKeyArmored == "" || rec.WrappedGroupKey == "" || rec.Fingerprint == "" || rec.ID == "" {
		t.Fatalf("recipient missing expected fields: %+v", rec)
	}
}

// TestV3ToV4Migration — a hand-built format_version 3 file (identity +
// group_key_self_wrapped, task 012 kształt) musi się otworzyć i zostać
// zmigrowany do format_version 4: tożsamość trafia do jedynego recipienta
// (IsSelf:true), legacy pola znikają — bez utraty danych ani zmiany
// group_key.
func TestV3ToV4Migration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v3.sharqey")
	masterPassword := "correct horse battery staple"

	v, err := Create(path, "V3 Vault", masterPassword)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	added, err := v.AddSecret("account", "GitHub", "alice", "https://github.com", "", true, []byte(`{"password":"hunter2"}`))
	if err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	// Ręcznie "postarz" plik do kształtu format_version 3.
	v.f.LegacyIdentity = identity{
		PublicKeyArmored:  v.f.Recipients[0].PublicKeyArmored,
		PrivateKeyArmored: v.f.Recipients[0].PrivateKeyArmored,
	}
	v.f.LegacyGroupKeySelfWrapped = v.f.Recipients[0].WrappedGroupKey
	v.f.Recipients = nil
	v.f.FormatVersion = 3
	if err := v.save(); err != nil {
		t.Fatalf("save v3 fixture: %v", err)
	}

	migrated, err := Unlock(path, masterPassword)
	if err != nil {
		t.Fatalf("Unlock (v3->v4 migration): %v", err)
	}
	if migrated.VaultName() != "V3 Vault" {
		t.Fatalf("VaultName after migration = %q, want %q", migrated.VaultName(), "V3 Vault")
	}
	secrets, err := migrated.ListSecrets()
	if err != nil {
		t.Fatalf("ListSecrets after migration: %v", err)
	}
	if len(secrets) != 1 || secrets[0].Title != "GitHub" {
		t.Fatalf("unexpected migrated secret: %+v", secrets)
	}
	_, plaintext, err := migrated.DecryptSecret(added.ID)
	if err != nil {
		t.Fatalf("DecryptSecret after migration: %v", err)
	}
	if string(plaintext) != `{"password":"hunter2"}` {
		t.Fatalf("plaintext after migration = %q", plaintext)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migrated file: %v", err)
	}
	var onDisk file
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatalf("unmarshal migrated file: %v", err)
	}
	if onDisk.FormatVersion != FormatVersionRecipients {
		t.Fatalf("format_version on disk = %d, want %d", onDisk.FormatVersion, FormatVersionRecipients)
	}
	if len(onDisk.Recipients) != 1 || !onDisk.Recipients[0].IsSelf || onDisk.Recipients[0].Fingerprint == "" {
		t.Fatalf("unexpected recipients on disk: %+v", onDisk.Recipients)
	}
	if onDisk.LegacyIdentity.PrivateKeyArmored != "" || onDisk.LegacyGroupKeySelfWrapped != "" {
		t.Fatalf("legacy identity fields not cleared after migration: %+v", onDisk)
	}
}

// TestRecipientsAddListRemoveAndUnlockWithExternalKey — task 067, Faza 1:
// nowy recipient (obcy klucz publiczny, bez osadzonego private key) musi
// dać dostęp do dokładnie tych samych sekretów co hasło główne, przez
// UnlockWithExternalKey zamiast Unlock — to jest dokładnie ten mechanizm,
// którego terraform-provider-sharqey używa dla local_vault_identity_key_file.
func TestRecipientsAddListRemoveAndUnlockWithExternalKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")
	v, err := Create(path, "My Vault", "pw")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := v.AddSecret("account", "GitHub", "alice", "", "", false, []byte(`{"password":"hunter2"}`)); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	externalKeypair, err := pgpcrypto.GenerateIdentityKeypair("", "")
	if err != nil {
		t.Fatalf("GenerateIdentityKeypair (external): %v", err)
	}
	added, err := v.AddRecipient("CI key", externalKeypair.PublicKeyArmored)
	if err != nil {
		t.Fatalf("AddRecipient: %v", err)
	}
	if added.IsSelf {
		t.Fatal("recipient added via AddRecipient should not be IsSelf")
	}
	if added.Fingerprint == "" || added.ID == "" {
		t.Fatalf("unexpected recipient: %+v", added)
	}

	list := v.ListRecipients()
	if len(list) != 2 {
		t.Fatalf("ListRecipients len = %d, want 2", len(list))
	}

	viaExternal, err := UnlockWithExternalKey(path, externalKeypair.PrivateKeyArmored, "")
	if err != nil {
		t.Fatalf("UnlockWithExternalKey: %v", err)
	}
	secrets, err := viaExternal.ListSecrets()
	if err != nil {
		t.Fatalf("ListSecrets (via external key): %v", err)
	}
	if len(secrets) != 1 || secrets[0].Title != "GitHub" {
		t.Fatalf("unexpected secrets via external key: %+v", secrets)
	}
	_, plaintext, err := viaExternal.DecryptSecret(secrets[0].ID)
	if err != nil {
		t.Fatalf("DecryptSecret (via external key): %v", err)
	}
	if string(plaintext) != `{"password":"hunter2"}` {
		t.Fatalf("plaintext via external key = %q", plaintext)
	}

	// Nie można usunąć ostatniego recipienta.
	reopened, err := Unlock(path, "pw")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := reopened.RemoveRecipient(added.ID); err != nil {
		t.Fatalf("RemoveRecipient: %v", err)
	}
	if len(reopened.ListRecipients()) != 1 {
		t.Fatalf("ListRecipients after remove = %d, want 1", len(reopened.ListRecipients()))
	}
	remaining := reopened.ListRecipients()[0]
	if err := reopened.RemoveRecipient(remaining.ID); err == nil {
		t.Fatal("RemoveRecipient should refuse to remove the last recipient")
	}

	if _, err := UnlockWithExternalKey(path, externalKeypair.PrivateKeyArmored, ""); err == nil {
		t.Fatal("UnlockWithExternalKey should fail after the matching recipient was removed")
	}
}

// TestUnlockWithExternalKeyOnOldFormatFails — plik < v4 nie ma recipients[]
// wcale, więc UnlockWithExternalKey musi odmówić czytelnym błędem zamiast
// próbować deszyfrowania skazanego na porażkę.
func TestUnlockWithExternalKeyOnOldFormatFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")
	v, err := Create(path, "My Vault", "pw")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	v.f.LegacyIdentity = identity{
		PublicKeyArmored:  v.f.Recipients[0].PublicKeyArmored,
		PrivateKeyArmored: v.f.Recipients[0].PrivateKeyArmored,
	}
	v.f.LegacyGroupKeySelfWrapped = v.f.Recipients[0].WrappedGroupKey
	v.f.Recipients = nil
	v.f.FormatVersion = 3
	if err := v.save(); err != nil {
		t.Fatalf("save v3 fixture: %v", err)
	}

	if _, err := UnlockWithExternalKey(path, v.f.LegacyIdentity.PrivateKeyArmored, "pw"); err == nil {
		t.Fatal("UnlockWithExternalKey on a v3 file should fail")
	}
}

// TestReloadPicksUpExternalChange — user feedback 2026-09-22: dodał sekret
// przez sharqey-mcp (osobny Unlock tego samego pliku, patrz Server.unlock w
// internal/mcpserver) do bazy otwartej równocześnie w GUI, a Cmd/Ctrl+R w GUI
// tego nie pokazywał. Symuluje dokładnie ten scenariusz: dwa niezależne
// uchwyty *Vault na ten sam plik, drugi coś dopisuje i zapisuje, pierwszy
// woła Reload i powinien to zobaczyć bez podawania hasła ponownie.
func TestReloadPicksUpExternalChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")

	guiVault, err := Create(path, "My Vault", "correct horse battery staple")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	secrets, err := guiVault.ListSecrets()
	if err != nil {
		t.Fatalf("ListSecrets (before external change): %v", err)
	}
	if len(secrets) != 0 {
		t.Fatalf("ListSecrets len = %d, want 0", len(secrets))
	}

	mcpVault, err := Unlock(path, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Unlock (simulating sharqey-mcp): %v", err)
	}
	if _, err := mcpVault.AddSecret("account", "GitHub", "alice", "https://github.com", "", false, []byte(`{"password":"hunter2"}`)); err != nil {
		t.Fatalf("AddSecret (via mcpVault): %v", err)
	}

	// Bez Reload guiVault dalej widzi stary, pusty stan w pamięci.
	secrets, err = guiVault.ListSecrets()
	if err != nil {
		t.Fatalf("ListSecrets (stale, before Reload): %v", err)
	}
	if len(secrets) != 0 {
		t.Fatalf("ListSecrets len = %d before Reload, want 0 (stale in-memory state)", len(secrets))
	}

	if err := guiVault.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	secrets, err = guiVault.ListSecrets()
	if err != nil {
		t.Fatalf("ListSecrets (after Reload): %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("ListSecrets len = %d after Reload, want 1", len(secrets))
	}
	if secrets[0].Title != "GitHub" {
		t.Fatalf("secrets[0].Title = %q, want GitHub", secrets[0].Title)
	}
	if _, _, err := guiVault.DecryptSecret(secrets[0].ID); err != nil {
		t.Fatalf("DecryptSecret after Reload: %v", err)
	}
}

// TestMutationKeepsExternalChange — task 013 pkt 1: mutacja na instancji ze
// starym stanem w pamięci (okno GUI otwarte, a w międzyczasie iPhone przez
// iCloud / sharqey-mcp dopisał sekret) NIE może nadpisać tamtej zmiany.
// Odpowiednik mobile: integration_test/local_vault_service_test.dart,
// "mutacja nie gubi sekretu zapisanego z zewnątrz".
func TestMutationKeepsExternalChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")
	guiVault, err := Create(path, "My Vault", "correct horse battery staple")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	otherVault, err := Unlock(path, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	if _, err := otherVault.AddSecret("account", "From phone", "", "", "", false, []byte(`{}`)); err != nil {
		t.Fatalf("AddSecret (other): %v", err)
	}
	group, err := otherVault.CreateGroup("Phone group", "")
	if err != nil {
		t.Fatalf("CreateGroup (other): %v", err)
	}
	// guiVault NIE robi Reload — mutacja sama musi przeładować plik. Grupa
	// utworzona z zewnątrz musi też przejść walidację w AddSecret.
	if _, err := guiVault.AddSecret("account", "From desktop", "", "", group.ID, false, []byte(`{}`)); err != nil {
		t.Fatalf("AddSecret (gui) into externally created group: %v", err)
	}

	fresh, err := Unlock(path, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Unlock (fresh): %v", err)
	}
	secrets, err := fresh.ListSecrets()
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	titles := map[string]bool{}
	for _, s := range secrets {
		titles[s.Title] = true
	}
	if !titles["From phone"] || !titles["From desktop"] || len(secrets) != 2 {
		t.Fatalf("secrets on disk = %v, want both 'From phone' and 'From desktop'", titles)
	}
	if len(fresh.ListGroups()) != 1 {
		t.Fatalf("groups on disk = %d, want 1", len(fresh.ListGroups()))
	}
	// Stan w pamięci GUI też jest po mutacji aktualny.
	if got, _ := guiVault.ListSecrets(); len(got) != 2 {
		t.Fatalf("guiVault in-memory secrets = %d after mutation, want 2", len(got))
	}
}

// TestMutationRefusesNewerFormatOnDisk — jeśli nowszy klient podniósł
// format_version pliku, mutacja ze starszej instancji ma zwrócić błąd i NIE
// ruszać pliku (zapis cofnąłby go do starszego formatu).
func TestMutationRefusesNewerFormatOnDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")
	v, err := Create(path, "My Vault", "pw")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	raw["format_version"] = FormatVersion + 1
	b, _ = json.Marshal(raw)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := v.AddSecret("env", "X", "", "", "", false, []byte(`{}`)); err == nil {
		t.Fatal("AddSecret over newer format succeeded, want error")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(b) {
		t.Fatal("file on disk changed despite format_version mismatch")
	}
}

func TestUnlockWrongPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")
	if _, err := Create(path, "My Vault", "correct-password"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := Unlock(path, "wrong-password"); err == nil {
		t.Fatal("Unlock with wrong password succeeded, want error")
	}
}

func TestGroupsCreateAssignRoundtripAndDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")

	v, err := Create(path, "My Vault", "pw")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	work, err := v.CreateGroup("Work", "")
	if err != nil {
		t.Fatalf("CreateGroup(root): %v", err)
	}
	if work.ParentID != "" {
		t.Fatalf("top-level group ParentID = %q, want empty", work.ParentID)
	}
	sub, err := v.CreateGroup("Infra", work.ID)
	if err != nil {
		t.Fatalf("CreateGroup(sub): %v", err)
	}

	secret, err := v.AddSecret("account", "Prod DB", "admin", "", sub.ID, false, []byte(`{"password":"x"}`))
	if err != nil {
		t.Fatalf("AddSecret into group: %v", err)
	}

	// Nieznana grupa nadrzędna/GroupID musi być odrzucona.
	if _, err := v.CreateGroup("Bad", "nope"); err == nil {
		t.Fatal("CreateGroup with unknown parent should fail")
	}
	if _, err := v.AddSecret("account", "X", "", "", "nope", false, []byte("{}")); err == nil {
		t.Fatal("AddSecret with unknown group should fail")
	}

	// Pusta grupa nie blokuje usunięcia; niepusta (ma podgrupę albo sekret) — tak.
	if err := v.DeleteGroup(work.ID); err == nil {
		t.Fatal("DeleteGroup should fail: contains subgroup")
	}
	if err := v.DeleteGroup(sub.ID); err == nil {
		t.Fatal("DeleteGroup should fail: contains secret")
	}

	// Roundtrip przez dysk — drzewo grup i przypisanie sekretu muszą przeżyć Unlock.
	reopened, err := Unlock(path, "pw")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	groups := reopened.ListGroups()
	if len(groups) != 2 {
		t.Fatalf("ListGroups len = %d, want 2", len(groups))
	}
	secrets, err := reopened.ListSecrets()
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(secrets) != 1 || secrets[0].GroupID != sub.ID {
		t.Fatalf("unexpected secrets after reopen: %+v", secrets)
	}

	if err := reopened.RenameGroup(work.ID, "Work Renamed"); err != nil {
		t.Fatalf("RenameGroup: %v", err)
	}
	for _, g := range reopened.ListGroups() {
		if g.ID == work.ID && g.Name != "Work Renamed" {
			t.Fatalf("RenameGroup didn't stick: %+v", g)
		}
	}

	// Przenosimy sekret z powrotem do roota (groupID="") — to zwalnia "sub"
	// (teraz pustą, do skasowania), ale "work" wciąż zawiera "sub" i musi
	// dalej być zablokowana.
	if err := reopened.UpdateSecret(secret.ID, "Prod DB", "admin", "", "", false, nil); err != nil {
		t.Fatalf("UpdateSecret (move to root): %v", err)
	}
	if err := reopened.DeleteGroup(work.ID); err == nil {
		t.Fatal("DeleteGroup should still fail: contains subgroup")
	}
	if err := reopened.DeleteGroup(sub.ID); err != nil {
		t.Fatalf("DeleteGroup(sub) should succeed once empty: %v", err)
	}
	if err := reopened.DeleteGroup(work.ID); err != nil {
		t.Fatalf("DeleteGroup(work) should succeed once empty: %v", err)
	}
}

// TestExportForMigrationPreservesGroupTreeWithPerGroupKeys — follow-up taska
// 011 (password-manager-desktop/tasks/todo/011-local-vault-groups.md):
// migracja do organizacji online musi zachować drzewo grup zamiast
// spłaszczać wszystko do jednego roota, a każda podgrupa musi dostać WŁASNY,
// świeżo wygenerowany group_key (organizacja online, w przeciwieństwie do
// lokalnego pliku, nie dzieli jednego group_key między grupami).
func TestExportForMigrationPreservesGroupTreeWithPerGroupKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")
	v, err := Create(path, "My Vault", "pw")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	work, err := v.CreateGroup("Work", "")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, err := v.AddSecret("account", "Root Secret", "", "", "", false, []byte("root-plaintext")); err != nil {
		t.Fatalf("AddSecret(root): %v", err)
	}
	if _, err := v.AddSecret("account", "Work Secret", "", "", work.ID, false, []byte("work-plaintext")); err != nil {
		t.Fatalf("AddSecret(work): %v", err)
	}

	pubKey, privKey, rootWrapped, groups, secrets, err := v.ExportForMigration()
	if err != nil {
		t.Fatalf("ExportForMigration: %v", err)
	}
	if len(groups) != 1 || groups[0].LocalID != work.ID || groups[0].ParentLocalID != "" {
		t.Fatalf("unexpected groups: %+v", groups)
	}
	if groups[0].GroupKeySelfWrapped == "" || groups[0].GroupKeySelfWrapped == rootWrapped {
		t.Fatalf("subgroup should get its own, different self-wrapped key, got %q (root %q)", groups[0].GroupKeySelfWrapped, rootWrapped)
	}

	var rootSecret, workSecret *MigrationSecret
	for i := range secrets {
		switch secrets[i].Title {
		case "Root Secret":
			rootSecret = &secrets[i]
		case "Work Secret":
			workSecret = &secrets[i]
		}
	}
	if rootSecret == nil || rootSecret.GroupLocalID != "" {
		t.Fatalf("root secret unexpected: %+v", rootSecret)
	}
	if workSecret == nil || workSecret.GroupLocalID != work.ID {
		t.Fatalf("work secret unexpected: %+v", workSecret)
	}

	// Root secret musi się nadal odszyfrować pod ISTNIEJĄCYM group_key
	// pliku (rootWrapped/v.groupKey) — migracja rootowego sekretu nie
	// zmienia jego klucza.
	rootGroupKeyHex, err := pgpcrypto.DecryptArmoredMessageWithPassphrase(rootWrapped, privKey, "pw")
	if err != nil {
		t.Fatalf("decrypt root group key: %v", err)
	}
	rootRawKey, err := decodeGroupKey(rootGroupKeyHex)
	if err != nil {
		t.Fatalf("decode root group key: %v", err)
	}
	rootPlain, err := decryptRaw(rootRawKey, rootSecret.Ciphertext, rootSecret.GroupEncryptedSecretKey)
	if err != nil {
		t.Fatalf("decrypt root secret: %v", err)
	}
	if rootPlain != "root-plaintext" {
		t.Fatalf("root plaintext = %q, want %q", rootPlain, "root-plaintext")
	}

	// Work secret musi się odszyfrować pod NOWYM group_key podgrupy — a NIE
	// pod v.groupKey pliku (dowód że faktycznie użyto osobnego klucza).
	workGroupKeyHex, err := pgpcrypto.DecryptArmoredMessageWithPassphrase(groups[0].GroupKeySelfWrapped, privKey, "pw")
	if err != nil {
		t.Fatalf("decrypt work group key: %v", err)
	}
	workRawKey, err := decodeGroupKey(workGroupKeyHex)
	if err != nil {
		t.Fatalf("decode work group key: %v", err)
	}
	workPlain, err := decryptRaw(workRawKey, workSecret.Ciphertext, workSecret.GroupEncryptedSecretKey)
	if err != nil {
		t.Fatalf("decrypt work secret: %v", err)
	}
	if workPlain != "work-plaintext" {
		t.Fatalf("work plaintext = %q, want %q", workPlain, "work-plaintext")
	}
	if _, err := decryptRaw(rootRawKey, workSecret.Ciphertext, workSecret.GroupEncryptedSecretKey); err == nil {
		t.Fatal("work secret should NOT decrypt under the root's group key")
	}
	if pubKey == "" {
		t.Fatal("expected non-empty public key")
	}
}

func TestGroupDepthLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")
	v, err := Create(path, "My Vault", "pw")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	parentID := ""
	for i := 0; i < maxGroupDepth; i++ {
		g, err := v.CreateGroup("g", parentID)
		if err != nil {
			t.Fatalf("CreateGroup depth %d: %v", i, err)
		}
		parentID = g.ID
	}
	if _, err := v.CreateGroup("too deep", parentID); err == nil {
		t.Fatal("CreateGroup beyond maxGroupDepth should fail")
	}
}

// TestDeleteSecret — TASK-013 follow-up (MCP delete_secret): usuwa jeden
// sekret bez ruszania reszty, roundtrip przez dysk, i odrzuca nieznane ID.
func TestDeleteSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")
	v, err := Create(path, "My Vault", "pw")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	keep, err := v.AddSecret("account", "Keep", "", "", "", false, []byte(`{"password":"a"}`))
	if err != nil {
		t.Fatalf("AddSecret(keep): %v", err)
	}
	gone, err := v.AddSecret("account", "Gone", "", "", "", false, []byte(`{"password":"b"}`))
	if err != nil {
		t.Fatalf("AddSecret(gone): %v", err)
	}

	if err := v.DeleteSecret("nope"); err == nil {
		t.Fatal("DeleteSecret with unknown id should fail")
	}
	if err := v.DeleteSecret(gone.ID); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	reopened, err := Unlock(path, "pw")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	secrets, err := reopened.ListSecrets()
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(secrets) != 1 || secrets[0].ID != keep.ID {
		t.Fatalf("unexpected secrets after DeleteSecret+reopen: %+v", secrets)
	}
}

// TestMoveGroup — TASK-013 follow-up (MCP move_group): reparenting happy
// path + roundtrip, i wszystkie odrzucone przypadki (nieznana grupa/rodzic,
// samo-rodzicielstwo, przeniesienie w swoje własne poddrzewo, przekroczenie
// maxGroupDepth liczone dla najgłębszego potomka przenoszonego poddrzewa).
func TestMoveGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")
	v, err := Create(path, "My Vault", "pw")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	a, err := v.CreateGroup("A", "")
	if err != nil {
		t.Fatalf("CreateGroup(A): %v", err)
	}
	b, err := v.CreateGroup("B", "")
	if err != nil {
		t.Fatalf("CreateGroup(B): %v", err)
	}
	aChild, err := v.CreateGroup("A-child", a.ID)
	if err != nil {
		t.Fatalf("CreateGroup(A-child): %v", err)
	}

	if err := v.MoveGroup("nope", ""); err == nil {
		t.Fatal("MoveGroup with unknown id should fail")
	}
	if err := v.MoveGroup(a.ID, "nope"); err == nil {
		t.Fatal("MoveGroup to unknown parent should fail")
	}
	if err := v.MoveGroup(a.ID, a.ID); err == nil {
		t.Fatal("MoveGroup onto itself should fail")
	}
	if err := v.MoveGroup(a.ID, aChild.ID); err == nil {
		t.Fatal("MoveGroup into own descendant should fail")
	}

	// Happy path: A (z A-child pod spodem) przenosi się pod B.
	if err := v.MoveGroup(a.ID, b.ID); err != nil {
		t.Fatalf("MoveGroup(A -> under B): %v", err)
	}

	reopened, err := Unlock(path, "pw")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	found := map[string]string{}
	for _, g := range reopened.ListGroups() {
		found[g.ID] = g.ParentID
	}
	if found[a.ID] != b.ID {
		t.Fatalf("A.ParentID after move+reopen = %q, want %q", found[a.ID], b.ID)
	}
	if found[aChild.ID] != a.ID {
		t.Fatalf("A-child.ParentID should be unchanged, got %q", found[aChild.ID])
	}

	// Głębokość teraz: root(0) -> B(1) -> A(2) -> A-child(3). Dobudowujemy
	// A-grandchild pod A-child, więc poddrzewo A ma wysokość 2 (A -> A-child
	// -> A-grandchild). Osobno budujemy łańcuch P1->P2->P3 o głębokości 3, i
	// próbujemy przenieść CAŁE poddrzewo A pod P3 — najgłębszy potomek
	// wylądowałby na głębokości 3+1+2=6, ponad maxGroupDepth(4), więc musi
	// się nie udać, mimo że sama A (bez potomków) zmieściłaby się bez
	// problemu.
	if _, err := reopened.CreateGroup("A-grandchild", aChild.ID); err != nil {
		t.Fatalf("CreateGroup(A-grandchild): %v", err)
	}
	p1, err := reopened.CreateGroup("P1", "")
	if err != nil {
		t.Fatalf("CreateGroup(P1): %v", err)
	}
	p2, err := reopened.CreateGroup("P2", p1.ID)
	if err != nil {
		t.Fatalf("CreateGroup(P2): %v", err)
	}
	p3, err := reopened.CreateGroup("P3", p2.ID)
	if err != nil {
		t.Fatalf("CreateGroup(P3): %v", err)
	}
	if err := reopened.MoveGroup(a.ID, p3.ID); err == nil {
		t.Fatal("MoveGroup should fail when a descendant would exceed maxGroupDepth")
	}
}

func TestHasMasterPassword(t *testing.T) {
	dir := t.TempDir()
	withPassword := filepath.Join(dir, "pw.sharqey")
	if _, err := Create(withPassword, "pw", "master"); err != nil {
		t.Fatal(err)
	}
	if ok, err := HasMasterPassword(withPassword); err != nil || !ok {
		t.Fatalf("password database: ok=%v err=%v", ok, err)
	}

	kp, err := pgpcrypto.GenerateEphemeralKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyOnly := filepath.Join(dir, "key.sharqey")
	if _, err := CreateWithExternalKey(keyOnly, "key", kp.PublicKeyArmored); err != nil {
		t.Fatal(err)
	}
	if ok, err := HasMasterPassword(keyOnly); err != nil || ok {
		t.Fatalf("external-key database: ok=%v err=%v", ok, err)
	}

	if _, err := HasMasterPassword(filepath.Join(dir, "missing.sharqey")); err == nil {
		t.Fatal("missing file: want error")
	}
}
