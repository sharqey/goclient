package localvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sharqey/goclient/filesecret"
)

func readRawFile(t *testing.T, path string) file {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestAddFileRoundtripAndVersionBump(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")
	v, err := Create(path, "My Vault", "pw")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := v.AddSecret("env", "TOKEN", "", "", "", false, []byte(`{"value":"x"}`)); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}
	if got := readRawFile(t, path).FormatVersion; got != FormatVersionRecipients {
		t.Fatalf("vault bez plików: format_version = %d, want %d", got, FormatVersionRecipients)
	}

	data := []byte("-----BEGIN CERT-----\x00\x01binary\xff")
	s, err := v.AddFile("runner.p12", "", "/some/dir/runner.p12", data)
	if err != nil {
		t.Fatalf("AddFile: %v", err)
	}
	if s.Type != TypeFile || s.Filename != "runner.p12" || s.Size != int64(len(data)) {
		t.Fatalf("AddFile view = %+v", s)
	}

	raw := readRawFile(t, path)
	if raw.FormatVersion != FormatVersionFiles {
		t.Fatalf("format_version = %d, want %d", raw.FormatVersion, FormatVersionFiles)
	}
	var rec secretRecord
	for _, r := range raw.Secrets {
		if r.ID == s.ID {
			rec = r
		}
	}
	if rec.FileBlob == "" || rec.Title != "runner.p12" {
		t.Fatalf("rekord na dysku = %+v", rec)
	}
	// Blob w formacie serwera: odszyfrowuje się file_key z metadanych
	// w kopercie, bez żadnej lokalnej warstwy pośrodku.
	env, err := v.decryptSecretRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := filesecret.ParseMetadata(env.Content)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := base64.StdEncoding.DecodeString(rec.FileBlob)
	if plain, err := filesecret.DecryptBlob(blob, meta.FileKey); err != nil || !bytes.Equal(plain, data) {
		t.Fatalf("DecryptBlob = %q, %v", plain, err)
	}
	if strings.Contains(string(mustRead(t, path)), meta.FileKey) {
		t.Fatal("file_key jawnym tekstem w pliku vaulta")
	}

	v2, err := Unlock(path, "pw")
	if err != nil {
		t.Fatalf("Unlock v5: %v", err)
	}
	got, gotData, err := v2.ReadFile(s.ID)
	if err != nil || !bytes.Equal(gotData, data) || got.Filename != "runner.p12" {
		t.Fatalf("ReadFile = %+v, %q, %v", got, gotData, err)
	}
	list, err := v2.ListSecrets()
	if err != nil || len(list) != 2 {
		t.Fatalf("ListSecrets = %+v, %v", list, err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFileSecretGuards(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")
	v, err := Create(path, "My Vault", "pw")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	s, err := v.AddFile("cert", "", "cert.pem", []byte("abc"))
	if err != nil {
		t.Fatalf("AddFile: %v", err)
	}
	if _, _, err := v.DecryptSecret(s.ID); err == nil {
		t.Fatal("DecryptSecret na pliku zwróciło metadane z file_key, want error")
	}
	if _, err := v.AddSecret(TypeFile, "x", "", "", "", false, []byte("{}")); err == nil {
		t.Fatal("AddSecret(type file) bez bloba przeszło, want error")
	}
	if err := v.UpdateSecret(s.ID, "cert", "", "", "", false, []byte(`{}`)); err == nil {
		t.Fatal("UpdateSecret z plaintextem na pliku przeszło, want error")
	}
	if _, err := v.AddFile("big", "", "big.bin", make([]byte, MaxFileSize+1)); err == nil {
		t.Fatal("AddFile ponad MaxFileSize przeszło, want error")
	}
	if _, _, _, _, _, err := v.ExportForMigration(); err == nil {
		t.Fatal("ExportForMigration z plikiem przeszło, want error")
	}

	// Zmiana samych metadanych (tytuł) nie może zgubić bloba.
	if err := v.UpdateSecret(s.ID, "cert renamed", "", "", "", false, nil); err != nil {
		t.Fatalf("UpdateSecret metadata-only: %v", err)
	}
	got, data, err := v.ReadFile(s.ID)
	if err != nil || string(data) != "abc" || got.Title != "cert renamed" {
		t.Fatalf("po rename: %+v, %q, %v", got, data, err)
	}
}

func TestReplaceFileKeepsIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")
	v, err := Create(path, "My Vault", "pw")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	g, err := v.CreateGroup("ios", "")
	if err != nil {
		t.Fatal(err)
	}
	s, err := v.AddFile("profile", g.ID, "old.mobileprovision", []byte("old"))
	if err != nil {
		t.Fatal(err)
	}
	oldBlob := readRawFile(t, path).Secrets[0].FileBlob
	r, err := v.ReplaceFile(s.ID, "new.mobileprovision", []byte("new content"))
	if err != nil {
		t.Fatalf("ReplaceFile: %v", err)
	}
	if r.ID != s.ID || r.Title != "profile" || r.GroupID != g.ID || r.Filename != "new.mobileprovision" {
		t.Fatalf("ReplaceFile view = %+v", r)
	}
	if readRawFile(t, path).Secrets[0].FileBlob == oldBlob {
		t.Fatal("blob się nie zmienił")
	}
	if _, data, err := v.ReadFile(s.ID); err != nil || string(data) != "new content" {
		t.Fatalf("ReadFile = %q, %v", data, err)
	}

	env, err := v.AddSecret("env", "E", "", "", "", false, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.ReplaceFile(env.ID, "x", []byte("x")); err == nil {
		t.Fatal("ReplaceFile na sekrecie env przeszło, want error")
	}
}

// TestMutationAfterExternalFileAdd — inny proces dodał plik (dysk: v5), a ta
// instancja otworzyła vault jeszcze jako v4. Jej zapis nie może ani odmówić,
// ani zgubić bloba, ani cofnąć wersji.
func TestMutationAfterExternalFileAdd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")
	a, err := Create(path, "My Vault", "pw")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	b, err := Unlock(path, "pw")
	if err != nil {
		t.Fatal(err)
	}
	s, err := b.AddFile("f", "", "f.txt", []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddSecret("env", "E", "", "", "", false, []byte(`{}`)); err != nil {
		t.Fatalf("AddSecret po zewnętrznym AddFile: %v", err)
	}
	raw := readRawFile(t, path)
	if raw.FormatVersion != FormatVersionFiles || len(raw.Secrets) != 2 {
		t.Fatalf("na dysku: v%d, %d sekretów", raw.FormatVersion, len(raw.Secrets))
	}
	if _, data, err := a.ReadFile(s.ID); err != nil || string(data) != "data" {
		t.Fatalf("ReadFile = %q, %v", data, err)
	}
}

func TestInspectWithoutUnlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sharqey")
	v, err := Create(path, "My Vault", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.AddSecret("env", "E", "", "", "", false, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	info, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.FormatVersion != FormatVersionRecipients || len(info.Recipients) != 1 || !info.Recipients[0].IsSelf || len(info.Titles) != 1 || info.Titles[0] != "E" {
		t.Fatalf("Inspect = %+v", info)
	}
}

// Golden file — wzorcowy vault v5 dla implementacji w innych językach
// (flutter, Swift extension, Android). Oczekiwane wartości w
// v5-file.expected.json. Regeneracja: go test ./localvault -run Golden -update-golden
var updateGolden = flag.Bool("update-golden", false, "regenerate testdata/v5-file.sharqey")

type goldenExpected struct {
	Password      string         `json:"password"`
	VaultName     string         `json:"vault_name"`
	FormatVersion int            `json:"format_version"`
	Groups        []Group        `json:"groups"`
	Secrets       []goldenSecret `json:"secrets"`
}

type goldenSecret struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Type    string `json:"type"`
	GroupID string `json:"group_id"`
	// Content — plaintext koperty dla sekretów innych niż file.
	Content string `json:"content,omitempty"`
	// Pliki: metadane bez file_key + oczekiwane bajty.
	Filename      string `json:"filename,omitempty"`
	Mime          string `json:"mime,omitempty"`
	Size          int64  `json:"size,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	ContentBase64 string `json:"content_base64,omitempty"`
}

const goldenPath = "testdata/v5-file.sharqey"
const goldenExpectedPath = "testdata/v5-file.expected.json"

func TestGoldenV5File(t *testing.T) {
	if *updateGolden {
		writeGolden(t)
	}
	var exp goldenExpected
	if err := json.Unmarshal(mustRead(t, goldenExpectedPath), &exp); err != nil {
		t.Fatal(err)
	}
	// Kopia: Unlock v5 nie zapisuje, ale test nie może zależeć od tego,
	// że golden zostanie nietknięty.
	path := filepath.Join(t.TempDir(), "golden.sharqey")
	if err := os.WriteFile(path, mustRead(t, goldenPath), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := Unlock(path, exp.Password)
	if err != nil {
		t.Fatalf("Unlock golden: %v", err)
	}
	if v.VaultName() != exp.VaultName || v.f.FormatVersion != exp.FormatVersion {
		t.Fatalf("name=%q v=%d", v.VaultName(), v.f.FormatVersion)
	}
	if groups := v.ListGroups(); len(groups) != len(exp.Groups) || groups[0] != exp.Groups[0] {
		t.Fatalf("groups = %+v", groups)
	}
	list, err := v.ListSecrets()
	if err != nil || len(list) != len(exp.Secrets) {
		t.Fatalf("ListSecrets = %+v, %v", list, err)
	}
	for _, es := range exp.Secrets {
		if es.Type == TypeFile {
			s, data, err := v.ReadFile(es.ID)
			if err != nil {
				t.Fatalf("ReadFile %s: %v", es.Title, err)
			}
			sum := sha256.Sum256(data)
			if s.Title != es.Title || s.GroupID != es.GroupID || s.Filename != es.Filename || s.Mime != es.Mime || s.Size != es.Size ||
				hex.EncodeToString(sum[:]) != es.SHA256 || base64.StdEncoding.EncodeToString(data) != es.ContentBase64 {
				t.Fatalf("plik %s: %+v", es.Title, s)
			}
			continue
		}
		s, content, err := v.DecryptSecret(es.ID)
		if err != nil || s.Title != es.Title || s.Type != es.Type || s.GroupID != es.GroupID || string(content) != es.Content {
			t.Fatalf("sekret %s: %+v %q %v", es.Title, s, content, err)
		}
	}
	if !bytes.Equal(mustRead(t, path), mustRead(t, goldenPath)) {
		t.Fatal("Unlock pliku v5 zmienił go na dysku")
	}
}

func writeGolden(t *testing.T) {
	t.Helper()
	exp := goldenExpected{Password: "sharqey-golden-v5", VaultName: "Golden v5", FormatVersion: FormatVersionFiles}
	_ = os.Remove(goldenPath)
	v, err := Create(goldenPath, exp.VaultName, exp.Password)
	if err != nil {
		t.Fatal(err)
	}
	g, err := v.CreateGroup("ios", "")
	if err != nil {
		t.Fatal(err)
	}
	exp.Groups = []Group{g}
	envContent := `{"value":"p12-password-123","notes":""}`
	e, err := v.AddSecret("env", "P12_PASSWORD", "", "", g.ID, false, []byte(envContent))
	if err != nil {
		t.Fatal(err)
	}
	exp.Secrets = append(exp.Secrets, goldenSecret{ID: e.ID, Title: e.Title, Type: e.Type, GroupID: g.ID, Content: envContent})
	data := []byte("Sharqey golden file\n\x00\x01\x02\xfe\xff binary tail\n")
	f, err := v.AddFile("runner.p12", g.ID, "runner.p12", data)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	exp.Secrets = append(exp.Secrets, goldenSecret{
		ID: f.ID, Title: f.Title, Type: TypeFile, GroupID: g.ID, Filename: f.Filename, Mime: f.Mime, Size: f.Size,
		SHA256: hex.EncodeToString(sum[:]), ContentBase64: base64.StdEncoding.EncodeToString(data),
	})
	b, _ := json.MarshalIndent(exp, "", "  ")
	if err := os.WriteFile(goldenExpectedPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
