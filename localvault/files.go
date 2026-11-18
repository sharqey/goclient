package localvault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sharqey/goclient/filesecret"
)

// Sekrety typu "file" (format_version 5, patrz FormatVersion).

// TypeFile — secretEnvelope.Type sekretu-pliku (ta sama nazwa co na serwerze).
const TypeFile = "file"

// MaxFileSize — limit na jeden plik. Blob leży inline w JSON-ie vaulta (+33%
// na base64), a cały vault jest trzymany w pamięci i przepisywany przy
// każdym zapisie. Certy i provisioning profile to kilkanaście KB.
const MaxFileSize = 5 << 20

// VaultSizeWarning — powyżej tego rozmiaru pliku vaulta appki powinny
// ostrzec usera (nie blokować): każdy zapis przepisuje całość, a iCloud/git
// synchronizują cały plik.
const VaultSizeWarning = 20 << 20

func hasFileBlobs(f file) bool {
	for _, rec := range f.Secrets {
		if rec.FileBlob != "" {
			return true
		}
	}
	return false
}

// secretView — publiczny widok rekordu. Dla pliku dokłada nazwę, typ MIME i
// rozmiar z metadanych, nigdy file_key.
func secretView(rec secretRecord, env secretEnvelope) Secret {
	s := Secret{ID: rec.ID, Type: env.Type, Title: rec.Title, Username: env.Username, URL: env.URL, HasTOTP: env.HasTOTP, GroupID: rec.GroupID}
	if env.Type == TypeFile {
		var m filesecret.Metadata
		if json.Unmarshal([]byte(env.Content), &m) == nil {
			s.Filename, s.Mime, s.Size = m.Filename, m.Mime, m.Size
		}
	}
	return s
}

// encryptFile — świeży file_key i blob (filesecret.EncryptBlob, ten sam
// format co upload na serwer), metadane w kopercie, blob w FileBlob.
func (v *Vault) encryptFile(title, filename string, data []byte) (secretRecord, error) {
	if len(data) > MaxFileSize {
		return secretRecord{}, fmt.Errorf("plik ma %d B, limit w lokalnym vaulcie to %d B", len(data), MaxFileSize)
	}
	blob, fileKey, err := filesecret.EncryptBlob(data)
	if err != nil {
		return secretRecord{}, fmt.Errorf("szyfrowanie pliku nieudane: %w", err)
	}
	meta := filesecret.NewMetadata(filename, data, fileKey)
	rec, err := v.encryptEnvelope(title, secretEnvelope{Type: TypeFile, Content: meta.JSON()})
	if err != nil {
		return secretRecord{}, err
	}
	rec.FileBlob = base64.StdEncoding.EncodeToString(blob)
	return rec, nil
}

// AddFile dodaje nowy sekret typu plik. filename trafia do metadanych (bez
// katalogu), title jest jawnym tytułem rekordu jak dla każdego sekretu.
func (v *Vault) AddFile(title, groupID, filename string, data []byte) (Secret, error) {
	rec, err := v.encryptFile(title, filename, data)
	if err != nil {
		return Secret{}, err
	}
	id, err := randomID()
	if err != nil {
		return Secret{}, fmt.Errorf("generowanie ID sekretu nieudane: %w", err)
	}
	rec.ID = id
	rec.GroupID = groupID
	if err := v.mutate(func() error {
		if groupID != "" {
			if _, ok := v.findGroup(groupID); !ok {
				return fmt.Errorf("nieznana grupa %q", groupID)
			}
		}
		v.f.Secrets = append(v.f.Secrets, rec)
		return nil
	}); err != nil {
		return Secret{}, err
	}
	env, err := v.decryptSecretRecord(rec)
	if err != nil {
		return Secret{}, err
	}
	return secretView(rec, env), nil
}

// ReplaceFile podmienia zawartość istniejącego sekretu-pliku (nowy file_key
// i blob), zachowując ID, tytuł i grupę.
func (v *Vault) ReplaceFile(id, filename string, data []byte) (Secret, error) {
	var out Secret
	err := v.mutate(func() error {
		for i := range v.f.Secrets {
			old := v.f.Secrets[i]
			if old.ID != id {
				continue
			}
			env, err := v.decryptSecretRecord(old)
			if err != nil {
				return fmt.Errorf("odczyt obecnej treści sekretu nieudany: %w", err)
			}
			if env.Type != TypeFile {
				return fmt.Errorf("sekret %q nie jest plikiem (typ %q)", id, env.Type)
			}
			rec, err := v.encryptFile(old.Title, filename, data)
			if err != nil {
				return err
			}
			rec.ID = old.ID
			rec.GroupID = old.GroupID
			v.f.Secrets[i] = rec
			newEnv, err := v.decryptSecretRecord(rec)
			if err != nil {
				return err
			}
			out = secretView(rec, newEnv)
			return nil
		}
		return fmt.Errorf("nieznany sekret %q", id)
	})
	return out, err
}

// ReadFile odszyfrowuje sekret-plik: zwraca jego widok (z nazwą pliku) i
// bajty. Rozmiar jest sprawdzany z metadanymi, tak jak filesecret.Download.
func (v *Vault) ReadFile(id string) (Secret, []byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, rec := range v.f.Secrets {
		if rec.ID != id {
			continue
		}
		env, err := v.decryptSecretRecord(rec)
		if err != nil {
			return Secret{}, nil, fmt.Errorf("odszyfrowanie %q nieudane: %w", id, err)
		}
		if env.Type != TypeFile {
			return Secret{}, nil, fmt.Errorf("sekret %q nie jest plikiem (typ %q)", id, env.Type)
		}
		meta, err := filesecret.ParseMetadata(env.Content)
		if err != nil {
			return Secret{}, nil, err
		}
		blob, err := base64.StdEncoding.DecodeString(rec.FileBlob)
		if err != nil {
			return Secret{}, nil, fmt.Errorf("file_blob sekretu %q uszkodzony: %w", id, err)
		}
		data, err := filesecret.DecryptBlob(blob, meta.FileKey)
		if err != nil {
			return Secret{}, nil, fmt.Errorf("odszyfrowanie pliku %q nieudane: %w", id, err)
		}
		if int64(len(data)) != meta.Size {
			return Secret{}, nil, fmt.Errorf("rozmiar pliku %q (%d B) nie zgadza się z metadanymi (%d B)", id, len(data), meta.Size)
		}
		return secretView(rec, env), data, nil
	}
	return Secret{}, nil, fmt.Errorf("nieznany sekret %q", id)
}

// Info — to, co widać w pliku BEZ odblokowania: wersja formatu, recipienci
// (bez surowej kryptografii) i jawne tytuły sekretów.
type Info struct {
	FormatVersion int
	Recipients    []Recipient
	Titles        []string
}

// Inspect czyta jawne pola pliku bez hasła i bez migracji (np. `sharqey
// local recipients ls` — audyt "kto może otworzyć ten plik").
func Inspect(path string) (Info, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Info{}, fmt.Errorf("odczyt pliku vaulta nieudany: %w", err)
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return Info{}, fmt.Errorf("plik vaulta uszkodzony: %w", err)
	}
	info := Info{FormatVersion: f.FormatVersion}
	for _, r := range f.Recipients {
		info.Recipients = append(info.Recipients, Recipient{ID: r.ID, Label: r.Label, Fingerprint: r.Fingerprint, IsSelf: r.IsSelf})
	}
	for _, s := range f.Secrets {
		info.Titles = append(info.Titles, s.Title)
	}
	return info, nil
}
