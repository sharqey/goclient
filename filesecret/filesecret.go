// Package filesecret — sekrety typu "file" (password-manager
// tasks/todo/075): szyfrowanie pliku i protokół upload/download.
//
// Format (wspólny dla WSZYSTKICH klientów — web/rozszerzenie, desktop,
// CLI, flutter — zmiana tu = zmiana wszędzie):
//
//	file_key   = losowe 32B
//	blob       = IV(12) || AES-256-GCM(file_key, plik)   (surowe bajty, nie base64)
//	metadane   = {"v":1,"filename":…,"mime":…,"size":<bajty plaintextu>,"file_key":"<hex>"}
//
// Metadane (JSON) są zwykłym plaintextem sekretu — szyfrowane jak każdy
// inny sekret (pgpcrypto.EncryptWithGroupKey / EncryptOwnerSecret) i
// zapisywane jako jego ciphertext. Dzięki temu Move/rotacja/share
// przeszyfrowują tylko metadane, nigdy bloba.
package filesecret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"path/filepath"
	"strings"

	"github.com/sharqey/goclient/apiclient"
)

// FormatV1 — jednorazowy AES-GCM całego pliku w pamięci.
const FormatV1 = 1

type Metadata struct {
	V        int    `json:"v"`
	Filename string `json:"filename"`
	Mime     string `json:"mime,omitempty"`
	Size     int64  `json:"size"`
	FileKey  string `json:"file_key"`
}

// ParseMetadata — plaintext sekretu typu "file" -> Metadata.
func ParseMetadata(plaintext string) (Metadata, error) {
	var m Metadata
	if err := json.Unmarshal([]byte(plaintext), &m); err != nil {
		return m, fmt.Errorf("file metadata: %w", err)
	}
	if m.V != FormatV1 {
		return m, fmt.Errorf("unsupported file secret format v%d — update the client", m.V)
	}
	if m.FileKey == "" {
		return m, fmt.Errorf("file metadata has no file_key")
	}
	return m, nil
}

// JSON — metadane jako plaintext sekretu do zaszyfrowania.
func (m Metadata) JSON() string {
	b, _ := json.Marshal(m)
	return string(b)
}

func newGCM(keyHex string) (cipher.AEAD, error) {
	key, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("invalid file key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// EncryptBlob — nowy losowy file_key, blob = IV || AES-GCM(file_key, data).
func EncryptBlob(data []byte) (blob []byte, fileKeyHex string, err error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, "", err
	}
	fileKeyHex = hex.EncodeToString(key)
	gcm, err := newGCM(fileKeyHex)
	if err != nil {
		return nil, "", err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, "", err
	}
	return gcm.Seal(iv, iv, data, nil), fileKeyHex, nil
}

func DecryptBlob(blob []byte, fileKeyHex string) ([]byte, error) {
	gcm, err := newGCM(fileKeyHex)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, fmt.Errorf("blob too short")
	}
	out, err := gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt file: %w", err)
	}
	return out, nil
}

// Upload szyfruje plik, rejestruje blob w groupID i wysyła go. Zwraca
// blobID i metadane — wołający szyfruje metadane.JSON() jako ciphertext
// sekretu i woła CreateSecret{Type:"file", BlobID} albo UpdateSecret{BlobID}.
func Upload(api *apiclient.Client, groupID, filename string, data []byte) (blobID string, meta Metadata, err error) {
	blob, fileKey, err := EncryptBlob(data)
	if err != nil {
		return "", meta, err
	}
	up, err := api.CreateBlob(groupID, int64(len(blob)))
	if err != nil {
		return "", meta, err
	}
	if _, err := api.DoPresigned(up.Upload, blob); err != nil {
		return "", meta, err
	}
	return up.BlobID, NewMetadata(filename, data, fileKey), nil
}

// NewMetadata — metadane dla świeżo zaszyfrowanego pliku (EncryptBlob).
// Wspólne dla uploadu na serwer i lokalnego vaulta (localvault.AddFile),
// żeby oba zapisywały identyczny kształt.
func NewMetadata(filename string, data []byte, fileKeyHex string) Metadata {
	mt := mime.TypeByExtension(filepath.Ext(filename))
	if mt == "" {
		mt = "application/octet-stream"
	}
	return Metadata{V: FormatV1, Filename: filepath.Base(filename), Mime: mt, Size: int64(len(data)), FileKey: fileKeyHex}
}

// Download pobiera i odszyfrowuje plik; metadataPlaintext to odszyfrowany
// ciphertext sekretu (patrz ParseMetadata).
func Download(api *apiclient.Client, groupID, secretID, metadataPlaintext string) ([]byte, Metadata, error) {
	meta, err := ParseMetadata(metadataPlaintext)
	if err != nil {
		return nil, meta, err
	}
	dl, err := api.FileDownloadURL(groupID, secretID)
	if err != nil {
		return nil, meta, err
	}
	blob, err := api.DoPresigned(dl.Download, nil)
	if err != nil {
		return nil, meta, err
	}
	data, err := DecryptBlob(blob, meta.FileKey)
	if err != nil {
		return nil, meta, err
	}
	if int64(len(data)) != meta.Size {
		return nil, meta, fmt.Errorf("decrypted file size %d does not match metadata %d", len(data), meta.Size)
	}
	return data, meta, nil
}
