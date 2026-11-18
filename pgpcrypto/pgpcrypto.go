// Package pgpcrypto — kryptografia klienta: generowanie efemerycznych
// kluczy OpenPGP do device-linkingu, deszyfrowanie wiadomości armored, i
// model "group key" (PGP-wrapped AES-256 group key -> AES-GCM secret key ->
// AES-GCM ciphertext) — dokładnie ten sam algorytm co
// extension/src/groupkey.js i internal/device w repo password-manager.
// Wspólne dla wszystkich klientów Go (CLI, desktop) — wydzielone z
// password-manager-desktop/internal/cryptox i cmd/cli/{crypto,keygen}.go,
// które miały dwie niezależne implementacje tego samego algorytmu.
package pgpcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Keypair to efemeryczny keypair OpenPGP wygenerowany lokalnie do jednego
// device-link handshake'u (curve25519, tak jak reszta systemu — patrz
// internal/device/model_test.go w repo password-manager).
type Keypair struct {
	PublicKeyArmored  string
	PrivateKeyArmored string
	entity            *openpgp.Entity
}

// GenerateEphemeralKeypair generuje nowy keypair EdDSA/Curve25519 (podpis +
// automatyczny subkey ECDH do szyfrowania, patrz openpgp.NewEntity).
func GenerateEphemeralKeypair() (*Keypair, error) {
	entity, err := openpgp.NewEntity("Sharqey Device Link", "", "", &packet.Config{
		Algorithm: packet.PubKeyAlgoEdDSA,
	})
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}

	pub, err := serializeArmored("PGP PUBLIC KEY BLOCK", entity.Serialize)
	if err != nil {
		return nil, fmt.Errorf("armor public key: %w", err)
	}
	priv, err := serializeArmored("PGP PRIVATE KEY BLOCK", func(w io.Writer) error {
		return entity.SerializePrivate(w, nil)
	})
	if err != nil {
		return nil, fmt.Errorf("armor private key: %w", err)
	}

	return &Keypair{PublicKeyArmored: pub, PrivateKeyArmored: priv, entity: entity}, nil
}

// GenerateIdentityKeypair generuje NOWY klucz tożsamości organizacji/konta
// (RSA-4096 — dokładnie jak web/templates/auth/setup-key.html:
// openpgp.generateKey({type:'rsa', rsaBits:4096}), NIE Curve25519 jak
// GenerateEphemeralKeypair — to inny algorytm dla innego trust modelu:
// długożyjący klucz do sekretów organizacji, nie jednorazowy handshake).
// Jeśli passphrase != "", prywatny klucz jest nią chroniony przy
// serializacji (PrivateKey.Encrypt) — użyj DecryptArmoredMessageWithPassphrase
// żeby go później odblokować. Pusta passphrase = plaintext, świadomie
// dozwolone (ten sam trade-off co reszta systemu, user może pominąć pole
// w UI — patrz setup-key.html "(recommended)", nie wymagane).
func GenerateIdentityKeypair(email, passphrase string) (*Keypair, error) {
	entity, err := openpgp.NewEntity("Sharqey", "", email, &packet.Config{
		Algorithm: packet.PubKeyAlgoRSA,
		RSABits:   4096,
	})
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}

	if passphrase != "" {
		if err := entity.PrivateKey.Encrypt([]byte(passphrase)); err != nil {
			return nil, fmt.Errorf("encrypt private key: %w", err)
		}
		for _, sub := range entity.Subkeys {
			if sub.PrivateKey != nil {
				if err := sub.PrivateKey.Encrypt([]byte(passphrase)); err != nil {
					return nil, fmt.Errorf("encrypt subkey: %w", err)
				}
			}
		}
	}

	pub, err := serializeArmored("PGP PUBLIC KEY BLOCK", entity.Serialize)
	if err != nil {
		return nil, fmt.Errorf("armor public key: %w", err)
	}
	// SerializePrivateWithoutSigning, NIE SerializePrivate — ta druga zawsze
	// re-podpisuje tożsamości używając klucza prywatnego jako signera
	// (Entity.serializePrivate, reSign=true), co panickuje po
	// PrivateKey.Encrypt() (klucz nie nadaje się już do podpisywania).
	// Re-podpisywanie i tak niepotrzebne — self-signature już powstał
	// poprawnie w NewEntity, zanim cokolwiek zaszyfrowaliśmy.
	priv, err := serializeArmored("PGP PRIVATE KEY BLOCK", func(w io.Writer) error {
		return entity.SerializePrivateWithoutSigning(w, nil)
	})
	if err != nil {
		return nil, fmt.Errorf("armor private key: %w", err)
	}

	return &Keypair{PublicKeyArmored: pub, PrivateKeyArmored: priv, entity: entity}, nil
}

func serializeArmored(blockType string, write func(w io.Writer) error) (string, error) {
	buf := new(bytes.Buffer)
	w, err := armor.Encode(buf, blockType, nil)
	if err != nil {
		return "", err
	}
	if err := write(w); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Fingerprint formatuje fingerprint klucza tak samo jak internal/device.
// ComputeFingerprint (Go, serwer) i formatFingerprintJS (extension) —
// ostatnie 8 hex znaków, "XXXX-XXXX". Liczony LOKALNIE, nigdy przyjmowany od
// serwera, żeby dwa niezależne ekrany dało się wizualnie porównać.
func (k *Keypair) Fingerprint() string {
	return formatFingerprint(k.entity.PrimaryKey.Fingerprint)
}

// FingerprintFromArmoredPublicKey liczy fingerprint z armorowanego klucza
// publicznego — używane do weryfikacji cudzego klucza, symetrycznie z
// internal/device.ComputeFingerprint.
func FingerprintFromArmoredPublicKey(armoredPublicKey string) (string, error) {
	entities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPublicKey))
	if err != nil {
		return "", fmt.Errorf("parse public key: %w", err)
	}
	if len(entities) == 0 || entities[0].PrimaryKey == nil {
		return "", fmt.Errorf("public key has no primary key")
	}
	return formatFingerprint(entities[0].PrimaryKey.Fingerprint), nil
}

// FullFingerprintFromArmoredPublicKey liczy PEŁNY, 40-znakowy hex fingerprint
// (bez skracania przez formatFingerprint) — do automatycznej weryfikacji
// klucza pobranego z zewnętrznego źródła (lokalny GPG keyring, keyserver)
// względem fingerprintu, który user podał z zaufanego, osobnego kanału.
// Skrócona forma (FingerprintFromArmoredPublicKey, 32 bity) wystarcza do
// wyświetlenia, ale NIE do takiego porównania — kolizja na 32 bitach jest
// praktycznie osiągalna, na 160 nie.
func FullFingerprintFromArmoredPublicKey(armoredPublicKey string) (string, error) {
	entities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPublicKey))
	if err != nil {
		return "", fmt.Errorf("parse public key: %w", err)
	}
	if len(entities) == 0 || entities[0].PrimaryKey == nil {
		return "", fmt.Errorf("public key has no primary key")
	}
	return strings.ToUpper(hex.EncodeToString(entities[0].PrimaryKey.Fingerprint)), nil
}

func formatFingerprint(fp []byte) string {
	full := strings.ToUpper(hex.EncodeToString(fp))
	short := full
	if len(full) > 8 {
		short = full[len(full)-8:]
	}
	return short[:4] + "-" + short[4:]
}

// PublicKeyFromPrivateKeyArmored wyciąga zarmorowany klucz publiczny z
// zarmorowanego materiału prywatnego — odpowiednik openpgp.js
// `privateKey.toPublic()` (patrz extension/background.js:
// handleGenerateGroupKey), używany tam żeby nigdy nie trzeba było
// przechowywać klucza publicznego osobno od prywatnego. go-crypto po
// ReadArmoredKeyRing wypełnia część publiczną (PrimaryKey/Subkeys[].PublicKey)
// entity nawet dla private-key-ringa, więc zwykłe entity.Serialize() (ta sama
// funkcja, której już używa GenerateIdentityKeypair) wystarcza.
func PublicKeyFromPrivateKeyArmored(armoredPrivateKey string) (string, error) {
	entities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPrivateKey))
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	if len(entities) == 0 {
		return "", fmt.Errorf("private key ring is empty")
	}
	pub, err := serializeArmored("PGP PUBLIC KEY BLOCK", entities[0].Serialize)
	if err != nil {
		return "", fmt.Errorf("armor public key: %w", err)
	}
	return pub, nil
}

// PlaintextPrivateKeyArmored odblokowuje armorowany klucz prywatny daną
// passphrase (no-op jeśli klucz nią nie jest chroniony) i zwraca go
// PONOWNIE zserializowany BEZ ochrony passphrase. Używane wyłącznie do
// przygotowania klucza do wysłania device-linkiem: protokół wymaga, żeby
// klucze przekazywane tą drogą były zawsze plaintext (CLIENT_SPEC.md
// "Device linking"), tak samo jak klucze, które B odbiera — żeby B mógł ich
// użyć bez znajomości passphrase A. SerializePrivateWithoutSigning z tego
// samego powodu co GenerateIdentityKeypair: re-podpisywanie panikuje po
// odblokowaniu klucza.
func PlaintextPrivateKeyArmored(armoredPrivateKey, passphrase string) (string, error) {
	entities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPrivateKey))
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	if len(entities) == 0 {
		return "", fmt.Errorf("private key ring is empty")
	}
	entity := entities[0]
	if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
		if err := entity.PrivateKey.Decrypt([]byte(passphrase)); err != nil {
			return "", fmt.Errorf("nieprawidłowa passphrase klucza: %w", err)
		}
	}
	for _, sub := range entity.Subkeys {
		if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
			if err := sub.PrivateKey.Decrypt([]byte(passphrase)); err != nil {
				return "", fmt.Errorf("nieprawidłowa passphrase subkeya: %w", err)
			}
		}
	}
	return serializeArmored("PGP PRIVATE KEY BLOCK", func(w io.Writer) error {
		return entity.SerializePrivateWithoutSigning(w, nil)
	})
}

// DecryptArmoredMessage odszyfrowuje wiadomość PGP armored kluczem
// prywatnym tego keypaira (device-link blob od urządzenia A).
func (k *Keypair) DecryptArmoredMessage(armoredMessage string) (string, error) {
	return decryptArmoredMessage(armoredMessage, openpgp.EntityList{k.entity})
}

// DecryptArmoredMessageWithKey odszyfrowuje wiadomość PGP armored dowolnym
// armorowanym kluczem prywatnym BEZ passphrase — używane do odszyfrowania
// group_key sekretu kluczem prywatnym organizacji/personal workspace
// odebranym przez device-link (te klucze zawsze przychodzą plaintext,
// świadomy dług — patrz TASK.md). Dla kluczy chronionych passphrase (własny
// klucz konta, patrz password-manager-desktop/TASK-002-full-client.md
// Ustalenie #3) użyj DecryptArmoredMessageWithPassphrase.
func DecryptArmoredMessageWithKey(armoredMessage, armoredPrivateKey string) (string, error) {
	return DecryptArmoredMessageWithPassphrase(armoredMessage, armoredPrivateKey, "")
}

// DecryptArmoredMessageWithPassphrase — jak DecryptArmoredMessageWithKey,
// ale odblokowuje najpierw klucz prywatny (i jego subkeye) daną passphrase,
// jeśli klucz jest nią chroniony (`PrivateKey.Encrypted`) — bezpieczne do
// wywołania z pustą passphrase na kluczu BEZ ochrony (no-op, tak jak robi
// to cmd/cli/crypto.go: decryptOpenPGP, źródło tej logiki).
func DecryptArmoredMessageWithPassphrase(armoredMessage, armoredPrivateKey, passphrase string) (string, error) {
	entities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPrivateKey))
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	for _, e := range entities {
		if e.PrivateKey != nil && e.PrivateKey.Encrypted {
			if err := e.PrivateKey.Decrypt([]byte(passphrase)); err != nil {
				return "", fmt.Errorf("nieprawidłowa passphrase klucza: %w", err)
			}
		}
		for _, sub := range e.Subkeys {
			if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
				if err := sub.PrivateKey.Decrypt([]byte(passphrase)); err != nil {
					return "", fmt.Errorf("nieprawidłowa passphrase subkeya: %w", err)
				}
			}
		}
	}
	return decryptArmoredMessage(armoredMessage, entities)
}

func decryptArmoredMessage(armoredMessage string, keyring openpgp.EntityList) (string, error) {
	block, err := armor.Decode(strings.NewReader(armoredMessage))
	if err != nil {
		return "", fmt.Errorf("armor decode: %w", err)
	}
	md, err := openpgp.ReadMessage(block.Body, keyring, nil, nil)
	if err != nil {
		return "", fmt.Errorf("read message: %w", err)
	}
	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", fmt.Errorf("read plaintext: %w", err)
	}
	return string(plaintext), nil
}

// EncryptArmoredMessage szyfruje plaintext armorowanym kluczem PUBLICZNYM —
// odpowiednik gpgEncrypt w extension/background.js. Używane m.in. do
// zaszyfrowania nowo wygenerowanego group key do WŁASNEGO klucza publicznego
// (patrz GenerateEncryptedGroupKey), dokładnie jak web/templates/group/new.html:
// createOrganization() -> window.PM.generateGroupKey.
func EncryptArmoredMessage(plaintext, armoredPublicKey string) (string, error) {
	entities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPublicKey))
	if err != nil {
		return "", fmt.Errorf("parse public key: %w", err)
	}
	return encryptArmoredMessage(plaintext, entities)
}

// Rewrapper przepakowuje wiele wiadomości z jednego klucza prywatnego na
// jeden klucz publiczny (klucze grup gałęzi dla nowego członka), parsując oba
// klucze RAZ — parsowanie z weryfikacją podpisów kosztuje więcej niż samo
// szyfrowanie klucza grupy (odpowiednik SHARE_GROUP_KEYS w
// extension/background.js).
type Rewrapper struct {
	private   openpgp.EntityList
	recipient openpgp.EntityList
}

// NewRewrapper — klucz prywatny bez passphrase (jak
// DecryptArmoredMessageWithKey) i klucz publiczny odbiorcy.
func NewRewrapper(armoredPrivateKey, recipientArmoredPublicKey string) (*Rewrapper, error) {
	private, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	recipient, err := openpgp.ReadArmoredKeyRing(strings.NewReader(recipientArmoredPublicKey))
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return &Rewrapper{private: private, recipient: recipient}, nil
}

// Rewrap odszyfrowuje wiadomość kluczem prywatnym i szyfruje treść dla
// odbiorcy.
func (r *Rewrapper) Rewrap(armoredMessage string) (string, error) {
	plaintext, err := decryptArmoredMessage(armoredMessage, r.private)
	if err != nil {
		return "", err
	}
	return encryptArmoredMessage(plaintext, r.recipient)
}

func encryptArmoredMessage(plaintext string, entities openpgp.EntityList) (string, error) {
	buf := new(bytes.Buffer)
	aw, err := armor.Encode(buf, "PGP MESSAGE", nil)
	if err != nil {
		return "", fmt.Errorf("armor encode: %w", err)
	}
	w, err := openpgp.Encrypt(aw, entities, nil, nil, nil)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	if _, err := w.Write([]byte(plaintext)); err != nil {
		return "", fmt.Errorf("write plaintext: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("close message writer: %w", err)
	}
	if err := aw.Close(); err != nil {
		return "", fmt.Errorf("close armor writer: %w", err)
	}
	return buf.String(), nil
}

// GenerateEncryptedGroupKey — losowy klucz AES-256 grupy (32 bajty, hex),
// zaszyfrowany do podanego klucza publicznego. Odpowiednik generateGroupKey
// w extension/src/groupkey.js. groupKeyHex zwracany OSOBNO (nie tylko
// encryptedGroupKey) na wypadek gdyby wołający chciał od razu zaszyfrować
// nim pierwszy sekret w tej samej operacji, bez ponownego PGP-decrypt.
func GenerateEncryptedGroupKey(armoredPublicKey string) (groupKeyHex, encryptedGroupKey string, err error) {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", "", fmt.Errorf("generate group key: %w", err)
	}
	groupKeyHex = hex.EncodeToString(keyBytes)
	encryptedGroupKey, err = EncryptArmoredMessage(groupKeyHex, armoredPublicKey)
	if err != nil {
		return "", "", fmt.Errorf("encrypt group key: %w", err)
	}
	return groupKeyHex, encryptedGroupKey, nil
}

// ── AES-256-GCM ──────────────────────────────────────────────────────────────
// Format ciphertext: base64(IV[12 bajtów] + ciphertext+tag) — dokładnie
// aesGCMDecryptRaw w extension/background.js.

// AESGCMDecryptRaw odszyfrowuje base64(IV[12] + ciphertext+tag) danym
// 32-bajtowym kluczem AES-256.
func AESGCMDecryptRaw(b64 string, key []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) < 12 {
		return "", fmt.Errorf("ciphertext too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv, ct := raw[:12], raw[12:]
	plaintext, err := gcm.Open(nil, iv, ct, nil)
	if err != nil {
		return "", fmt.Errorf("aes-gcm decrypt: %w", err)
	}
	return string(plaintext), nil
}

// AESGCMEncryptRaw szyfruje plaintext danym 32-bajtowym kluczem AES-256,
// losowym IV (12 bajtów) — format wyjścia base64(IV + ciphertext+tag),
// odwrotność AESGCMDecryptRaw, dokładnie jak aesGCMEncryptRaw w
// extension/background.js.
func AESGCMEncryptRaw(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("generate iv: %w", err)
	}
	ct := gcm.Seal(nil, iv, []byte(plaintext), nil)
	out := append(iv, ct...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// ErrNoGroupKey — serwer nie ma klucza tej grupy dla tego konta: ma rolę w
// grupie, ale nikt jeszcze mu go nie udostępnił (serwer nie zna kluczy grup,
// robi to przeglądarka kogoś, kto je ma — "Sync" w Sharqey). Wcześniej
// wychodziło z tego "decrypt group key: armor decode: EOF" (BUGS.md
// 2026-09-12), z którego nie dało się wyczytać przyczyny.
var ErrNoGroupKey = errors.New("this account has a role in the group, but nobody has shared the group's key with it yet — a group manager needs to open the group in Sharqey and click Sync")

// EncryptWithGroupKey — odwrotność DecryptWithGroupKey, dokładny odpowiednik
// encryptWithGroupKey w extension/src/groupkey.js:
//  1. PGP-odszyfruj encryptedGroupKey armoredPrivateKey -> hex group key (32B).
//  2. Losowy secret key (32B), AES-GCM zaszyfrowany group keyem -> groupEncryptedSecretKey.
//  3. AES-GCM zaszyfruj plaintext secret keyem -> ciphertext.
func EncryptWithGroupKey(plaintext, encryptedGroupKey, armoredPrivateKey string) (ciphertext, groupEncryptedSecretKey string, err error) {
	return EncryptWithGroupKeyPassphrase(plaintext, encryptedGroupKey, armoredPrivateKey, "")
}

// EncryptWithGroupKeyPassphrase — jak EncryptWithGroupKey, ale dla kluczy
// prywatnych chronionych passphrase (własny klucz konta).
func EncryptWithGroupKeyPassphrase(plaintext, encryptedGroupKey, armoredPrivateKey, passphrase string) (ciphertext, groupEncryptedSecretKey string, err error) {
	if strings.TrimSpace(encryptedGroupKey) == "" {
		return "", "", ErrNoGroupKey
	}
	groupKeyHex, err := DecryptArmoredMessageWithPassphrase(encryptedGroupKey, armoredPrivateKey, passphrase)
	if err != nil {
		return "", "", fmt.Errorf("decrypt group key: %w", err)
	}
	groupKeyBytes, err := hex.DecodeString(strings.TrimSpace(groupKeyHex))
	if err != nil {
		return "", "", fmt.Errorf("decode group key hex: %w", err)
	}

	secretKeyBytes := make([]byte, 32)
	if _, err := rand.Read(secretKeyBytes); err != nil {
		return "", "", fmt.Errorf("generate secret key: %w", err)
	}
	secretKeyHex := hex.EncodeToString(secretKeyBytes)

	ciphertext, err = AESGCMEncryptRaw(plaintext, secretKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("encrypt plaintext: %w", err)
	}
	groupEncryptedSecretKey, err = AESGCMEncryptRaw(secretKeyHex, groupKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("encrypt secret key: %w", err)
	}
	return ciphertext, groupEncryptedSecretKey, nil
}

// DecryptWithGroupKey — dokładny odpowiednik handleDecryptWithGroupKey /
// decryptWithGroupKey (extension/src/groupkey.js):
//  1. PGP-odszyfruj encryptedGroupKey armoredPrivateKey -> hex group key (32B).
//  2. AES-GCM odszyfruj groupEncryptedSecretKey group keyem -> hex secret key (32B).
//  3. AES-GCM odszyfruj ciphertext secret keyem -> plaintext.
func DecryptWithGroupKey(ciphertext, groupEncryptedSecretKey, encryptedGroupKey, armoredPrivateKey string) (string, error) {
	return DecryptWithGroupKeyPassphrase(ciphertext, groupEncryptedSecretKey, encryptedGroupKey, armoredPrivateKey, "")
}

// DecryptWithGroupKeyPassphrase — jak DecryptWithGroupKey, ale dla kluczy
// prywatnych chronionych passphrase (własny klucz konta, nie klucz z
// device-linku — patrz DecryptArmoredMessageWithPassphrase).
// DecryptDirectSecret odszyfrowuje sekret zawinięty jednopoziomowo — ścieżka
// DirectKey (per-secret share, password-manager tasks/done/022): symetryczny
// klucz sekretu zawinięty WPROST kluczem publicznym usera, bez pośredniczenia
// przez klucz grupy (w odróżnieniu od DecryptWithGroupKey). Przeniesione z
// password-manager/pkg/secretcrypto.GPGDecrypt (2026-09-07, tasks/todo/065)
// przy wydzielaniu password-manager-cli.
func DecryptDirectSecret(ciphertext, encryptedKey, armoredPrivateKey, passphrase string) (string, error) {
	symKeyHex, err := DecryptArmoredMessageWithPassphrase(encryptedKey, armoredPrivateKey, passphrase)
	if err != nil {
		return "", fmt.Errorf("decrypt secret key: %w", err)
	}
	symKeyBytes, err := hex.DecodeString(strings.TrimSpace(symKeyHex))
	if err != nil {
		return "", fmt.Errorf("decode secret key hex: %w", err)
	}
	return AESGCMDecryptRaw(ciphertext, symKeyBytes)
}

// EncryptOwnerSecret — odwrotność DecryptDirectSecret: szyfruje plaintext
// WPROST kluczem publicznym (bez group_key, bez odpakowania ŻADNEGO klucza
// prywatnego — public key encrypt tego nie wymaga). Odpowiednik
// handleEncrypt w extension/background.js (PM.encryptSecret) i
// CryptoUtil.encryptWithOwnerKey (Android) / encryptWithOwnerKey (iOS
// Swift) / CryptoService.encryptWithOwnerKey (Dart) — TASK-018
// (password-manager-flutter), runda 5: sekrety w grupie Private
// (Group.IsPrivateTo != nil) są szyfrowane wyłącznie tym sposobem,
// `owner_encrypted_secret_key` zamiast `group_encrypted_secret_key`.
func EncryptOwnerSecret(plaintext, ownerPublicKeyArmored string) (ciphertext, ownerEncryptedSecretKey string, err error) {
	secretKeyBytes := make([]byte, 32)
	if _, err := rand.Read(secretKeyBytes); err != nil {
		return "", "", fmt.Errorf("generate secret key: %w", err)
	}
	secretKeyHex := hex.EncodeToString(secretKeyBytes)

	ciphertext, err = AESGCMEncryptRaw(plaintext, secretKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("encrypt plaintext: %w", err)
	}
	ownerEncryptedSecretKey, err = EncryptArmoredMessage(secretKeyHex, ownerPublicKeyArmored)
	if err != nil {
		return "", "", fmt.Errorf("encrypt secret key: %w", err)
	}
	return ciphertext, ownerEncryptedSecretKey, nil
}

func DecryptWithGroupKeyPassphrase(ciphertext, groupEncryptedSecretKey, encryptedGroupKey, armoredPrivateKey, passphrase string) (string, error) {
	if strings.TrimSpace(encryptedGroupKey) == "" {
		return "", ErrNoGroupKey
	}
	groupKeyHex, err := DecryptArmoredMessageWithPassphrase(encryptedGroupKey, armoredPrivateKey, passphrase)
	if err != nil {
		return "", fmt.Errorf("decrypt group key: %w", err)
	}
	groupKeyBytes, err := hex.DecodeString(strings.TrimSpace(groupKeyHex))
	if err != nil {
		return "", fmt.Errorf("decode group key hex: %w", err)
	}

	secretKeyHex, err := AESGCMDecryptRaw(groupEncryptedSecretKey, groupKeyBytes)
	if err != nil {
		return "", fmt.Errorf("decrypt secret key: %w", err)
	}
	secretKeyBytes, err := hex.DecodeString(strings.TrimSpace(secretKeyHex))
	if err != nil {
		return "", fmt.Errorf("decode secret key hex: %w", err)
	}

	plaintext, err := AESGCMDecryptRaw(ciphertext, secretKeyBytes)
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}
	return plaintext, nil
}
