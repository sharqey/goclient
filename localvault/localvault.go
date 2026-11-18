// Package localvault — JEDYNA implementacja formatu pliku ".sharqey" w Go
// (password-manager-cli TASK-004, 2026-09-27). Wcześniej były trzy kopie:
// password-manager-desktop/internal/localvault (wzorcowa, z niej przeniesiony
// ten kod), terraform-provider-sharqey/internal/localvault i
// password-manager-cli/cmd/cli/local.go. Zmiana formatu idzie TYLKO tutaj;
// pozostali klienci Go importują ten pakiet. Rzeczy specyficzne dla jednej
// appki (domyślny katalog desktopu, lista ostatnich plików, iCloud) zostają
// u niej — ten pakiet zawsze dostaje jawną ścieżkę.
//
// Analogon apiclient, ale operuje na lokalnym
// zaszyfrowanym pliku zamiast HTTP: dokładnie ten sam model kryptograficzny
// co tryb online (pgpcrypto, RSA-4096 identity key, AES-256 group_key
// self-wrapped PGP do własnego klucza, AES-GCM sekrety, patrz
// App.CreateOrganization/CreateSecret w app.go), zero nowej kryptografii —
// tylko inne miejsce zapisu (plik zamiast serwer) i inne wołanie
// istniejących funkcji pgpcrypto (patrz encryptRaw/decryptRaw niżej).
//
// Format pliku (format_version 3, task 012, 2026-09-08 — nadpisuje
// format_version 2 sprzed kilku godzin tego samego dnia): plik NIE ujawnia
// niczego bez hasła głównego poza tym że istnieje i, per sekret, jego jawnym
// "title" — reszta metadanych (type/username/url/has_totp) i wartość żyją
// WEWNĄTRZ "ciphertext" (patrz secretEnvelope). Title wrócił do jawnego
// tekstu (cofnięcie części decyzji z format_version 2, "nie widzę wartości w
// zostawianiu czegokolwiek jawnym tekstem") bo plik bywa trzymany w repo git
// (np. jako źródło sekretów dla Terraforma) i w pełni zaszyfrowane metadane
// robią `git diff` bezużytecznym — nie widać KTÓRY sekret się zmienił.
// Analogicznie vault_name: zaszyfrowany ("vault_name_ciphertext"/
// "vault_name_key_wrapped", bez zmian względem v2), bez odblokowania appka
// pokazuje userowi wyłącznie nazwę pliku (patrz recent.go).
//
// Klucz grupowy jest odszyfrowywany PGP-em (S2K passphrase + RSA) tylko RAZ,
// przy Create/Unlock, i trzymany w pamięci jako surowe 32B (Vault.groupKey)
// — hasło główne samo w sobie NIE jest nigdzie trzymane po powrocie z
// Create/Unlock (w przeciwieństwie do format_version 1, gdzie każda
// operacja na sekrecie na nowo odszyfrowywała group_key_self_wrapped
// przez PGP+S2K — poprawne, ale bez tego appka musiałaby robić to za
// KAŻDYM razem gdy user rozwija listę sekretów, żeby odszyfrować resztę
// metadanych poza title). Reużywa wprost pgpcrypto.AESGCMEncryptRaw/
// AESGCMDecryptRaw (te same funkcje, których
// EncryptWithGroupKeyPassphrase/DecryptWithGroupKeyPassphrase i tak używają
// pod spodem) — nie ma tu żadnego nowego prymitywu kryptograficznego, tylko
// pominięty, redundantny przy każdym wywołaniu krok PGP-decrypt klucza grupy.
//
// Pliki sprzed tej zmiany nadal się otwierają — Unlock migruje je w locie i
// od razu zapisuje wynik na dysk, zero wymaganej akcji usera (ten sam wzorzec
// co planowana migracja formatu dla grup, patrz
// tasks/todo/011-local-vault-groups.md): format_version 1 (jawne
// title/username/url/type/has_totp per sekret, jawne vault_name) migruje
// bezpośrednio do 3 (migrateLegacyFormat), format_version 2 (title też
// zaszyfrowany, wewnątrz koperty) migruje do 3 wyciągając title z koperty
// (migrateV2ToV3).
package localvault

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sharqey/goclient/pgpcrypto"
)

// FormatVersion — dla przyszłych migracji formatu pliku. Pliki starsze niż
// 3 są migrowane w locie przy Unlock, patrz dokumentacja pakietu wyżej,
// migrateLegacyFormat (v1->v3) i migrateV2ToV3.
//
// format_version 3 (2026-09-08, task 012): jedyna zmiana względem 2 — "title"
// wraca jawnym polem secretRecord zamiast żyć wewnątrz zaszyfrowanej koperty.
// Powód: plik .sharqey bywa trzymany w repo git (np. jako źródło sekretów dla
// Terraforma) i w pełni zaszyfrowane metadane robią `git diff` bezużytecznym
// — nie widać KTÓRY sekret się zmienił. Reszta metadanych (type/username/url/
// has_totp) i wartość zostają zaszyfrowane jak w v2 — to świadomy kompromis,
// nie cofnięcie decyzji z 2: tytuł sam w sobie ma niską wartość dla atakującego
// (patrz secretEnvelope), a znacząco ułatwia code review zmian w repo.
//
// format_version 4 (2026-09-12, task 067): jedyny sposób odblokowania grupowego
// klucza dziś to `identity`+`group_key_self_wrapped` (hasło główne → S2K →
// klucz tożsamości vaulta → group key). Zastąpione tablicą `recipients[]` —
// każdy wpis to jeden, niezależny sposób odblokowania (surowy group key
// zaszyfrowany wprost PGP-em do klucza publicznego tego recipienta).
// Recipient wygenerowany przy Create ma dodatkowo osadzony, passphrase-
// chroniony private key (`is_self: true`) — to dokładnie dzisiejszy
// `identity`, tylko przeniesiony do jednoelementowej listy. Motywacja:
// `terraform-provider-sharqey` w trybie lokalnym ma umieć odblokować plik
// kluczem prywatnym PGP z environmentu (jak sops z kluczem spoza repo),
// zamiast hasła głównego — wymaga to recipienta BEZ osadzonego klucza
// prywatnego, którego provider dostarcza z zewnątrz. Zero nowej kryptografii:
// `pgpcrypto.EncryptArmoredMessage`/`DecryptArmoredMessageWithPassphrase` już
// działają na dowolnym, obcym armored kluczu, nie tylko na wygenerowanej tu
// parze (patrz Create/pgpcrypto.GenerateIdentityKeypair).
//
// format_version 5 (2026-09-27, password-manager-cli TASK-004): sekrety typu
// "file". Rekord dostaje pole "file_blob" = base64 (std, z paddingiem) z
// bloba w DOKŁADNIE tym samym formacie co na serwerze
// (password-manager-goclient/filesecret): IV(12) || AES-256-GCM(file_key,
// plik). Koperta takiego rekordu ma type "file", a jej content to metadane
// {"v":1,"filename","mime","size","file_key"} — ten sam plaintext, który
// serwer trzyma jako ciphertext sekretu typu file. Przeniesienie pliku
// vault <-> serwer to więc przepięcie bloba bez przeszyfrowania bajtów.
// Blob leży inline, żeby vault został jednym plikiem (git, iCloud, kopia);
// limit MaxFileSize na plik. Wzorcowy plik: testdata/v5-file.sharqey (+
// v5-file.expected.json) — wspólny dla implementacji w innych językach.
//
// Wersja 5 jest zapisywana TYLKO gdy plik faktycznie zawiera choć jeden
// rekord z file_blob (patrz save): vault bez plików zostaje v4 i czytają go
// dalej wszyscy klienci v4 (flutter, Swift extension, wydany provider).
// Klient v4 odmawia otwarcia v5, więc nie zgubi file_blob przy zapisie.
// Wersja nigdy nie spada (usunięcie ostatniego pliku zostawia 5).
const FormatVersion = 5

// FormatVersionRecipients — minimalna wersja zapisywana przez ten pakiet
// (recipients[], task 067). Starsze pliki są migrowane do niej przy Unlock.
const FormatVersionRecipients = 4

// FormatVersionFiles — pierwsza wersja z sekretami typu "file" (file_blob).
const FormatVersionFiles = 5

// file — kształt na dysku (JSON). Pakiet celowo NIE eksportuje tego typu —
// wołający (app.go) dostaje tylko Vault, Secret i MigrationSecret, nigdy
// surowego pliku z kluczem prywatnym/ciphertextami w środku.
type file struct {
	FormatVersion       int    `json:"format_version"`
	VaultNameCiphertext string `json:"vault_name_ciphertext,omitempty"`
	VaultNameKeyWrapped string `json:"vault_name_key_wrapped,omitempty"`
	// Recipients — format_version 4+ (task 067), patrz dokumentacja pakietu i
	// typu recipient niżej. Zastępuje Identity/GroupKeySelfWrapped jako
	// aktywny kształt; te dwa pola żyją dalej jako Legacy* WYŁĄCZNIE do
	// odczytu plików sprzed migracji.
	Recipients []recipient    `json:"recipients,omitempty"`
	Secrets    []secretRecord `json:"secrets"`
	// Groups — podgrupy w tym pliku (task 011). Świadomie NIE ma tu wpisu
	// reprezentującego sam vault-root: root to zawsze cały plik (patrz
	// ListGroupTree w app.go, depth 0), a Groups trzyma WYŁĄCZNIE
	// podgrupy pod nim — ParentID=="" znaczy "bezpośrednio pod
	// vault-rootem", niepuste ParentID musi wskazywać ID innej pozycji w
	// tej samej liście. Jeden WSPÓLNY GroupKeySelfWrapped dla całego
	// pliku wystarcza (ustalenie z userem 2026-09-09) — w przeciwieństwie
	// do trybu online to jeden plik z jednym właścicielem, więc osobny
	// group_key per podgrupa nie daje tu żadnej realnej korzyści
	// bezpieczeństwa. Pliki sprzed tego taska nie mają tego pola wcale —
	// zero-value (nil slice) to poprawny, w pełni działający stan "brak
	// podgrup, wszystkie sekrety w rootcie", więc UNMARSHAL starych
	// plików nie wymaga żadnej migracji (w przeciwieństwie do
	// migrateLegacyFormat/migrateV2ToV3 wyżej).
	Groups []Group `json:"groups,omitempty"`

	// LegacyVaultName — jawny tekst z plików format_version < 2. Ta wersja
	// appki nigdy tego pola nie zapisuje (stąd omitempty) — czyta je
	// WYŁĄCZNIE raz, w migrateLegacyFormat, żeby przenieść wartość do
	// VaultNameCiphertext i wyczyścić to pole przy pierwszym zapisie.
	LegacyVaultName string `json:"vault_name,omitempty"`

	// LegacyIdentity/LegacyGroupKeySelfWrapped — kształt format_version < 4
	// (task 067): jedna, sztywna tożsamość zamiast Recipients. Ta wersja
	// appki nigdy tego nie zapisuje (stąd omitempty) — czyta WYŁĄCZNIE przy
	// odblokowaniu starego pliku (Unlock) i migrateV3ToV4 przenosi wartość
	// do jedynego, self-wrapped Recipient, czyszcząc oba pola.
	LegacyIdentity            identity `json:"identity,omitempty"`
	LegacyGroupKeySelfWrapped string   `json:"group_key_self_wrapped,omitempty"`
}

// identity — kształt format_version < 4 (patrz file.LegacyIdentity).
type identity struct {
	PublicKeyArmored  string `json:"public_key_armored"`
	PrivateKeyArmored string `json:"private_key_armored"`
}

// recipient — jeden sposób odblokowania grupowego klucza (format_version 4+,
// task 067): WrappedGroupKey to surowy 32B group key (hex), zaszyfrowany
// WPROST PGP-em do PublicKeyArmored (pgpcrypto.EncryptArmoredMessage) — zero
// S2K/passphrase na tym poziomie, to zwykły PGP pubkey-encrypt do klucza tego
// konkretnego recipienta. PrivateKeyArmored jest obecne WYŁĄCZNIE dla
// recipienta wygenerowanego przez Create (IsSelf) — dla recipientów
// dodanych później (obcy klucz publiczny, patrz AddRecipient) private key
// mieszka poza plikiem, dokładnie jak w sops. Fingerprint liczony raz przy
// dodaniu recipienta (pgpcrypto.FingerprintFromArmoredPublicKey) — czysto
// informacyjny, do weryfikacji przez usera osobnym kanałem (task 067, Faza 2).
type recipient struct {
	ID                string `json:"id"`
	Label             string `json:"label,omitempty"`
	PublicKeyArmored  string `json:"public_key_armored"`
	Fingerprint       string `json:"fingerprint,omitempty"`
	WrappedGroupKey   string `json:"wrapped_group_key"`
	PrivateKeyArmored string `json:"private_key_armored,omitempty"`
	IsSelf            bool   `json:"is_self,omitempty"`
}

// Recipient — widok recipienta zwracany wołającemu (app.go) przez
// ListRecipients/AddRecipient — bez WrappedGroupKey/PrivateKeyArmored,
// dokładnie ten sam wzorzec co secretRecord/Secret (surowa kryptografia
// nigdy nie opuszcza tego pakietu poza ExportForMigration).
type Recipient struct {
	ID          string
	Label       string
	Fingerprint string
	IsSelf      bool
}

// Group — podgrupa/folder wewnątrz jednego lokalnego pliku vaulta (task
// 011). Jawne (bez szyfrowania) — dokładnie ta sama logika co Title na
// secretRecord (patrz tam): nazwy folderów mają niską wartość dla
// atakującego i jawność znacząco ułatwia `git diff` na pliku trzymanym w
// repo. ParentID=="" -> bezpośrednio pod vault-rootem (patrz file.Groups).
type Group struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	ParentID string `json:"parent_id,omitempty"`
}

// secretRecord — kształt sekretu NA DYSKU. Wszystko poza ID i Title jest
// zaszyfrowane (patrz secretEnvelope) — to jedyny typ w tym pakiecie, który
// appka (app.go) w ogóle widzi z surowym "Ciphertext"/"GroupEncryptedSecretKey"
// w środku (przez ExportForMigration -> MigrationSecret), bo tylko migracja do
// organizacji online potrzebuje gotowej koperty kryptograficznej zamiast
// odszyfrowanej treści.
type secretRecord struct {
	ID string `json:"id"`
	// Title — jawny tytuł sekretu (format_version 3+, task 012). Celowo BEZ
	// omitempty i BEZ osobnego "Legacy" odpowiednika: pliki format_version 1
	// miały "title" jako jawne pole DOKŁADNIE pod tym samym kluczem JSON, więc
	// to jedno pole Unmarshal-uje się poprawnie z plików w OBU formatach (1 i
	// 3) bez żadnej specjalnej obsługi — migrateLegacyFormat (v1->v3) nie
	// musi nigdzie przepisywać title, tylko zostawić je na miejscu. Format
	// version 2 (pośredni, już nie zapisywany) nie miał tego pola na tym
	// poziomie wcale (title żyło w kopercie) — migrateV2ToV3 wyciąga je stamtąd
	// i dopiero wtedy wypełnia to pole.
	Title                   string `json:"title"`
	Ciphertext              string `json:"ciphertext"`
	GroupEncryptedSecretKey string `json:"group_encrypted_secret_key"`
	// GroupID — który Group (task 011) ten sekret zawiera; ""=vault-root,
	// dokładnie jak Group.ParentID=="" wyżej. Jawne z tego samego powodu
	// co Title. Pliki sprzed taska 011 nie mają go wcale — zero-value ""
	// odczytuje się jako "w rootcie", więc istniejące sekrety nie
	// wymagają żadnej migracji przy wczytaniu.
	GroupID string `json:"group_id,omitempty"`
	// FileBlob — format_version 5+, tylko dla sekretów typu "file": base64
	// bloba IV || AES-GCM(file_key, plik), patrz FormatVersion. file_key
	// żyje w zaszyfrowanej kopercie, więc samo pole niczego nie ujawnia poza
	// rozmiarem pliku.
	FileBlob string `json:"file_blob,omitempty"`

	// Legacy (format_version < 2) — jawne pola, czyszczone przy migracji,
	// patrz LegacyVaultName wyżej. Title NIE jest tu — patrz komentarz wyżej.
	LegacyType     string `json:"type,omitempty"`
	LegacyUsername string `json:"username,omitempty"`
	LegacyURL      string `json:"url,omitempty"`
	LegacyHasTOTP  bool   `json:"has_totp,omitempty"`
}

// secretEnvelope — kształt PO odszyfrowaniu secretRecord.Ciphertext. Content
// to dokładnie te bajty, które wołający (app.go) przekazał do AddSecret/
// UpdateSecret jako plaintext (np. {"password":...,"notes":...} —
// localvault nie zna ani nie waliduje tego kształtu, to sprawa wołającego).
type secretEnvelope struct {
	Type     string `json:"type"`
	Username string `json:"username"`
	URL      string `json:"url"`
	HasTOTP  bool   `json:"has_totp"`
	Content  string `json:"content"`
}

// Secret — odszyfrowany WIDOK metadanych sekretu (analogon
// apiclient.SearchResult okrojony do pól sensownych lokalnie). Zwracany
// przez ListSecrets/SecretByID/DecryptSecret — nigdy nie niesie surowego
// ciphertextu, patrz secretRecord/MigrationSecret dla tego.
type Secret struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Title    string `json:"title"`
	Username string `json:"username"`
	URL      string `json:"url"`
	HasTOTP  bool   `json:"has_totp"`
	GroupID  string `json:"group_id"`
	// Filename/Mime/Size — tylko dla Type=="file" (z metadanych w kopercie,
	// BEZ file_key). Size to rozmiar plaintextu pliku.
	Filename string `json:"filename,omitempty"`
	Mime     string `json:"mime,omitempty"`
	Size     int64  `json:"size,omitempty"`
}

// MigrationSecret — kształt 1:1 z apiclient.ImportSecretParams, zwracany
// WYŁĄCZNIE przez ExportForMigration. W przeciwieństwie do online-mode
// ciphertextu (który szyfruje TYLKO wartość sekretu, metadane server-side są
// jawne w DB), lokalny format_version 2 szyfruje metadane RAZEM z wartością
// — ExportForMigration musi więc każdy sekret odszyfrować i zaszyfrować na
// nowo (samą wartość, bez metadanych) pod TYM SAMYM group_key, żeby wynik
// pasował do modelu online. To jedyne miejsce w tym pakiecie, które
// re-encryptuje przy eksporcie zamiast robić czysty upload gotowych bajtów
// — nieuniknione po przenosinach metadanych do środka koperty (patrz
// dokumentacja pakietu).
type MigrationSecret struct {
	Type                    string
	Title                   string
	Username                string
	URL                     string
	HasTOTP                 bool
	Ciphertext              string
	GroupEncryptedSecretKey string
	// GroupLocalID — który MigrationGroup.LocalID (patrz niżej) zawiera ten
	// sekret; ""=root organizacji. Bezpośrednio localvault.Secret.GroupID —
	// żadnego przemapowania, bo LocalID podgrup w MigrationGroup TO WŁAŚNIE
	// localvault.Group.ID (patrz tam).
	GroupLocalID string
}

// MigrationGroup — jedna podgrupa lokalnego pliku do odtworzenia w
// organizacji online (follow-up taska 011, "migracja musi zacząć zachowywać
// drzewo grup" — ExportForMigration już nie spłaszcza wszystkiego do jednego
// roota). LocalID to WPROST localvault.Group.ID (nie trzeba osobnej mapy —
// server rozwiązuje drzewo po tych samych ID, patrz
// apiclient.ImportGroupParams/group.Repository.ImportVault w
// password-manager). GroupKeySelfWrapped to ŚWIEŻO wygenerowany przy
// eksporcie group_key dla TEJ podgrupy (self-wrapped do tego samego
// identity key co reszta importu) — w przeciwieństwie do lokalnego pliku
// (gdzie WSZYSTKIE grupy dzielą jeden groupKey, ustalenie z userem
// 2026-09-09) organizacja online wymaga osobnego group_key per grupa, więc
// ExportForMigration generuje je tu, na granicy eksportu, zamiast trzymać
// je w pliku na stałe.
type MigrationGroup struct {
	LocalID             string
	ParentLocalID       string
	Name                string
	GroupKeySelfWrapped string
}

// Vault — otwarty (odblokowany) lokalny vault w pamięci procesu. Trzyma
// WYŁĄCZNIE surowy klucz grupowy (groupKey, 32B AES) i odszyfrowaną nazwę
// vaulta — hasło główne nie jest tu nigdzie retencjonowane, patrz
// dokumentacja pakietu.
type Vault struct {
	// mu — chroni f i vaultName: GUI (Wails woła bindingi z osobnych
	// gorutyn) czyta i mutuje ten sam *Vault równolegle, a każda mutacja
	// (patrz mutate) PODMIENIA całe f świeżo wczytanym z dysku.
	mu        sync.Mutex
	path      string
	groupKey  []byte
	vaultName string
	f         file
	// diskHash — sha256 pliku w chwili ostatniego save()/odczytu przez tę
	// instancję, patrz ChangedOnDisk.
	diskHash [sha256.Size]byte
}

// mutate — JEDYNA droga zapisu dla publicznych mutacji (task 013 pkt 1):
// przeładowuje plik z dysku, dopiero potem woła fn (mutacja v.f w pamięci) i
// save(). Bez tego każda mutacja zapisywała CAŁY plik ze stanu z momentu
// Unlock/Reload, po cichu kasując zmiany zrobione w międzyczasie przez inny
// proces na tym samym pliku — iPhone przez iCloud Drive, sharqey-mcp,
// sharqey-cli. Port LocalVaultService._mutate z password-manager-flutter
// (commit fa0c9e3). Walidacje w fn (istnienie grupy, głębokość itd.) liczą
// się więc zawsze względem AKTUALNEGO pliku, nie zdjęcia z pamięci.
//
// Okno wyścigu między odczytem a rename w save() dalej istnieje (brak
// blokady na poziomie pliku, iCloud i tak by jej nie respektował), ale
// skurczyło się z "od Unlock, czyli godzin" do milisekund.
func (v *Vault) mutate(fn func() error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.reloadLocked(); err != nil {
		return err
	}
	if err := fn(); err != nil {
		return err
	}
	return v.save()
}

// FileExtension — rozszerzenie plików vaulta produktu Sharqey. Nowe pliki
// tworzone przez appki zawsze dostają to rozszerzenie; istniejące pliki ze
// starym ".pvvault" (sprzed rebrandingu na Sharqey, 2026-09-07)
// nadal się otwierają bez zmian — Unlock przyjmuje dowolną ścieżkę, rozszerzenie nie jest tu w żaden sposób
// wymuszane/walidowane, więc stare pliki nie wymagają migracji.
const FileExtension = ".sharqey"

// LegacyFileExtension — rozszerzenie sprzed rebrandingu, wciąż spotykane na
// dyskach userów którzy mieli appkę przed 2026-09-07. Używane WYŁĄCZNIE do
// filtra w natywnym dialogu "Otwórz" (app.go), żeby te pliki nie zniknęły z
// widoku — appka nigdy niczego pod tym rozszerzeniem sama nie tworzy.
const LegacyFileExtension = ".pvvault"

// absPath — ścieżka pliku vaulta jako absolutna. Pusty path to błąd:
// domyślne lokalizacje są sprawą appki (desktop ma własny katalog i
// DefaultPath), nie formatu. Kanoniczność jest ważna dla wołających, które
// kluczują otwarte vaulty po ścieżce (desktop, task 010).
func absPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("nie podano ścieżki pliku vaulta")
	}
	return filepath.Abs(path)
}

// encryptRaw/decryptRaw — dokładnie ten sam dwupoziomowy schemat co
// pgpcrypto.EncryptWithGroupKeyPassphrase/DecryptWithGroupKeyPassphrase
// (losowy 32B secret_key -> AES-GCM plaintext, secret_key -> AES-GCM
// groupKey), ale przyjmujący JUŻ ODSZYFROWANY groupKey zamiast robić PGP-
// decrypt group_key_self_wrapped za każdym razem — patrz dokumentacja
// pakietu. Zero nowej kryptografii: to te same pgpcrypto.AESGCM*Raw, których
// wspomniane funkcje i tak używają pod spodem.
func encryptRaw(groupKey []byte, plaintext string) (ciphertext, wrappedKey string, err error) {
	secretKeyBytes := make([]byte, 32)
	if _, err := rand.Read(secretKeyBytes); err != nil {
		return "", "", fmt.Errorf("generowanie klucza sekretu nieudane: %w", err)
	}
	ciphertext, err = pgpcrypto.AESGCMEncryptRaw(plaintext, secretKeyBytes)
	if err != nil {
		return "", "", fmt.Errorf("szyfrowanie nieudane: %w", err)
	}
	wrappedKey, err = pgpcrypto.AESGCMEncryptRaw(hex.EncodeToString(secretKeyBytes), groupKey)
	if err != nil {
		return "", "", fmt.Errorf("zawinięcie klucza sekretu nieudane: %w", err)
	}
	return ciphertext, wrappedKey, nil
}

func decryptRaw(groupKey []byte, ciphertext, wrappedKey string) (string, error) {
	secretKeyHex, err := pgpcrypto.AESGCMDecryptRaw(wrappedKey, groupKey)
	if err != nil {
		return "", fmt.Errorf("odszyfrowanie klucza sekretu nieudane: %w", err)
	}
	secretKeyBytes, err := hex.DecodeString(strings.TrimSpace(secretKeyHex))
	if err != nil {
		return "", fmt.Errorf("dekodowanie klucza sekretu nieudane: %w", err)
	}
	return pgpcrypto.AESGCMDecryptRaw(ciphertext, secretKeyBytes)
}

// findSelfRecipient — recipient z osadzonym, passphrase-chronionym private
// key (patrz recipient.IsSelf) — dokładnie ta jedna tożsamość, którą hasło
// główne odblokowuje. Plik może w teorii mieć co najwyżej jeden taki wpis
// (tylko Create go tworzy) — pętla i tak przechodzi po wszystkich, żeby nie
// zakładać tego na sztywno.
func findSelfRecipient(recipients []recipient) (recipient, bool) {
	for _, r := range recipients {
		if r.IsSelf && r.PrivateKeyArmored != "" {
			return r, true
		}
	}
	return recipient{}, false
}

func decodeGroupKey(groupKeyHex string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(groupKeyHex))
	if err != nil {
		return nil, fmt.Errorf("dekodowanie klucza grupy nieudane: %w", err)
	}
	return b, nil
}

// encryptEnvelope/decryptSecretRecord — pakują/rozpakowują secretEnvelope
// (metadane poza title + treść) do/z jednej koperty na groupKey Vaulta. ID
// świadomie NIE jest ustawiane tutaj (wołający decyduje: AddSecret generuje
// nowe, UpdateSecret/migrateLegacyFormat/migrateV2ToV3 zachowują istniejące).
// title przechodzi OBOK koperty, prosto do secretRecord.Title (format_version
// 3, task 012) — patrz dokumentacja secretRecord.Title.
func (v *Vault) encryptEnvelope(title string, env secretEnvelope) (secretRecord, error) {
	b, err := json.Marshal(env)
	if err != nil {
		return secretRecord{}, fmt.Errorf("serializacja sekretu nieudana: %w", err)
	}
	ciphertext, wrapped, err := encryptRaw(v.groupKey, string(b))
	if err != nil {
		return secretRecord{}, fmt.Errorf("szyfrowanie sekretu nieudane: %w", err)
	}
	return secretRecord{Title: title, Ciphertext: ciphertext, GroupEncryptedSecretKey: wrapped}, nil
}

func (v *Vault) decryptSecretRecord(rec secretRecord) (secretEnvelope, error) {
	plaintext, err := decryptRaw(v.groupKey, rec.Ciphertext, rec.GroupEncryptedSecretKey)
	if err != nil {
		return secretEnvelope{}, err
	}
	var env secretEnvelope
	if err := json.Unmarshal([]byte(plaintext), &env); err != nil {
		return secretEnvelope{}, fmt.Errorf("deserializacja sekretu nieudana: %w", err)
	}
	return env, nil
}

// maxGroupDepth — spójne z limitem serwera online (parent.Depth >= 4 blokuje
// utworzenie kolejnej podgrupy, patrz apiclient/client.go:666) — ustalenie z
// userem 2026-09-09, task 011: ten sam limit tu, żeby lokalny plik nie
// zaskakiwał usera przy przyszłej migracji drzewa grup do organizacji.
const maxGroupDepth = 4

func (v *Vault) findGroup(id string) (Group, bool) {
	for _, g := range v.f.Groups {
		if g.ID == id {
			return g, true
		}
	}
	return Group{}, false
}

// groupDepth — vault-root (id=="") to depth 0, każdy poziom zagnieżdżenia w
// Groups dodaje 1 — dokładnie ta sama skala co apiclient.GroupNode.Depth dla
// organizacji online (org-root=0), więc maxGroupDepth==4 znaczy to samo w
// obu trybach.
func (v *Vault) groupDepth(id string) int {
	depth := 0
	for id != "" {
		g, ok := v.findGroup(id)
		if !ok {
			return depth
		}
		depth++
		id = g.ParentID
	}
	return depth
}

// CreateGroup dodaje nową podgrupę pod parentID (""=bezpośrednio pod
// vault-rootem) — walidacja że parentID istnieje (jeśli niepuste) i że nie
// przekracza maxGroupDepth, wzorem AddSecret (randomID, zapis od razu na
// dysk).
func (v *Vault) CreateGroup(name, parentID string) (Group, error) {
	var g Group
	err := v.mutate(func() error {
		if parentID != "" {
			if _, ok := v.findGroup(parentID); !ok {
				return fmt.Errorf("nieznana grupa nadrzędna %q", parentID)
			}
		}
		if v.groupDepth(parentID) >= maxGroupDepth {
			return fmt.Errorf("przekroczono maksymalną głębokość zagnieżdżenia grup (%d)", maxGroupDepth)
		}
		id, err := randomID()
		if err != nil {
			return fmt.Errorf("generowanie ID grupy nieudane: %w", err)
		}
		g = Group{ID: id, Name: name, ParentID: parentID}
		v.f.Groups = append(v.f.Groups, g)
		return nil
	})
	if err != nil {
		return Group{}, err
	}
	return g, nil
}

// ListGroups — wszystkie podgrupy tego pliku (bez wpisu dla samego
// vault-roota, patrz dokumentacja file.Groups). Kopia, żeby wołający nie
// mógł przez zwrócony slice zmutować v.f.Groups mimochodem.
func (v *Vault) ListGroups() []Group {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]Group, len(v.f.Groups))
	copy(out, v.f.Groups)
	return out
}

// RenameGroup zmienia nazwę istniejącej podgrupy.
func (v *Vault) RenameGroup(id, name string) error {
	return v.mutate(func() error {
		for i := range v.f.Groups {
			if v.f.Groups[i].ID == id {
				v.f.Groups[i].Name = name
				return nil
			}
		}
		return fmt.Errorf("nieznana grupa %q", id)
	})
}

// DeleteGroup usuwa podgrupę — WYMAGA, żeby była pusta (ustalenie z userem
// 2026-09-09: blokować zamiast kasować kaskadowo, prostsze i bez ryzyka
// utraty danych bez cofnięcia) — ani podgrup, ani sekretów przypisanych
// bezpośrednio do niej.
func (v *Vault) DeleteGroup(id string) error {
	return v.mutate(func() error {
		idx := -1
		for i, g := range v.f.Groups {
			if g.ID == id {
				idx = i
				break
			}
		}
		if idx == -1 {
			return fmt.Errorf("nieznana grupa %q", id)
		}
		for _, g := range v.f.Groups {
			if g.ParentID == id {
				return fmt.Errorf("grupa zawiera podgrupy — usuń je najpierw")
			}
		}
		for _, rec := range v.f.Secrets {
			if rec.GroupID == id {
				return fmt.Errorf("grupa zawiera sekrety — przenieś lub usuń je najpierw")
			}
		}
		v.f.Groups = append(v.f.Groups[:idx], v.f.Groups[idx+1:]...)
		return nil
	})
}

// subtreeHeight — najdłuższa ścieżka w DÓŁ od id (0 = id sam jest liściem,
// bez podgrup). Używane przez MoveGroup do sprawdzenia, czy przeniesienie
// całego poddrzewa nie przekroczy maxGroupDepth GDZIEŚ w środku, nie tylko
// dla samego id (patrz MoveGroup).
func (v *Vault) subtreeHeight(id string) int {
	maxChildHeight := -1
	for _, g := range v.f.Groups {
		if g.ParentID != id {
			continue
		}
		if h := v.subtreeHeight(g.ID); h > maxChildHeight {
			maxChildHeight = h
		}
	}
	return maxChildHeight + 1
}

// isDescendant — czy candidateID leży gdzieś pod ancestorID (włącznie z
// candidateID==ancestorID). Używane przez MoveGroup, żeby zablokować
// przeniesienie grupy w jej własne poddrzewo (co odcięłoby ją i wszystko
// pod nią od reszty pliku, bez żadnego błędu przy zapisie — ParentID
// wskazywałby na coś, co samo jest potomkiem).
func (v *Vault) isDescendant(candidateID, ancestorID string) bool {
	for candidateID != "" {
		if candidateID == ancestorID {
			return true
		}
		g, ok := v.findGroup(candidateID)
		if !ok {
			return false
		}
		candidateID = g.ParentID
	}
	return false
}

// MoveGroup zmienia rodzica istniejącej podgrupy (reparenting) — newParentID
// ""=bezpośrednio pod vault-rootem. Blokuje to samo co CreateGroup
// (maxGroupDepth), ale liczone dla NAJGŁĘBSZEGO potomka przenoszonego
// poddrzewa, nie tylko dla samej grupy id — inaczej przeniesienie grupy z
// własnymi podgrupami mogłoby po cichu wepchnąć jej potomków głębiej niż
// limit pozwala. Blokuje też przeniesienie w obrębie własnego poddrzewa
// (patrz isDescendant) — jedyny sposób na "urwanie" kawałka drzewa bez
// jawnego błędu, którego tu świadomie unikamy.
func (v *Vault) MoveGroup(id, newParentID string) error {
	return v.mutate(func() error {
		if _, ok := v.findGroup(id); !ok {
			return fmt.Errorf("nieznana grupa %q", id)
		}
		if newParentID != "" {
			if _, ok := v.findGroup(newParentID); !ok {
				return fmt.Errorf("nieznana grupa docelowa %q", newParentID)
			}
		}
		if id == newParentID {
			return fmt.Errorf("grupa nie może być swoim własnym rodzicem")
		}
		if v.isDescendant(newParentID, id) {
			return fmt.Errorf("nie można przenieść grupy do jej własnego poddrzewa")
		}
		newDepth := v.groupDepth(newParentID) + 1 + v.subtreeHeight(id)
		if newDepth > maxGroupDepth {
			return fmt.Errorf("przekroczono maksymalną głębokość zagnieżdżenia grup (%d)", maxGroupDepth)
		}
		for i := range v.f.Groups {
			if v.f.Groups[i].ID == id {
				v.f.Groups[i].ParentID = newParentID
				return nil
			}
		}
		return fmt.Errorf("nieznana grupa %q", id)
	})
}

// DeleteSecret usuwa pojedynczy sekret bezpowrotnie — w przeciwieństwie do
// DeleteGroup nie ma tu nic do zablokowania (sekret nie ma "zawartości",
// której usunięcie mogłoby ukryć), ale wołający (patrz internal/mcpserver)
// MUSI to jasno komunikować jako nieodwracalne, tego pliku to nie dotyczy —
// tu jest to zwykłe, jednorazowe usunięcie z v.f.Secrets.
func (v *Vault) DeleteSecret(id string) error {
	return v.mutate(func() error {
		for i, rec := range v.f.Secrets {
			if rec.ID == id {
				v.f.Secrets = append(v.f.Secrets[:i], v.f.Secrets[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("nieznany sekret %q", id)
	})
}

// Create generuje nowy identity key + self-wrapped group key (dokładnie ten
// sam mechanizm co App.CreateOrganization w app.go desktopu) i zapisuje
// świeży plik vaulta pod path, nadpisując istniejący bez pytania — wybór
// wolnej nazwy/ostrzeżenie o nadpisaniu to sprawa wołającego (desktop:
// resolveCreatePath i natywny dialog "Zapisz jako").
func Create(path, vaultName, masterPassword string) (*Vault, error) {
	resolved, err := absPath(path)
	if err != nil {
		return nil, fmt.Errorf("ustalenie ścieżki vaulta nieudane: %w", err)
	}

	// Email pusty — lokalny vault nie ma konta, w przeciwieństwie do
	// GenerateIdentityKeypair(a.email, ...) dla organizacji online (User ID
	// w PGP identity tam pełni rolę czysto informacyjną, nieużywaną
	// kryptograficznie przy encrypt/decrypt).
	keypair, err := pgpcrypto.GenerateIdentityKeypair("", masterPassword)
	if err != nil {
		return nil, fmt.Errorf("generowanie klucza tożsamości nieudane: %w", err)
	}
	groupKeyHex, encryptedGroupKey, err := pgpcrypto.GenerateEncryptedGroupKey(keypair.PublicKeyArmored)
	if err != nil {
		return nil, fmt.Errorf("generowanie group key nieudane: %w", err)
	}
	groupKey, err := decodeGroupKey(groupKeyHex)
	if err != nil {
		return nil, err
	}
	fingerprint, err := pgpcrypto.FingerprintFromArmoredPublicKey(keypair.PublicKeyArmored)
	if err != nil {
		return nil, fmt.Errorf("obliczenie fingerprintu tożsamości nieudane: %w", err)
	}
	recipientID, err := randomID()
	if err != nil {
		return nil, fmt.Errorf("generowanie ID recipienta nieudane: %w", err)
	}

	v := &Vault{
		path:      resolved,
		groupKey:  groupKey,
		vaultName: vaultName,
		f: file{
			FormatVersion: FormatVersionRecipients,
			Recipients: []recipient{{
				ID:                recipientID,
				Label:             "hasło główne",
				PublicKeyArmored:  keypair.PublicKeyArmored,
				Fingerprint:       fingerprint,
				WrappedGroupKey:   encryptedGroupKey,
				PrivateKeyArmored: keypair.PrivateKeyArmored,
				IsSelf:            true,
			}},
		},
	}
	nameCiphertext, nameWrapped, err := encryptRaw(v.groupKey, vaultName)
	if err != nil {
		return nil, fmt.Errorf("szyfrowanie nazwy vaulta nieudane: %w", err)
	}
	v.f.VaultNameCiphertext = nameCiphertext
	v.f.VaultNameKeyWrapped = nameWrapped

	if err := v.save(); err != nil {
		return nil, err
	}
	return v, nil
}

// CreateWithExternalKey tworzy nowy plik szyfrowany WYŁĄCZNIE kluczem
// publicznym PGP recipienta podanym przez wołającego — zero hasła głównego,
// zero embedded private key w pliku (recipient IsSelf: false, dokładnie jak
// recipient dodany przez AddRecipient, tylko że to JEDYNY recipient od
// samego początku). Task 067 follow-up (user feedback 2026-09-13: "chcę
// tworzyć bazy tylko kluczem PGP, jak sops w repo") — docelowy sposób
// odblokowania to UnlockWithExternalKey/UnlockWithSystemGPG, NIE zwykły
// Unlock(masterPassword), który dla takiego pliku zawsze zwróci błąd "brak
// tożsamości chronionej hasłem głównym" (patrz findSelfRecipient).
//
// UWAGA (świadomy wybór, nie przeoczenie): jeśli klucz prywatny odpowiadający
// publicKeyArmored zostanie zgubiony bez backupu (i bez zapisanego
// revocation cert), ten plik jest NIEODWRACALNIE martwy — dokładnie takie
// samo ryzyko jak zapomniane hasło główne, tylko że mało kto na co dzień
// robi backup swojego keyringu GPG. Appka NIE ostrzega tu drugi raz —
// wołający (app.go/frontend) pokazuje to userowi PRZED wywołaniem tej
// funkcji, patrz newLocalPgpLossWarning w strings.js.
func CreateWithExternalKey(path, vaultName, publicKeyArmored string) (*Vault, error) {
	resolved, err := absPath(path)
	if err != nil {
		return nil, fmt.Errorf("ustalenie ścieżki vaulta nieudane: %w", err)
	}

	fingerprint, err := pgpcrypto.FingerprintFromArmoredPublicKey(publicKeyArmored)
	if err != nil {
		return nil, fmt.Errorf("nieprawidłowy klucz publiczny: %w", err)
	}
	groupKeyHex, encryptedGroupKey, err := pgpcrypto.GenerateEncryptedGroupKey(publicKeyArmored)
	if err != nil {
		return nil, fmt.Errorf("generowanie group key nieudane: %w", err)
	}
	groupKey, err := decodeGroupKey(groupKeyHex)
	if err != nil {
		return nil, err
	}
	recipientID, err := randomID()
	if err != nil {
		return nil, fmt.Errorf("generowanie ID recipienta nieudane: %w", err)
	}

	v := &Vault{
		path:      resolved,
		groupKey:  groupKey,
		vaultName: vaultName,
		f: file{
			FormatVersion: FormatVersionRecipients,
			Recipients: []recipient{{
				ID:               recipientID,
				Label:            "klucz PGP",
				PublicKeyArmored: publicKeyArmored,
				Fingerprint:      fingerprint,
				WrappedGroupKey:  encryptedGroupKey,
			}},
		},
	}
	nameCiphertext, nameWrapped, err := encryptRaw(v.groupKey, vaultName)
	if err != nil {
		return nil, fmt.Errorf("szyfrowanie nazwy vaulta nieudane: %w", err)
	}
	v.f.VaultNameCiphertext = nameCiphertext
	v.f.VaultNameKeyWrapped = nameWrapped

	if err := v.save(); err != nil {
		return nil, err
	}
	return v, nil
}

// Unlock wczytuje istniejący plik vaulta i weryfikuje masterPassword próbą
// odszyfrowania group_key_self_wrapped — błędne hasło ujawnia się TU, od
// razu przy odblokowaniu, zamiast dopiero przy pierwszym DecryptSecret.
// Pliki sprzed format_version 2 są migrowane w locie (migrateLegacyFormat) i
// od razu zapisane w nowym, w pełni zaszyfrowanym kształcie.
func Unlock(path, masterPassword string) (*Vault, error) {
	resolved, err := absPath(path)
	if err != nil {
		return nil, fmt.Errorf("ustalenie ścieżki vaulta nieudane: %w", err)
	}
	b, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("odczyt pliku vaulta nieudany: %w", err)
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("plik vaulta uszkodzony: %w", err)
	}
	if f.FormatVersion > FormatVersion {
		return nil, fmt.Errorf("plik vaulta zapisany nowszą wersją aplikacji (format_version %d) — zaktualizuj aplikację", f.FormatVersion)
	}

	var groupKeyHex string
	if f.FormatVersion >= 4 {
		self, ok := findSelfRecipient(f.Recipients)
		if !ok {
			return nil, fmt.Errorf("ten plik nie ma tożsamości chronionej hasłem głównym — użyj UnlockWithExternalKey")
		}
		groupKeyHex, err = pgpcrypto.DecryptArmoredMessageWithPassphrase(self.WrappedGroupKey, self.PrivateKeyArmored, masterPassword)
	} else {
		groupKeyHex, err = pgpcrypto.DecryptArmoredMessageWithPassphrase(f.LegacyGroupKeySelfWrapped, f.LegacyIdentity.PrivateKeyArmored, masterPassword)
	}
	if err != nil {
		return nil, fmt.Errorf("hasło główne nieprawidłowe")
	}
	groupKey, err := decodeGroupKey(groupKeyHex)
	if err != nil {
		return nil, fmt.Errorf("plik vaulta uszkodzony: %w", err)
	}

	v := &Vault{path: resolved, groupKey: groupKey, f: f, diskHash: sha256.Sum256(b)}

	if f.FormatVersion < 2 {
		if err := v.migrateLegacyFormat(); err != nil {
			return nil, fmt.Errorf("migracja starego formatu pliku nieudana: %w", err)
		}
		return v, nil
	}
	if f.FormatVersion == 2 {
		if err := v.migrateV2ToV3(); err != nil {
			return nil, fmt.Errorf("migracja formatu pliku (v2->v3) nieudana: %w", err)
		}
		return v, nil
	}
	if f.FormatVersion == 3 {
		if err := v.migrateV3ToV4(); err != nil {
			return nil, fmt.Errorf("migracja formatu pliku (v3->v4) nieudana: %w", err)
		}
		return v, nil
	}

	name, err := decryptRaw(v.groupKey, f.VaultNameCiphertext, f.VaultNameKeyWrapped)
	if err != nil {
		return nil, fmt.Errorf("odszyfrowanie nazwy vaulta nieudane: %w", err)
	}
	v.vaultName = name
	return v, nil
}

// UnlockWithExternalKey odblokowuje plik BEZ hasła głównego, kluczem
// prywatnym PGP dostarczonym przez wołającego (plik/env/gpg-agent — sposób
// pozyskania to sprawa wołającego, np. terraform-provider-sharqey czyta go z
// local_vault_identity_key_file). Wymaga format_version >= 4 — starsze pliki
// nie mają recipients[] wcale, więc trzeba je najpierw zmigrować zwykłym
// Unlock hasłem. Próbuje podanego klucza (i opcjonalnej passphrase, jeśli
// klucz sam jest nią chroniony — pusty string jest bezpieczny na kluczu bez
// ochrony, patrz pgpcrypto.DecryptArmoredMessageWithPassphrase) po kolei na
// wrapped_group_key KAŻDEGO recipienta, nie tylko is_self — klucz podany
// przez wołającego może pasować do dowolnego z nich.
func UnlockWithExternalKey(path, privateKeyArmored, passphrase string) (*Vault, error) {
	resolved, err := absPath(path)
	if err != nil {
		return nil, fmt.Errorf("ustalenie ścieżki vaulta nieudane: %w", err)
	}
	b, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("odczyt pliku vaulta nieudany: %w", err)
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("plik vaulta uszkodzony: %w", err)
	}
	if f.FormatVersion > FormatVersion {
		return nil, fmt.Errorf("plik vaulta zapisany nowszą wersją aplikacji (format_version %d) — zaktualizuj aplikację", f.FormatVersion)
	}
	if f.FormatVersion < 4 {
		return nil, fmt.Errorf("ten plik jest w starszym formacie (v%d) i nie obsługuje jeszcze zewnętrznych kluczy — otwórz go raz przez Unlock hasłem głównym, żeby zmigrować format", f.FormatVersion)
	}

	var groupKeyHex string
	matched := false
	for _, rec := range f.Recipients {
		candidate, decErr := pgpcrypto.DecryptArmoredMessageWithPassphrase(rec.WrappedGroupKey, privateKeyArmored, passphrase)
		if decErr != nil {
			continue
		}
		groupKeyHex = candidate
		matched = true
		break
	}
	if !matched {
		return nil, fmt.Errorf("podany klucz prywatny nie pasuje do żadnego recipienta tego pliku")
	}
	groupKey, err := decodeGroupKey(groupKeyHex)
	if err != nil {
		return nil, fmt.Errorf("plik vaulta uszkodzony: %w", err)
	}

	v := &Vault{path: resolved, groupKey: groupKey, f: f, diskHash: sha256.Sum256(b)}
	name, err := decryptRaw(v.groupKey, f.VaultNameCiphertext, f.VaultNameKeyWrapped)
	if err != nil {
		return nil, fmt.Errorf("odszyfrowanie nazwy vaulta nieudane: %w", err)
	}
	v.vaultName = name
	return v, nil
}

// ResolveGPGBinary znajduje binarkę gpg — najpierw przez PATH (exec.LookPath),
// a jeśli to zawiedzie, po typowych ścieżkach instalacji na macOS. Aplikacje
// uruchamiane z Docka/Findera/Spotlight (w odróżnieniu od terminala)
// dostają od launchd okrojony PATH (zwykle tylko /usr/bin:/bin:/usr/sbin:
// /sbin, bez /usr/local/bin czy /opt/homebrew/bin) — samo LookPath potrafi
// więc nie znaleźć gpg, mimo że jest zainstalowany i działa z terminala.
// Eksportowana, bo ten sam problem dotyczy keysource.go (main), nie tylko
// UnlockWithSystemGPG tutaj.
func ResolveGPGBinary() (string, error) {
	if p, err := exec.LookPath("gpg"); err == nil {
		return p, nil
	}
	candidates := []string{
		"/usr/local/MacGPG2/bin/gpg2", // GPG Suite
		"/opt/homebrew/bin/gpg",       // Homebrew (Apple Silicon)
		"/usr/local/bin/gpg",          // Homebrew (Intel) / instalacja ręczna
		"/opt/local/bin/gpg",          // MacPorts
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return c, nil
		}
	}
	return "", fmt.Errorf("gpg nie znaleziony w PATH ani w typowych lokalizacjach instalacji (%s) — zainstaluj GnuPG (albo GPG Suite na macOS), albo użyj odblokowania hasłem głównym", strings.Join(candidates, ", "))
}

// UnlockWithSystemGPG odblokowuje plik BEZ hasła głównego i BEZ przenoszenia
// klucza prywatnego do pamięci tej appki — deleguje samo odszyfrowanie do
// lokalnej binarki `gpg` (GPG Suite/GnuPG), a ta do gpg-agent, który sam
// decyduje którym kluczem z SYSTEMOWEGO keyringa da radę i sam pyta o hasło
// przez pinentry (ew. Touch ID, jeśli pinentry-mac jest tak skonfigurowany)
// — my nigdy nie widzimy ani klucza, ani jego hasła, w przeciwieństwie do
// UnlockWithExternalKey (tam klucz+passphrase trafiają wprost do naszego
// procesu). Próbuje po kolei wrapped_group_key KAŻDEGO recipienta — gpg sam
// odmówi bez pytania o cokolwiek, jeśli lokalny keyring nie ma pasującego
// sekretnego klucza dla danej wiadomości, więc pinentry wyskakuje dopiero
// przy recipiencie, który faktycznie pasuje. Wymaga format_version >= 4,
// tak jak UnlockWithExternalKey.
func UnlockWithSystemGPG(path string) (*Vault, error) {
	return unlockWithGPGDecrypt(path, gpgDecryptArmored)
}

// ErrGPGBadPassphrase — UnlockWithSystemGPGPassphrase: klucz pasuje do pliku,
// ale gpg-agent odrzucił podane hasło. Osobny błąd, żeby wołający mógł
// zapytać ponownie zamiast pokazywać surowy stderr gpg.
var ErrGPGBadPassphrase = errors.New("złe hasło do klucza PGP")

// UnlockWithSystemGPGPassphrase — jak UnlockWithSystemGPG, ale hasło do
// klucza podaje wołający (--pinentry-mode loopback, przez stdin — nigdy
// argv/env), więc systemowy pinentry, a z nim jego zapis hasła w Keychainie,
// w ogóle nie bierze udziału. Uwaga: gpg-agent i tak woli hasło już
// zcache'owane od podanego (złe hasło przejdzie, jeśli klucz jest w cache)
// i po sukcesie sam je cache'uje — sprzątanie cache agenta przed i po to
// sprawa wołającego (desktop: internal/gpgagent). Na kluczu bez hasła
// dowolne hasło przechodzi.
func UnlockWithSystemGPGPassphrase(path string, passphrase []byte) (*Vault, error) {
	return unlockWithGPGDecrypt(path, func(gpgBin, armored string) (string, error) {
		return gpgDecryptArmoredLoopback(gpgBin, armored, passphrase)
	})
}

// RecipientFingerprints — pełne (40 hex) fingerprinty wszystkich
// recipientów pliku, bez odblokowania. Liczone z public_key_armored, nie
// brane z pola fingerprint (to bywa skrócone "XXXX-XXXX", patrz
// pgpcrypto.FingerprintFromArmoredPublicKey). Recipient z nieczytelnym
// kluczem publicznym jest pomijany. Pliki < v4 nie mają recipientów.
func RecipientFingerprints(path string) ([]string, error) {
	f, _, _, err := readRecipientFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rec := range f.Recipients {
		fp, err := pgpcrypto.FullFingerprintFromArmoredPublicKey(rec.PublicKeyArmored)
		if err != nil {
			continue
		}
		out = append(out, fp)
	}
	return out, nil
}

// HasMasterPassword — czy plik da się otworzyć hasłem głównym (Unlock), bez
// odblokowania. false dla baz tylko na kluczu zewnętrznym/gpg
// (CreateWithExternalKey, TASK-016 desktopu) — takich nie otworzy np.
// rozszerzenie przeglądarki, które zna wyłącznie hasło główne. Pliki < v4
// zawsze mają hasło główne.
func HasMasterPassword(path string) (bool, error) {
	resolved, err := absPath(path)
	if err != nil {
		return false, err
	}
	b, err := os.ReadFile(resolved)
	if err != nil {
		return false, err
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return false, fmt.Errorf("plik vaulta uszkodzony: %w", err)
	}
	if f.FormatVersion < 4 {
		return true, nil
	}
	_, ok := findSelfRecipient(f.Recipients)
	return ok, nil
}

// readRecipientFile — wspólny początek ścieżek odblokowania przez gpg:
// odczyt pliku i sprawdzenie, że format ma recipientów (v4+).
func readRecipientFile(path string) (f file, resolved string, raw []byte, err error) {
	resolved, err = absPath(path)
	if err != nil {
		return f, "", nil, fmt.Errorf("ustalenie ścieżki vaulta nieudane: %w", err)
	}
	raw, err = os.ReadFile(resolved)
	if err != nil {
		return f, "", nil, fmt.Errorf("odczyt pliku vaulta nieudany: %w", err)
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return f, "", nil, fmt.Errorf("plik vaulta uszkodzony: %w", err)
	}
	if f.FormatVersion > FormatVersion {
		return f, "", nil, fmt.Errorf("plik vaulta zapisany nowszą wersją aplikacji (format_version %d) — zaktualizuj aplikację", f.FormatVersion)
	}
	if f.FormatVersion < 4 {
		return f, "", nil, fmt.Errorf("ten plik jest w starszym formacie (v%d) i nie obsługuje jeszcze recipientów PGP — otwórz go raz przez Unlock hasłem głównym, żeby zmigrować format", f.FormatVersion)
	}
	return f, resolved, raw, nil
}

func unlockWithGPGDecrypt(path string, decrypt func(gpgBin, armored string) (string, error)) (*Vault, error) {
	gpgBin, err := ResolveGPGBinary()
	if err != nil {
		return nil, err
	}
	f, resolved, b, err := readRecipientFile(path)
	if err != nil {
		return nil, err
	}

	var groupKeyHex string
	matched := false
	var lastErr error
	badPassphrase := false
	for _, rec := range f.Recipients {
		candidate, decErr := decrypt(gpgBin, rec.WrappedGroupKey)
		if decErr != nil {
			if errors.Is(decErr, ErrGPGBadPassphrase) {
				badPassphrase = true
			}
			lastErr = decErr
			continue
		}
		groupKeyHex = candidate
		matched = true
		break
	}
	if !matched {
		if badPassphrase {
			return nil, ErrGPGBadPassphrase
		}
		if lastErr != nil {
			return nil, fmt.Errorf("żaden klucz z lokalnego keyringa gpg nie pasuje do tego pliku: %w", lastErr)
		}
		return nil, fmt.Errorf("plik nie ma żadnego recipienta")
	}
	groupKey, err := decodeGroupKey(groupKeyHex)
	if err != nil {
		return nil, fmt.Errorf("plik vaulta uszkodzony: %w", err)
	}

	v := &Vault{path: resolved, groupKey: groupKey, f: f, diskHash: sha256.Sum256(b)}
	name, err := decryptRaw(v.groupKey, f.VaultNameCiphertext, f.VaultNameKeyWrapped)
	if err != nil {
		return nil, fmt.Errorf("odszyfrowanie nazwy vaulta nieudane: %w", err)
	}
	v.vaultName = name
	return v, nil
}

// gpgDecryptArmored — `gpg --batch --decrypt` na jednej, małej wiadomości
// PGP (tu: wrapped_group_key jednego recipienta). --batch wymusza pytanie o
// hasło PRZEZ gpg-agent/pinentry zamiast fallbacku na tty gpg, co jest tym,
// czego chcemy z aplikacji GUI (patrz dokumentacja UnlockWithSystemGPG).
func gpgDecryptArmored(gpgBin, armoredMessage string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, gpgBin, "--batch", "--decrypt")
	cmd.Stdin = strings.NewReader(armoredMessage)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("gpg --decrypt: przekroczono czas (2 min) — anulowano w pinentry?")
		}
		return "", fmt.Errorf("gpg --decrypt: %s", strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// gpgDecryptArmoredLoopback — jak gpgDecryptArmored, ale z hasłem od
// wołającego (--pinentry-mode loopback). stdin niesie hasło, więc samą
// wiadomość (zawinięty klucz grupy — jest i tak jawnie w pliku vaulta)
// dajemy przez plik tymczasowy; --passphrase-fd na innym deskryptorze
// (ExtraFiles) nie działa na Windows. Złe hasło rozpoznajemy po statusie
// "ERROR pkdecrypt_failed <kod>" z kodem GPG_ERR_BAD_PASSPHRASE — niezależnie
// od języka komunikatów gpg.
func gpgDecryptArmoredLoopback(gpgBin, armoredMessage string, passphrase []byte) (string, error) {
	tmp, err := os.CreateTemp("", "sharqey-gpg-*.asc")
	if err != nil {
		return "", fmt.Errorf("plik tymczasowy dla gpg: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(armoredMessage); err != nil {
		tmp.Close()
		return "", fmt.Errorf("plik tymczasowy dla gpg: %w", err)
	}
	tmp.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, gpgBin, "--batch", "--pinentry-mode", "loopback",
		"--passphrase-fd", "0", "--status-fd", "2", "--decrypt", tmp.Name())
	stdin := make([]byte, 0, len(passphrase)+1)
	stdin = append(append(stdin, passphrase...), '\n')
	defer clear(stdin)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("gpg --decrypt: przekroczono czas (2 min)")
		}
		if gpgStatusBadPassphrase(stderr.String()) {
			return "", ErrGPGBadPassphrase
		}
		return "", fmt.Errorf("gpg --decrypt: %s", gpgStderrWithoutStatus(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// gpgErrBadPassphrase — GPG_ERR_BAD_PASSPHRASE z libgpg-error; w statusie
// ERROR kod ma jeszcze źródło w wyższych bitach, stąd maska 0xFFFF.
const gpgErrBadPassphrase = 11

func gpgStatusBadPassphrase(stderr string) bool {
	for _, line := range strings.Split(stderr, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "[GNUPG:]" {
			continue
		}
		if fields[1] == "BAD_PASSPHRASE" {
			return true
		}
		if fields[1] == "ERROR" && len(fields) >= 4 {
			var code uint64
			if _, err := fmt.Sscanf(fields[3], "%d", &code); err == nil && code&0xFFFF == gpgErrBadPassphrase {
				return true
			}
		}
	}
	return false
}

func gpgStderrWithoutStatus(stderr string) string {
	var lines []string
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(line, "[GNUPG:]") || strings.TrimSpace(line) == "" {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// ListRecipients — wszyscy recipienci tego pliku, bez surowej kryptografii
// (patrz dokumentacja typu Recipient).
func (v *Vault) ListRecipients() []Recipient {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]Recipient, 0, len(v.f.Recipients))
	for _, r := range v.f.Recipients {
		out = append(out, Recipient{ID: r.ID, Label: r.Label, Fingerprint: r.Fingerprint, IsSelf: r.IsSelf})
	}
	return out
}

// AddRecipient zawija bieżący, już odblokowany surowy group key wprost do
// publicKeyArmored (zwykły PGP pubkey-encrypt, pgpcrypto.EncryptArmoredMessage
// — bez S2K/passphrase, to nie jest "hasło współdzielone", tylko klucz TEGO
// recipienta) i dopisuje nowy wpis do recipients[]. Recipient dodany tą drogą
// NIE ma osadzonego private key (IsSelf zostaje false) — ten mieszka poza
// plikiem, u recipienta, dokładnie jak w sops.
func (v *Vault) AddRecipient(label, publicKeyArmored string) (Recipient, error) {
	fingerprint, err := pgpcrypto.FingerprintFromArmoredPublicKey(publicKeyArmored)
	if err != nil {
		return Recipient{}, fmt.Errorf("nieprawidłowy klucz publiczny: %w", err)
	}
	wrapped, err := pgpcrypto.EncryptArmoredMessage(hex.EncodeToString(v.groupKey), publicKeyArmored)
	if err != nil {
		return Recipient{}, fmt.Errorf("zawinięcie klucza grupy nieudane: %w", err)
	}
	id, err := randomID()
	if err != nil {
		return Recipient{}, fmt.Errorf("generowanie ID recipienta nieudane: %w", err)
	}
	rec := recipient{ID: id, Label: label, PublicKeyArmored: publicKeyArmored, Fingerprint: fingerprint, WrappedGroupKey: wrapped}
	if err := v.mutate(func() error {
		v.f.Recipients = append(v.f.Recipients, rec)
		return nil
	}); err != nil {
		return Recipient{}, err
	}
	return Recipient{ID: id, Label: label, Fingerprint: fingerprint}, nil
}

// RemoveRecipient usuwa recipienta z listy — UWAGA, to NIE jest rewokacja
// dostępu (kto raz odblokował plik tym recipientem, znał surowy group key,
// mógł go zapamiętać/skopiować; realne odcięcie wymaga rotacji group key —
// poza zakresem tej funkcji, patrz task 067). Blokuje usunięcie ostatniego
// recipienta — zerowa lista recipientów to plik na zawsze nieodblokowywalny.
func (v *Vault) RemoveRecipient(id string) error {
	return v.mutate(func() error {
		if len(v.f.Recipients) <= 1 {
			return fmt.Errorf("nie można usunąć ostatniego recipienta — plik stałby się nieodblokowywalny")
		}
		idx := -1
		for i, r := range v.f.Recipients {
			if r.ID == id {
				idx = i
				break
			}
		}
		if idx == -1 {
			return fmt.Errorf("nieznany recipient %q", id)
		}
		v.f.Recipients = append(v.f.Recipients[:idx], v.f.Recipients[idx+1:]...)
		return nil
	})
}

// migrateLegacyFormat podnosi w pamięci plik format_version < 2 (jawne
// title/username/url/type/has_totp per sekret, jawne vault_name) BEZPOŚREDNIO
// do format_version 3 (task 012: pomija pośredni zapis w kształcie 2) — title
// zostaje jawny (już jest, pod tym samym kluczem JSON, patrz
// secretRecord.Title), reszta metadanych + wartość trafiają do koperty. Od
// razu zapisuje wynik na dysk — zero wymaganej akcji usera, ten sam wzorzec co
// planowana migracja formatu dla grup (patrz
// tasks/todo/011-local-vault-groups.md, punkt "Migracja formatu pliku przy
// Unlock").
func (v *Vault) migrateLegacyFormat() error {
	for i, rec := range v.f.Secrets {
		content, err := decryptRaw(v.groupKey, rec.Ciphertext, rec.GroupEncryptedSecretKey)
		if err != nil {
			return fmt.Errorf("odszyfrowanie sekretu %q (stary format) nieudane: %w", rec.ID, err)
		}
		newRec, err := v.encryptEnvelope(rec.Title, secretEnvelope{
			Type: rec.LegacyType, Username: rec.LegacyUsername,
			URL: rec.LegacyURL, HasTOTP: rec.LegacyHasTOTP, Content: content,
		})
		if err != nil {
			return fmt.Errorf("migracja sekretu %q nieudana: %w", rec.ID, err)
		}
		newRec.ID = rec.ID
		v.f.Secrets[i] = newRec
	}

	nameCiphertext, nameWrapped, err := encryptRaw(v.groupKey, v.f.LegacyVaultName)
	if err != nil {
		return fmt.Errorf("migracja nazwy vaulta nieudana: %w", err)
	}
	v.vaultName = v.f.LegacyVaultName
	v.f.VaultNameCiphertext = nameCiphertext
	v.f.VaultNameKeyWrapped = nameWrapped
	v.f.LegacyVaultName = ""
	v.f.FormatVersion = 3

	return v.migrateV3ToV4()
}

// migrateV2ToV3 podnosi w pamięci plik format_version 2 (WSZYSTKO poza id
// zaszyfrowane, łącznie z title wewnątrz koperty) do format_version 3 (task
// 012): dla każdego sekretu odszyfrowuje kopertę, przenosi envelope.Title do
// rec.Title (jawne), i szyfruje kopertę PONOWNIE bez title pod TYM SAMYM już
// odwiniętym kluczem sekretu — encryptRaw generuje świeży losowy secret_key i
// nonce (normalne dla AES-GCM, nieszkodliwe), ale GroupEncryptedSecretKey
// jako koncepcja (secret_key zawinięty w groupKey) się nie zmienia w sensie
// bezpieczeństwa, tylko fizycznie na dysku, bo to najprostszy sposób złożenia
// nowej koperty przez ten sam encryptEnvelope. Kończy się jak
// migrateLegacyFormat: FormatVersion=3 + save(), zero akcji usera.
func (v *Vault) migrateV2ToV3() error {
	// envelopeV2 — kształt koperty format_version 2, WYŁĄCZNIE do tej
	// jednorazowej migracji: identyczny jak dzisiejsze secretEnvelope plus
	// title, którego bieżąca (v3) secretEnvelope już nie ma.
	type envelopeV2 struct {
		Type     string `json:"type"`
		Title    string `json:"title"`
		Username string `json:"username"`
		URL      string `json:"url"`
		HasTOTP  bool   `json:"has_totp"`
		Content  string `json:"content"`
	}

	for i, rec := range v.f.Secrets {
		plaintext, err := decryptRaw(v.groupKey, rec.Ciphertext, rec.GroupEncryptedSecretKey)
		if err != nil {
			return fmt.Errorf("odszyfrowanie sekretu %q (v2) nieudane: %w", rec.ID, err)
		}
		var env envelopeV2
		if err := json.Unmarshal([]byte(plaintext), &env); err != nil {
			return fmt.Errorf("deserializacja sekretu %q (v2) nieudana: %w", rec.ID, err)
		}
		newRec, err := v.encryptEnvelope(env.Title, secretEnvelope{
			Type: env.Type, Username: env.Username, URL: env.URL, HasTOTP: env.HasTOTP, Content: env.Content,
		})
		if err != nil {
			return fmt.Errorf("migracja sekretu %q (v2->v3) nieudana: %w", rec.ID, err)
		}
		newRec.ID = rec.ID
		v.f.Secrets[i] = newRec
	}

	name, err := decryptRaw(v.groupKey, v.f.VaultNameCiphertext, v.f.VaultNameKeyWrapped)
	if err != nil {
		return fmt.Errorf("odszyfrowanie nazwy vaulta nieudane: %w", err)
	}
	v.vaultName = name
	v.f.FormatVersion = 3

	return v.migrateV3ToV4()
}

// migrateV3ToV4 podnosi w pamięci plik format_version 3 (jedna, sztywna
// tożsamość: LegacyIdentity+LegacyGroupKeySelfWrapped) do format_version 4
// (task 067): przenosi tożsamość do jedynego, self-wrapped Recipient
// (IsSelf:true — dokładnie ta sama para kluczy i ten sam wrapped group key,
// tylko w nowym kształcie), czyści oba legacy pola. Wołane jako WSPÓLNY,
// ostatni krok każdej migracji (migrateLegacyFormat/migrateV2ToV3 kończą się
// tutaj zamiast bezpośrednio zapisywać v3) — v1/v2 nigdy nie pomijają budowy
// recipienta. Kończy się jak reszta: FormatVersion=4 + save(), zero akcji
// usera.
func (v *Vault) migrateV3ToV4() error {
	id, err := randomID()
	if err != nil {
		return fmt.Errorf("generowanie ID recipienta nieudane: %w", err)
	}
	fingerprint, err := pgpcrypto.FingerprintFromArmoredPublicKey(v.f.LegacyIdentity.PublicKeyArmored)
	if err != nil {
		return fmt.Errorf("obliczenie fingerprintu tożsamości nieudane: %w", err)
	}
	v.f.Recipients = []recipient{{
		ID:                id,
		Label:             "hasło główne",
		PublicKeyArmored:  v.f.LegacyIdentity.PublicKeyArmored,
		Fingerprint:       fingerprint,
		WrappedGroupKey:   v.f.LegacyGroupKeySelfWrapped,
		PrivateKeyArmored: v.f.LegacyIdentity.PrivateKeyArmored,
		IsSelf:            true,
	}}
	v.f.LegacyIdentity = identity{}
	v.f.LegacyGroupKeySelfWrapped = ""
	v.f.FormatVersion = FormatVersionRecipients

	name, err := decryptRaw(v.groupKey, v.f.VaultNameCiphertext, v.f.VaultNameKeyWrapped)
	if err != nil {
		return fmt.Errorf("odszyfrowanie nazwy vaulta nieudane: %w", err)
	}
	v.vaultName = name

	return v.save()
}

func (v *Vault) save() error {
	// Najniższa wersja, która pomieści zawartość (patrz FormatVersion): plik
	// z choć jednym file_blob musi być v5, żeby klient v4 go nie otworzył i
	// nie zgubił bloba przy swoim zapisie.
	if v.f.FormatVersion < FormatVersionFiles && hasFileBlobs(v.f) {
		v.f.FormatVersion = FormatVersionFiles
	}
	b, err := json.MarshalIndent(v.f, "", "  ")
	if err != nil {
		return fmt.Errorf("serializacja vaulta nieudana: %w", err)
	}
	dir := filepath.Dir(v.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("utworzenie katalogu vaulta nieudane: %w", err)
	}
	// Zapis przez plik tymczasowy + rename — atomowo, żeby crash appki w
	// trakcie zapisu nie zostawił obciętego pliku. W przeciwieństwie do
	// trybu online (serwer ma transakcje DB) ten plik jest jedyną kopią
	// danych usera, więc to nie jest opcjonalna ostrożność.
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("zapis pliku vaulta nieudany: %w", err)
	}
	if err := os.Rename(tmp, v.path); err != nil {
		return fmt.Errorf("zapis pliku vaulta nieudany: %w", err)
	}
	v.diskHash = sha256.Sum256(b)
	return nil
}

func (v *Vault) Path() string { return v.path }

func (v *Vault) VaultName() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.vaultName
}

// Reload re-czyta plik z dysku i podmienia grupy/sekrety w pamięci — bez
// tego GUI trzyma wyłącznie zdjęcie stanu z momentu Unlock (patrz
// dokumentacja pakietu), więc zmiany zrobione przez inny proces na tym samym
// pliku (sharqey-cli, sharqey-mcp — Server.unlock w internal/mcpserver robi
// świeży Unlock z dysku przy KAŻDYM tool callu, bez cache) nigdy nie były
// widoczne w już otwartym oknie GUI, nawet po Cmd/Ctrl+R (user feedback
// 2026-09-22: dodał sekret przez MCP, odświeżenie w GUI go nie pokazywało).
// Nie wymaga ponownego hasła głównego — groupKey zostaje w pamięci
// niezmieniony (żaden istniejący przepływ nie rotuje surowego klucza grupy
// pod istniejącym recipientem), reload tylko podmienia f i na wszelki
// wypadek na nowo odszyfrowuje vault_name (mógł zostać zmieniony z zewnątrz
// tak samo jak grupy/sekrety).
func (v *Vault) Reload() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.reloadLocked()
}

// reloadLocked — ciało Reload, wołający trzyma v.mu. format_version spoza
// [FormatVersionRecipients, FormatVersion] to błąd, także przy mutacji
// (patrz mutate): wyższa wersja na dysku znaczy, że nowszy klient zmigrował
// plik, a zapis z tej instancji cofnąłby go do formatu, którego nie rozumie.
// Zmiana 4 -> 5 w międzyczasie (inny proces dodał plik) jest w porządku:
// v.f jest podmieniane w całości na to z dysku, razem z wersją.
func (v *Vault) reloadLocked() error {
	b, err := os.ReadFile(v.path)
	if err != nil {
		return fmt.Errorf("odczyt pliku vaulta nieudany: %w", err)
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("plik vaulta uszkodzony: %w", err)
	}
	if f.FormatVersion < FormatVersionRecipients || f.FormatVersion > FormatVersion {
		return fmt.Errorf("format pliku zmienił się od otwarcia (format_version %d, inny proces zmigrował go w międzyczasie) — zamknij i otwórz plik ponownie", f.FormatVersion)
	}
	name, err := decryptRaw(v.groupKey, f.VaultNameCiphertext, f.VaultNameKeyWrapped)
	if err != nil {
		return fmt.Errorf("odszyfrowanie nazwy vaulta nieudane: %w", err)
	}
	v.f = f
	v.vaultName = name
	v.diskHash = sha256.Sum256(b)
	return nil
}

// Delete usuwa plik vaulta z dysku. Wołane WYŁĄCZNIE po jawnym, osobnym
// potwierdzeniu usera po udanej migracji (brief kanoniczny "Otwarte
// pytania" #3 — "zostaw, zapytaj osobno czy skasować, nigdy nie kasuj
// milcząco") — appka nigdy nie woła tego automatycznie po samym
// MigrateLocalVaultToOrganization.
func Delete(path string) error {
	resolved, err := absPath(path)
	if err != nil {
		return fmt.Errorf("ustalenie ścieżki vaulta nieudane: %w", err)
	}
	if err := os.Remove(resolved); err != nil {
		return fmt.Errorf("usunięcie pliku vaulta nieudane: %w", err)
	}
	return nil
}

// ExportForMigration zwraca dokładnie to, czego potrzebuje
// apiclient.ImportGroup do zamiany tego vaulta w nową organizację online —
// public_key_armored, self-wrapped group key roota, całe drzewo podgrup
// (groups, follow-up taska 011: migracja MUSI zachować strukturę, nie
// spłaszczać do samego roota) i wszystkie sekrety. W przeciwieństwie do
// format_version 1 to NIE jest już czysty upload gotowych ciphertextów:
// skoro lokalny format szyfruje metadane RAZEM z wartością, a model online
// szyfruje WYŁĄCZNIE wartość (metadane jawne w DB, patrz
// apiclient.ImportSecretParams), każdy sekret jest tu odszyfrowany i
// zaszyfrowany na nowo (sama wartość, pod group_key WŁAŚCIWEJ dla niego
// grupy — patrz niżej) — patrz dokumentacja MigrationSecret.
//
// Klucze grupowe podgrup: lokalny plik ma JEDEN wspólny groupKey dla całego
// pliku (ustalenie z userem 2026-09-09, patrz file.Groups) — organizacja
// online wymaga OSOBNEGO group_key per grupa (CLIENT_SPEC.md "Model
// kryptograficzny"). Ta funkcja więc dla KAŻDEJ lokalnej podgrupy generuje
// świeży 32B group_key i self-wrapped go do tego samego identity key co
// reszta importu (dokładnie jak CreateSubgroup w app.go dla ręcznie
// tworzonej subgrupy) — root NIE dostaje nowego klucza, zostaje przy
// istniejącym v.f.GroupKeySelfWrapped/v.groupKey, bez zmian względem sprzed
// taska 011.
//
// ZWRACA TEŻ privateKeyArmored (odstępstwo od pierwotnego brzmienia tasku
// 003 punkt 3, świadome, ustalone z userem 2026-08-23): appka MUSI
// zarejestrować ten klucz w lokalnym keychainie (app.go, przez ten sam
// mechanizm co ImportOrgKey) zaraz po udanym imporcie, inaczej organizacja
// powstaje na serwerze, ale appka nigdy nie ma czym odszyfrować jej
// sekretów — nie istnieje żaden inny plik z backupem tego klucza do
// wklejenia. To NIE jest "surowy dostęp" w sensie ryzyka: klucz cały czas
// zostaje na tym samym urządzeniu (kopiowany z pliku vaulta do
// keychain.json, nigdy przez sieć), dalej chroniony tą samą passphrase co
// dziś (hasło główne vaulta) — dokładnie ten sam poziom ochrony co każdy
// inny wpis w keychain.json.
func (v *Vault) ExportForMigration() (publicKeyArmored, privateKeyArmored, groupKeySelfWrapped string, groups []MigrationGroup, secrets []MigrationSecret, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	self, ok := findSelfRecipient(v.f.Recipients)
	if !ok {
		return "", "", "", nil, nil, fmt.Errorf("ten plik nie ma tożsamości z osadzonym kluczem prywatnym — migracja do organizacji wymaga trybu hasła głównego")
	}

	// rawKeyByGroupID — surowy (odszyfrowany) 32B AES group_key dla każdej
	// grupy tego eksportu, kluczowane localvault.Group.ID ("" = root, czyli
	// v.groupKey — bez zmian). Świeże klucze podgrup generowane TERAZ, tylko
	// na potrzeby tego eksportu — plik na dysku ich nie trzyma (patrz wyżej).
	rawKeyByGroupID := map[string][]byte{"": v.groupKey}
	outGroups := make([]MigrationGroup, 0, len(v.f.Groups))
	for _, group := range v.f.Groups {
		groupKeyHex, encryptedGroupKey, genErr := pgpcrypto.GenerateEncryptedGroupKey(self.PublicKeyArmored)
		if genErr != nil {
			return "", "", "", nil, nil, fmt.Errorf("generowanie group key dla podgrupy %q nieudane: %w", group.Name, genErr)
		}
		rawKey, decErr := decodeGroupKey(groupKeyHex)
		if decErr != nil {
			return "", "", "", nil, nil, fmt.Errorf("dekodowanie group key dla podgrupy %q nieudane: %w", group.Name, decErr)
		}
		rawKeyByGroupID[group.ID] = rawKey
		outGroups = append(outGroups, MigrationGroup{
			LocalID: group.ID, ParentLocalID: group.ParentID, Name: group.Name, GroupKeySelfWrapped: encryptedGroupKey,
		})
	}

	if hasFileBlobs(v.f) {
		// Migracja pliku wymaga uploadu bloba (filesecret) — jeszcze nie
		// zrobione. Lepiej odmówić niż po cichu zgubić pliki w organizacji.
		return "", "", "", nil, nil, fmt.Errorf("ten plik zawiera sekrety typu plik — ich migracja do organizacji nie jest jeszcze obsługiwana")
	}
	out := make([]MigrationSecret, 0, len(v.f.Secrets))
	for _, rec := range v.f.Secrets {
		env, decErr := v.decryptSecretRecord(rec)
		if decErr != nil {
			return "", "", "", nil, nil, fmt.Errorf("odszyfrowanie sekretu %q nieudane (migracja): %w", rec.ID, decErr)
		}
		rawKey, ok := rawKeyByGroupID[rec.GroupID]
		if !ok {
			return "", "", "", nil, nil, fmt.Errorf("sekret %q wskazuje nieznaną grupę %q", rec.ID, rec.GroupID)
		}
		ciphertext, wrapped, encErr := encryptRaw(rawKey, env.Content)
		if encErr != nil {
			return "", "", "", nil, nil, fmt.Errorf("przygotowanie sekretu %q do migracji nieudane: %w", rec.ID, encErr)
		}
		out = append(out, MigrationSecret{
			Type: env.Type, Title: rec.Title, Username: env.Username, URL: env.URL, HasTOTP: env.HasTOTP,
			Ciphertext: ciphertext, GroupEncryptedSecretKey: wrapped, GroupLocalID: rec.GroupID,
		})
	}
	return self.PublicKeyArmored, self.PrivateKeyArmored, self.WrappedGroupKey, outGroups, out, nil
}

// ListSecrets — metadane wszystkich sekretów (analogon apiclient.
// GroupSecrets). W przeciwieństwie do format_version 1 wymaga odszyfrowania
// KAŻDEGO sekretu (metadane żyją wewnątrz koperty) — tanie, bo groupKey jest
// już w pamięci (patrz dokumentacja pakietu): jedna AES-GCM operacja na
// sekret, żadnego PGP.
func (v *Vault) ListSecrets() ([]Secret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]Secret, 0, len(v.f.Secrets))
	for _, rec := range v.f.Secrets {
		env, err := v.decryptSecretRecord(rec)
		if err != nil {
			return nil, fmt.Errorf("odszyfrowanie sekretu %q nieudane: %w", rec.ID, err)
		}
		out = append(out, secretView(rec, env))
	}
	return out, nil
}

// SecretByID — metadane jednego sekretu (np. do zachowania HasTOTP przy
// metadata-only update, patrz App.UpdateSecret). found==false ⇔ nie ma
// takiego ID; err!=nil ⇔ ID istnieje, ale odszyfrowanie się nie powiodło
// (plik uszkodzony) — te dwa przypadki wołający powinien rozróżniać.
func (v *Vault) SecretByID(id string) (secret Secret, found bool, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, rec := range v.f.Secrets {
		if rec.ID != id {
			continue
		}
		env, decErr := v.decryptSecretRecord(rec)
		if decErr != nil {
			return Secret{}, true, fmt.Errorf("odszyfrowanie sekretu %q nieudane: %w", id, decErr)
		}
		return secretView(rec, env), true, nil
	}
	return Secret{}, false, nil
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// AddSecret szyfruje metadane+plaintext RAZEM w jedną kopertę (secretEnvelope
// -> encryptEnvelope, AES-GCM secret_key losowy per sekret, secret_key ->
// AES-GCM groupKey — dokładnie ten sam prymityw co App.CreateSecret dla
// trybu online, tylko z groupKey już w pamięci zamiast re-derywowanego z PGP)
// i dopisuje nowy sekret do pliku, zapisując od razu na dysk — lokalny plik
// jest jedynym "serwerem" tego trybu, bez write-through restart appki
// zgubiłby zmianę.
func (v *Vault) AddSecret(secretType, title, username, url, groupID string, hasTOTP bool, plaintext []byte) (Secret, error) {
	if secretType == TypeFile {
		return Secret{}, fmt.Errorf("sekret typu plik dodaje się przez AddFile")
	}
	rec, err := v.encryptEnvelope(title, secretEnvelope{
		Type: secretType, Username: username, URL: url, HasTOTP: hasTOTP, Content: string(plaintext),
	})
	if err != nil {
		return Secret{}, fmt.Errorf("szyfrowanie sekretu nieudane: %w", err)
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
	return Secret{ID: id, Type: secretType, Title: title, Username: username, URL: url, HasTOTP: hasTOTP, GroupID: groupID}, nil
}

// UpdateSecret nadpisuje metadane sekretu id i, jeśli plaintext != nil,
// re-encryptuje jego zawartość (nil = zostaw obecną, ten sam kontrakt co
// apiclient.UpdateSecretParams z polami wskaźnikowymi). Metadane i treść
// żyją w JEDNEJ kopercie (patrz dokumentacja pakietu), więc KAŻDE wywołanie
// odszyfrowuje istniejący rekord (żeby zachować Type i, przy metadata-only
// update, Content) i zapisuje nową kopertę — w przeciwieństwie do
// format_version 1 ciphertext zmienia się nawet gdy plaintext==nil (nowy
// nonce/AEAD-tag, ta sama treść: normalne dla AES-GCM, nieszkodliwe).
func (v *Vault) UpdateSecret(id, title, username, url, groupID string, hasTOTP bool, plaintext []byte) error {
	return v.mutate(func() error {
		if groupID != "" {
			if _, ok := v.findGroup(groupID); !ok {
				return fmt.Errorf("nieznana grupa %q", groupID)
			}
		}
		for i := range v.f.Secrets {
			if v.f.Secrets[i].ID != id {
				continue
			}
			existing, err := v.decryptSecretRecord(v.f.Secrets[i])
			if err != nil {
				return fmt.Errorf("odczyt obecnej treści sekretu nieudany: %w", err)
			}
			content := existing.Content
			if plaintext != nil {
				if existing.Type == TypeFile {
					return fmt.Errorf("sekret %q jest plikiem — treść podmienia się przez ReplaceFile", id)
				}
				content = string(plaintext)
			}
			rec, err := v.encryptEnvelope(title, secretEnvelope{
				Type: existing.Type, Username: username, URL: url, HasTOTP: hasTOTP, Content: content,
			})
			if err != nil {
				return fmt.Errorf("szyfrowanie sekretu nieudane: %w", err)
			}
			rec.ID = id
			rec.GroupID = groupID
			rec.FileBlob = v.f.Secrets[i].FileBlob
			v.f.Secrets[i] = rec
			return nil
		}
		return fmt.Errorf("nieznany sekret %q", id)
	})
}

// DecryptSecret odszyfrowuje treść jednego sekretu wraz z jego metadanymi
// (jedna koperta, patrz dokumentacja pakietu) — ten sam algorytm co
// App.decryptResult dla trybu online, tylko bez PGP-decrypt group key za
// każdym razem (groupKey już w pamięci). Zwraca też metadane (Secret) żeby
// wołający nie musiał osobno wołać SecretByID. Dla typu "file" odmawia:
// treścią koperty są metadane z file_key, które nie mogą trafić do UI,
// schowka ani MCP — plik czyta się przez ReadFile.
func (v *Vault) DecryptSecret(id string) (Secret, []byte, error) {
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
		if env.Type == TypeFile {
			return Secret{}, nil, fmt.Errorf("sekret %q jest plikiem — użyj ReadFile", id)
		}
		return secretView(rec, env), []byte(env.Content), nil
	}
	return Secret{}, nil, fmt.Errorf("nieznany sekret %q", id)
}
