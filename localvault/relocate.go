package localvault

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Operacje na samym pliku otwartego vaulta (przeniesione z desktopu razem z
// resztą pakietu — potrzebują v.mu/v.path/v.diskHash). Logika iCloud
// (wykrywanie folderu, lista plików) zostaje w desktopie.

// Relocate przenosi plik tego vaulta do katalogu destDir (np. desktop:
// włączenie synchronizacji -> folder iCloud, wyłączenie -> domyślny katalog) i przepina v.path.
// Nazwa pliku bez zmian, przy kolizji "Nazwa 2.sharqey", "Nazwa 3.sharqey"…
// (jak Finder i mobile, local_vault_relocation.dart). Pod v.mu, więc żadna
// mutacja nie zapisze w międzyczasie pod starą ścieżką. Zwraca nową ścieżkę.
func (v *Vault) Relocate(destDir string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return "", fmt.Errorf("utworzenie katalogu docelowego nieudane: %w", err)
	}
	dest := freeName(destDir, filepath.Base(v.path))
	if err := moveFile(v.path, dest); err != nil {
		return "", fmt.Errorf("przeniesienie pliku nieudane: %w", err)
	}
	v.path = dest
	return dest, nil
}

func freeName(dir, base string) string {
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	candidate := filepath.Join(dir, base)
	for n := 2; ; n++ {
		if _, err := os.Lstat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate
		}
		candidate = filepath.Join(dir, fmt.Sprintf("%s %d%s", stem, n, ext))
	}
}

// moveFile — os.Rename, a między wolumenami (EXDEV, np. plik na dysku
// zewnętrznym) kopia + fsync + usunięcie oryginału. Kopia idzie przez
// ".tmp" + rename, żeby w folderze docelowym (iCloud!) nigdy nie leżał
// obcięty plik pod docelową nazwą.
func moveFile(src, dest string) error {
	err := os.Rename(src, dest)
	if err == nil {
		return nil
	}
	var linkErr *os.LinkError
	if !errors.As(err, &linkErr) || !errors.Is(linkErr.Err, syscall.EXDEV) {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dest + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Remove(src)
}

// ChangedOnDisk — czy plik na dysku różni się od tego, co ta instancja
// ostatnio sama zapisała albo wczytała (hash całej zawartości). Pozwala
// watcherowi (task 013 pkt 4) odróżnić zmianę z zewnątrz (iPhone przez
// iCloud, sharqey-mcp/cli) od echa własnego save(). Brak pliku zwraca błąd
// spełniający errors.Is(err, os.ErrNotExist) — plik przeniesiony albo
// usunięty (np. wyłączenie synchronizacji na innym urządzeniu).
func (v *Vault) ChangedOnDisk() (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	b, err := os.ReadFile(v.path)
	if err != nil {
		return false, err
	}
	return sha256.Sum256(b) != v.diskHash, nil
}
