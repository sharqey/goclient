package localvault

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// withTempGNUPGHOME — osobny keyring i gpg-agent na czas testu. Katalog w
// /tmp, nie t.TempDir(): na macOS ścieżka t.TempDir() jest za długa na
// sockety agenta ("File name too long").
func withTempGNUPGHOME(t *testing.T) {
	t.Helper()
	if _, err := ResolveGPGBinary(); err != nil {
		t.Skip("brak gpg:", err)
	}
	home, err := os.MkdirTemp("/tmp", "gh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "gpg-agent.conf"), []byte("allow-loopback-pinentry\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", home)
	t.Cleanup(func() {
		exec.Command("gpgconf", "--kill", "gpg-agent").Run()
		os.RemoveAll(home)
	})
}

func gpgRun(t *testing.T, args ...string) string {
	t.Helper()
	gpgBin, _ := ResolveGPGBinary()
	out, err := exec.Command(gpgBin, args...).Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("gpg %v: %v %s", args, err, stderr)
	}
	return string(out)
}

func TestUnlockWithSystemGPGPassphrase(t *testing.T) {
	withTempGNUPGHOME(t)
	gpgRun(t, "--batch", "--pinentry-mode", "loopback", "--passphrase", "right-one",
		"--quick-generate-key", "Test <t@example.com>", "default", "default", "never")
	pub := gpgRun(t, "--batch", "--export", "--armor", "t@example.com")
	var fpr string
	for _, line := range strings.Split(gpgRun(t, "--batch", "--with-colons", "--fingerprint", "t@example.com"), "\n") {
		if strings.HasPrefix(line, "fpr:") {
			fpr = strings.Split(line, ":")[9]
			break
		}
	}

	path := filepath.Join(t.TempDir(), "gpg.sharqey")
	if _, err := CreateWithExternalKey(path, "GPG vault", pub); err != nil {
		t.Fatalf("CreateWithExternalKey: %v", err)
	}

	fps, err := RecipientFingerprints(path)
	if err != nil {
		t.Fatalf("RecipientFingerprints: %v", err)
	}
	if len(fps) != 1 || fps[0] != fpr {
		t.Fatalf("RecipientFingerprints = %v, want [%s]", fps, fpr)
	}

	// Generowanie klucza przez loopback zostawia hasło w cache agenta, a
	// zcache'owane hasło wygrywa z podanym — bez flush złe hasło by przeszło.
	gpgconnect := exec.Command("gpg-connect-agent", "reloadagent", "/bye")
	if out, err := gpgconnect.CombinedOutput(); err != nil {
		t.Fatalf("reloadagent: %v %s", err, out)
	}

	if _, err := UnlockWithSystemGPGPassphrase(path, []byte("wrong")); !errors.Is(err, ErrGPGBadPassphrase) {
		t.Fatalf("złe hasło: err = %v, want ErrGPGBadPassphrase", err)
	}
	v, err := UnlockWithSystemGPGPassphrase(path, []byte("right-one"))
	if err != nil {
		t.Fatalf("dobre hasło: %v", err)
	}
	if v.VaultName() != "GPG vault" {
		t.Fatalf("VaultName = %q", v.VaultName())
	}
}

func TestGPGStatusBadPassphrase(t *testing.T) {
	cases := map[string]bool{
		"gpg: public key decryption failed: Bad passphrase\n[GNUPG:] ERROR pkdecrypt_failed 67108875\n": true,
		"[GNUPG:] BAD_PASSPHRASE 453139C92156C4C2\n":                                                    true,
		"[GNUPG:] ERROR pkdecrypt_failed 67108881\n":                                                    false,
		"gpg: decryption failed: No secret key\n":                                                       false,
	}
	for in, want := range cases {
		if got := gpgStatusBadPassphrase(in); got != want {
			t.Errorf("gpgStatusBadPassphrase(%q) = %v, want %v", in, got, want)
		}
	}
}
