package apiclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Fake serwer odtwarzający kontrakt z password-manager/tasks/todo/086-mfa-totp.md.
func newMFATestServer(t *testing.T) *httptest.Server {
	t.Helper()
	writeJSON := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/login", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Email, Password string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch {
		case in.Password != "ok":
			writeJSON(w, 401, map[string]string{"error": "invalid credentials"})
		case in.Email == "mfa@example.com":
			writeJSON(w, 401, map[string]string{"error": "mfa_required", "mfa_token": "mfa-jwt"})
		default:
			writeJSON(w, 200, map[string]string{"token": "tok", "refresh_token": "ref"})
		}
	})
	mux.HandleFunc("POST /api/v1/login/mfa", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			MFAToken string `json:"mfa_token"`
			Code     string `json:"code"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch {
		case in.MFAToken != "mfa-jwt":
			writeJSON(w, 401, map[string]string{"error": "mfa_token_expired"})
		case in.Code == "123456":
			writeJSON(w, 200, map[string]string{"token": "tok", "refresh_token": "ref"})
		case in.Code == "abcde-fghij":
			writeJSON(w, 200, map[string]any{"token": "tok", "refresh_token": "ref", "recovery_code_used": true, "recovery_codes_remaining": 3})
		case in.Code == "000000":
			writeJSON(w, 429, map[string]string{"error": "too_many_attempts"})
		default:
			writeJSON(w, 401, map[string]string{"error": "invalid_code"})
		}
	})
	mux.HandleFunc("GET /api/v1/me/mfa", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		writeJSON(w, 200, map[string]any{"totp_enabled": true, "recovery_codes_remaining": 7, "required": true})
	})
	mux.HandleFunc("POST /api/v1/me/mfa/totp/setup", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"secret": "JBSWY3DP", "otpauth_url": "otpauth://totp/x", "qr_png": "data:image/png;base64,AA=="})
	})
	mux.HandleFunc("POST /api/v1/me/mfa/totp/enable", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Code string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch in.Code {
		case "123456":
			writeJSON(w, 200, map[string]any{"recovery_codes": []string{"aaaaa-bbbbb", "ccccc-ddddd"}, "token": "tok-mfa", "refresh_token": "ref-mfa"})
		case "409":
			writeJSON(w, 409, map[string]string{"error": "no_pending_setup"})
		default:
			writeJSON(w, 400, map[string]string{"error": "invalid_code"})
		}
	})
	mux.HandleFunc("POST /api/v1/me/mfa/totp/disable", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Code string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Code == "policy" {
			writeJSON(w, 409, map[string]string{"error": "required_by_policy"})
			return
		}
		if in.Code != "123456" {
			writeJSON(w, 400, map[string]string{"error": "invalid_code"})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/v1/me/mfa/recovery-codes", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 409, map[string]string{"error": "not_enabled"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestLoginWithoutMFAUnchanged(t *testing.T) {
	c := New(newMFATestServer(t).URL)
	tok, ref, err := c.Login("plain@example.com", "ok")
	if err != nil || tok != "tok" || ref != "ref" {
		t.Fatalf("Login = %q, %q, %v", tok, ref, err)
	}
}

func TestLoginInvalidCredentialsIsNotMFA(t *testing.T) {
	c := New(newMFATestServer(t).URL)
	_, _, err := c.Login("mfa@example.com", "bad")
	var mfaErr *MFARequiredError
	if err == nil || errors.As(err, &mfaErr) {
		t.Fatalf("oczekiwany zwykły błąd, jest %v", err)
	}
	// Tekst błędu bez zmian względem sprzed APIError — wołający mogą go
	// pokazywać/przeszukiwać.
	if !strings.Contains(err.Error(), "HTTP 401") || !strings.Contains(err.Error(), "invalid credentials") {
		t.Fatalf("zmieniony tekst błędu: %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code() != "invalid credentials" {
		t.Fatalf("brak *APIError z kodem: %v", err)
	}
}

func TestLoginMFARequired(t *testing.T) {
	c := New(newMFATestServer(t).URL)
	_, _, err := c.Login("mfa@example.com", "ok")
	var mfaErr *MFARequiredError
	if !errors.As(err, &mfaErr) || mfaErr.MFAToken != "mfa-jwt" {
		t.Fatalf("oczekiwany *MFARequiredError, jest %v", err)
	}
}

func TestLoginMFA(t *testing.T) {
	c := New(newMFATestServer(t).URL)

	res, err := c.LoginMFA("mfa-jwt", "123456")
	if err != nil || res.Token != "tok" || res.RefreshToken != "ref" || res.RecoveryCodeUsed {
		t.Fatalf("TOTP: %+v, %v", res, err)
	}

	res, err = c.LoginMFA("mfa-jwt", "abcde-fghij")
	if err != nil || !res.RecoveryCodeUsed || res.RecoveryCodesRemaining != 3 {
		t.Fatalf("kod zapasowy: %+v, %v", res, err)
	}

	for code, want := range map[string]error{
		"111111": ErrMFAInvalidCode,
		"000000": ErrMFATooManyAttempts,
	} {
		if _, err := c.LoginMFA("mfa-jwt", code); !errors.Is(err, want) {
			t.Errorf("kod %s: oczekiwany %v, jest %v", code, want, err)
		}
	}
	if _, err := c.LoginMFA("stary", "123456"); !errors.Is(err, ErrMFATokenExpired) {
		t.Errorf("oczekiwany ErrMFATokenExpired, jest %v", err)
	}
}

func TestMFAManagement(t *testing.T) {
	c := New(newMFATestServer(t).URL)
	c.SetToken("tok")

	st, err := c.MFAStatus()
	if err != nil || !st.TOTPEnabled || st.RecoveryCodesRemaining != 7 || !st.Required {
		t.Fatalf("MFAStatus: %+v, %v", st, err)
	}

	setup, err := c.TOTPSetup()
	if err != nil || setup.Secret != "JBSWY3DP" || setup.OTPAuthURL == "" || !strings.HasPrefix(setup.QRPNG, "data:image/png") {
		t.Fatalf("TOTPSetup: %+v, %v", setup, err)
	}

	en, err := c.TOTPEnable("123456")
	if err != nil || len(en.RecoveryCodes) != 2 || en.Token != "tok-mfa" || en.RefreshToken != "ref-mfa" {
		t.Fatalf("TOTPEnable: %+v, %v", en, err)
	}
	if _, err := c.TOTPEnable("999999"); !errors.Is(err, ErrMFAInvalidCode) {
		t.Errorf("TOTPEnable zły kod: %v", err)
	}
	if _, err := c.TOTPEnable("409"); !errors.Is(err, ErrMFANoPendingSetup) {
		t.Errorf("TOTPEnable bez setupu: %v", err)
	}

	if err := c.TOTPDisable("123456"); err != nil {
		t.Errorf("TOTPDisable: %v", err)
	}
	if err := c.TOTPDisable("1"); !errors.Is(err, ErrMFAInvalidCode) {
		t.Errorf("TOTPDisable zły kod: %v", err)
	}
	if err := c.TOTPDisable("policy"); !errors.Is(err, ErrMFARequiredByPolicy) {
		t.Errorf("TOTPDisable przy wymogu: %v", err)
	}

	if _, err := c.RegenerateRecoveryCodes("123456"); !errors.Is(err, ErrMFANotEnabled) {
		t.Errorf("RegenerateRecoveryCodes: %v", err)
	}
}

// Etap 2: wymuszone MFA — 403 na /api/*, redirect 303 na /mfa poza /api/.
func newEnforcedTestServer(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	posts := 0
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /api/v1/me/identities", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 403, map[string]any{"error": "mfa_enforced", "totp_enabled": false})
	})
	mux.HandleFunc("POST /g/{id}/secrets", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/mfa?next=%2F", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /mfa", func(w http.ResponseWriter, r *http.Request) {
		// Gdyby klient podążył za redirectem, "POST" wyglądałby na udany.
		posts++
		w.Write([]byte("<html>kod</html>"))
	})
	mux.HandleFunc("GET /api/v1/me/mfa", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"totp_enabled": true, "recovery_codes_remaining": 10, "required": true})
	})
	mux.HandleFunc("POST /api/v1/me/mfa/verify", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Code string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Code != "123456" {
			writeJSON(w, 400, map[string]string{"error": "invalid_code"})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "token": "tok-mfa", "refresh_token": "ref-mfa", "recovery_code_used": true, "recovery_codes_remaining": 9})
	})
	mux.HandleFunc("GET /g/{id}/mfa-settings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"require_mfa": true, "members": []map[string]any{{"user_id": "u1", "email": "a@x", "name": "A", "role": "owner", "totp_enabled": true}}})
	})
	mux.HandleFunc("PATCH /g/{id}/mfa-settings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]bool{"require_mfa": false})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &posts
}

func TestMFAEnforced(t *testing.T) {
	srv, followed := newEnforcedTestServer(t)
	c := New(srv.URL)
	c.SetToken("tok")
	var hooked []*MFAEnforcedError
	c.SetMFAEnforcedHandler(func(e *MFAEnforcedError) { hooked = append(hooked, e) })

	_, err := c.MyIdentities()
	var enforced *MFAEnforcedError
	if !errors.As(err, &enforced) || enforced.TOTPEnabled {
		t.Fatalf("403: oczekiwany *MFAEnforcedError{false}, jest %v", err)
	}
	if !strings.HasPrefix(err.Error(), "mfa_enforced") {
		t.Errorf("Error() bez prefiksu mfa_enforced: %q", err.Error())
	}

	_, err = c.CreateSecret("g1", CreateSecretParams{})
	if !errors.As(err, &enforced) || !enforced.TOTPEnabled {
		t.Fatalf("redirect /mfa: oczekiwany *MFAEnforcedError{true}, jest %v", err)
	}
	if *followed != 0 {
		t.Fatal("klient podążył za redirectem na /mfa")
	}
	if len(hooked) != 2 {
		t.Fatalf("handler wołany %d razy, oczekiwane 2", len(hooked))
	}

	if _, err := c.VerifySession("1"); !errors.Is(err, ErrMFAInvalidCode) {
		t.Errorf("VerifySession zły kod: %v", err)
	}
	res, err := c.VerifySession("123456")
	if err != nil || res.Token != "tok-mfa" || res.RefreshToken != "ref-mfa" || !res.RecoveryCodeUsed || res.RecoveryCodesRemaining != 9 {
		t.Fatalf("VerifySession: %+v, %v", res, err)
	}
}

func TestOrgMFASettings(t *testing.T) {
	srv, _ := newEnforcedTestServer(t)
	c := New(srv.URL)
	c.SetToken("tok")

	st, err := c.GetOrgMFASettings("org1")
	if err != nil || !st.RequireMFA || len(st.Members) != 1 || st.Members[0].Role != "owner" || !st.Members[0].TOTPEnabled {
		t.Fatalf("GetOrgMFASettings: %+v, %v", st, err)
	}
	if err := c.SetOrgRequireMFA("org1", false); err != nil {
		t.Fatalf("SetOrgRequireMFA: %v", err)
	}
}

// "Zapamiętaj to urządzenie" (086 etap 3).
func TestRememberDevice(t *testing.T) {
	writeJSON := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	const exp = "2026-11-08T10:00:00Z"
	var lastBody map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/login", func(w http.ResponseWriter, r *http.Request) {
		lastBody = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&lastBody)
		if lastBody["mfa_remember_token"] == "rt" {
			writeJSON(w, 200, map[string]string{"token": "tok-mfa", "refresh_token": "ref-mfa"})
			return
		}
		writeJSON(w, 401, map[string]string{"error": "mfa_required", "mfa_token": "mfa-jwt"})
	})
	mux.HandleFunc("POST /api/v1/login/mfa", func(w http.ResponseWriter, r *http.Request) {
		lastBody = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&lastBody)
		out := map[string]any{"token": "tok", "refresh_token": "ref"}
		if lastBody["remember"] == true {
			out["mfa_remember_token"] = "rt"
			out["mfa_remember_expires_at"] = exp
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("POST /api/v1/me/mfa/verify", func(w http.ResponseWriter, r *http.Request) {
		lastBody = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&lastBody)
		out := map[string]any{"ok": true, "token": "tok-mfa", "refresh_token": "ref-mfa"}
		switch {
		case lastBody["mfa_remember_token"] == "rt":
		case lastBody["mfa_remember_token"] != nil:
			writeJSON(w, 400, map[string]string{"error": "invalid_remember_token"})
			return
		case lastBody["remember"] == true:
			out["mfa_remember_token"] = "rt2"
			out["mfa_remember_expires_at"] = exp
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("POST /api/v1/me/mfa/totp/enable", func(w http.ResponseWriter, r *http.Request) {
		lastBody = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&lastBody)
		writeJSON(w, 200, map[string]any{"recovery_codes": []string{"a"}, "token": "t", "refresh_token": "r", "mfa_remember_token": "rt3", "mfa_remember_expires_at": exp})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := New(srv.URL)

	// Login bez tokenu nie wysyła pola wcale (stare zachowanie).
	_, _, err := c.Login("a@x", "pw")
	var mfaErr *MFARequiredError
	if !errors.As(err, &mfaErr) {
		t.Fatalf("Login: %v", err)
	}
	if _, ok := lastBody["mfa_remember_token"]; ok {
		t.Error("Login wysłał mfa_remember_token")
	}
	// Zły token = zwykłe mfa_required.
	if _, _, err := c.LoginRemembered("a@x", "pw", "stary"); !errors.As(err, &mfaErr) {
		t.Fatalf("LoginRemembered zły token: %v", err)
	}
	tok, ref, err := c.LoginRemembered("a@x", "pw", "rt")
	if err != nil || tok != "tok-mfa" || ref != "ref-mfa" {
		t.Fatalf("LoginRemembered: %q %q %v", tok, ref, err)
	}

	res, err := c.LoginMFARemember("mfa-jwt", "123456", true)
	if err != nil || res.RememberToken != "rt" || res.RememberExpiresAt.Format(time.RFC3339) != exp {
		t.Fatalf("LoginMFARemember: %+v, %v", res, err)
	}
	res, err = c.LoginMFA("mfa-jwt", "123456")
	if err != nil || res.RememberToken != "" || lastBody["remember"] != false {
		t.Fatalf("LoginMFA bez remember: %+v, %v, body %v", res, err, lastBody)
	}

	res, err = c.VerifySessionRemember("123456", true)
	if err != nil || res.RememberToken != "rt2" || res.Token != "tok-mfa" {
		t.Fatalf("VerifySessionRemember: %+v, %v", res, err)
	}
	res, err = c.VerifySessionWithRememberToken("rt")
	if err != nil || res.Token != "tok-mfa" || res.RefreshToken != "ref-mfa" {
		t.Fatalf("VerifySessionWithRememberToken: %+v, %v", res, err)
	}
	if _, ok := lastBody["code"]; ok {
		t.Error("VerifySessionWithRememberToken wysłał code")
	}
	if _, err := c.VerifySessionWithRememberToken("zły"); !errors.Is(err, ErrMFAInvalidRememberToken) {
		t.Fatalf("zły remember token: %v", err)
	}

	en, err := c.TOTPEnableRemember("123456", true)
	if err != nil || en.RememberToken != "rt3" || lastBody["remember"] != true {
		t.Fatalf("TOTPEnableRemember: %+v, %v", en, err)
	}
}
