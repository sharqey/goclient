package apiclient

// MFA (TOTP) dla logowania hasłem — kontrakt API w
// password-manager/tasks/todo/086-mfa-totp.md (źródło prawdy, nie zgaduj
// kształtu). Dotyczy WYŁĄCZNIE Login (hasło): passkey/Google/Apple/org SSO
// i RefreshToken nigdy nie pytają o kod.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// MFARequiredError — Login: hasło poprawne, ale konto ma włączone TOTP.
// MFAToken (JWT, ~5 min, NIE nadaje się na Bearer) przekazuje się do
// LoginMFA razem z kodem od usera.
type MFARequiredError struct {
	MFAToken string
}

func (e *MFARequiredError) Error() string {
	return "wymagany kod weryfikacyjny (MFA)"
}

// Sentinele dla kodów błędów MFA z serwera (pole "error" w JSON) —
// errors.Is zamiast porównywania stringów po stronie wołającego. Komunikat
// to fallback do pokazania wprost; UI z własnymi tłumaczeniami rozróżnia po
// samym sentinelu.
var (
	// ErrMFAInvalidCode — zły kod TOTP / kod zapasowy. LoginMFA: zostań na
	// ekranie kodu, mfa_token wciąż ważny.
	ErrMFAInvalidCode = errors.New("nieprawidłowy kod weryfikacyjny")
	// ErrMFATokenExpired — mfa_token wygasł (5 min) albo jest niepoprawny:
	// trzeba wrócić do hasła, ponowna próba kodu nic nie da.
	ErrMFATokenExpired = errors.New("weryfikacja wygasła, zaloguj się ponownie")
	// ErrMFATooManyAttempts — limit nieudanych prób per user (5 na 15 min),
	// niezależnie od mfa_tokena.
	ErrMFATooManyAttempts = errors.New("zbyt wiele nieudanych prób, spróbuj ponownie później")
	ErrMFAAlreadyEnabled  = errors.New("weryfikacja dwuetapowa jest już włączona")
	ErrMFANoPendingSetup  = errors.New("brak rozpoczętej konfiguracji weryfikacji dwuetapowej")
	ErrMFANotEnabled      = errors.New("weryfikacja dwuetapowa nie jest włączona")
	// ErrMFARequiredByPolicy — TOTPDisable, gdy organizacja albo instancja
	// wymaga MFA (etap 2): user nie może go sam wyłączyć.
	ErrMFARequiredByPolicy = errors.New("weryfikacja dwuetapowa jest wymagana przez organizację")
	// ErrMFAInvalidRememberToken — VerifySessionWithRememberToken: token
	// zapamiętanego urządzenia zły, wygasły (30 dni) albo unieważniony
	// (wyłączenie/reset MFA). Wołający powinien go skasować i poprosić o kod.
	ErrMFAInvalidRememberToken = errors.New("urządzenie nie jest już zapamiętane")
)

var mfaErrorCodes = map[string]error{
	"invalid_code":           ErrMFAInvalidCode,
	"mfa_token_expired":      ErrMFATokenExpired,
	"too_many_attempts":      ErrMFATooManyAttempts,
	"already_enabled":        ErrMFAAlreadyEnabled,
	"no_pending_setup":       ErrMFANoPendingSetup,
	"not_enabled":            ErrMFANotEnabled,
	"required_by_policy":     ErrMFARequiredByPolicy,
	"invalid_remember_token": ErrMFAInvalidRememberToken,
}

// mapMFAError — *APIError ze znanym kodem MFA -> sentinel, reszta bez zmian
// (offline, 5xx, nieznany kod zostają czytelne dla wołającego jak dotąd).
func mapMFAError(err error) error {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		if sentinel, ok := mfaErrorCodes[apiErr.Code()]; ok {
			return sentinel
		}
	}
	return err
}

// mfaRequiredFrom — *MFARequiredError gdy err to 401 {error:"mfa_required",
// mfa_token}, inaczej nil. Bez niepustego mfa_token to nie jest stan, z
// którego da się dokończyć logowanie — zostaje zwykłym błędem.
func mfaRequiredFrom(err error) *MFARequiredError {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
		return nil
	}
	var body struct {
		Error    string `json:"error"`
		MFAToken string `json:"mfa_token"`
	}
	if json.Unmarshal(apiErr.Body, &body) != nil || body.Error != "mfa_required" || body.MFAToken == "" {
		return nil
	}
	return &MFARequiredError{MFAToken: body.MFAToken}
}

// ── Wymuszone MFA (etap 2) ──────────────────────────────────────────────────

// MFAEnforcedError — organizacja albo instancja wymaga MFA, a bieżąca sesja
// go nie przeszła (logowanie passkeyem/Google/Apple/SSO albo hasłem bez
// TOTP). Serwer odrzuca wtedy KAŻDY endpoint poza /api/v1/me/mfa*:
// TOTPEnabled=true -> poproś o kod i VerifySession, false -> wymuszony
// enrollment (TOTPSetup + TOTPEnable). To 403, nie 401: nie odświeżaj
// tokena i nie wylogowuj. Error() zaczyna się od "mfa_enforced", żeby
// klienci przekazujący błędy jako tekst (Wails) mogli go rozpoznać.
type MFAEnforcedError struct {
	TOTPEnabled bool
}

func (e *MFAEnforcedError) Error() string {
	return "mfa_enforced: wymagana weryfikacja dwuetapowa"
}

// SetMFAEnforcedHandler — fn wołane przy KAŻDYM *MFAEnforcedError z
// dowolnej metody (oprócz zwrócenia błędu), żeby klient mógł pokazać krok
// MFA centralnie zamiast w każdym miejscu wywołania. fn nie może wołać
// klienta synchronicznie w sposób blokujący na sobie samym; wołane z
// goroutine'y wykonującej request.
func (c *Client) SetMFAEnforcedHandler(fn func(*MFAEnforcedError)) {
	c.onMFAEnforced = fn
}

// isMFAStepUpRedirect — redirect na webową stronę kodu (auth.writeMFAEnforced
// w password-manager dla ścieżek spoza /api/).
func isMFAStepUpRedirect(u *url.URL) bool {
	return u != nil && u.Path == "/mfa"
}

// checkResponse — wspólne dla do()/doForm(): status >= 300 -> błąd
// (*MFAEnforcedError albo *APIError).
func (c *Client) checkResponse(method, path string, resp *http.Response, body []byte) error {
	if resp.StatusCode < 300 {
		return nil
	}
	if enforced := c.mfaEnforcedFrom(resp, body); enforced != nil {
		if c.onMFAEnforced != nil {
			c.onMFAEnforced(enforced)
		}
		return enforced
	}
	return &APIError{Method: method, Path: path, StatusCode: resp.StatusCode, Body: body}
}

func (c *Client) mfaEnforcedFrom(resp *http.Response, body []byte) *MFAEnforcedError {
	if resp.StatusCode == http.StatusForbidden {
		var b struct {
			Error       string `json:"error"`
			TOTPEnabled bool   `json:"totp_enabled"`
		}
		if json.Unmarshal(body, &b) == nil && b.Error == "mfa_enforced" {
			return &MFAEnforcedError{TOTPEnabled: b.TOTPEnabled}
		}
		return nil
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc, err := resp.Location()
		if err != nil || !isMFAStepUpRedirect(loc) {
			return nil
		}
		// Redirect nie niesie totp_enabled — /api/v1/me/mfa jest dostępne
		// także sesji czekającej na kod. Przy błędzie zakładamy enrollment:
		// TOTPSetup i tak odpowie already_enabled, jeśli TOTP już jest.
		enforced := &MFAEnforcedError{}
		if st, err := c.MFAStatus(); err == nil {
			enforced.TOTPEnabled = st.TOTPEnabled
		}
		return enforced
	}
	return nil
}

// VerifySession — POST /api/v1/me/mfa/verify {code}: podnosi bieżącą sesję
// do "po MFA" po *MFAEnforcedError z TOTPEnabled=true. Zwraca NOWĄ parę
// tokenów (stara sesja nie ma flagi mfa) — wołający MUSI ją zapisać, także
// refresh token. Błędy: ErrMFAInvalidCode, ErrMFATooManyAttempts,
// ErrMFANotEnabled (wtedy enrollment zamiast kodu).
func (c *Client) VerifySession(code string) (*MFALoginResult, error) {
	return c.VerifySessionRemember(code, false)
}

// VerifySessionRemember — VerifySession z "zapamiętaj to urządzenie":
// remember=true -> odpowiedź niesie też RememberToken/RememberExpiresAt.
func (c *Client) VerifySessionRemember(code string, remember bool) (*MFALoginResult, error) {
	return c.verifySession(map[string]any{"code": code, "remember": remember})
}

// VerifySessionWithRememberToken — POST /api/v1/me/mfa/verify
// {mfa_remember_token}: podnosi sesję przy wymuszonym MFA BEZ kodu, tokenem
// zapamiętanego urządzenia (np. po logowaniu passkeyem/Google/SSO). Nowa
// para tokenów jak przy VerifySession. ErrMFAInvalidRememberToken = token
// już nie działa, trzeba kodu.
func (c *Client) VerifySessionWithRememberToken(rememberToken string) (*MFALoginResult, error) {
	return c.verifySession(map[string]any{"mfa_remember_token": rememberToken})
}

func (c *Client) verifySession(body map[string]any) (*MFALoginResult, error) {
	var out MFALoginResult
	if err := c.do(http.MethodPost, "/api/v1/me/mfa/verify", body, &out); err != nil {
		return nil, mapMFAError(err)
	}
	return &out, nil
}

// MFALoginResult — wynik LoginMFA. RecoveryCodeUsed: user wpisał kod
// zapasowy zamiast TOTP — klient powinien ostrzec, ile zostało
// (RecoveryCodesRemaining), a przy 0 mocniej: "wygeneruj nowe".
//
// RememberToken/RememberExpiresAt — tylko przy remember=true: token
// zapamiętanego urządzenia (30 dni, termin stały) do wysyłania w
// LoginRemembered / VerifySessionWithRememberToken zamiast kodu. Sekret —
// przechowywać jak refresh token.
type MFALoginResult struct {
	Token                  string    `json:"token"`
	RefreshToken           string    `json:"refresh_token"`
	RecoveryCodeUsed       bool      `json:"recovery_code_used"`
	RecoveryCodesRemaining int       `json:"recovery_codes_remaining"`
	RememberToken          string    `json:"mfa_remember_token"`
	RememberExpiresAt      time.Time `json:"mfa_remember_expires_at"`
}

// LoginMFA — POST /api/v1/login/mfa {mfa_token, code}: drugi krok po Login
// zwracającym *MFARequiredError. code to 6 cyfr TOTP albo kod zapasowy —
// serwer sam rozpoznaje po formacie, więc klient przekazuje to, co user
// wpisał, bez normalizacji. Błędy: ErrMFAInvalidCode, ErrMFATokenExpired,
// ErrMFATooManyAttempts.
func (c *Client) LoginMFA(mfaToken, code string) (*MFALoginResult, error) {
	return c.LoginMFARemember(mfaToken, code, false)
}

// LoginMFARemember — LoginMFA z "zapamiętaj to urządzenie" (remember=true ->
// RememberToken w wyniku).
func (c *Client) LoginMFARemember(mfaToken, code string, remember bool) (*MFALoginResult, error) {
	var out MFALoginResult
	err := c.do(http.MethodPost, "/api/v1/login/mfa", map[string]any{
		"mfa_token": mfaToken,
		"code":      code,
		"remember":  remember,
	}, &out)
	if err != nil {
		return nil, mapMFAError(err)
	}
	return &out, nil
}

// MFAStatus — GET /api/v1/me/mfa. Required: organizacja albo instancja
// wymaga MFA — TOTPDisable zwróci ErrMFARequiredByPolicy, UI nie powinien
// proponować wyłączenia.
type MFAStatus struct {
	TOTPEnabled            bool `json:"totp_enabled"`
	RecoveryCodesRemaining int  `json:"recovery_codes_remaining"`
	Required               bool `json:"required"`
}

func (c *Client) MFAStatus() (*MFAStatus, error) {
	var out MFAStatus
	if err := c.do(http.MethodGet, "/api/v1/me/mfa", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// TOTPSetup — POST /api/v1/me/mfa/totp/setup. Nowy, niepotwierdzony
// enrollment (nadpisuje poprzedni niepotwierdzony); TOTP NIE jest jeszcze
// włączone, dopóki TOTPEnable nie potwierdzi kodem. QRPNG to gotowy data URL
// (data:image/png;base64,...) do <img src>. 409 -> ErrMFAAlreadyEnabled.
type TOTPSetup struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
	QRPNG      string `json:"qr_png"`
}

func (c *Client) TOTPSetup() (*TOTPSetup, error) {
	var out TOTPSetup
	if err := c.do(http.MethodPost, "/api/v1/me/mfa/totp/setup", nil, &out); err != nil {
		return nil, mapMFAError(err)
	}
	return &out, nil
}

// TOTPEnableResult — RecoveryCodes: 10 kodów zapasowych, serwer trzyma
// tylko hashe, więc to jedyny moment, kiedy da się je pokazać userowi.
// Token/RefreshToken (etap 2): poprawny kod przy enrollmencie podnosi sesję
// do "po MFA" — przy Bearer serwer zwraca nową parę, którą wołający MUSI
// zapisać (inaczej wymuszone MFA dalej blokuje starą sesję). Puste, gdy
// serwer ich nie zwrócił (starszy backend albo sesja cookie).
// RememberToken/RememberExpiresAt — tylko przy TOTPEnableRemember(…, true).
type TOTPEnableResult struct {
	RecoveryCodes     []string  `json:"recovery_codes"`
	Token             string    `json:"token"`
	RefreshToken      string    `json:"refresh_token"`
	RememberToken     string    `json:"mfa_remember_token"`
	RememberExpiresAt time.Time `json:"mfa_remember_expires_at"`
}

// TOTPEnable — POST /api/v1/me/mfa/totp/enable {code}. Błędy:
// ErrMFAInvalidCode, ErrMFANoPendingSetup, ErrMFAAlreadyEnabled.
func (c *Client) TOTPEnable(code string) (*TOTPEnableResult, error) {
	return c.TOTPEnableRemember(code, false)
}

// TOTPEnableRemember — TOTPEnable z "zapamiętaj to urządzenie".
func (c *Client) TOTPEnableRemember(code string, remember bool) (*TOTPEnableResult, error) {
	var out TOTPEnableResult
	if err := c.do(http.MethodPost, "/api/v1/me/mfa/totp/enable", map[string]any{"code": code, "remember": remember}, &out); err != nil {
		return nil, mapMFAError(err)
	}
	return &out, nil
}

// TOTPDisable — POST /api/v1/me/mfa/totp/disable {code}; code to TOTP albo
// kod zapasowy. Błędy: ErrMFAInvalidCode, ErrMFATooManyAttempts,
// ErrMFARequiredByPolicy.
func (c *Client) TOTPDisable(code string) error {
	if err := c.do(http.MethodPost, "/api/v1/me/mfa/totp/disable", map[string]string{"code": code}, nil); err != nil {
		return mapMFAError(err)
	}
	return nil
}

// RegenerateRecoveryCodes — POST /api/v1/me/mfa/recovery-codes {code}; code
// to WYŁĄCZNIE TOTP (nie kod zapasowy). Stare kody przestają działać.
// Błędy: ErrMFAInvalidCode, ErrMFANotEnabled.
func (c *Client) RegenerateRecoveryCodes(code string) (recoveryCodes []string, err error) {
	var out struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := c.do(http.MethodPost, "/api/v1/me/mfa/recovery-codes", map[string]string{"code": code}, &out); err != nil {
		return nil, mapMFAError(err)
	}
	return out.RecoveryCodes, nil
}

// ── Organizacja: wymóg MFA (admin+) ────────────────────────────────────

// OrgMFAMember — członek roota organizacji ze stanem MFA (kształt 1:1 z
// password-manager/internal/mfa.MemberStatus).
type OrgMFAMember struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	TOTPEnabled bool   `json:"totp_enabled"`
}

type OrgMFASettings struct {
	RequireMFA bool           `json:"require_mfa"`
	Members    []OrgMFAMember `json:"members"`
}

// GetOrgMFASettings — GET /g/{orgID}/mfa-settings. Admin+ (403 dla
// niższych ról, zwykły *APIError).
func (c *Client) GetOrgMFASettings(orgID string) (*OrgMFASettings, error) {
	var out OrgMFASettings
	if err := c.do(http.MethodGet, "/g/"+url.PathEscape(orgID)+"/mfa-settings", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetOrgRequireMFA — PATCH /g/{orgID}/mfa-settings {require_mfa}. Admin+.
// Członkowie odczują zmianę najpóźniej po ~60 s (cache polityki w backendzie).
func (c *Client) SetOrgRequireMFA(orgID string, require bool) error {
	return c.do(http.MethodPatch, "/g/"+url.PathEscape(orgID)+"/mfa-settings", map[string]bool{"require_mfa": require}, nil)
}
