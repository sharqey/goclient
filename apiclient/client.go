// Package apiclient — klient HTTP do serwera password-manager, wspólny dla
// wszystkich klientów Go (CLI, desktop, docelowo inne). Kształt
// requestów/response'ów przepisany 1:1 z handlerami w repo password-manager
// (internal/api, internal/device, internal/group) — czytaj tamten kod jako
// źródło prawdy, nie zgaduj kształtu API. Wydzielone z
// password-manager-desktop/internal/apiclient i password-manager/internal/client
// (drugie miało też metody CRUD organizacji celujące w endpointy /api/v1/orgs/*,
// które już nie istnieją server-side — świadomie NIE przeniesione tutaj,
// patrz password-manager-desktop/TASK-002-full-client.md).
package apiclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrOffline — request nie dotarł do serwera w ogóle (DNS/connection
// refused/timeout), w odróżnieniu od requestu który dotarł i dostał
// odpowiedź z kodem błędu (4xx/5xx — to nadal "online", tylko aplikacyjny
// błąd). Wołający (np. password-manager-desktop/app.go) używa
// errors.Is(err, apiclient.ErrOffline) żeby odróżnić "jestem offline, pokaż
// cache/zablokuj zapis" od zwykłego błędu do pokazania userowi wprost —
// patrz password-manager/tasks/todo/046-offline-resilience-online-orgs.md.
var ErrOffline = errors.New("brak połączenia z serwerem")

// APIError — request dotarł do serwera i dostał odpowiedź z kodem >= 300.
// Error() daje dokładnie ten sam tekst co wcześniejszy fmt.Errorf (wołający,
// którzy pokazują błąd userowi albo szukają w nim "HTTP 409", nie widzą
// różnicy), a errors.As pozwala rozróżnić konkretny kod błędu bez parsowania
// stringa — potrzebne od MFA (086), gdzie 401 "mfa_required" to nie porażka,
// tylko drugi krok logowania.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Body       []byte
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.Path, e.StatusCode, string(e.Body))
}

// Code — pole "error" z JSON-owego body ({"error": "..."}, konwencja
// handlerów password-manager). "" gdy body nie jest JSON-em tego kształtu.
func (e *APIError) Code() string {
	var body struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(e.Body, &body) != nil {
		return ""
	}
	return body.Error
}

type Client struct {
	baseURL string
	token   string
	http    *http.Client

	// onMFAEnforced — patrz SetMFAEnforcedHandler.
	onMFAEnforced func(*MFAEnforcedError)
}

// requestTimeout — zweryfikowane empirycznie (2026-08-24): http.Client
// naprawdę czeka pełen Timeout zanim zwróci błąd na nieosiągalny host (nie
// krócej, connect/DNS/TLS wliczone), więc to bezpośrednio determinuje jak
// długo user patrzy na "Loading..." zanim appka pokaże cache/błąd offline
// (patrz apiclient.ErrOffline). 15s (poprzednia wartość) sprawiało wrażenie
// zawieszenia appki. 8s to kompromis — wciąż wystarczające dla legitnie
// wolnego, ale działającego połączenia (motywacja offline-resilience,
// password-manager/tasks/todo/046), a dużo mniej boli kiedy sieci
// faktycznie nie ma.
const requestTimeout = 8 * time.Second

func New(baseURL string) *Client {
	return &Client{baseURL: baseURL, http: &http.Client{
		Timeout: requestTimeout,
		// Wymuszone MFA (086 etap 2): ścieżki spoza /api/ (np. /g/{id}/...)
		// odpowiadają sesji bez kodu redirectem 303 na stronę web /mfa
		// zamiast 403 JSON. Podążanie za nim dałoby 200 z HTML-em — POST
		// bez body odpowiedzi wyglądałby na udany, choć nic się nie stało.
		// Zatrzymujemy się na tym redirekcie, checkResponse zamienia go na
		// *MFAEnforcedError. Pozostałe redirecty bez zmian.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if isMFAStepUpRedirect(req.URL) {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}}
}

func (c *Client) SetToken(token string) {
	c.token = token
}

func (c *Client) do(method, path string, body any, out any) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.baseURL+path, reqBody)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOffline, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := c.checkResponse(method, path, resp, respBody); err != nil {
		return err
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("%s %s: decode response: %w", method, path, err)
		}
	}
	return nil
}

// doForm — jak do(), ale application/x-www-form-urlencoded zamiast JSON.
// Kilka starszych endpointów (np. POST /g/{groupID}/secrets) czyta
// r.FormValue, nie JSON body — to nie jest niespójność do naprawienia po
// cichu, tylko fakt tego API, patrz internal/secret/handler.go w
// password-manager i web/templates/group/show.html (fetch z
// URLSearchParams) jako referencja formatu.
func (c *Client) doForm(method, path string, form url.Values, out any) error {
	req, err := http.NewRequest(method, c.baseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOffline, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := c.checkResponse(method, path, resp, respBody); err != nil {
		return err
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("%s %s: decode response: %w", method, path, err)
		}
	}
	return nil
}

// Login — POST /api/v1/login {email, password} -> {token, refresh_token}.
// Zwraca też refresh token (30 dni, jednorazowego użytku, rotujący) —
// wołający powinien go zapisać lokalnie i użyć RefreshToken zamiast
// wymagać hasła ponownie po wygaśnięciu 24h access tokenu, patrz
// password-manager-desktop/TASK-002-full-client.md, Ustalenie #2.
//
// Konto z włączonym TOTP (086): hasło poprawne, ale zamiast tokenów serwer
// zwraca 401 {error: "mfa_required", mfa_token} — wtedy Login zwraca
// *MFARequiredError (errors.As), a wołający dokańcza logowanie przez
// LoginMFA. Pozostałe błędy bez zmian.
func (c *Client) Login(email, password string) (token, refreshToken string, err error) {
	return c.LoginRemembered(email, password, "")
}

// LoginRemembered — Login z tokenem zapamiętanego urządzenia
// (MFALoginResult.RememberToken z LoginMFARemember/VerifySessionRemember):
// ważny token zastępuje kod TOTP, sesja jest od razu "po MFA". Zły albo
// wygasły token serwer traktuje jak jego brak — wynik to zwykłe
// *MFARequiredError, wołający może wtedy token skasować. Pusty token = Login.
func (c *Client) LoginRemembered(email, password, rememberToken string) (token, refreshToken string, err error) {
	var out struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	body := map[string]string{
		"email":    email,
		"password": password,
	}
	if rememberToken != "" {
		body["mfa_remember_token"] = rememberToken
	}
	err = c.do(http.MethodPost, "/api/v1/login", body, &out)
	if err != nil {
		if mfaErr := mfaRequiredFrom(err); mfaErr != nil {
			return "", "", mfaErr
		}
		return "", "", err
	}
	return out.Token, out.RefreshToken, nil
}

// LoginGoogle — POST /api/v1/login/google {id_token} -> {token,
// refresh_token, email}. id_token jest gołym Google id_token (JWT z
// scope=openid), zdobytym przez wołającego samodzielnie (system browser +
// PKCE authorization code flow przeciw Google, patrz
// password-manager-desktop/internal/googlelogin) — ten klient TYLKO
// przekazuje go dalej do backendu (password-manager/internal/sso,
// tasks/done/053-native-client-social-sso-login.md sekcja 1) do weryfikacji
// przeciw JWKS Google. Backend zwraca email użytkownika bo dla nowego konta
// (pierwsze logowanie Google) wołający nie zna go z góry, w odróżnieniu od
// Login powyżej gdzie user sam je wpisał.
func (c *Client) LoginGoogle(idToken string) (token, refreshToken, email string, err error) {
	var out struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
		Email        string `json:"email"`
	}
	err = c.do(http.MethodPost, "/api/v1/login/google", map[string]string{
		"id_token": idToken,
	}, &out)
	if err != nil {
		return "", "", "", err
	}
	return out.Token, out.RefreshToken, out.Email, nil
}

// LoginApple — POST /api/v1/login/apple {identity_token, first_name,
// last_name} -> {token, refresh_token, email}. identity_token to goły
// Apple identity token (JWT), zdobyty przez wołającego samodzielnie —
// na desktopie macOS przez NATYWNY `ASAuthorizationAppleIDProvider`
// (patrz password-manager-desktop/internal/applelogin), w odróżnieniu od
// LoginGoogle powyżej, który idzie przez system browser + PKCE. Apple
// wysyła imię/nazwisko TYLKO przy pierwszym logowaniu danego
// Apple ID — first_name/last_name będą puste przy kolejnych, backend to
// obsługuje (patrz tasks/done/053-native-client-social-sso-login.md
// sekcja 2, "Apple wysyła email/imię TYLKO przy pierwszym logowaniu").
func (c *Client) LoginApple(identityToken, firstName, lastName string) (token, refreshToken, email string, err error) {
	var out struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
		Email        string `json:"email"`
	}
	err = c.do(http.MethodPost, "/api/v1/login/apple", map[string]string{
		"identity_token": identityToken,
		"first_name":     firstName,
		"last_name":      lastName,
	}, &out)
	if err != nil {
		return "", "", "", err
	}
	return out.Token, out.RefreshToken, out.Email, nil
}

// Identity — jeden wiersz z GET /api/v1/me/identities, kształt 1:1 z
// password-manager/internal/sso.Identity (bez json tagów po tamtej stronie,
// więc pola serializują się PascalCase — nie zgaduj, to jest źródło prawdy).
type Identity struct {
	ID              string
	UserID          string
	Provider        string
	OrgID           *string
	SubjectID       string
	EmailAtProvider string
	LinkedAt        time.Time
}

// Passkey — jeden wiersz z GET /api/v1/me/identities (pole "passkeys"),
// kształt 1:1 z password-manager/internal/webauthn.CredentialView.
type Passkey struct {
	ID         string
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// InstanceInfo — GET /api/v1/instance-info, nieautoryzowany. Pozwala
// sprawdzić, jakie metody logowania obsługuje dany serwer (self-hosted
// instancja wpisana ręcznie przez usera), zanim klient przerysuje ekran
// logowania pod ten serwer, patrz password-manager-desktop SetServerURL.
type InstanceInfo struct {
	RegistrationEnabled bool `json:"registration_enabled"`
	GoogleSSOEnabled    bool `json:"google_sso_enabled"`
	AppleSSOEnabled     bool `json:"apple_sso_enabled"`
	AllowNewOrgs        bool `json:"allow_new_orgs"`
}

func (c *Client) InstanceInfo() (*InstanceInfo, error) {
	var out InstanceInfo
	if err := c.do(http.MethodGet, "/api/v1/instance-info", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// LoginMethods — odpowiedź GET /api/v1/me/identities: tożsamości SSO,
// passkeye i hasło (HasPassword + Email konta, bo hasło to też metoda
// logowania — bez tego konto z samym hasłem wyglądało w klientach jak bez
// żadnej metody).
type LoginMethods struct {
	Identities  []Identity `json:"identities"`
	Passkeys    []Passkey  `json:"passkeys"`
	HasPassword bool       `json:"has_password"`
	Email       string     `json:"email"`
}

// MyIdentities — GET /api/v1/me/identities. Listing metod logowania danego
// konta dla ekranu "Metody logowania" (TASK-009 sekcja 5) — samo listowanie,
// linkowanie/odłączanie to LinkGoogle/LinkApple/LinkOrg/UnlinkIdentity/
// DeletePasskey/RegisterPasskey*.
func (c *Client) MyIdentities() (*LoginMethods, error) {
	var out LoginMethods
	if err := c.do(http.MethodGet, "/api/v1/me/identities", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UnlinkIdentity — POST /settings/sso/unlink/{identityID}. To NIE jest JSON
// API — endpoint web-owy, sukces = 303 (redirect do /settings, który klient
// świadomie NIE podąża, patrz postNoRedirect), błąd = zwykły tekst w body
// (nie JSON), np. gdy to jedyna pozostała metoda logowania konta.
// Mirror password-manager-flutter/lib/services/api_client.dart (jedyny
// istniejący precedens tego wołania spoza web), które robi dokładnie to samo
// z followRedirects=false. Tylko tożsamości SSO — passkey ma osobny
// endpoint, patrz DeletePasskey.
func (c *Client) UnlinkIdentity(identityID string) error {
	if err := c.postNoRedirect("/settings/sso/unlink/" + url.PathEscape(identityID)); err != nil {
		return fmt.Errorf("unlink identity: %w", err)
	}
	return nil
}

// DeletePasskey — POST /settings/webauthn/{credentialID}, ten sam
// web-owy kształt co UnlinkIdentity (303 = sukces, błąd tekstem/JSON-em w
// body). Backend sam pilnuje "nie usuwaj ostatniej metody logowania".
func (c *Client) DeletePasskey(credentialID string) error {
	if err := c.postNoRedirect("/settings/webauthn/" + url.PathEscape(credentialID)); err != nil {
		return fmt.Errorf("delete passkey: %w", err)
	}
	return nil
}

func (c *Client) postNoRedirect(path string) error {
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	noRedirectClient := &http.Client{
		Timeout:       requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOffline, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

// BeginPasskeyRegistration — POST /me/webauthn/register/begin -> {token,
// options}. Rejestracja NOWEGO passkeya do już zalogowanego konta. options
// to surowy JSON `protocol.CredentialCreation` (go-webauthn) — klient sam go
// dekoduje i woła natywne API platformy (Windows Hello / macOS
// AuthenticationServices), goclient nie zależy od biblioteki WebAuthn.
func (c *Client) BeginPasskeyRegistration() (token string, options json.RawMessage, err error) {
	var out struct {
		Token   string          `json:"token"`
		Options json.RawMessage `json:"options"`
	}
	if err := c.do(http.MethodPost, "/me/webauthn/register/begin", nil, &out); err != nil {
		return "", nil, err
	}
	return out.Token, out.Options, nil
}

// FinishPasskeyRegistration — POST /me/webauthn/register/finish?token=&label=
// z gotowym JSON-em `CredentialCreationResponse` (attestation) w body.
func (c *Client) FinishPasskeyRegistration(token, label string, credential json.RawMessage) error {
	q := url.Values{"token": {token}}
	if label != "" {
		q.Set("label", label)
	}
	return c.do(http.MethodPost, "/me/webauthn/register/finish?"+q.Encode(), credential, nil)
}

// ChangePassword — POST /api/v1/me/password {current_password, new_password}.
// Konto bez hasła (SSO/passkey-only) dostaje je po raz pierwszy —
// currentPassword wtedy ignorowane. 403 = złe obecne hasło.
func (c *Client) ChangePassword(currentPassword, newPassword string) error {
	return c.do(http.MethodPost, "/api/v1/me/password", map[string]string{
		"current_password": currentPassword,
		"new_password":     newPassword,
	}, nil)
}

// CreateLinkTicket — POST /api/v1/me/link-tickets -> {ticket}. Jednorazowy,
// krótkożyjący token (5 min) wymagany PRZED otwarciem systemowej przeglądarki
// na StartLinkOrg (LinkOrg niżej) — przeglądarka nie niesie ani ciastka
// appki, ani jej nagłówka Authorization, więc backend musi się dowiedzieć KTO
// linkuje jakoś inaczej niż normalna sesja (patrz password-manager/internal/
// sso.LinkTicket). Google/Apple linkowanie tego NIE potrzebuje — patrz
// LinkGoogle/LinkApple, które nie przechodzą wcale przez przeglądarkę backendu.
func (c *Client) CreateLinkTicket() (ticket string, err error) {
	var out struct {
		Ticket string `json:"ticket"`
	}
	if err := c.do(http.MethodPost, "/api/v1/me/link-tickets", nil, &out); err != nil {
		return "", err
	}
	return out.Ticket, nil
}

// LinkGoogle — POST /api/v1/me/link/google {id_token}. Dogrywa Google jako
// dodatkową metodę logowania do JUŻ zalogowanego konta (Bearer z SetToken) —
// id_token zdobyty tym samym PKCE flow co LoginGoogle, wołający tylko
// przekazuje go dalej. 409 gdy to konto Google jest już podpięte do INNEGO
// konta Sharqey (password-manager: ErrIdentityTaken) — zwrócone jako zwykły
// błąd, wołający dekoduje treść z komunikatem.
func (c *Client) LinkGoogle(idToken string) error {
	return c.do(http.MethodPost, "/api/v1/me/link/google", map[string]string{
		"id_token": idToken,
	}, nil)
}

// LinkApple — POST /api/v1/me/link/apple {identity_token}, analogiczne do
// LinkGoogle. Apple nie wysyła imienia/nazwiska poza pierwszą autoryzacją —
// nieistotne tutaj, LinkIdentityChecked po stronie backendu ich nie używa
// (w przeciwieństwie do LoginApple, gdzie zakładają nowe konto).
func (c *Client) LinkApple(identityToken string) error {
	return c.do(http.MethodPost, "/api/v1/me/link/apple", map[string]string{
		"identity_token": identityToken,
	}, nil)
}

// RefreshToken — POST /api/v1/token/refresh {refresh_token} -> {token,
// refresh_token}. Rotujący: odpowiedź niesie NOWY refresh token, ten
// przekazany przestaje działać (jednorazowy użytek) — wołający MUSI
// zapisać nowy refresh token, nie tylko nowy access token.
func (c *Client) RefreshToken(refreshToken string) (token, newRefreshToken string, err error) {
	var out struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	err = c.do(http.MethodPost, "/api/v1/token/refresh", map[string]string{
		"refresh_token": refreshToken,
	}, &out)
	if err != nil {
		return "", "", err
	}
	return out.Token, out.RefreshToken, nil
}

// CreateDeviceLinkRequest — POST /api/v1/device-link/requests. Serwer
// przelicza fingerprint sam z ephemeralPublicKey — wołający MUSI niezależnie
// przeliczyć go lokalnie i porównać z tym co user widzi na innym urządzeniu
// (patrz pgpcrypto.Keypair.Fingerprint), nigdy nie ufać wyłącznie temu polu.
type DeviceLinkRequest struct {
	ID          string    `json:"id"`
	Fingerprint string    `json:"fingerprint"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (c *Client) CreateDeviceLinkRequest(ephemeralPublicKeyArmored, deviceLabel, linkedVia string) (*DeviceLinkRequest, error) {
	var out DeviceLinkRequest
	err := c.do(http.MethodPost, "/api/v1/device-link/requests", map[string]string{
		"ephemeral_public_key": ephemeralPublicKeyArmored,
		"device_label":         deviceLabel,
		"linked_via":           linkedVia,
	}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// PollDeviceLinkRequest — GET /api/v1/device-link/requests/{id}/poll.
// status: pending | consumed | expired | cancelled. EncryptedBlob niepuste
// tylko przy pierwszym odczycie po fulfilled (serwer zaraz potem oznacza
// consumed).
type PollResult struct {
	Status        string `json:"status"`
	EncryptedBlob string `json:"encrypted_blob"`
}

func (c *Client) PollDeviceLinkRequest(requestID string) (*PollResult, error) {
	var out PollResult
	if err := c.do(http.MethodGet, "/api/v1/device-link/requests/"+requestID+"/poll", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CancelDeviceLinkRequest — POST /api/v1/device-link/requests/{id}/cancel.
// Wołane przez stronę zgłaszającą request (B), gdy rezygnuje z parowania
// przed jego wypełnieniem — np. zamknięcie modala parowania w UI — żeby nie
// zostawiać osieroconego pending requestu do wygaśnięcia. TA SAMA metoda
// służy stronie A do jawnego odrzucenia cudzej (a raczej: innego swojego
// urządzenia) prośby, patrz internal/device/handler.go CancelRequest — oba
// kierunki to ten sam user_id, więc identyczny endpoint.
func (c *Client) CancelDeviceLinkRequest(requestID string) error {
	return c.do(http.MethodPost, "/api/v1/device-link/requests/"+requestID+"/cancel", nil, nil)
}

// PendingDeviceLinkRequest — jeden pending request od INNEGO urządzenia
// zalogowanego na to samo konto (kształt 1:1 z Handler.ListRequests).
// Fingerprint tu zwrócony przez serwer NIE jest zaufanym źródłem prawdy —
// wołający MUSI przeliczyć własny fingerprint z EphemeralPublicKey (patrz
// pgpcrypto.FingerprintFromArmoredPublicKey) i porównać oba, dokładnie ten
// sam wzorzec co przy CreateDeviceLinkRequest.
type PendingDeviceLinkRequest struct {
	ID                 string `json:"id"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Fingerprint        string `json:"fingerprint"`
	DeviceLabel        string `json:"device_label"`
	LinkedVia          string `json:"linked_via"`
}

// ListDeviceLinkRequests — GET /api/v1/device-link/requests. Strona A: lista
// pending requestów od urządzeń zalogowanych na to samo konto (żadnego
// dodatkowego "claim"/kodu — user_id już to koreluje server-side).
func (c *Client) ListDeviceLinkRequests() ([]PendingDeviceLinkRequest, error) {
	var out []PendingDeviceLinkRequest
	if err := c.do(http.MethodGet, "/api/v1/device-link/requests", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// FulfillDeviceLinkRequest — POST /api/v1/device-link/requests/{id}/fulfill
// {encrypted_blob}. Strona A: encryptedBlob to CAŁY lokalny pęk kluczy A,
// już zaszyfrowany PGP do ephemeral_public_key TEGO requestu (patrz
// pgpcrypto.EncryptArmoredMessage) — serwer widzi wyłącznie ciphertext.
func (c *Client) FulfillDeviceLinkRequest(requestID, encryptedBlob string) error {
	return c.do(http.MethodPost, "/api/v1/device-link/requests/"+requestID+"/fulfill", map[string]string{
		"encrypted_blob": encryptedBlob,
	}, nil)
}

// SearchResult — kształt 1:1 z internal/secret.SearchResult (JSON zwracany
// przez GET /api/v1/secrets/by-url, /g/{groupID}/secrets, /g/{groupID}/search).
// WYŁĄCZNIE metadane (2026-08-30, patrz HANDOFF.md w password-manager) —
// ciphertext/group_encrypted_secret_key/group_key backend już nie zwraca
// tu, tylko przez osobne GetSecret, dopiero gdy faktycznie chcesz
// odszyfrować JEDEN konkretny sekret.
type SearchResult struct {
	ID            string    `json:"id"`
	GroupID       string    `json:"group_id"`
	Type          string    `json:"type"` // "account", "env" albo "file"
	Slug          string    `json:"slug"`
	Title         string    `json:"title"`
	Username      string    `json:"username"`
	URL           string    `json:"url"`
	HasTOTP       bool      `json:"has_totp"`
	UpdatedAt     time.Time `json:"updated_at"`
	GroupFullPath string    `json:"group_full_path"`
	GroupName     string    `json:"group_name"`
	OrgName       string    `json:"org_name"`
	OrgIsPersonal bool      `json:"org_is_personal"`
	OrgID         string    `json:"org_id"`
}

// SecretDetail — GET /g/{groupID}/secrets/{secretID}, jedyne miejsce gdzie
// backend oddaje ciphertext + klucze szyfrujące JEDNEGO sekretu (2026-08-30,
// patrz HANDOFF.md w password-manager) — surowy materiał kryptograficzny do
// lokalnego odszyfrowania (patrz pgpcrypto.DecryptWithGroupKey), serwer
// nigdy nie widzi plaintextu.
type SecretDetail struct {
	Ciphertext              string `json:"ciphertext"`
	GroupEncryptedSecretKey string `json:"group_encrypted_secret_key"`
	// OwnerEncryptedSecretKey — niepuste WYŁĄCZNIE dla sekretów w grupie
	// Private (TASK-018, password-manager-flutter, migracja 021 w
	// password-manager) — secret_key zawinięty wprost kluczem publicznym
	// właściciela, bez group_key. Odszyfrowanie: pgpcrypto.DecryptDirectSecret
	// (ten sam kształt co DirectKey niżej, per-secret-share).
	OwnerEncryptedSecretKey string `json:"owner_encrypted_secret_key,omitempty"`
	DirectKey               string `json:"direct_key,omitempty"`
	DirectRole              string `json:"direct_role,omitempty"`
	GroupKey                string `json:"group_key"`
}

// GetSecret — GET /g/{groupID}/secrets/{secretID} — ciphertext + klucze
// JEDNEGO sekretu, wołane leniwie zamiast razem z GroupSecrets/SearchGroup/
// SearchByURL.
func (c *Client) GetSecret(groupID, secretID string) (*SecretDetail, error) {
	var out SecretDetail
	if err := c.do(http.MethodGet, "/g/"+url.PathEscape(groupID)+"/secrets/"+url.PathEscape(secretID), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) SearchByURL(u string) ([]SearchResult, error) {
	var out []SearchResult
	if err := c.do(http.MethodGet, "/api/v1/secrets/by-url?url="+url.QueryEscape(u), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Workspace — kształt 1:1 z Handler.Workspaces (GET /api/v1/me/workspaces).
type Workspace struct {
	ID         string `json:"id"`
	Slug       string `json:"slug"`
	Name       string `json:"name"`
	IsPersonal bool   `json:"is_personal"`
	FullPath   string `json:"full_path"`
	// PendingDeletionAt — termin finalnego usunięcia organizacji w karencji
	// (password-manager tasks/076), nil gdy żadne nie jest zaplanowane.
	PendingDeletionAt *time.Time `json:"pending_deletion_at,omitempty"`
	// CanCancelDeletion — czy ten user (admin/owner) może anulować
	// zaplanowane usunięcie, patrz CancelOrgDeletion.
	CanCancelDeletion bool `json:"can_cancel_deletion,omitempty"`
}

func (c *Client) Workspaces() ([]Workspace, error) {
	var out struct {
		Workspaces []Workspace `json:"workspaces"`
	}
	if err := c.do(http.MethodGet, "/api/v1/me/workspaces", nil, &out); err != nil {
		return nil, err
	}
	return out.Workspaces, nil
}

// GroupNode — kształt 1:1 z Handler.Tree (GET /api/v1/groups/tree).
// IsPersonal to martwe pole z osobnej, nigdy niepodłączonej po stronie
// backendu koncepcji (patrz Workspace.IsPersonal) — nie mylić z IsPrivate,
// które backend faktycznie wypełnia z Group.IsPrivateTo (własna prywatna
// grupa TEGO usera w danym workspace, mirror web MyPrivateGroupID).
type GroupNode struct {
	ID         string  `json:"id"`
	ParentID   *string `json:"parent_id"`
	Slug       string  `json:"slug"`
	Name       string  `json:"name"`
	FullPath   string  `json:"full_path"`
	Depth      int     `json:"depth"`
	IsPersonal bool    `json:"is_personal"`
	IsPrivate  bool    `json:"is_private"`
}

// GroupTree — płaska lista wszystkich grup w poddrzewie danego workspace'u
// (rootPath = Workspace.FullPath).
func (c *Client) GroupTree(rootPath string) ([]GroupNode, error) {
	var out []GroupNode
	if err := c.do(http.MethodGet, "/api/v1/groups/tree?root_path="+url.QueryEscape(rootPath), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GroupSecrets — GET /g/{groupID}/secrets — wszystkie sekrety TEJ (nie
// poddrzewa) grupy, z kluczami do bezpośredniego odszyfrowania.
func (c *Client) GroupSecrets(groupID string) ([]SearchResult, error) {
	var out []SearchResult
	if err := c.do(http.MethodGet, "/g/"+url.PathEscape(groupID)+"/secrets", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SearchGroup — GET /g/{groupID}/search?q=... — sekrety pasujące do query
// (title/username/url) w TEJ grupie i jej CAŁYM poddrzewie (nie tylko
// bezpośrednich dzieciach) — żeby przeszukać całą organizację, wywołaj z
// groupID jej roota. Puste query zwraca pustą listę (świadome, server-side
// — patrz Handler.Search w password-manager), nie błąd.
func (c *Client) SearchGroup(groupID, query string) ([]SearchResult, error) {
	var out []SearchResult
	if err := c.do(http.MethodGet, "/g/"+url.PathEscape(groupID)+"/search?q="+url.QueryEscape(query), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SearchGroupLimit — jak SearchGroup, z jawnym limitem (serwer: domyślnie 50,
// max 500). Żeby wykryć ucięcie, poproś o N+1 i sprawdź, czy przyszło więcej
// niż N.
func (c *Client) SearchGroupLimit(groupID, query string, limit int) ([]SearchResult, error) {
	var out []SearchResult
	path := "/g/" + url.PathEscape(groupID) + "/search?q=" + url.QueryEscape(query) + "&limit=" + strconv.Itoa(limit)
	if err := c.do(http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ── Rejestracja + własny klucz tożsamości ───────────────────────────────────

// Register — POST /api/v1/register {email, password, first_name,
// last_name}. Konto NIE materializuje się od razu — user musi kliknąć link
// weryfikacyjny w mailu (poza appką, w przeglądarce) zanim będzie mógł się
// zalogować. Świadomie BEZ CAPTCHA — patrz auth.Handler.RegisterAPI
// (password-manager) i password-manager-desktop/TASK-002-full-client.md.
func (c *Client) Register(email, password, firstName, lastName string) error {
	return c.do(http.MethodPost, "/api/v1/register", map[string]string{
		"email":      email,
		"password":   password,
		"first_name": firstName,
		"last_name":  lastName,
	}, nil)
}

// CreateOrg — POST /groups {name, slug, public_key} -> {group_id,
// full_path}. Root organizacja (nigdy subgrupa) — pierwsza organizacja usera
// to moment, w którym web generuje jego klucz tożsamości
// (web/templates/group/new.html: createOrganization), patrz
// GenerateIdentityKeypair + StoreGroupKey niżej dla tego samego flow po
// stronie klienta API. publicKeyArmored jest WYMAGANY przez serwer (tasks/043,
// twardy gate group.Handler.CreateRoot) — grupa, klucz tożsamości twórcy i
// jego "owner" membership powstają atomowo w jednej transakcji, więc nie ma
// już osobnego kroku SetPublicKey po tym wywołaniu (starsza wersja tego
// klienta go miała — serwer to teraz odrzuca z "public_key required" jeśli
// go tu zabraknie). slug może być puste — serwer wtedy slugifikuje name.
type CreateOrgResult struct {
	GroupID  string `json:"group_id"`
	FullPath string `json:"full_path"`
}

func (c *Client) CreateOrg(name, slug, publicKeyArmored string) (*CreateOrgResult, error) {
	var out CreateOrgResult
	if err := c.do(http.MethodPost, "/groups", map[string]string{"name": name, "slug": slug, "public_key": publicKeyArmored}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ImportSecretParams — jeden sekret w bulk-importzie lokalnego offline
// vaulta (tasks/002/003 w tym repo, brief kanoniczny 045 w password-manager).
// Ciphertext/GroupEncryptedSecretKey przychodzą już gotowe z localvault —
// migracja to czysty upload, ZERO re-encryptu.
type ImportSecretParams struct {
	Type                    string // "account" albo "env"
	Title                   string
	Username                string
	URL                     string
	HasTOTP                 bool
	Ciphertext              string
	GroupEncryptedSecretKey string
	// GroupLocalID — który z ImportGroupParams.LocalID (patrz niżej) zawiera
	// ten sekret; ""=root organizacji. Follow-up taska
	// password-manager-desktop/tasks/todo/011-local-vault-groups.md — bez
	// tego pola import spłaszczał całe drzewo do jednej grupy root.
	GroupLocalID string
}

// ImportGroupParams — jedna podgrupa z lokalnego pliku do odtworzenia w
// organizacji online razem z resztą importu. LocalID/ParentLocalID to
// identyfikatory NADANE PRZEZ WOŁAJĄCEGO (localvault.Group.ID w
// password-manager-desktop) — server nie zna hierarchii z góry, sam ją
// rozwiązuje po tych ID (patrz group.Repository.ImportVault w
// password-manager). ParentLocalID=="" znaczy "bezpośrednio pod właśnie
// tworzonym rootem tego importu".
//
// GroupKeySelfWrapped — w przeciwieństwie do sekretów (które re-używają
// group key SWOJEJ grupy) każda podgrupa dostaje WŁASNY, świeżo
// wygenerowany przez wołającego group_key (dokładnie jak CreateSubgroup w
// password-manager-desktop/app.go generuje go dla ręcznie tworzonej
// subgrupy) — self-wrapped do TEGO SAMEGO identity key co reszta importu
// (publicKeyArmored przekazany do ImportGroup), bo to jeden świeżo tworzony
// org z jednym właścicielem/kluczem tożsamości.
type ImportGroupParams struct {
	LocalID             string
	ParentLocalID       string
	Name                string
	GroupKeySelfWrapped string
}

// ImportGroupResult — jak CreateOrgResult, ta sama para pól (group.Handler.
// ImportVault w password-manager zwraca dokładnie ten sam kształt co CreateRoot).
type ImportGroupResult struct {
	GroupID  string `json:"group_id"`
	FullPath string `json:"full_path"`
}

// ImportGroup — POST /api/v1/groups/import. Materializuje lokalny offline
// vault jako nową organizację w JEDNEJ transakcji serwerowej: grupa +
// identity key (publicKeyArmored) + membership "owner" + self-wrapped group
// key (groupKeySelfWrapped) + wszystkie podgrupy (groups, follow-up taska
// password-manager-desktop/tasks/todo/011) + wszystkie sekrety. Zero
// dodatkowej kryptografii tutaj — patrz internal/group/repository.go
// ImportVault (password-manager) i
// tasks/003-migrate-local-vault-to-organization.md w tym repo. groups może
// być nil/puste (stary, płaski import sprzed 011 — wszystko ląduje w
// rootcie, dokładnie jak dawniej).
func (c *Client) ImportGroup(name, publicKeyArmored, groupKeySelfWrapped string, groups []ImportGroupParams, secrets []ImportSecretParams) (*ImportGroupResult, error) {
	type importGroupBody struct {
		LocalID             string `json:"local_id"`
		ParentLocalID       string `json:"parent_local_id,omitempty"`
		Name                string `json:"name"`
		GroupKeySelfWrapped string `json:"group_key_self_wrapped"`
	}
	type importSecretBody struct {
		Type                    string `json:"type"`
		Title                   string `json:"title"`
		Username                string `json:"username,omitempty"`
		URL                     string `json:"url,omitempty"`
		HasTOTP                 bool   `json:"has_totp,omitempty"`
		Ciphertext              string `json:"ciphertext"`
		GroupEncryptedSecretKey string `json:"group_encrypted_secret_key"`
		GroupLocalID            string `json:"group_local_id,omitempty"`
	}
	body := struct {
		Name                string             `json:"name"`
		PublicKeyArmored    string             `json:"public_key_armored"`
		GroupKeySelfWrapped string             `json:"group_key_self_wrapped"`
		Groups              []importGroupBody  `json:"groups,omitempty"`
		Secrets             []importSecretBody `json:"secrets"`
	}{
		Name:                name,
		PublicKeyArmored:    publicKeyArmored,
		GroupKeySelfWrapped: groupKeySelfWrapped,
		Groups:              make([]importGroupBody, len(groups)),
		Secrets:             make([]importSecretBody, len(secrets)),
	}
	for i, g := range groups {
		body.Groups[i] = importGroupBody{
			LocalID: g.LocalID, ParentLocalID: g.ParentLocalID, Name: g.Name, GroupKeySelfWrapped: g.GroupKeySelfWrapped,
		}
	}
	for i, s := range secrets {
		body.Secrets[i] = importSecretBody{
			Type: s.Type, Title: s.Title, Username: s.Username, URL: s.URL,
			HasTOTP: s.HasTOTP, Ciphertext: s.Ciphertext, GroupEncryptedSecretKey: s.GroupEncryptedSecretKey,
			GroupLocalID: s.GroupLocalID,
		}
	}
	var out ImportGroupResult
	if err := c.do(http.MethodPost, "/api/v1/groups/import", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CheckSlug — POST /api/v1/check-slug {slug} -> {taken}. Do żywej walidacji
// w wizardzie zakładania organizacji (web/templates/group/new.html:
// validateStep1), zanim user w ogóle dojdzie do CreateOrg.
func (c *Client) CheckSlug(slug string) (taken bool, err error) {
	var out struct {
		Taken bool `json:"taken"`
	}
	if err := c.do(http.MethodPost, "/api/v1/check-slug", map[string]string{"slug": slug}, &out); err != nil {
		return false, err
	}
	return out.Taken, nil
}

// CreateGroupResult — jak CreateOrgResult, ta sama para pól z odpowiedzi
// serwera (patrz group.Handler.CreateSub w password-manager).
type CreateGroupResult struct {
	GroupID  string `json:"group_id"`
	FullPath string `json:"full_path"`
}

// CreateGroup — POST /g/{parentGroupID}/groups {name} -> {group_id,
// full_path}. Tworzy PODGRUPĘ istniejącej grupy (w przeciwieństwie do
// CreateOrg, który zawsze tworzy nowy root) — wymaga roli manager+ w grupie
// rodzicu, serwer sam pilnuje limitu głębokości (400 "max group depth
// reached" jeśli parent.Depth >= 4). Twórca jest automatycznie dodany jako
// manager nowej grupy po stronie serwera — nic dodatkowego do zrobienia tu
// dla członkostwa, tylko group key (patrz pgpcrypto.GenerateEncryptedGroupKey
// + StoreGroupKey, ta nowa grupa NIE dziedziczy klucza rodzica).
func (c *Client) CreateGroup(parentGroupID, name string) (*CreateGroupResult, error) {
	var out CreateGroupResult
	path := "/g/" + url.PathEscape(parentGroupID) + "/groups"
	if err := c.do(http.MethodPost, path, map[string]string{"name": name}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// MyPrivateGroupResult — jak CreateGroupResult, odpowiedź
// CreateOrGetMyPrivateGroup (password-manager/internal/group/handler.go).
type MyPrivateGroupResult struct {
	GroupID  string `json:"group_id"`
	FullPath string `json:"full_path"`
}

// MyPrivateGroup — POST /orgs/{orgID}/my-private-group -> {group_id,
// full_path}. Zwraca (tworząc jeśli trzeba) płaską, nieudostępnianą nikomu
// innemu subgrupę wołającego w tej organizacji (tasks/done/030,
// password-manager repo) — jedyny wymóg to bycie DOWOLNYM memberem
// organizacji. Idempotentne, bezpieczne do wołania za każdym razem. Zwraca
// zawsze TĘ SAMĄ grupę dla danego (orgID, usera) — jej slug zawiera userID,
// więc wołający nie musi go znać/hardkodować (patrz sharqey CLI, alias
// "private:<org>").
func (c *Client) MyPrivateGroup(orgID string) (*MyPrivateGroupResult, error) {
	var out MyPrivateGroupResult
	path := "/orgs/" + url.PathEscape(orgID) + "/my-private-group"
	if err := c.do(http.MethodPost, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetPublicKey — PATCH /api/v1/me/public-key {org_id, public_key}. Rejestruje
// klucz tożsamości (org_identity_keys) wołającego dla TEJ organizacji —
// każda organizacja ma niezależny keypair, żaden nie jest reużywany między
// organizacjami. Zwraca alreadySet=true jeśli inny tab/klient już ustawił
// klucz dla tej organizacji pierwszy (HTTP 409) — wołający powinien wtedy
// odrzucić lokalnie wygenerowany klucz i zapytać serwer o ten, który już
// tam jest, zamiast desynchronizować się z resztą systemu.
func (c *Client) SetPublicKey(orgID, publicKeyArmored string) (alreadySet bool, err error) {
	err = c.do(http.MethodPatch, "/api/v1/me/public-key", map[string]string{
		"org_id":     orgID,
		"public_key": publicKeyArmored,
	}, nil)
	if err != nil {
		if strings.Contains(err.Error(), "HTTP 409") {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// CancelOrgDeletion — DELETE /g/{orgID}/deletion. Anuluje zaplanowane
// usunięcie organizacji (password-manager tasks/076); wymaga admin/owner
// roota, 404 gdy nic nie było zaplanowane.
func (c *Client) CancelOrgDeletion(orgID string) error {
	return c.do(http.MethodDelete, "/g/"+url.PathEscape(orgID)+"/deletion", nil, nil)
}

// StoreGroupKey — POST /g/{groupID}/group-key {encrypted_key}. Zapisuje
// (PGP-zaszyfrowany do WŁASNEGO klucza publicznego, patrz
// pgpcrypto.GenerateEncryptedGroupKey) klucz AES tej grupy dla wołającego —
// bez tego user ma klucz tożsamości, ale żadnego group key, więc nie może
// jeszcze ani czytać, ani zapisywać sekretów w tej organizacji.
func (c *Client) StoreGroupKey(groupID, encryptedGroupKey string) error {
	return c.do(http.MethodPost, "/g/"+url.PathEscape(groupID)+"/group-key", map[string]string{
		"encrypted_key": encryptedGroupKey,
	}, nil)
}

// ShareGroupKey — jak StoreGroupKey, ale z target_user_id: zapisuje group key
// zaszyfrowany do KLUCZA PUBLICZNEGO INNEGO membera (nie wołającego), którego
// wołający wcześniej sam odszyfrował swoim kluczem i zaszyfrował ponownie do
// klucza docelowego — serwer nigdy nie widzi plaintextu. Wymaga manager+ w tej
// grupie (h.canManage) — z jednym wyjątkiem: twórca świeżo utworzonej subgrupy
// bez ŻADNEGO group_key może zapisać PIERWSZY klucz dla delegowanego managera
// (patrz group.Handler.StoreGroupKey, bootstrap comment), to jest ten sam
// endpoint.
//
// UWAGA na kolejność parametrów (ustalona 2026-08-23 przy scalaniu z
// równoległą, osieroconą gałęzią goclienta która miała odwrotną kolejność
// (groupID, encryptedGroupKey, targetUserID) — TA wersja wygrała, bo
// password-manager-desktop/app.go już woła ją w tej kolejności
// (a.api.ShareGroupKey(groupID, targetUserID, sharedEncryptedKey)) i to jest
// jedyny działający konsument tego klienta dziś).
func (c *Client) ShareGroupKey(groupID, targetUserID, encryptedGroupKey string) error {
	return c.do(http.MethodPost, "/g/"+url.PathEscape(groupID)+"/group-key", map[string]string{
		"encrypted_key":  encryptedGroupKey,
		"target_user_id": targetUserID,
	}, nil)
}

// OrgMemberCandidate — jedna pozycja z ListOrgMembersForPicker.
type OrgMemberCandidate struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	PublicKey   string `json:"public_key"`
}

// ListOrgMembersForPicker — GET /g/{groupID}/org-members[?full=1]. Domyślnie
// (full=false) zwraca członków organizacji tej (pod)grupy, którzy jeszcze
// NIE są jej bezpośrednimi członkami — kandydaci do AddSubgroupMember.
// full=true wyłącza to filtrowanie po istniejącym członkostwie — użyj przy
// wyborze managera dla NOWEJ (jeszcze nieistniejącej) subgrupy, gdzie osoby
// już będące managerami rodzica są jak najbardziej prawidłowymi kandydatami
// (patrz group.Handler.OrgMembersForPicker w password-manager). Wywołujący
// jest zawsze wykluczony. Wymaga manager+ w TEJ grupie.
func (c *Client) ListOrgMembersForPicker(groupID string, full bool) ([]OrgMemberCandidate, error) {
	path := "/g/" + url.PathEscape(groupID) + "/org-members"
	if full {
		path += "?full=1"
	}
	var out []OrgMemberCandidate
	if err := c.do(http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// AddSubgroupMemberResult — odpowiedź AddSubgroupMember, zawiera public_key
// dodanego usera do natychmiastowego re-encryptu group key (ShareGroupKey).
type AddSubgroupMemberResult struct {
	UserID     string `json:"user_id"`
	Email      string `json:"email"`
	PublicKey  string `json:"public_key"`
	KeysShared int    `json:"keys_shared"` // tylko AddSubgroupMemberWithKeys
}

// AddSubgroupMember — POST /g/{groupID}/members {email, role}. WYŁĄCZNIE dla
// subgrup (group.Handler.AddMember zwraca 403 dla org-roota — tam jedyna
// droga to CreateInvite). role: viewer/editor/manager (group.SubgroupRole),
// puste = "viewer". Dodaje TYLKO rolę/membership — group key trzeba
// udostępnić osobno przez ShareGroupKey z public_key z tej odpowiedzi,
// inaczej dodany user ma rolę, ale nic nie odszyfruje (patrz "Sync" fallback
// w web/templates/group/settings.html, ten sam wzorzec).
func (c *Client) AddSubgroupMember(groupID, email, role string) (*AddSubgroupMemberResult, error) {
	var out AddSubgroupMemberResult
	if err := c.do(http.MethodPost, "/g/"+url.PathEscape(groupID)+"/members", map[string]string{
		"email": email,
		"role":  role,
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AddSubgroupMemberWithKeys — jak AddSubgroupMember, ale razem z kluczami
// gałęzi (ta grupa i podgrupy) już zaszyfrowanymi dla nowego członka (klucz
// publiczny z ListOrgMembersForPicker). Serwer zapisuje rolę i klucze w
// jednej transakcji — przerwanie przed zapisem nie zostawia nikogo z rolą bez
// kluczy, wystarczy dodać jeszcze raz. Puste keys = sama rola.
func (c *Client) AddSubgroupMemberWithKeys(groupID, email, role string, keys []GroupKeyForUser) (*AddSubgroupMemberResult, error) {
	if keys == nil {
		keys = []GroupKeyForUser{}
	}
	var out AddSubgroupMemberResult
	if err := c.do(http.MethodPost, "/g/"+url.PathEscape(groupID)+"/members", map[string]any{
		"email": email,
		"role":  role,
		"keys":  keys,
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// MemberPublicKey — jedna pozycja z MembersNeedingKey.
type MemberPublicKey struct {
	UserID    string `json:"user_id"`
	PublicKey string `json:"public_key"`
}

// MembersNeedingKey — GET /g/{groupID}/members-needing-key. Członkowie z
// jakąś rolą w tej grupie (bezpośrednią lub kaskadową), ale bez group key
// (wołający wykluczony) — dokładnie zbiór potrzebny do napędzenia przycisku
// "🔑 Sync" (patrz ShareGroupKey), bez wysyłania public_key WSZYSTKICH
// członków tylko po to, żeby znaleźć tych kilku.
func (c *Client) MembersNeedingKey(groupID string) ([]MemberPublicKey, error) {
	var out []MemberPublicKey
	if err := c.do(http.MethodGet, "/g/"+url.PathEscape(groupID)+"/members-needing-key", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SubtreeKey — grupa z gałęzi razem z group key wywołującego.
type SubtreeKey struct {
	ID             string `json:"id"`
	FullPath       string `json:"full_path"`
	MyEncryptedKey string `json:"my_encrypted_key"`
}

// KeyedSubtree — GET /g/{groupID}/keyed-subtree?with_keys=1: wszystkie grupy
// gałęzi (ta i niżej), do których wywołujący ma klucz, jednym zapytaniem.
// Rola kaskaduje w dół, klucz nie — kto dostaje rolę w gałęzi, potrzebuje
// kluczy wszystkich tych grup (patrz ShareSubtreeGroupKeys).
func (c *Client) KeyedSubtree(groupID string) ([]SubtreeKey, error) {
	var out []SubtreeKey
	if err := c.do(http.MethodGet, "/g/"+url.PathEscape(groupID)+"/keyed-subtree?with_keys=1", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GroupKeyForUser — klucz jednej grupy zaszyfrowany do klucza publicznego
// odbiorcy.
type GroupKeyForUser struct {
	GroupID      string `json:"group_id"`
	EncryptedKey string `json:"encrypted_key"`
}

// ShareSubtreeGroupKeys — POST /g/{groupID}/subtree-group-keys: klucze wielu
// grup z gałęzi groupID dla jednego usera, w jednej transakcji (wszystkie
// albo żaden). Wywołujący musi zarządzać każdą z tych grup.
func (c *Client) ShareSubtreeGroupKeys(groupID, targetUserID string, keys []GroupKeyForUser) error {
	return c.do(http.MethodPost, "/g/"+url.PathEscape(groupID)+"/subtree-group-keys", map[string]any{
		"target_user_id": targetUserID,
		"keys":           keys,
	}, nil)
}

// MemberNeedingKey — członek z rolą w grupie bez jej klucza. Reason: "no_key"
// albo "old_key" (klucz zaszyfrowany dla poprzedniego klucza członka — tylko
// z includeOldKey; takich NIE synchronizuj automatycznie, to właśnie
// podstawiłby złośliwy serwer).
type MemberNeedingKey struct {
	UserID    string `json:"user_id"`
	PublicKey string `json:"public_key"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Reason    string `json:"reason"`
}

// SubtreeGroupNeedingKey — grupa z gałęzi z członkami bez jej klucza i
// kluczem wywołującego do przepakowania.
type SubtreeGroupNeedingKey struct {
	GroupID        string             `json:"group_id"`
	Name           string             `json:"name"`
	FullPath       string             `json:"full_path"`
	MyEncryptedKey string             `json:"my_encrypted_key"`
	Members        []MemberNeedingKey `json:"members"`
}

// SubtreeMembersNeedingKey — GET /g/{groupID}/subtree-members-needing-key:
// MembersNeedingKey dla całej gałęzi (grupy, których klucz wywołujący ma i
// którymi zarządza). Po przeniesieniu grupy pod nowego rodzica to są
// członkowie rodzica, którzy dostali w gałęzi rolę bez kluczy.
func (c *Client) SubtreeMembersNeedingKey(groupID string, includeOldKey bool) ([]SubtreeGroupNeedingKey, error) {
	path := "/g/" + url.PathEscape(groupID) + "/subtree-members-needing-key"
	if includeOldKey {
		path += "?include_old_key=1"
	}
	var out []SubtreeGroupNeedingKey
	if err := c.do(http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteGroup — DELETE /g/{groupID}. Wymaga manager+ — org-root (grupa bez
// ParentID) jest bezwarunkowo odrzucany server-side ("deleting an
// organization is not supported yet", group.Handler.DeleteGroup), świadomie
// bez UI do tego po stronie klienta.
func (c *Client) DeleteGroup(groupID string) error {
	return c.do(http.MethodDelete, "/g/"+url.PathEscape(groupID), nil, nil)
}

// RenameGroupResult/MoveGroupResult — Rename/MoveGroup w password-manager
// (group.Handler) robią writeJSON(w, 200, g) na *group.Group, który NIE MA
// json tagów (internal/group/model.go) — encoding/json więc serializuje pod
// dokładnymi (capitalized) nazwami pól Go, nie snake_case jak reszta API.
type RenameGroupResult struct {
	ID       string `json:"ID"`
	Name     string `json:"Name"`
	FullPath string `json:"FullPath"`
}

// RenameGroup — PATCH /g/{groupID} {name}. Zmienia WYŁĄCZNIE display name
// (nie slug/full_path) — manager+ w tej grupie, działa też na org-roocie
// (w przeciwieństwie do DeleteGroup, brak blast radius).
func (c *Client) RenameGroup(groupID, name string) (*RenameGroupResult, error) {
	var out RenameGroupResult
	if err := c.do(http.MethodPatch, "/g/"+url.PathEscape(groupID), map[string]string{"name": name}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type MoveGroupResult struct {
	ID       string `json:"ID"`
	FullPath string `json:"FullPath"`
	Depth    int    `json:"Depth"`
}

// MoveGroup — POST /g/{groupID}/move {new_parent_id}. Reparentuje subgrupę
// (nigdy org-root) w OBRĘBIE tej samej organizacji — serwer waliduje cykl,
// cross-org, prywatne grupy i max głębokość (group.Handler.MoveGroup),
// klient tylko przekazuje błąd. Wymaga manager+ w grupie źródłowej I
// docelowej. Zero kryptografii — reparenting nie rusza group_key ani żadnego
// ciphertextu.
func (c *Client) MoveGroup(groupID, newParentID string) (*MoveGroupResult, error) {
	var out MoveGroupResult
	if err := c.do(http.MethodPost, "/g/"+url.PathEscape(groupID)+"/move", map[string]string{"new_parent_id": newParentID}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ── Zarządzanie członkami grupy (org-root LUB subgrupa) ──────────────────────
// ListMembers/UpdateMemberRole/RemoveMember działają identycznie dla obu —
// group.Handler branch'uje isOrgRoot wewnętrznie i sam dobiera słownik ról
// (org-root: viewer/admin/owner, group.OrgRole; subgrupa: viewer/editor/
// manager, group.SubgroupRole, bez ownera). Dodawanie kogoś do ORGANIZACJI
// idzie WYŁĄCZNIE przez zaproszenie (CreateInvite) — group.Handler.AddMember
// zwraca 403 dla org-roota (bezpośrednie dodanie po samym emailu pozwalało
// dodać kogoś bez jego zgody). Dodawanie do SUBGRUPY idzie przez
// AddSubgroupMember (picker już-zaufanych członków organizacji, bez invite).

// Member — jedna pozycja rostera z GET /g/{groupID}/members
// (group.Handler.Members, MemberJSON — kształt zaprojektowany specjalnie
// dla API-only klientów jak ten).
type Member struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	IsDirect    bool   `json:"is_direct"`
	HasGroupKey bool   `json:"has_group_key"`
}

// ListMembers — GET /g/{groupID}/members. Wymaga roli manager+ (na org-roocie:
// admin+) w tej grupie — serwer zwraca 403 inaczej, roster ujawnia emaile
// wszystkich członków.
func (c *Client) ListMembers(groupID string) ([]Member, error) {
	var out []Member
	if err := c.do(http.MethodGet, "/g/"+url.PathEscape(groupID)+"/members", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateMemberRole — PATCH /g/{groupID}/members/{userID} {role}. Dla org-roota
// role to viewer/admin/owner (group.OrgRole) — serwer sam pilnuje że tylko
// owner nadaje/zmienia owner/admin i że ostatni owner nie może zostać
// zdegradowany, appka nie musi tego sprawdzać z góry.
func (c *Client) UpdateMemberRole(groupID, targetUserID, role string) error {
	return c.do(http.MethodPatch, "/g/"+url.PathEscape(groupID)+"/members/"+url.PathEscape(targetUserID), map[string]string{
		"role": role,
	}, nil)
}

// RemoveMember — DELETE /g/{groupID}/members/{userID}.
func (c *Client) RemoveMember(groupID, targetUserID string) error {
	return c.do(http.MethodDelete, "/g/"+url.PathEscape(groupID)+"/members/"+url.PathEscape(targetUserID), nil, nil)
}

// ── Service accounty (maszynowa tożsamość scoped do subgrupy) ───────────────
// Roster + remove + szczegóły/edycja OIDC bindingu + tokeny (task 058 w
// password-manager dostarczył GET/PATCH/DELETE). Tworzenie nowego SA
// (keygen + group key sharing) to osobny, późniejszy krok — patrz desktop
// TASK-011.

// IsNotFound sprawdza czy błąd z do() to HTTP 404 — przydatne gdy 404
// oznacza legalny stan (np. "OIDC binding jeszcze nie ustawiony bo wizard
// tworzenia SA nie doszedł do końca"), nie awarię do pokazania userowi wprost.
func IsNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), ": HTTP 404:")
}

// ServiceAccount — jedna pozycja rostera z GET /g/{groupID}/service-accounts
// (serviceaccount.Handler.List). Backend serializuje surowy struct BEZ json
// tagów — klucze w odpowiedzi są PascalCase, inaczej niż w Member (roster
// ludzi, snake_case) — to realna asymetria dwóch różnych handlerów, nie
// literówka tutaj.
type ServiceAccount struct {
	UserID      string     `json:"UserID"`
	OrgID       string     `json:"OrgID"`
	Name        string     `json:"Name"`
	Description string     `json:"Description"`
	AuthType    string     `json:"AuthType"` // "token" | "oidc"
	CreatedBy   string     `json:"CreatedBy"`
	CreatedAt   time.Time  `json:"CreatedAt"`
	DisabledAt  *time.Time `json:"DisabledAt"`
	Role        string     `json:"Role"`
}

// ListServiceAccounts — GET /g/{groupID}/service-accounts. Roster service
// accountów dodanych bezpośrednio do TEJ grupy (bez kaskady).
func (c *Client) ListServiceAccounts(groupID string) ([]ServiceAccount, error) {
	var out []ServiceAccount
	if err := c.do(http.MethodGet, "/g/"+url.PathEscape(groupID)+"/service-accounts", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RemoveServiceAccount — DELETE /g/{groupID}/service-accounts/{userID}.
// Pełne usunięcie (group membership + disable + rewokacja tokenów
// server-side), nie da się cofnąć.
func (c *Client) RemoveServiceAccount(groupID, userID string) error {
	return c.do(http.MethodDelete, "/g/"+url.PathEscape(groupID)+"/service-accounts/"+url.PathEscape(userID), nil, nil)
}

// OIDCBinding — konfiguracja workload identity federation jednego SA typu
// oidc (serviceaccount.Handler.GetOIDCBinding/UpdateOIDCBinding). Backend
// serializuje surowy struct bez json tagów — PascalCase klucze, jak
// ServiceAccount powyżej.
type OIDCBinding struct {
	ID               string   `json:"ID"`
	ServiceAccountID string   `json:"ServiceAccountID"`
	IssuerURL        string   `json:"IssuerURL"`
	AllowedAudiences []string `json:"AllowedAudiences"`
	SubjectPattern   string   `json:"SubjectPattern"`
}

// TokenMeta — metadata jednego tokenu SA. Surowy token NIGDY nie jest tu
// zwracany — istnieje wyłącznie jako hash w bazie, nieodzyskiwalny z zasady.
type TokenMeta struct {
	ID         string     `json:"ID"`
	CreatedAt  time.Time  `json:"CreatedAt"`
	ExpiresAt  time.Time  `json:"ExpiresAt"`
	LastUsedAt *time.Time `json:"LastUsedAt"`
	RevokedAt  *time.Time `json:"RevokedAt"`
}

// GetServiceAccountOIDCBinding — GET /service-accounts/{userID}/oidc-binding.
// Zwraca 404 (sprawdź apiclient.IsNotFound) gdy SA jest typu oidc, ale
// wizard tworzenia nie doszedł jeszcze do ustawienia bindingu.
func (c *Client) GetServiceAccountOIDCBinding(userID string) (*OIDCBinding, error) {
	var out OIDCBinding
	if err := c.do(http.MethodGet, "/service-accounts/"+url.PathEscape(userID)+"/oidc-binding", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateServiceAccountOIDCBinding — PATCH /service-accounts/{userID}/oidc-binding.
// Nadpisuje cały binding (jeden na SA, wymuszone UNIQUE constraintem
// server-side) — nie ma częściowej aktualizacji pojedynczych pól.
func (c *Client) UpdateServiceAccountOIDCBinding(userID, issuerURL string, allowedAudiences []string, subjectPattern string) error {
	return c.do(http.MethodPatch, "/service-accounts/"+url.PathEscape(userID)+"/oidc-binding", map[string]any{
		"issuer_url":        issuerURL,
		"allowed_audiences": allowedAudiences,
		"subject_pattern":   subjectPattern,
	}, nil)
}

// ListServiceAccountTokens — GET /service-accounts/{userID}/tokens.
func (c *Client) ListServiceAccountTokens(userID string) ([]TokenMeta, error) {
	var out []TokenMeta
	if err := c.do(http.MethodGet, "/service-accounts/"+url.PathEscape(userID)+"/tokens", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeServiceAccountToken — DELETE /service-accounts/{userID}/tokens/{tokenID}.
// Rewokacja pojedynczego tokenu (nie wszystkich naraz — to robi
// RemoveServiceAccount).
func (c *Client) RevokeServiceAccountToken(userID, tokenID string) error {
	return c.do(http.MethodDelete, "/service-accounts/"+url.PathEscape(userID)+"/tokens/"+url.PathEscape(tokenID), nil, nil)
}

// CreateServiceAccountTokenResult — odpowiedź CreateServiceAccountToken.
// Token pokazywany DOKŁADNIE RAZ tutaj — nieodzyskiwalny po tym wywołaniu,
// istnieje server-side wyłącznie jako hash.
type CreateServiceAccountTokenResult struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CreateServiceAccountToken — POST /service-accounts/{userID}/token
// {ttl_days}. ttlDays<=0 lub >365 → serwer sam bierze domyślne 90.
func (c *Client) CreateServiceAccountToken(userID string, ttlDays int) (*CreateServiceAccountTokenResult, error) {
	var out CreateServiceAccountTokenResult
	if err := c.do(http.MethodPost, "/service-accounts/"+url.PathEscape(userID)+"/token", map[string]int{"ttl_days": ttlDays}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Invite — jedna pending pozycja z ListInvites.
type Invite struct {
	Token string `json:"token"`
	Email string `json:"email"`
}

// InviteResult — odpowiedź CreateInvite.
type InviteResult struct {
	Token string `json:"token"`
	URL   string `json:"url"`
	Email string `json:"email"`
}

// CreateInvite — POST /g/{groupID}/invites {email}. groupID MUSI być
// org-rootem (invitation.Handler.Create odrzuca subgrupy) — jedyna droga
// dołączenia kogoś do organizacji, zapraszany musi świadomie zaakceptować
// (link /invite/{token} w mailu), inaczej niż CreateGroup dla subgrup, gdzie
// user jest dodawany od razu z listy już-zaufanych członków organizacji.
func (c *Client) CreateInvite(orgID, email string) (*InviteResult, error) {
	var out InviteResult
	if err := c.do(http.MethodPost, "/g/"+url.PathEscape(orgID)+"/invites", map[string]string{"email": email}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListInvites — GET /g/{groupID}/invites — pending zaproszenia tej organizacji.
func (c *Client) ListInvites(orgID string) ([]Invite, error) {
	var out []Invite
	if err := c.do(http.MethodGet, "/g/"+url.PathEscape(orgID)+"/invites", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CancelInvite — DELETE /g/{groupID}/invites/{token}.
func (c *Client) CancelInvite(orgID, token string) error {
	return c.do(http.MethodDelete, "/g/"+url.PathEscape(orgID)+"/invites/"+url.PathEscape(token), nil, nil)
}

// GetMyGroupKey — GET /g/{groupID}/my-group-key -> wołającego PGP-zaszyfrowany
// klucz AES tej grupy (do odszyfrowania pgpcrypto.DecryptArmoredMessageWithKey,
// potem użycia w EncryptWithGroupKey przy tworzeniu nowego sekretu). 404
// jeśli wołający nie ma jeszcze klucza dla tej grupy — patrz StoreGroupKey.
func (c *Client) GetMyGroupKey(groupID string) (encryptedGroupKey string, err error) {
	var out struct {
		EncryptedKey string `json:"encrypted_key"`
	}
	if err := c.do(http.MethodGet, "/g/"+url.PathEscape(groupID)+"/my-group-key", nil, &out); err != nil {
		return "", err
	}
	return out.EncryptedKey, nil
}

// CreateSecretParams — pola formularza POST /g/{groupID}/secrets.
// Ciphertext/GroupEncryptedSecretKey MUSZĄ już być zaszyfrowane po stronie
// klienta (patrz pgpcrypto.EncryptWithGroupKey) — serwer nigdy nie widzi
// plaintextu ani group key.
// GroupEncryptedSecretKey XOR OwnerEncryptedSecretKey — serwer wymaga
// DOKŁADNIE jednego z dwóch, zależnie czy groupID jest Private (TASK-018,
// password-manager-flutter runda 5: Private nie ma group_key w OGÓLE).
// Sprawdź czy grupa jest Private przez apiclient.IsNotFound(err) na
// GetMyGroupKey — Private NIGDY nie ma wiersza group_keys.
type CreateSecretParams struct {
	Type                    string // "account" albo "env"
	Title                   string
	Username                string
	URL                     string
	Ciphertext              string
	GroupEncryptedSecretKey string
	OwnerEncryptedSecretKey string
	HasTOTP                 bool
	// BlobID — wymagane dla Type "file" (password-manager tasks/todo/075):
	// blob wgrany wcześniej przez CreateBlob + UploadBlob.
	BlobID string
}

// CreateSecret — POST /g/{groupID}/secrets, form-urlencoded (patrz doForm) ->
// nowy secret_id.
func (c *Client) CreateSecret(groupID string, p CreateSecretParams) (secretID string, err error) {
	form := url.Values{
		"type":       {p.Type},
		"title":      {p.Title},
		"username":   {p.Username},
		"url":        {p.URL},
		"ciphertext": {p.Ciphertext},
	}
	if p.OwnerEncryptedSecretKey != "" {
		form.Set("owner_encrypted_secret_key", p.OwnerEncryptedSecretKey)
	} else {
		form.Set("group_encrypted_secret_key", p.GroupEncryptedSecretKey)
	}
	if p.HasTOTP {
		form.Set("has_totp", "1")
	}
	if p.BlobID != "" {
		form.Set("blob_id", p.BlobID)
	}
	var out struct {
		SecretID string `json:"secret_id"`
	}
	if err := c.doForm(http.MethodPost, "/g/"+url.PathEscape(groupID)+"/secrets", form, &out); err != nil {
		return "", err
	}
	return out.SecretID, nil
}

// UpdateSecretParams — pola PUT /g/{groupID}/secrets/{secretID}. Ten
// endpoint, w odróżnieniu od Create, dekoduje JSON (json.NewDecoder), nie
// form-urlencoded — sprawdzone w internal/secret/handler.go: Update
// (password-manager). Ciphertext/GroupEncryptedSecretKey są opcjonalne
// (nil = zostaw stary ciphertext bez zmian) — wysyłaj je tylko gdy
// re-encryptujesz treść (nowe hasło/wartość), tak jak web
// (group/show.html: saveSecret).
type UpdateSecretParams struct {
	Title                   string
	Username                string
	URL                     string
	HasTOTP                 bool
	Ciphertext              *string
	GroupEncryptedSecretKey *string
	OwnerEncryptedSecretKey *string
	// BlobID — podmiana pliku sekretu typu "file"; wymaga Ciphertext
	// (metadane z nowym file_key).
	BlobID *string
}

// UpdateSecret — PUT /g/{groupID}/secrets/{secretID}.
func (c *Client) UpdateSecret(groupID, secretID string, p UpdateSecretParams) error {
	body := struct {
		Title                   string  `json:"title"`
		Username                string  `json:"username"`
		URL                     string  `json:"url"`
		HasTotp                 bool    `json:"has_totp"`
		Ciphertext              *string `json:"ciphertext,omitempty"`
		GroupEncryptedSecretKey *string `json:"group_encrypted_secret_key,omitempty"`
		OwnerEncryptedSecretKey *string `json:"owner_encrypted_secret_key,omitempty"`
		BlobID                  *string `json:"blob_id,omitempty"`
	}{
		Title: p.Title, Username: p.Username, URL: p.URL, HasTotp: p.HasTOTP,
		Ciphertext: p.Ciphertext, GroupEncryptedSecretKey: p.GroupEncryptedSecretKey,
		OwnerEncryptedSecretKey: p.OwnerEncryptedSecretKey, BlobID: p.BlobID,
	}
	path := "/g/" + url.PathEscape(groupID) + "/secrets/" + url.PathEscape(secretID)
	return c.do(http.MethodPut, path, body, nil)
}

// DeleteSecret — DELETE /g/{groupID}/secrets/{secretID}. Wymaga roli
// editor+ w grupie (serwer i tak to wymusza, klient nie sprawdza z góry).
func (c *Client) DeleteSecret(groupID, secretID string) error {
	path := "/g/" + url.PathEscape(groupID) + "/secrets/" + url.PathEscape(secretID)
	return c.do(http.MethodDelete, path, nil, nil)
}

// MoveSecret — POST /g/{groupID}/secrets/{secretID}/move (groupID = grupa
// ŹRÓDŁOWA). Ciphertext/GroupEncryptedSecretKey MUSZĄ już być re-encryptowane
// do group key grupy DOCELOWEJ przez wołającego (serwer tylko waliduje role i
// zapisuje gotowy ciphertext, jak Create) — patrz web/templates/group/
// show.html: moveSecret dla dokładnego przepisu: 1) odszyfruj istniejący
// ciphertext własnym group key ŹRÓDŁOWEJ grupy, 2) pobierz group key grupy
// DOCELOWEJ (GetMyGroupKey na targetGroupID — 404 jeśli wołający jeszcze nie
// ma tam klucza, np. świeżo dodana subgrupa), 3) zaszyfruj ten sam plaintext
// pod TEN klucz. Wymaga roli editor+ w OBU grupach (serwer wymusza).
// groupEncryptedSecretKey XOR ownerEncryptedSecretKey — pusty ten, który nie
// dotyczy grupy DOCELOWEJ (Private wymaga owner_encrypted_secret_key, patrz
// CreateSecretParams).
func (c *Client) MoveSecret(sourceGroupID, secretID, targetGroupID, ciphertext, groupEncryptedSecretKey, ownerEncryptedSecretKey string) error {
	path := "/g/" + url.PathEscape(sourceGroupID) + "/secrets/" + url.PathEscape(secretID) + "/move"
	body := map[string]string{
		"target_group_id": targetGroupID,
		"ciphertext":      ciphertext,
	}
	if ownerEncryptedSecretKey != "" {
		body["owner_encrypted_secret_key"] = ownerEncryptedSecretKey
	} else {
		body["group_encrypted_secret_key"] = groupEncryptedSecretKey
	}
	return c.do(http.MethodPost, path, body, nil)
}

// CreateOneTimeShareResult — POST /g/{groupID}/secrets/{secretID}/one-time-share
// response. Token jest hex, wołający buduje sam link finalny
// `{baseURL}/s/{token}#{base64(K)}` — K (klucz AES-256-GCM świeżo
// wygenerowany po stronie klienta) nigdy nie jest wysyłany do serwera,
// dlatego nie ma go w tym wyniku, patrz CreateOneTimeShare.
type CreateOneTimeShareResult struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CreateOneTimeShare — POST /g/{groupID}/secrets/{secretID}/one-time-share
// (task 068, password-manager: internal/onetimeshare/handler.go). Ciphertext
// musi być już gotowy: base64(iv (12B) || AES-256-GCM ciphertext), zaszyfrowany
// LOKALNIE świeżym losowym 32-bajtowym kluczem K (albo SHA-256(K||hasło) gdy
// user dodał opcjonalne hasło — wtedy hasPassword=true, to tylko podpowiedź
// UI dla strony reveal, serwer nie przechowuje żadnego materiału hasła).
// Serwer nigdy nie widzi K ani plaintextu. expiresInSeconds<=0 albo >24h
// (86400) jest po stronie serwera przycinane do 24h — można podać 0 żeby
// dostać maksimum wprost. Wymaga roli editor+ w grupie sekretu (403
// {"error":"editor role required"} inaczej) i włączonej polityki organizacji
// (403 {"error":"one-time sharing is disabled for this organization"} —
// wołający pokazuje to jako zwykły komunikat błędu, nic więcej do zrobienia).
func (c *Client) CreateOneTimeShare(groupID, secretID, ciphertext string, hasPassword bool, expiresInSeconds int) (*CreateOneTimeShareResult, error) {
	path := "/g/" + url.PathEscape(groupID) + "/secrets/" + url.PathEscape(secretID) + "/one-time-share"
	body := struct {
		Ciphertext       string `json:"ciphertext"`
		HasPassword      bool   `json:"has_password"`
		ExpiresInSeconds int    `json:"expires_in_seconds,omitempty"`
	}{Ciphertext: ciphertext, HasPassword: hasPassword, ExpiresInSeconds: expiresInSeconds}
	var out CreateOneTimeShareResult
	if err := c.do(http.MethodPost, path, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ── CLI login (device-code flow) ────────────────────────────────────────────
// Świadomie BEZ tokenu w obu wywołaniach — to jest KROK w którym CLI dopiero
// zdobywa token, nie ma go jeszcze skąd wziąć. Przeniesione z
// password-manager/pkg/client (2026-09-07, patrz password-manager/tasks/
// todo/065) przy wydzielaniu password-manager-cli — jedyny konsument to CLI
// (device-code flow zakłada terminal bez przeglądarki), ale żyje tu razem z
// resztą klienta zamiast duplikować się po raz trzeci.

type CLILoginRequestResult struct {
	ID        string `json:"id"`
	Code      string `json:"code"`
	ExpiresAt string `json:"expires_at"`
}

func (c *Client) CreateCLILoginRequest(deviceLabel string) (*CLILoginRequestResult, error) {
	var out CLILoginRequestResult
	if err := c.do(http.MethodPost, "/api/v1/cli/login-requests", map[string]string{"device_label": deviceLabel}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type CLILoginPollResult struct {
	Status string `json:"status"`
	Token  string `json:"token"`
}

func (c *Client) PollCLILoginRequest(requestID string) (*CLILoginPollResult, error) {
	var out CLILoginPollResult
	if err := c.do(http.MethodGet, "/api/v1/cli/login-requests/"+requestID+"/poll", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ── Service account auth (tasks/029) ────────────────────────────────────────
// Przeniesione razem z CLI login (patrz komentarz wyżej) — service accounty
// dziś logują się wyłącznie z CLI (CI), ale terraform-provider-sharqey
// będzie tego potrzebował gdy dostanie własne SA-auth (password-manager/
// tasks/todo/062, dziś jeszcze auth token-only bez tej ścieżki).

// ServiceAccountLogin wymienia kredencjał service accounta na krótkotrwałą
// sesję Sharqey — dokładnie jeden z token/webIdentityToken niepusty.
// webIdentityToken to surowy id_token z workload identity federation danej
// platformy CI (np. GitLab CI id_tokens:), branżowy wzorzec jak AWS
// AssumeRoleWithWebIdentity/Vault JWT auth.
func (c *Client) ServiceAccountLogin(token, webIdentityToken string) (string, error) {
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := c.do(http.MethodPost, "/api/v1/service-accounts/login", map[string]string{
		"token":              token,
		"web_identity_token": webIdentityToken,
	}, &out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("no access_token in response")
	}
	return out.AccessToken, nil
}

// ServiceAccountSelf — GET /api/v1/service-accounts/me. Wołane zamiast
// Workspaces po service-account loginie: SA nigdy nie jest membershipem org
// roota (tylko subgrupy, patrz password-manager/internal/serviceaccount),
// więc Workspaces zawsze zwróciłby dla niego pustą listę.
type ServiceAccountSelf struct {
	OrgID       string `json:"org_id"`
	OrgSlug     string `json:"org_slug"`
	OrgName     string `json:"org_name"`
	OrgFullPath string `json:"org_full_path"`
}

func (c *Client) ServiceAccountSelf() (*ServiceAccountSelf, error) {
	var out ServiceAccountSelf
	if err := c.do(http.MethodGet, "/api/v1/service-accounts/me", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ── Resolucja ścieżek grup ("acme/infra/prod") ──────────────────────────────
// Współdzielone przez password-manager-cli (`sharqey ls`/`get`) i
// terraform-provider-sharqey — oba adresują grupy identycznie po
// full_path, nie po UUID. Przeniesione z password-manager/pkg/client
// (2026-09-07, tasks/todo/065/062).

// ResolveGroup zwraca węzeł drzewa (workspace root albo subgrupę) dla danej
// ścieżki full_path, np. "acme" albo "acme/infra/prod".
func (c *Client) ResolveGroup(path string) (*GroupNode, error) {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil, fmt.Errorf("empty path")
	}
	rootSlug := strings.SplitN(path, "/", 2)[0]

	root, err := c.resolveRootWorkspace(rootSlug)
	if err != nil {
		return nil, err
	}

	tree, err := c.GroupTree(root.FullPath)
	if err != nil {
		return nil, fmt.Errorf("group tree: %w", err)
	}
	for i := range tree {
		if tree[i].FullPath == path {
			return &tree[i], nil
		}
	}
	if path == root.FullPath {
		return &GroupNode{ID: root.ID, Slug: root.Slug, Name: root.Name, FullPath: root.FullPath, Depth: 0}, nil
	}
	return nil, fmt.Errorf("unknown group %q", path)
}

// OrgIDForPath — root workspace ID dla ścieżki grupy (org identity keys są
// keyowane po ID ROOT grupy, nigdy po ID subgrupy — patrz password-manager
// project_org_independent_keys_per_org). Dla ścieżki będącej samym rootem to
// po prostu ResolveGroup(path).ID, ale wołający nie musi znać tej różnicy.
func (c *Client) OrgIDForPath(fullPath string) (string, error) {
	rootSlug := strings.SplitN(strings.Trim(fullPath, "/"), "/", 2)[0]
	root, err := c.resolveRootWorkspace(rootSlug)
	if err != nil {
		return "", err
	}
	return root.ID, nil
}

// resolveRootWorkspace — Workspaces (org root membership, ludzie) z
// fallbackiem na ServiceAccountSelf: service accounty NIGDY nie są
// membershipem org roota (tylko subgrupy), więc Workspaces zawsze zwróci dla
// nich pustą listę — bez tego fallbacku żaden dostęp do sekretów po
// service-account loginie nie mógłby rozwiązać ścieżki grupy do organizacji.
// ServiceAccountSelf zwraca błąd (zignorowany tu) dla zwykłej sesji
// człowieka, więc nie ma ryzyka fałszywego dopasowania.
func (c *Client) resolveRootWorkspace(rootSlug string) (Workspace, error) {
	workspaces, err := c.Workspaces()
	if err != nil {
		return Workspace{}, fmt.Errorf("list workspaces: %w", err)
	}
	for _, w := range workspaces {
		if w.FullPath == rootSlug {
			return w, nil
		}
	}
	if self, err := c.ServiceAccountSelf(); err == nil && self.OrgFullPath == rootSlug {
		return Workspace{ID: self.OrgID, Slug: self.OrgSlug, Name: self.OrgName, FullPath: self.OrgFullPath}, nil
	}
	return Workspace{}, fmt.Errorf("unknown organization %q", rootSlug)
}

// ── Audit log (kto odczytał/zmienił który sekret, password-manager
// tasks/todo/047/061) — opt-in per organizacja, próg admin+ na org roocie
// (jak SSO config/reszta "danger zone" ustawień organizacji). ───────────────

// GetAuditSettings — GET /g/{orgID}/audit-settings. 403 dla non-admin.
func (c *Client) GetAuditSettings(orgID string) (enabled bool, err error) {
	var out struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.do(http.MethodGet, "/g/"+url.PathEscape(orgID)+"/audit-settings", nil, &out); err != nil {
		return false, err
	}
	return out.Enabled, nil
}

// SetAuditSettings — PATCH /g/{orgID}/audit-settings {enabled}.
func (c *Client) SetAuditSettings(orgID string, enabled bool) error {
	return c.do(http.MethodPatch, "/g/"+url.PathEscape(orgID)+"/audit-settings", map[string]bool{
		"enabled": enabled,
	}, nil)
}

// AuditLogEntry — jeden wpis z GET /g/{orgID}/audit-log
// (group.AuditLogEntryView w password-manager). Metadata dziś niesie
// wyłącznie "title" (tytuł sekretu w momencie akcji, przeżywa rename/delete),
// ale to dowolna mapa — nowe akcje mogą dorzucić więcej pól bez zmiany
// kształtu tego structa.
type AuditLogEntry struct {
	Seq         int64          `json:"seq"`
	OccurredAt  time.Time      `json:"occurred_at"`
	Action      string         `json:"action"`
	TargetType  string         `json:"target_type"`
	TargetID    string         `json:"target_id"`
	Metadata    map[string]any `json:"metadata"`
	ActorUserID string         `json:"actor_user_id,omitempty"`
	ActorEmail  string         `json:"actor_email,omitempty"`
}

// AuditLogFilter — pola puste/zero są ignorowane (brak filtra) po stronie
// serwera. Dokładnie jedno z SecretID/UserID ma sens naraz w praktyce
// (historia jednego sekretu vs. co robił jeden user).
type AuditLogFilter struct {
	SecretID  string
	UserID    string
	BeforeSeq int64 // paginacja "starsze niż" — seq ostatniego wpisu poprzedniej strony
	Limit     int   // 0 = domyślne 50 po stronie serwera
}

// GetAuditLog — GET /g/{orgID}/audit-log, strona wpisów malejąco wg seq
// (najnowsze pierwsze).
func (c *Client) GetAuditLog(orgID string, filter AuditLogFilter) ([]AuditLogEntry, error) {
	q := url.Values{}
	if filter.SecretID != "" {
		q.Set("secret_id", filter.SecretID)
	}
	if filter.UserID != "" {
		q.Set("user_id", filter.UserID)
	}
	if filter.BeforeSeq > 0 {
		q.Set("before_seq", fmt.Sprintf("%d", filter.BeforeSeq))
	}
	if filter.Limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", filter.Limit))
	}
	path := "/g/" + url.PathEscape(orgID) + "/audit-log"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var out []AuditLogEntry
	if err := c.do(http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}
