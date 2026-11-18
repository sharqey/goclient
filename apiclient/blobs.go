package apiclient

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Sekrety typu "file" (password-manager tasks/todo/075). Zaszyfrowane bajty
// pliku idą NIE przez API, tylko na URL zwrócony przez API (presigned S3 albo
// podpisany endpoint serwera — klient nie wie który i nie musi). Kryptografia:
// pakiet filesecret.

// PresignedRequest — gotowy request do uploadu/downloadu bloba. Wykonuj go
// DOKŁADNIE z podanymi nagłówkami i NIGDY z tokenem Sharqey (URL może
// wskazywać na obcy host, np. S3).
type PresignedRequest struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers,omitempty"`
	ExpiresAt time.Time         `json:"expires_at"`
}

type BlobUpload struct {
	BlobID string           `json:"blob_id"`
	Upload PresignedRequest `json:"upload"`
}

// CreateBlob — POST /g/{groupID}/blobs {size}: rejestruje blob i zwraca URL
// do uploadu. size to rozmiar ZASZYFROWANEGO bloba.
func (c *Client) CreateBlob(groupID string, size int64) (*BlobUpload, error) {
	var out BlobUpload
	if err := c.do(http.MethodPost, "/g/"+url.PathEscape(groupID)+"/blobs", map[string]int64{"size": size}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type FileDownload struct {
	Download PresignedRequest `json:"download"`
	Size     int64            `json:"size"`
}

// FileDownloadURL — GET /g/{groupID}/secrets/{secretID}/file.
func (c *Client) FileDownloadURL(groupID, secretID string) (*FileDownload, error) {
	var out FileDownload
	path := "/g/" + url.PathEscape(groupID) + "/secrets/" + url.PathEscape(secretID) + "/file"
	if err := c.do(http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DoPresigned wykonuje PresignedRequest (upload gdy body != nil) bez
// nagłówka Authorization.
func (c *Client) DoPresigned(p PresignedRequest, body []byte) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(p.Method, p.URL, rd)
	if err != nil {
		return nil, err
	}
	for k, v := range p.Headers {
		if http.CanonicalHeaderKey(k) == "Content-Length" {
			continue // net/http ustawia go sam z długości body
		}
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOffline, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s blob: HTTP %d: %s", p.Method, resp.StatusCode, truncate(string(out), 300))
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
