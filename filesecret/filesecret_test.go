package filesecret

import (
	"bytes"
	"testing"
)

func TestBlobRoundTrip(t *testing.T) {
	data := []byte("-----BEGIN CERT----- \x00\x01\xff binary")
	blob, key, err := EncryptBlob(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != 12+len(data)+16 {
		t.Fatalf("blob length %d, want IV+ct+tag", len(blob))
	}
	got, err := DecryptBlob(blob, key)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("round trip: %q %v", got, err)
	}
	blob[20] ^= 1
	if _, err := DecryptBlob(blob, key); err == nil {
		t.Fatal("tampered blob must fail")
	}
}

func TestMetadataVersion(t *testing.T) {
	if _, err := ParseMetadata(`{"v":2,"file_key":"aa"}`); err == nil {
		t.Fatal("unknown version must be rejected")
	}
	m := Metadata{V: FormatV1, Filename: "a.p12", Size: 3, FileKey: "ab"}
	back, err := ParseMetadata(m.JSON())
	if err != nil || back != m {
		t.Fatalf("%+v %v", back, err)
	}
}
