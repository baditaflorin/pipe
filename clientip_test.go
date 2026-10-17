package main

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPTrustsOnlyTheProxysOwnEntry(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "203.0.113.7:5555"
	r.Header.Set("X-Forwarded-For", "198.51.100.1, 192.0.2.44")

	trustProxy = false
	if got := clientIP(r); got != "203.0.113.7" {
		t.Errorf("without PIPE_TRUST_PROXY the header must be ignored: %q", got)
	}
	trustProxy = true
	t.Cleanup(func() { trustProxy = false })
	if got := clientIP(r); got != "192.0.2.44" {
		t.Errorf("behind a proxy the last entry (the one it appended) counts, not the client's own: %q", got)
	}
	r.Header.Set("X-Forwarded-For", "192.0.2.9")
	if got := clientIP(r); got != "192.0.2.9" {
		t.Errorf("single entry: %q", got)
	}
}
