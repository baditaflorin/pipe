package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

// SelftestCheck is one named gate in the selftest pipeline.
type SelftestCheck struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

// Selftest exercises the real handler end-to-end (create → read → burn →
// expire → caps) against an in-process httptest server, so the deploy smoke
// gate verifies the code path, not just that the binary booted. 200 = all
// green, 503 = any check failed.
func (h *Handlers) Selftest(w http.ResponseWriter, _ *http.Request) {
	checks, ok := runSelftest()
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": ok, "service": ServiceID, "version": Version, "checks": checks,
	})
}

func runSelftest() ([]SelftestCheck, bool) {
	var checks []SelftestCheck
	pass := func(n string) { checks = append(checks, SelftestCheck{Name: n, Pass: true}) }
	fail := func(n, d string) { checks = append(checks, SelftestCheck{Name: n, Pass: false, Detail: d}) }

	store := NewStore(StoreConfig{MaxEntries: 16, MaxBytes: 1 << 20, MaxTTL: 5 * time.Minute})
	h := &Handlers{Store: store, Limiter: NewRateLimiter(0, time.Minute), MaxBytes: 1 << 20, MaxTTL: 5 * time.Minute, Version: Version}
	ts := httptest.NewServer(http.HandlerFunc(h.Root))
	defer ts.Close()
	c := ts.Client()

	// 1) random put → 201 + URL; read back the bytes.
	id, body := "", "hello-pipe-selftest"
	if resp, err := c.Post(ts.URL+"/", "text/plain", strings.NewReader(body)); err != nil {
		fail("put-random", err.Error())
	} else {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 201 {
			fail("put-random", "expected 201, got "+resp.Status)
		} else {
			url := strings.TrimSpace(string(b))
			if i := strings.LastIndexByte(url, '/'); i >= 0 {
				id = url[i+1:]
			}
			pass("put-random")
		}
	}

	// 2) GET the id twice → both 200, body matches (multi-read default).
	if id != "" {
		for i, want := range []string{body, body} {
			if got, code := httpGet(c, ts.URL+"/"+id); code != 200 {
				fail("get-multi", "read failed, code "+http.StatusText(code))
				break
			} else if got != want {
				fail("get-multi", "body mismatch on read")
				break
			} else if i == 1 {
				pass("get-multi")
			}
		}
	}

	// 3) burn=1 → readable once, then 404.
	if resp, err := c.Post(ts.URL+"/?burn=1", "text/plain", strings.NewReader("one-time")); err == nil {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		bid := lastSeg(strings.TrimSpace(string(b)))
		if got, code := httpGet(c, ts.URL+"/"+bid); code != 200 || got != "one-time" {
			fail("burn-first-read", "first read should return the body")
		} else if _, code2 := httpGet(c, ts.URL+"/"+bid); code2 != 404 {
			fail("burn-second-read", "second read should be 404")
		} else {
			pass("burn")
		}
	} else {
		fail("burn", err.Error())
	}

	// 4) named slot is write-once while live → second PUT is 409.
	if _, code := httpPut(c, ts.URL+"/slot-selftest", "v1"); code != 201 {
		fail("named-put", "first named put should be 201")
	} else if _, code2 := httpPut(c, ts.URL+"/slot-selftest", "v2"); code2 != 409 {
		fail("named-conflict", "second named put should be 409")
	} else {
		pass("named-write-once")
	}

	// 5) reserved name rejected; invalid name rejected; empty body rejected.
	if _, code := httpPut(c, ts.URL+"/health", "x"); code != 409 {
		fail("reserved-name", "claiming 'health' should be 409")
	} else {
		pass("reserved-name")
	}
	if resp, err := c.Post(ts.URL+"/", "text/plain", strings.NewReader("")); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode != 400 {
			fail("empty-body", "empty body should be 400")
		} else {
			pass("empty-body")
		}
	}

	// 6) TTL expiry via injected clock — put, jump past expiry, expect gone.
	{
		st := NewStore(StoreConfig{MaxEntries: 4, MaxBytes: 1 << 20, MaxTTL: time.Minute})
		base := time.Now()
		st.now = func() time.Time { return base }
		_ = st.Put("k", []byte("v"), PutOpts{TTL: time.Minute})
		st.now = func() time.Time { return base.Add(2 * time.Minute) }
		if _, ok := st.Get("k"); ok {
			fail("ttl-expiry", "entry should be gone after TTL")
		} else {
			pass("ttl-expiry")
		}
	}

	// 7) replace slot is last-write-wins; word-code ids resolve; byte budget caps.
	{
		st := NewStore(StoreConfig{MaxEntries: 8, MaxBytes: 1 << 20, MaxTotalBytes: 1 << 20, MaxTTL: time.Minute})
		_ = st.Put("clip", []byte("v1"), PutOpts{TTL: time.Minute, Replace: true})
		if err := st.Put("clip", []byte("v2"), PutOpts{TTL: time.Minute, Replace: true}); err != nil {
			fail("replace-slot", "replace write should succeed: "+err.Error())
		} else if got, ok := st.Get("clip"); !ok || string(got) != "v2" {
			fail("replace-slot", "replace should return the newest value")
		} else {
			pass("replace-slot")
		}
		if wid, err := st.PutWords([]byte("w"), PutOpts{TTL: time.Minute}); err != nil || strings.Count(wid, "-") != 3 {
			fail("word-code", "expected a 4-word id, got "+wid)
		} else if got, ok := st.Get(wid); !ok || string(got) != "w" {
			fail("word-code", "word-code id should round-trip")
		} else {
			pass("word-code")
		}
		if err := st.Put("big", make([]byte, (1<<20)+1), PutOpts{TTL: time.Minute}); err != ErrFull {
			fail("byte-budget", "over-budget write should be ErrFull")
		} else {
			pass("byte-budget")
		}
	}

	allPass := true
	for _, c := range checks {
		if !c.Pass {
			allPass = false
		}
	}
	return checks, allPass
}

func httpGet(c *http.Client, url string) (string, int) {
	resp, err := c.Get(url)
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode
}

func httpPut(c *http.Client, url, body string) (string, int) {
	req, _ := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	resp, err := c.Do(req)
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode
}

func lastSeg(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}
