package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestHandlers() *Handlers {
	return &Handlers{
		Store:    NewStore(StoreConfig{MaxEntries: 16, MaxBytes: 1 << 20, MaxTTL: 5 * time.Minute}),
		Limiter:  NewRateLimiter(0, time.Minute), // 0 = unlimited for tests
		MaxBytes: 1 << 20,
		MaxTTL:   5 * time.Minute,
		Version:  "test",
	}
}

func newTestServer() (*httptest.Server, *http.Client) {
	ts := httptest.NewServer(http.HandlerFunc(newTestHandlers().Root))
	return ts, ts.Client()
}

func do(t *testing.T, c *http.Client, method, url, body string) (string, int, http.Header) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode, resp.Header
}

func TestRandomPushPull(t *testing.T) {
	ts, c := newTestServer()
	defer ts.Close()

	body, code, _ := do(t, c, http.MethodPost, ts.URL+"/", "payload-bytes")
	if code != http.StatusCreated {
		t.Fatalf("push code = %d, want 201", code)
	}
	url := strings.TrimSpace(body)
	if !strings.HasPrefix(url, ts.URL+"/") {
		t.Fatalf("returned url %q has unexpected base", url)
	}

	got, code, _ := do(t, c, http.MethodGet, url, "")
	if code != http.StatusOK || got != "payload-bytes" {
		t.Fatalf("pull = %q,%d want payload-bytes,200", got, code)
	}
}

func TestEmptyBodyRejected(t *testing.T) {
	ts, c := newTestServer()
	defer ts.Close()
	_, code, _ := do(t, c, http.MethodPost, ts.URL+"/", "")
	if code != http.StatusBadRequest {
		t.Fatalf("empty body code = %d, want 400", code)
	}
}

func TestNamedSlotWriteOnce(t *testing.T) {
	ts, c := newTestServer()
	defer ts.Close()
	if _, code, _ := do(t, c, http.MethodPut, ts.URL+"/my-slot", "v1"); code != http.StatusCreated {
		t.Fatalf("first named put = %d, want 201", code)
	}
	if _, code, _ := do(t, c, http.MethodPut, ts.URL+"/my-slot", "v2"); code != http.StatusConflict {
		t.Fatalf("second named put = %d, want 409", code)
	}
	got, code, _ := do(t, c, http.MethodGet, ts.URL+"/my-slot", "")
	if code != http.StatusOK || got != "v1" {
		t.Fatalf("named read = %q,%d want v1,200", got, code)
	}
}

func TestReservedNameRejected(t *testing.T) {
	ts, c := newTestServer()
	defer ts.Close()
	if _, code, _ := do(t, c, http.MethodPut, ts.URL+"/health", "x"); code != http.StatusConflict {
		t.Fatalf("reserved name code = %d, want 409", code)
	}
}

func TestInvalidNameRejected(t *testing.T) {
	ts, c := newTestServer()
	defer ts.Close()
	// Leading dot violates the "leading alnum" rule.
	if _, code, _ := do(t, c, http.MethodPut, ts.URL+"/.hidden", "x"); code != http.StatusBadRequest {
		t.Fatalf("invalid name code = %d, want 400", code)
	}
}

func TestBurnOnceThen404(t *testing.T) {
	ts, c := newTestServer()
	defer ts.Close()
	body, code, hdr := do(t, c, http.MethodPost, ts.URL+"/?burn=1", "one-time")
	if code != http.StatusCreated {
		t.Fatalf("burn push code = %d, want 201", code)
	}
	if hdr.Get("X-Pipe-Burn") != "1" {
		t.Fatalf("X-Pipe-Burn header = %q, want 1", hdr.Get("X-Pipe-Burn"))
	}
	url := strings.TrimSpace(body)
	if got, code, _ := do(t, c, http.MethodGet, url, ""); code != http.StatusOK || got != "one-time" {
		t.Fatalf("first burn read = %q,%d want one-time,200", got, code)
	}
	if _, code, _ := do(t, c, http.MethodGet, url, ""); code != http.StatusNotFound {
		t.Fatalf("second burn read = %d, want 404", code)
	}
}

func TestServeSetsSafeHeaders(t *testing.T) {
	ts, c := newTestServer()
	defer ts.Close()
	body, _, _ := do(t, c, http.MethodPost, ts.URL+"/", "data")
	url := strings.TrimSpace(body)
	_, code, hdr := do(t, c, http.MethodGet, url, "")
	if code != http.StatusOK {
		t.Fatalf("serve code = %d, want 200", code)
	}
	if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
	if nosniff := hdr.Get("X-Content-Type-Options"); nosniff != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", nosniff)
	}
}

func TestMissingIDIs404(t *testing.T) {
	ts, c := newTestServer()
	defer ts.Close()
	if _, code, _ := do(t, c, http.MethodGet, ts.URL+"/does-not-exist", ""); code != http.StatusNotFound {
		t.Fatalf("missing id code = %d, want 404", code)
	}
}

func TestDeleteRemovesEntry(t *testing.T) {
	ts, c := newTestServer()
	defer ts.Close()
	body, _, _ := do(t, c, http.MethodPost, ts.URL+"/", "delete-me")
	url := strings.TrimSpace(body)
	if _, code, _ := do(t, c, http.MethodDelete, url, ""); code != http.StatusNoContent {
		t.Fatalf("delete code = %d, want 204", code)
	}
	if _, code, _ := do(t, c, http.MethodGet, url, ""); code != http.StatusNotFound {
		t.Fatalf("read after delete = %d, want 404", code)
	}
}

func TestBodyTooLarge(t *testing.T) {
	h := newTestHandlers()
	h.MaxBytes = 8
	ts := httptest.NewServer(http.HandlerFunc(h.Root))
	defer ts.Close()
	c := ts.Client()
	if _, code, _ := do(t, c, http.MethodPost, ts.URL+"/", "this body is way over eight bytes"); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body code = %d, want 413", code)
	}
}

func TestUsageServedOnRoot(t *testing.T) {
	ts, c := newTestServer()
	defer ts.Close()
	got, code, _ := do(t, c, http.MethodGet, ts.URL+"/", "")
	if code != http.StatusOK {
		t.Fatalf("usage code = %d, want 200", code)
	}
	if !strings.Contains(got, "curl --data-binary @-") {
		t.Fatalf("usage text missing the canonical push example")
	}
	if strings.Contains(got, "{{B}}") {
		t.Fatalf("usage text still has an unsubstituted {{B}} placeholder")
	}
}

func TestShellHelperServed(t *testing.T) {
	ts, c := newTestServer()
	defer ts.Close()
	got, code, _ := do(t, c, http.MethodGet, ts.URL+"/?shell=1", "")
	if code != http.StatusOK {
		t.Fatalf("shell helper code = %d, want 200", code)
	}
	if !strings.Contains(got, "p()") {
		t.Fatalf("shell helper missing the p() function")
	}
}

// getAccept issues GET url with a specific Accept header and returns
// (body, status, contentType).
func getAccept(t *testing.T, c *http.Client, url, accept string) (string, int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode, resp.Header.Get("Content-Type")
}

func TestRootContentNegotiation(t *testing.T) {
	ts, c := newTestServer()
	defer ts.Close()

	// Browser (Accept: text/html) → HTML app.
	body, code, ct := getAccept(t, c, ts.URL+"/", "text/html,application/xhtml+xml")
	if code != http.StatusOK {
		t.Fatalf("browser GET / = %d, want 200", code)
	}
	if !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("browser Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(body, "<!doctype html>") || !strings.Contains(body, "AES-CTR") {
		t.Fatalf("browser response is not the encrypt/decrypt app")
	}

	// curl (Accept: */*) → plain-text usage.
	body, _, ct = getAccept(t, c, ts.URL+"/", "*/*")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("curl Content-Type = %q, want text/plain", ct)
	}
	if !strings.Contains(body, "curl --data-binary @-") {
		t.Fatalf("curl response is not the plain usage text")
	}

	// ?app=1 forces HTML even for a curl-y Accept.
	if _, _, ct = getAccept(t, c, ts.URL+"/?app=1", "*/*"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("?app=1 Content-Type = %q, want text/html", ct)
	}

	// ?raw=1 forces plain text even for a browser Accept.
	if _, _, ct = getAccept(t, c, ts.URL+"/?raw=1", "text/html"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("?raw=1 Content-Type = %q, want text/plain", ct)
	}

	// ?shell=1 wins regardless of Accept, and stays text/plain.
	body, _, ct = getAccept(t, c, ts.URL+"/?shell=1", "text/html")
	if !strings.HasPrefix(ct, "text/plain") || !strings.Contains(body, "p()") {
		t.Fatalf("?shell=1 should serve the text/plain helper even to a browser")
	}
}

func TestWordCodeCreate(t *testing.T) {
	ts, c := newTestServer()
	defer ts.Close()
	body, code, _ := do(t, c, http.MethodPost, ts.URL+"/?words=1", "hi")
	if code != http.StatusCreated {
		t.Fatalf("words push = %d, want 201", code)
	}
	url := strings.TrimSpace(body)
	id := url[strings.LastIndexByte(url, '/')+1:]
	if strings.Count(id, "-") != 3 {
		t.Fatalf("word-code id %q should have 4 words / 3 hyphens", id)
	}
	if got, code, _ := do(t, c, http.MethodGet, url, ""); code != 200 || got != "hi" {
		t.Fatalf("word-code read = %q,%d want hi,200", got, code)
	}
}

func TestReplaceSlotOverwrites(t *testing.T) {
	ts, c := newTestServer()
	defer ts.Close()
	if _, code, _ := do(t, c, http.MethodPut, ts.URL+"/clip?replace=1", "v1"); code != http.StatusCreated {
		t.Fatalf("first replace put = %d, want 201", code)
	}
	if _, code, _ := do(t, c, http.MethodPut, ts.URL+"/clip?replace=1", "v2"); code != http.StatusCreated {
		t.Fatalf("second replace put = %d, want 201 (not 409)", code)
	}
	if got, _, _ := do(t, c, http.MethodGet, ts.URL+"/clip", ""); got != "v2" {
		t.Fatalf("replace read = %q, want v2", got)
	}
	// Without ?replace it stays write-once → 409.
	if _, code, _ := do(t, c, http.MethodPut, ts.URL+"/clip", "v3"); code != http.StatusConflict {
		t.Fatalf("non-replace put over live slot = %d, want 409", code)
	}
}

func TestQRCreateAndServe(t *testing.T) {
	ts, c := newTestServer()
	defer ts.Close()
	// POST ?qr=1 → 201 with the QR art followed by the URL.
	body, code, hdr := do(t, c, http.MethodPost, ts.URL+"/?qr=1", "hi")
	if code != http.StatusCreated || !strings.HasPrefix(hdr.Get("Content-Type"), "text/plain") {
		t.Fatalf("qr create = %d/%s, want 201/text", code, hdr.Get("Content-Type"))
	}
	if !strings.Contains(body, "█") || !strings.Contains(body, ts.URL+"/") {
		t.Fatalf("qr create body should contain QR blocks and the URL")
	}
	// GET /{id}?qr=png → image/png.
	if _, _, hdr := do(t, c, http.MethodGet, ts.URL+"/anyid?qr=png", ""); hdr.Get("Content-Type") != "image/png" {
		t.Fatalf("qr png Content-Type = %q, want image/png", hdr.Get("Content-Type"))
	}
}

func TestReadReceipt(t *testing.T) {
	ts, c := newTestServer()
	defer ts.Close()
	// Create with ?notify=1 — the watch URL comes back in a header.
	body, code, hdr := do(t, c, http.MethodPost, ts.URL+"/?notify=1", "secret")
	if code != http.StatusCreated {
		t.Fatalf("notify push = %d, want 201", code)
	}
	watch := hdr.Get("X-Pipe-Watch")
	if !strings.Contains(watch, "?watch=") {
		t.Fatalf("missing X-Pipe-Watch header, got %q", watch)
	}
	url := strings.TrimSpace(body)

	// Wrong watch token → 403.
	if _, code, _ := do(t, c, http.MethodGet, url+"?watch=wrong", ""); code != http.StatusForbidden {
		t.Fatalf("bad-token watch = %d, want 403", code)
	}
	// Read it once (marks read), then the watch returns read:true immediately
	// (so the test never hits the 25s long-poll).
	if got, _, _ := do(t, c, http.MethodGet, url, ""); got != "secret" {
		t.Fatalf("read = %q, want secret", got)
	}
	rb, code, _ := do(t, c, http.MethodGet, watch, "")
	if code != http.StatusOK || !strings.Contains(rb, `"read":true`) {
		t.Fatalf("watch after read = %q,%d want read:true,200", rb, code)
	}
	// Watching a non-notify id reports gone.
	plain, _, _ := do(t, c, http.MethodPost, ts.URL+"/", "x")
	pid := strings.TrimSpace(plain)
	if rb, code, _ := do(t, c, http.MethodGet, pid+"?watch=anything", ""); code != http.StatusNotFound || !strings.Contains(rb, `"gone":true`) {
		t.Fatalf("watch non-notify = %q,%d want gone:true,404", rb, code)
	}
}

func TestShellPathServesHelper(t *testing.T) {
	h := newTestHandlers()
	req := httptest.NewRequest(http.MethodGet, "/shell", nil)
	rec := httptest.NewRecorder()
	h.Shell(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/shell code = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("/shell Content-Type = %q, want text/plain", ct)
	}
	if !strings.Contains(rec.Body.String(), "p()") {
		t.Fatalf("/shell did not serve the p() helper")
	}
}

func TestSelftestGreen(t *testing.T) {
	checks, ok := runSelftest()
	if !ok {
		for _, c := range checks {
			if !c.Pass {
				t.Errorf("selftest check %q failed: %s", c.Name, c.Detail)
			}
		}
		t.Fatal("runSelftest reported not-ok")
	}
}

// shellRun sources the served helper into bash against a live test server and runs script.
func shellRun(t *testing.T, base, dir, script string) (string, string, error) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("no openssl")
	}
	cmd := exec.Command(bash, "-c", `eval "$(curl -s "$PIPE_URL/shell")"; `+script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PIPE_URL="+base)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	return out.String(), errb.String(), err
}

// A file sent with -f carries its name, size and sha256 sealed inside the payload: the server
// never sees the name, `p save` restores it, and `p open` still prints the bytes.
func TestShellHelperSealsFileMetadata(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl")
	}
	h := newTestHandlers()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/shell" {
			h.Shell(w, r)
			return
		}
		h.Root(w, r)
	}))
	defer ts.Close()
	dir := t.TempDir()
	content := []byte("\x00\x01binary\xffbytes\nwith a newline\n")
	if err := os.WriteFile(filepath.Join(dir, "post-graphic.png"), content, 0o600); err != nil {
		t.Fatal(err)
	}

	link, serr, err := shellRun(t, ts.URL, dir, `p -e -f post-graphic.png`)
	if err != nil {
		t.Fatalf("p -e -f: %v\n%s", err, serr)
	}
	link = strings.TrimSpace(link)
	if !strings.Contains(link, "/#") || !strings.Contains(link, "~") {
		t.Fatalf("link %q", link)
	}
	h.Store.mu.Lock()
	for _, it := range h.Store.items {
		if strings.Contains(string(it.data), "post-graphic") {
			t.Error("the server holds the file name in the clear")
		}
		if raw, _ := base64.StdEncoding.DecodeString(string(it.data)); len(raw) == 0 || raw[0] != 3 {
			t.Errorf("envelope version = %v, want 3", raw[:1])
		}
	}
	h.Store.mu.Unlock()

	out, serr, err := shellRun(t, ts.URL, dir, `mkdir saved; p save '`+link+`' saved && p open '`+link+`' > opened.bin`)
	if err != nil {
		t.Fatalf("save/open: %v\n%s", err, serr)
	}
	if !strings.Contains(out, "saved/post-graphic.png") || !strings.Contains(serr, "name=post-graphic.png size=") {
		t.Errorf("save output %q, stderr %q", out, serr)
	}
	for _, f := range []string{"saved/post-graphic.png", "opened.bin"} {
		if b, err := os.ReadFile(filepath.Join(dir, f)); err != nil || !bytes.Equal(b, content) {
			t.Errorf("%s = %q, %v", f, b, err)
		}
	}
	// A second save refuses to replace the first; a missing source file uploads nothing.
	if _, serr, err := shellRun(t, ts.URL, dir, `p save '`+link+`' saved`); err == nil || !strings.Contains(serr, "not replacing") {
		t.Errorf("second save: %v %q", err, serr)
	}
	n := h.Store.Len()
	if _, _, err := shellRun(t, ts.URL, dir, `p -e -f missing.png`); err == nil || h.Store.Len() != n {
		t.Errorf("missing file: err=%v, stored %d->%d", err, n, h.Store.Len())
	}
}

// Without -f/-n nothing changes: version 1, so every older reader still opens it.
func TestShellHelperPlainEncryptStaysVersion1(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl")
	}
	h := newTestHandlers()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/shell" {
			h.Shell(w, r)
			return
		}
		h.Root(w, r)
	}))
	defer ts.Close()
	link, serr, err := shellRun(t, ts.URL, t.TempDir(), `echo plain | p -e`)
	if err != nil {
		t.Fatalf("%v %s", err, serr)
	}
	out, serr, err := shellRun(t, ts.URL, t.TempDir(), `p open '`+strings.TrimSpace(link)+`'`)
	if err != nil || out != "plain\n" || strings.Contains(serr, "file name=") {
		t.Errorf("open: %q %q %v", out, serr, err)
	}
	h.Store.mu.Lock()
	defer h.Store.mu.Unlock()
	for _, it := range h.Store.items {
		if raw, _ := base64.StdEncoding.DecodeString(string(it.data)); len(raw) == 0 || raw[0] != 1 {
			t.Errorf("envelope version = %v, want 1", raw[:1])
		}
	}
}

// The header is open: any key=value rides inside, is shown to the reader as data, and is never
// interpreted. Only name, size and sha256 mean anything to the helper.
func TestShellHelperCarriesArbitraryMetadata(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl")
	}
	h := newTestHandlers()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/shell" {
			h.Shell(w, r)
			return
		}
		h.Root(w, r)
	}))
	defer ts.Close()
	dir := t.TempDir()

	// Metadata with no file name at all, and values that need JSON escaping.
	link, serr, err := shellRun(t, ts.URL, dir,
		`echo payload | p -e -m kind=build -m 'note=say "hi" \ done' -m from=mba/claude.f360`)
	if err != nil {
		t.Fatalf("p -e -m: %v\n%s", err, serr)
	}
	out, serr, err := shellRun(t, ts.URL, dir, `p open '`+strings.TrimSpace(link)+`'`)
	if err != nil || out != "payload\n" {
		t.Fatalf("open: %q %q %v", out, serr, err)
	}
	for _, want := range []string{"pipe: meta kind=build", `pipe: meta note=say \"hi\" \\ done`, "pipe: meta from=mba/claude.f360"} {
		if !strings.Contains(serr, want) {
			t.Errorf("stderr missing %q:\n%s", want, serr)
		}
	}
	// The server holds only ciphertext: no key or value in the clear.
	h.Store.mu.Lock()
	for _, it := range h.Store.items {
		if strings.Contains(string(it.data), "build") || strings.Contains(string(it.data), "claude") {
			t.Error("the server holds metadata in the clear")
		}
	}
	h.Store.mu.Unlock()

	n := h.Store.Len()
	for name, script := range map[string]string{
		"bad key":      `echo x | p -e -m 'bad key=1'`,
		"reserved key": `echo x | p -e -m sha256=abc`,
		"too big":      `echo x | p -e -m big=` + strings.Repeat("a", 5000),
	} {
		if _, _, err := shellRun(t, ts.URL, dir, script); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if h.Store.Len() != n {
		t.Errorf("a refused metadata upload still stored something (%d -> %d)", n, h.Store.Len())
	}
}
