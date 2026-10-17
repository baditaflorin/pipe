package main

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Handlers carries the request-handling dependencies.
type Handlers struct {
	Store    *Store
	Limiter  *RateLimiter
	MaxBytes int64
	MaxTTL   time.Duration
	BaseURL  string // when non-empty, overrides per-request base derivation
	Version  string
}

// Root is the catch-all. main mounts /health and /version as exact
// patterns that win over this "/" handler.
func (h *Handlers) Root(w http.ResponseWriter, r *http.Request) {
	name := strings.Trim(r.URL.Path, "/")

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if name == "" {
			h.usage(w, r)
			return
		}
		h.serve(w, r, name)
	case http.MethodPost, http.MethodPut:
		h.create(w, r, name)
	case http.MethodDelete:
		h.Store.Delete(name)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, POST, PUT, DELETE")
		httpError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handlers) create(w http.ResponseWriter, r *http.Request, name string) {
	// A name with an embedded slash means a multi-segment path — unsupported.
	if strings.Contains(name, "/") {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	if name != "" {
		if reserved[name] {
			httpError(w, http.StatusConflict, "reserved name")
			return
		}
		if !validName.MatchString(name) {
			httpError(w, http.StatusBadRequest, "invalid name: use [A-Za-z0-9._-], 1-128 chars, leading alnum")
			return
		}
	}

	if !h.Limiter.Allow(clientIP(r)) {
		w.Header().Set("Retry-After", "60")
		httpError(w, http.StatusTooManyRequests, "rate limited: too many writes, slow down")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.MaxBytes))
	if err != nil {
		httpError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("body too large (max %d bytes)", h.MaxBytes))
		return
	}
	if len(body) == 0 {
		httpError(w, http.StatusBadRequest, "empty body — pipe something in: `... | curl --data-binary @- <url>`")
		return
	}

	q := r.URL.Query()
	opts := PutOpts{
		TTL:     h.parseTTL(r),
		Burn:    isTrue(q.Get("burn")),
		Replace: isTrue(q.Get("replace")), // last-write-wins named slot (clipboard)
		Notify:  isTrue(q.Get("notify")),  // arm a read-receipt
	}
	if opts.Notify {
		opts.WatchToken = newWatchToken()
	}

	var id string
	switch {
	case name != "":
		id, err = name, h.Store.Put(name, body, opts)
	case isTrue(q.Get("words")):
		id, err = h.Store.PutWords(body, opts) // say-it-out-loud id
	default:
		id, err = h.Store.PutRandom(body, opts, idLen)
	}
	switch err {
	case nil:
		// ok
	case ErrExists:
		w.Header().Set("Retry-After", strconv.Itoa(int(h.MaxTTL.Seconds())))
		httpError(w, http.StatusConflict, "name already taken — wait for it to expire or pick another")
		return
	case ErrFull:
		w.Header().Set("Retry-After", "30")
		httpError(w, http.StatusTooManyRequests, "store full — retry shortly")
		return
	default:
		httpError(w, http.StatusInternalServerError, "store error")
		return
	}

	url := h.base(r) + "/" + id

	// ?notify — hand the creator a private watch URL for the read-receipt.
	if opts.Notify {
		w.Header().Set("X-Pipe-Watch", url+"?watch="+opts.WatchToken)
	}

	// ?qr — hand back a scannable code for the new link instead of bare text.
	if f := qrFormat(r); f != "" {
		if f == "png" {
			writeQR(w, "png", url)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Pipe-Expires-In", strconv.Itoa(int(opts.TTL.Seconds())))
		if opts.Burn {
			w.Header().Set("X-Pipe-Burn", "1")
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, qrTextString(url))
		fmt.Fprintln(w, url)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Pipe-Expires-In", strconv.Itoa(int(opts.TTL.Seconds())))
	if opts.Burn {
		w.Header().Set("X-Pipe-Burn", "1")
	}
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, url)
}

func (h *Handlers) serve(w http.ResponseWriter, r *http.Request, id string) {
	if strings.Contains(id, "/") {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	// ?watch — read-receipt long-poll (read-only; never consumes a burn entry).
	if r.URL.Query().Get("watch") != "" {
		h.watch(w, r, id)
		return
	}
	// ?qr — return a scannable code for THIS link (not the stored bytes).
	if f := qrFormat(r); f != "" {
		writeQR(w, f, h.base(r)+"/"+id)
		return
	}
	data, ok := h.Store.Get(id)
	if !ok {
		httpError(w, http.StatusNotFound, "not found — wrong id, already burned, or expired")
		return
	}
	// Never let a browser sniff this into HTML/JS — it's untrusted bytes from
	// an anonymous writer. Always inline text, never executable.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(data)
}

// parseTTL reads ?ttl=<seconds>, clamped to (0, MaxTTL]; default MaxTTL.
func (h *Handlers) parseTTL(r *http.Request) time.Duration {
	q := r.URL.Query().Get("ttl")
	if q == "" {
		return h.MaxTTL
	}
	secs, err := strconv.Atoi(q)
	if err != nil || secs <= 0 {
		return h.MaxTTL
	}
	ttl := time.Duration(secs) * time.Second
	if ttl > h.MaxTTL {
		return h.MaxTTL
	}
	return ttl
}

// base returns the public origin (scheme://host) for building returned URLs.
// Prefers an explicit override, else derives from the gateway-forwarded
// headers, else the request Host.
func (h *Handlers) base(r *http.Request) string {
	if h.BaseURL != "" {
		return strings.TrimRight(h.BaseURL, "/")
	}
	scheme := "https"
	if xf := r.Header.Get("X-Forwarded-Proto"); xf != "" {
		scheme = xf
	} else if r.TLS == nil {
		scheme = "http"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host
}

func (h *Handlers) usage(w http.ResponseWriter, r *http.Request) {
	base := h.base(r)
	w.Header().Set("Cache-Control", "no-store")
	// Sourceable shell helper takes precedence (so `curl .../?shell=1` works
	// from a browser-y client too).
	if isTrue(r.URL.Query().Get("shell")) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, shellHelper(base))
		return
	}
	// A browser gets the in-page encrypt/decrypt app; curl & friends get the
	// plain-text usage. This HTML is our own trusted content (no user bytes),
	// so serving text/html here is safe — the /{id} read path stays nosniff'd.
	if wantsHTML(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Referrer-Policy", "no-referrer")
		fmt.Fprint(w, appHTML)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, strings.ReplaceAll(usageText, "{{B}}", base))
}

// Shell serves the sourceable `p` helper at a query-free path (/shell), so
// `eval "$(curl -s {{B}}/shell)"` needs no quoting — zsh globs the `?` in the
// older `/?shell=1` form and dies with "no matches found".
func (h *Handlers) Shell(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, shellHelper(h.base(r)))
}
