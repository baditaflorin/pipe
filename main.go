// pipe — ephemeral, unauthenticated cross-machine copy/paste relay.
//
// The whole point: move a blob of text between two Linux machines with
// nothing installed but curl, and have it auto-expire. Think transfer.sh /
// 0x0.st / termbin, but held in RAM with a hard ≤5-minute TTL.
//
//	# machine A — push stdin, get back a URL
//	some-command 2>&1 | curl --data-binary @- https://pipe.0exec.com
//	# → https://pipe.0exec.com/Xq7k2aPb
//
//	# machine B — pull the raw bytes (within the TTL)
//	curl https://pipe.0exec.com/Xq7k2aPb
//
//	# or target a named slot, then read it by the same name
//	... | curl --data-binary @- https://pipe.0exec.com/my-slot
//	curl https://pipe.0exec.com/my-slot
//
//	# one-time secret: deleted on first read
//	... | curl --data-binary @- 'https://pipe.0exec.com?burn=1'
//
// Endpoints:
//
//	GET  /                 → usage text for curl; in-page encrypt/decrypt app
//	                         for browsers (GET /?shell=1 → sourceable bash/zsh
//	                         helper; GET /?app=1 → force the browser app)
//	POST|PUT /             → store body, 201 + URL of a random id
//	POST|PUT /{name}       → store body in a named slot, 201 + URL
//	GET  /{id}             → 200 raw body (text/plain) | 404 if gone/expired
//	DELETE /{id}           → 204 (best-effort early delete)
//	GET  /selftest         → 200 if the in-process put/get/burn roundtrip holds
//
// Deliberately public: there is no token. Security comes from unguessable
// random ids + a short TTL + opt-in burn-after-read. See README.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	ServiceID = "pipe"
	Version   = "0.6.0"
)

func main() {
	maxTTL := capDuration(envDuration("PIPE_MAX_TTL", 5*time.Minute), 5*time.Minute)
	maxBytes := int64(envInt("PIPE_MAX_BODY_BYTES", 10<<20)) // 10 MiB per blob
	store := NewStore(StoreConfig{
		MaxEntries:    envInt("PIPE_MAX_ENTRIES", 4096),
		MaxBytes:      maxBytes,
		MaxTotalBytes: int64(envInt("PIPE_MAX_TOTAL_BYTES", 512<<20)), // 512 MiB RAM budget
		MaxTTL:        maxTTL,
	})
	store.StartJanitor(30 * time.Second)

	h := &Handlers{
		Store:    store,
		MaxBytes: maxBytes,
		MaxTTL:   maxTTL,
		BaseURL:  envString("PIPE_PUBLIC_BASE_URL", ""), // "" = derive from request
		Limiter:  NewRateLimiter(envInt("PIPE_WRITES_PER_MIN", 60), time.Minute),
		Version:  Version,
	}
	trustProxy = isTrue(os.Getenv("PIPE_TRUST_PROXY"))

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"service": ServiceID, "version": Version})
	})
	mux.HandleFunc("/", h.Root)
	mux.HandleFunc("/selftest", h.Selftest)
	mux.HandleFunc("/install", h.Install) // richer client: wormhole + clipboard
	mux.HandleFunc("/shell", h.Shell)     // query-free `p` helper (zsh-safe, no ? to quote)

	addr := envString("PIPE_ADDR", ":"+envString("PORT", "18272"))
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute, // a 10 MiB upload over a slow link
		WriteTimeout:      2 * time.Minute, // longer than a read-receipt long-poll (about 25 s)
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()
	log.Printf("%s %s listening on %s", ServiceID, Version, addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
	}
}

func capDuration(d, max time.Duration) time.Duration {
	if d <= 0 || d > max {
		return max
	}
	return d
}

func envString(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(k))); err == nil {
		return v
	}
	return def
}

func envDuration(k string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(strings.TrimSpace(os.Getenv(k))); err == nil {
		return v
	}
	return def
}
