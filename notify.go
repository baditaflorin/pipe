package main

import (
	"fmt"
	"net/http"
	"time"
)

// Read-receipts (?notify) — find out the instant your link is opened.
//
//	# create with a receipt; the watch URL comes back in a header
//	WATCH=$(echo secret | curl -sD - --data-binary @- 'https://pipe.0exec.com/?notify=1' \
//	          | awk 'tolower($1)=="x-pipe-watch:"{print $2}' | tr -d "\r")
//	# block until someone reads it (long-poll, ~25s per call — loop if needed)
//	curl -s "$WATCH"      # → {"read":true,"readAt":"2026-..."}
//
// The magic: know the moment your secret was actually seen (and, with ?burn,
// that it was consumed). Only the creator can watch — the receipt is gated by
// a random watch token returned alongside the link, never derivable from the id.

const watchPoll = 25 * time.Second // long-poll budget per request (< typical 30s proxy idle)

func newWatchToken() string { return randID(16) }

// watch handles GET /{id}?watch=<token>: long-poll until the entry is first
// read, then report when. Read-only — it never consumes a burn entry.
func (h *Handlers) watch(w http.ResponseWriter, r *http.Request, id string) {
	token := r.URL.Query().Get("watch")
	storedToken, readAt, ch, ok := h.Store.ReadStatus(id)
	if !ok {
		// No armed+live entry: it was never notify-armed, already burned, or
		// expired. Tell the watcher it's gone so they stop polling.
		writeJSON(w, http.StatusNotFound, map[string]any{"read": false, "gone": true})
		return
	}
	if token == "" || token != storedToken {
		httpError(w, http.StatusForbidden, "wrong or missing watch token")
		return
	}
	if !readAt.IsZero() {
		writeJSON(w, http.StatusOK, map[string]any{"read": true, "readAt": readAt.UTC().Format(time.RFC3339)})
		return
	}
	// Not read yet — wait for the first read, a timeout, or client disconnect.
	select {
	case <-ch:
		_, ra, _, _ := h.Store.ReadStatus(id)
		if ra.IsZero() {
			ra = time.Now()
		}
		writeJSON(w, http.StatusOK, map[string]any{"read": true, "readAt": ra.UTC().Format(time.RFC3339)})
	case <-time.After(watchPoll):
		writeJSON(w, http.StatusOK, map[string]any{"read": false}) // poll again
	case <-r.Context().Done():
	}
}

func writeJSON(w http.ResponseWriter, code int, v map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	// Tiny hand-rolled object keeps this dependency-free and key-order stable.
	first := true
	_, _ = fmt.Fprint(w, "{")
	for _, k := range []string{"read", "readAt", "gone"} {
		val, present := v[k]
		if !present {
			continue
		}
		if !first {
			_, _ = fmt.Fprint(w, ",")
		}
		first = false
		switch x := val.(type) {
		case bool:
			_, _ = fmt.Fprintf(w, "%q:%t", k, x)
		default:
			_, _ = fmt.Fprintf(w, "%q:%q", k, fmt.Sprint(x))
		}
	}
	_, _ = fmt.Fprintln(w, "}")
}
