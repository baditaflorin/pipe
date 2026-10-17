# Changelog

## 0.6.0 — 2026-10-17

First public release. Earlier versions ran privately as the author's fleet relay; their history is not part of this
repository.

- Ephemeral, unauthenticated relay held in RAM with a hard 5-minute TTL: random ids, write-once named slots, `?burn=1`
  (read once), `?ttl=`, `?words` (say-it-out-loud ids), `?replace` (last-write-wins slots), `?qr` / `?qr=png`,
  `?notify=1` read receipts.
- End-to-end encryption in the shell helper (`p -e`) and the browser app: the key stays in the link's `#fragment`.
  Envelope version 3 seals a file's name, size and sha256 (and any `-m key=value` pairs) inside the ciphertext.
- No private dependencies: the server is the Go standard library and QR codes use github.com/skip2/go-qrcode (MIT).
- The per-IP write limit no longer trusts a client-sent `X-Forwarded-For`: the header is used only with
  `PIPE_TRUST_PROXY=1`, and then only its last entry (the one the proxy appended).
- `PIPE_ADDR` sets the listen address.
