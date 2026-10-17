# pipe

**Website: https://baditaflorin.github.io/pipe/**

Ephemeral, unauthenticated cross-machine copy/paste relay. Move a blob of
text between two Linux machines with nothing installed but `curl`, and have
it auto-expire. Think `transfer.sh` / `0x0.st` / `termbin`, but held in RAM
with a hard **≤5-minute TTL**.

A public instance runs at **https://pipe.0exec.com** (run by the author, for anyone to use within its
limits); the server is one static Go binary, so you can run your own (see [Run your own](#run-your-own)).

## Quickstart

```bash
# machine A — push stdin, get back a URL
some-command 2>&1 | curl --data-binary @- https://pipe.0exec.com
# → https://pipe.0exec.com/Xq7k2aPb

# machine B — pull the raw bytes (within the TTL)
curl https://pipe.0exec.com/Xq7k2aPb
```

`--data-binary @-` streams stdin verbatim; plain `-d` would strip trailing
newlines and mangle the payload. The same `curl` lines work unchanged on
Linux and macOS, in `bash` and `zsh` — nothing to install.

Real, copy-pasteable examples:

```bash
# share your last command's output
dmesg | tail -50 | curl --data-binary @- https://pipe.0exec.com

# move a file between two boxes (no scp, no keys)
curl --data-binary @- https://pipe.0exec.com < report.txt        # machine A
curl https://pipe.0exec.com/Xq7k2aPb > report.txt                # machine B

# pipe a diff or a log for 5 minutes
git diff | curl --data-binary @- https://pipe.0exec.com
# anything secret: encrypt it first with the p helper (see "End-to-end encryption")
kubectl config view --raw | p -e
```

### Named slots

Target a name instead of a random id. Write-once while the slot is live:

```bash
# machine A
uname -a | curl --data-binary @- https://pipe.0exec.com/my-slot

# machine B
curl https://pipe.0exec.com/my-slot
```

A second write to a live name returns `409` — wait for it to expire or pick
another. An expired name is reclaimable.

### One-time secrets (burn-after-read)

```bash
echo 's3cr3t' | curl --data-binary @- 'https://pipe.0exec.com?burn=1'
# the first GET returns the body; the second is 404
```

### Shorter TTL

```bash
cmd | curl --data-binary @- 'https://pipe.0exec.com?ttl=60'   # 60s, capped at 300
```

### Say-it-out-loud links, QR codes, bigger files

```bash
# a link you can read over the phone (otter-maple-river-stone)
uname -a | curl --data-binary @- 'https://pipe.0exec.com/?words=1'

# push from a headless box, then scan the QR straight off your terminal
journalctl -n100 | curl --data-binary @- 'https://pipe.0exec.com/?qr=1'
curl 'https://pipe.0exec.com/Xq7k2aPb?qr'          # QR for an existing link
curl 'https://pipe.0exec.com/Xq7k2aPb?qr=png' > link.png

# files up to 10 MiB now (was 1 MiB)
curl --data-binary @- https://pipe.0exec.com < build.log
```

`?words` links are shorter to say but lower-entropy than the random 8-char ids,
so pair them with `?burn=1` or `-e` for anything sensitive.

### Shell helper

Drop a `p` function into your shell. Works in **bash and zsh, on Linux and
macOS** (the only dependency is `openssl`, which both ship). Put the `eval`
line in `~/.bashrc` or `~/.zshrc`:

```bash
eval "$(curl -s https://pipe.0exec.com/shell)"   # /shell has no '?', so no zsh quoting
cmd | p                      # push, prints the URL
cmd | p my-slot              # push to a named slot
p get my-slot                # pull a slot / id
cmd | p -e                   # END-TO-END ENCRYPT → prints .../#<id>~<key>
p open 'https://pipe.0exec.com/#Xq7k2aPb~2f9c…'   # pull + decrypt (quote it!)
```

> The `/shell` path is the same helper as `/?shell=1` but without the `?`, so
> zsh won't choke with `no matches found`. (`/?shell=1` still works if you
> quote the whole URL.)

Set `PIPE_URL` to point the helper at a different endpoint, or `PIPE_OPENSSL`
to pick a specific `openssl` binary (e.g. Homebrew's on macOS).

### End-to-end encryption — one flag: `-e`

`-e` encrypts the payload **on your machine** and uploads only ciphertext. The
decryption key travels in the URL's `#fragment`, which browsers and `curl`
**never send to the server**:

```bash
# machine A — encrypt locally, get a self-contained link
echo 'database password: hunter2' | p -e
# → https://pipe.0exec.com/#Xq7k2aPb~2f9c4e…   (the part after ~ is the key)

# machine B — open that link in ANY browser to decrypt in-page,
#             or pull + decrypt from the terminal:
p open 'https://pipe.0exec.com/#Xq7k2aPb~2f9c4e…'
```

Why the fragment matters: the `#…` part of a URL is handled entirely by the
client. It is **not** put on the wire — not to the server, not past any proxy.
So the server only ever stores ciphertext, and a passive eavesdropper (your
ISP, a coffee-shop AP, a logging proxy) never sees the key even if they record
every request. Links round-trip between the CLI and the browser: a link made
with `p -e` opens and decrypts in the browser app, and a link made in the
browser decrypts with `p open`.

Cipher: AES-256-CTR with HMAC-SHA256 (encrypt-then-MAC); a 256-bit key from
`crypto.getRandomValues` / `openssl rand`. A wrong key or any tampering fails
loudly instead of returning garbage.

Combine with `?burn=1` for a one-shot encrypted secret:

```bash
echo 'one-time token' | p -e        # the helper posts to a random id;
                                     # add burn at the source if you want:
echo 'one-time token' | PIPE_URL='https://pipe.0exec.com?burn=1' p -e
```

### Files that describe themselves — `p -e -f`

The encrypted payload can carry a header, so a link needs nothing passed on the side:

```bash
p -e -f post-graphic.png          # → https://pipe.0exec.com/#Xq7k2aPb~2f9c…
cmd | p -e -n build.log           # name piped data instead

cmd | p -e -m kind=build -m from=mba/claude.f360   # any key=value, with or without a file

p save 'https://pipe.0exec.com/#Xq7k2aPb~2f9c…' [dir]   # → dir/post-graphic.png
p open '…'                        # still prints the bytes (header on stderr)
```

**The header is open metadata.** `-m key=value` (repeatable; keys `[A-Za-z0-9_.-]`, up to 32
chars; the whole header is capped at 4 KiB) adds any pairs the sender wants, and any writer in any
language can put whatever JSON object it likes there. Only `name`, `size` and `sha256` mean
anything to the pipe's own readers, which verify them; every other key is the sender's data: the
helper prints it as `pipe: meta k=v` on stderr and the browser lists it, with control characters
stripped, and nothing is ever executed or acted on. What an agent does with a key is its own
decision, so conventions can evolve without changing the pipe or a message carrier such as
[AiVoiceBus](https://github.com/baditaflorin/aivoicebus) (which stays a plain carrier: send the link in the message text).

The file's name, size and sha256 are sealed **inside** the ciphertext (envelope version 3:
`base64( 0x03 | iv | mac | AES-CTR( uint32be(metaLen) | JSON | bytes ) )`, the same MAC as
version 1, so the header is authenticated and the server never sees it). Readers verify size and
checksum, `p save` never overwrites and strips any path from the name, and the browser page shows
the name, an image preview for png/jpg/gif/webp and a download button. Without `-f`/`-n` nothing changes (version 1). A client older than this feature rejects
version 3 ("not an encrypted pipe"), so use `-f`/`-n` only toward readers that have it.

### Encrypt with one line — no helper, nothing to install

Don't want to source anything? It's two lines, just `curl` + `openssl`
(both already on every Mac and Linux box). **Make up a password** and share
it however you'd share a password — that's the whole skill:

```bash
# SEND  (PASS = any password you choose)
echo 'my secret' | openssl enc -aes256 -pbkdf2 -k PASS | curl -s --data-binary @- https://pipe.0exec.com
# → prints a link, e.g. https://pipe.0exec.com/oCwOc4q4

# RECEIVE  (same PASS, on the other machine)
curl -s https://pipe.0exec.com/oCwOc4q4 | openssl enc -d -aes256 -pbkdf2 -k PASS
```

The server only ever sees a scrambled blob — never your text, never your
password. A wrong password just prints `bad decrypt`. To send a whole file,
add `-in photo.jpg` to the first `openssl`. To keep the password out of your
shell history, drop `-k PASS` and openssl will quietly prompt for it.

> **zsh tip:** if you ever see `zsh: no matches found`, it's the `?` in a
> URL being read as a wildcard — just wrap that URL in quotes, e.g.
> `curl -s 'https://pipe.0exec.com/?shell=1'`.

(This `openssl` blob is self-contained and decrypts with the line above; it
does **not** open in the browser app — for a click-to-decrypt browser link,
use `p -e`.)

### Browser app (no install)

Open <https://pipe.0exec.com> in a browser for a tiny in-page app: type a
message, leave **End-to-end encrypt** ticked, and it encrypts client-side and
hands you a `#`-fragment link. Opening any such link decrypts it in the page.
`curl` and scripts still get the plain-text usage page from `GET /` — the HTML
app is only served to browsers (or with `?app=1`).

### Know when it's read (`?notify`)

Find out the instant your link is opened (and, with `?burn`, that it was
consumed). The watch URL comes back in a header; reading it long-polls until
the entry is first read:

```bash
W=$(echo secret | curl -sD - --data-binary @- 'https://pipe.0exec.com/?notify=1' \
      | awk 'tolower($1)=="x-pipe-watch:"{print $2}' | tr -d '\r')
curl -s "$W"      # blocks (~25s/call); → {"read":true,"readAt":"2026-…"} when opened
```

Only the creator can watch — the receipt is gated by a random token in the
watch URL, never derivable from the id.

### Wormhole + universal clipboard — `pipe` (one install)

A richer client adds two tricks on top of the relay. It's a **separate
install** (drops a `pipe` command in `~/.local/bin`), distinct from the inline
`?shell=1` helper:

```bash
curl -s https://pipe.0exec.com/install | sh

echo 'secret.tar' | pipe send     # → a short code like otter-maple-river-stone
pipe recv otter-maple-river-stone # on another machine: fetch + decrypt (one-time)

pipe pc                           # copy here   — encrypt your clipboard up
pipe pp                           # paste there — decrypt it onto this machine
```

The wormhole **code is both the address and the key** (it derives the slot
*and* the passphrase), and the blob is burn-after-read — so a wrong guess finds
nothing and the right one works exactly once. The clipboard syncs through a
private, last-write-wins slot encrypted with a per-machine key that never
leaves your computer. Needs only `curl` + `openssl` (clipboard also wants
`pbcopy`/`xclip`/`wl-clipboard`).

### Ask someone for a secret (browser)

In the browser app, click **Ask someone for a secret**. You get two links: a
**request** link to share and a private **inbox** link to keep. The other
person opens the request link, types a secret, and their browser seals it to
your key (ephemeral ECDH P-256 → AES-256-GCM) before uploading — so the server,
and anyone who intercepts the request link, only ever sees ciphertext. Open
your inbox link to decrypt it. Great for "paste your API key here" without the
secret ever touching a server in the clear.

## Endpoints

| Method     | Path        | Purpose                                                       |
| ---------- | ----------- | ------------------------------------------------------------- |
| GET        | `/`         | Plain usage text for `curl`; in-page encrypt/decrypt app for browsers (`/?shell=1` → sourceable bash/zsh helper, `/?app=1` → force the app) |
| POST / PUT | `/`         | Store body, `201` + URL of a fresh random id                  |
| POST / PUT | `/{name}`   | Store body in a named slot (write-once), `201` + URL          |
| GET / HEAD | `/{id}`     | `200` raw body (`text/plain`) \| `404` if gone/expired        |
| DELETE     | `/{id}`     | `204` — best-effort early delete                              |
| GET        | `/health`   | `ok`                                                          |
| GET        | `/version`  | `{"service":"pipe","version":"…"}`                           |
| GET        | `/install`  | Shell installer for the `pipe` client (`curl -s …/install \| sh`) |
| GET        | `/selftest` | In-process put/get/burn/expiry roundtrip — `200` all green / `503` |

Write responses carry `X-Pipe-Expires-In` (seconds) and, for burn entries,
`X-Pipe-Burn: 1`.

## Query params

| Param   | On       | Meaning                                                            |
| ------- | -------- | ----------------------------------------------------------------- |
| `burn`  | write    | `1`/`true`/`yes`/`on` → entry deleted on first read               |
| `ttl`   | write    | Lifetime in seconds, clamped to the 5-minute ceiling             |
| `words` | write    | `1` → assign a say-it-out-loud id like `otter-maple-river-stone`  |
| `replace` | write  | `1` → overwrite a live named slot instead of `409` (last-write-wins) |
| `qr`    | write / `GET /{id}` | `1` → return a scannable QR of the link (`qr=png` → PNG image) |
| `notify`| write    | `1` → arm a read-receipt; the watch URL comes back in `X-Pipe-Watch` |
| `watch` | `GET /{id}` | `<token>` → long-poll until first read, then `{"read":true,"readAt":…}` |
| `shell` | `GET /`  | `1` → return a sourceable bash/zsh helper instead of the usage text |
| `app`   | `GET /`  | `1` → force the HTML browser app (else: app for browsers, text for curl) |
| `raw`   | `GET /`  | `1` → force the plain-text usage page even in a browser           |

## Security model

There is **no token**, by design. Anyone who can
reach the URL within the TTL can read it. Security comes from:

- **Unguessable ids** — 8-char base62 from `crypto/rand` with rejection
  sampling (no modulo bias). The id is the bearer secret.
- **Hard ≤5-minute TTL** — enforced in code; `?ttl=` can only shorten it.
- **Opt-in burn-after-read** — `?burn=1` deletes on first read for secrets.
- **In-RAM only** — nothing touches disk; a process restart wipes
  everything. That's a feature for an ephemeral relay.
- **Body cap** — 10 MiB per blob (`413` over), plus a total in-RAM budget
  (`PIPE_MAX_TOTAL_BYTES`, default 512 MiB) so the relay can't be filled to OOM.
- **Per-IP write rate limit** — default 60 writes/min; reads unlimited.
- **No content sniffing** — `/{id}` is served `text/plain; charset=utf-8`
  with `X-Content-Type-Options: nosniff` and `Content-Disposition: inline`, so
  a browser never renders untrusted bytes as HTML/JS. (The HTML app is only
  served from `/`, and it shows decrypted text via `textContent`, never
  `innerHTML`.)

### Optional: end-to-end encryption (`-e`)

For payloads the server must never see, add **one flag** — `-e` (CLI) or the
**End-to-end encrypt** toggle (browser). Encryption happens on the client; the
key lives in the URL `#fragment` and is never transmitted. What that buys you,
stated honestly:

| Threat | Plain paste | `-e` (key in `#fragment`) |
| --- | --- | --- |
| Passive eavesdropper / ISP / logging proxy recording requests | sees plaintext over the wire only if TLS is broken | **never sees the key** — the fragment is not sent; the body is ciphertext |
| The server's logs / disk / a subpoena | server holds plaintext | server holds **ciphertext only**; the key was never sent to it |
| An **actively malicious / spoofed server** (MITM with a forged cert) | reads/edits plaintext | **CLI (`p open`)**: still safe — `openssl` runs locally, the key never leaves your box. **Browser app**: trusts the JS the server serves at decrypt time, so a hostile server *could* serve key-stealing JS — use the CLI (or a saved local copy of the page) when you must defend against the server itself. |

So `-e` reliably defeats passive network eavesdropping and turns the server
into a zero-knowledge ciphertext relay; for the strongest "even if the server
is hostile" guarantee, decrypt with the CLI rather than the in-page app.

Encryption is AES-256-CTR + HMAC-SHA256 (encrypt-then-MAC), the same scheme in
the shell helper and the browser, so links interoperate both ways.

You can also bring your own crypto — e.g. `age`:

```bash
echo secret | age -r <recipient> | curl --data-binary @- 'https://pipe.0exec.com?burn=1'
```

## Configuration (env)

| Variable               | Default   | Meaning                                                  |
| ---------------------- | --------- | -------------------------------------------------------- |
| `PORT`                 | `18272`   | HTTP listen port                                         |
| `PIPE_MAX_TTL`         | `5m`      | Hard entry lifetime ceiling (capped at 5m in code)       |
| `PIPE_MAX_ENTRIES`     | `4096`    | Max live entries before writes get `429`                 |
| `PIPE_MAX_BODY_BYTES`  | `10485760`| Per-blob body cap (10 MiB)                               |
| `PIPE_MAX_TOTAL_BYTES` | `536870912` | Total in-RAM budget across all entries (512 MiB); `0` disables |
| `PIPE_WRITES_PER_MIN`  | `60`      | Per-IP write rate limit (reads never limited)            |
| `PIPE_PUBLIC_BASE_URL` | (empty)   | Override the base in returned URLs; empty = derive from request |
| `PIPE_TRUST_PROXY`     | (empty)   | `1` only behind a reverse proxy that appends the client address to `X-Forwarded-For`: the write limit then uses the address it added (the last entry). Without it the header is ignored, so a client cannot pick its own address. |
| `PIPE_ADDR` / `PORT`   | `:18272`  | Listen address (`PIPE_ADDR` wins; `PORT` sets only the port) |

## Run your own

```bash
go install github.com/baditaflorin/pipe@latest   # or: docker compose up -d --build
PIPE_ADDR=127.0.0.1:18272 pipe
```

Put it behind a TLS reverse proxy (nginx, Caddy) for anything beyond your own machine, and set
`PIPE_TRUST_PROXY=1` there so the per-IP write limit sees real client addresses. Everything lives
in RAM: a restart empties it, which is the point. One instance holds its own entries, so if you
run several behind one name, route each name to a single instance (a read that lands on another
instance gets `404`).

## Why in-RAM and not SQLite

An ephemeral relay wants its data gone on restart, so persistence is an
anti-feature. Staying in-memory also sidesteps the documented
`modernc.org/sqlite` fcntl thread-explosion incident — no CGO, no disk, no
WAL recovery path.
