package main

import (
	"net/http"
	"strings"
)

// Install serves a one-line installer for the richer `pipe` client:
//
//	curl -s https://pipe.0exec.com/install | sh
//
// It drops a self-contained `pipe` command into ~/.local/bin that adds the two
// "magic" client-side tricks on top of the relay:
//   - wormhole: `echo x | pipe send` prints a short human code; `pipe recv <code>`
//     fetches + decrypts on another machine. The code is BOTH the slot address
//     and the passphrase, and the blob is burn-after-read.
//   - clipboard: `pipe pc` (copy here) encrypts your OS clipboard up to a
//     private last-write-wins slot; `pipe pp` (paste there) pulls it down.
//
// This is deliberately separate from the inline `?shell=1` helper: it installs
// a persistent command and a per-machine clipboard key, rather than eval'ing
// functions into the current shell.
func (h *Handlers) Install(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(strings.ReplaceAll(installScript, "{{B}}", h.base(r))))
}

// installScript is the served installer. {{B}} is replaced with the public base
// at request time (so the embedded `pipe` command bakes the right endpoint even
// inside the quoted heredoc — the substitution happens here, not in the shell).
const installScript = `#!/bin/sh
# pipe installer — curl -s {{B}}/install | sh
set -e
BASE="{{B}}"
BIN="${PIPE_BIN_DIR:-$HOME/.local/bin}"
CFG="$HOME/.config/pipe"
command -v openssl >/dev/null 2>&1 || { echo "pipe: needs openssl (not found)"; exit 1; }
command -v curl    >/dev/null 2>&1 || { echo "pipe: needs curl (not found)"; exit 1; }
mkdir -p "$BIN" "$CFG"
# Per-machine clipboard key — end-to-end; never leaves this machine.
if [ ! -f "$CFG/clip.key" ]; then openssl rand -hex 32 > "$CFG/clip.key"; chmod 600 "$CFG/clip.key"; fi

cat > "$BIN/pipe" <<'PIPE_EOF'
#!/bin/sh
# pipe — wormhole + clipboard over an ephemeral relay.
# Reinstall / update:  curl -s {{B}}/install | sh
PIPE_URL="${PIPE_URL:-{{B}}}"
O="${PIPE_OPENSSL:-openssl}"
CFG="$HOME/.config/pipe"

_slot() { printf '%s' "$1" | "$O" dgst -sha256 | sed 's/^.*= //' | cut -c1-20; }

_words() { # 4-word human code, e.g. otter-maple-river-stone (~96^4 ≈ 8.5e7)
  set -- otter maple river stone amber cedar comet coral delta ember falcon \
    garden harbor hazel heron ivory jasper kayak lagoon lantern lemon lily \
    lunar marble meadow nectar needle nova ocean olive onyx opal orbit panda \
    pebble pepper petal pine poppy quartz quail rabbit radish raven reef \
    robin rocket sage salt sand scout shade shell shore silver slate sloth \
    snow solar spruce stream sugar summer swan teal thistle tiger topaz \
    trail tulip turtle valley velvet vine willow walnut wave acorn anchor \
    arrow autumn beacon birch bison bloom brook cabin canoe canyon cliff \
    clover cobra cotton crane dawn dune eagle fern finch
  n=$#; out=""
  for _ in 1 2 3 4; do
    r=$("$O" rand 2 | od -An -tu2 | tr -d ' \n')
    idx=$(( r % n + 1 )); w=$(eval "printf '%s' \"\${$idx}\"")
    out="${out:+$out-}$w"
  done
  printf '%s' "$out"
}

_clip_get() {
  if   command -v pbpaste        >/dev/null 2>&1; then pbpaste
  elif command -v wl-paste       >/dev/null 2>&1; then wl-paste -n
  elif command -v xclip          >/dev/null 2>&1; then xclip -selection clipboard -o
  elif command -v xsel           >/dev/null 2>&1; then xsel -b
  elif command -v powershell.exe >/dev/null 2>&1; then powershell.exe -NoProfile -Command Get-Clipboard
  else echo "pipe: no clipboard tool (install xclip / wl-clipboard)" >&2; return 1; fi
}
_clip_set() {
  if   command -v pbcopy   >/dev/null 2>&1; then pbcopy
  elif command -v wl-copy  >/dev/null 2>&1; then wl-copy
  elif command -v xclip    >/dev/null 2>&1; then xclip -selection clipboard
  elif command -v xsel     >/dev/null 2>&1; then xsel -b
  elif command -v clip.exe >/dev/null 2>&1; then clip.exe
  else echo "pipe: no clipboard tool (install xclip / wl-clipboard)" >&2; return 1; fi
}

case "$1" in
  send) shift
    code=$(_words); slot=$(_slot "$code")
    "$O" enc -aes256 -pbkdf2 -k "$code" | \
      curl -fsS --data-binary @- "$PIPE_URL/$slot?burn=1&replace=1&ttl=300" >/dev/null || {
        echo "pipe: send failed" >&2; exit 1; }
    printf '%s\n' "$code" ;;
  recv|receive) shift
    [ -n "$1" ] || { echo "usage: pipe recv <code>" >&2; exit 2; }
    code="$1"; slot=$(_slot "$code")
    curl -fsS "$PIPE_URL/$slot" | "$O" enc -d -aes256 -pbkdf2 -k "$code" ;;
  pc) k=$(cat "$CFG/clip.key"); slot="clip-$(_slot "$k")"
    _clip_get | "$O" enc -aes256 -pbkdf2 -k "$k" | \
      curl -fsS --data-binary @- "$PIPE_URL/$slot?replace=1&ttl=300" >/dev/null && echo "clipboard pushed" ;;
  pp) k=$(cat "$CFG/clip.key"); slot="clip-$(_slot "$k")"
    curl -fsS "$PIPE_URL/$slot" | "$O" enc -d -aes256 -pbkdf2 -k "$k" | _clip_set && echo "clipboard pulled" ;;
  ""|help|-h|--help)
    cat <<USAGE
pipe — wormhole + clipboard (relay: $PIPE_URL)
  echo hi | pipe send     prints a short code (otter-maple-…); share it
  pipe recv <code>        fetch + decrypt on another machine (one-time)
  pipe pc                 copy here   (encrypt your clipboard up)
  pipe pp                 paste there (decrypt to this machine's clipboard)
Codes are end-to-end (the code is the key) and burn after one read.
USAGE
    ;;
  *) echo "pipe: unknown command '$1' (try: pipe help)" >&2; exit 2 ;;
esac
PIPE_EOF
chmod +x "$BIN/pipe"

echo "installed: $BIN/pipe"
case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "NOTE: add $BIN to your PATH, e.g.:"
     echo "  echo 'export PATH=\"$BIN:\$PATH\"' >> ~/.profile  # (or ~/.zshrc / ~/.bashrc)" ;;
esac
echo
echo "try it (note the 'pipe ' prefix — 'pc'/'pp' alone are other system tools):"
echo "  echo hi | pipe send        # prints a short code; 'pipe recv <code>' elsewhere"
echo "  pipe pc                     # copy:  encrypt this machine's clipboard up"
echo "  pipe pp                     # paste: decrypt it onto another machine"
echo
echo "want the quick 'p' helper too (push / pull / -e encrypt)? source it (no install):"
echo "  eval \"\$(curl -s $BASE/shell)\""
`
