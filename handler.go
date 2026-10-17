package main

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
)

const idLen = 8

// validName constrains user-chosen slot names: start alnum, then alnum / dot
// / dash / underscore, up to 128 chars total. Keeps paths flat and printable.
var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// reserved names collide with the server's own routes (a GET would hit those
// handlers instead of the slot), so we refuse to claim them.
var reserved = map[string]bool{
	"health": true, "version": true, "metrics": true, "capabilities": true,
	"selftest": true, "favicon.ico": true, "robots.txt": true,
}

// wantsHTML is true for real browsers (Accept includes text/html) or when the
// caller forces it with ?app=1. curl sends Accept: */* and gets plain text.
func wantsHTML(r *http.Request) bool {
	if isTrue(r.URL.Query().Get("app")) {
		return true
	}
	if isTrue(r.URL.Query().Get("raw")) {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// trustProxy (PIPE_TRUST_PROXY=1) says a reverse proxy in front of the pipe appends the
// client's address to X-Forwarded-For. Only then is the header used, and only its last entry,
// the one that proxy added: everything before it was sent by the client, which could otherwise
// name any address it likes and never meet the write limit.
var trustProxy bool

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); trustProxy && xff != "" {
		if i := strings.LastIndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[i+1:])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isTrue(s string) bool {
	switch strings.ToLower(s) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	fmt.Fprintln(w, msg)
}

const usageText = `pipe — ephemeral cross-machine copy/paste (in-RAM, <=5 min TTL)

PUSH (machine A):
  echo hi | curl --data-binary @- {{B}}
  cmd 2>&1 | curl --data-binary @- {{B}}/my-slot        # named slot
  cmd 2>&1 | curl --data-binary @- '{{B}}?burn=1'       # one-time (deleted on first read)
  cmd 2>&1 | curl --data-binary @- '{{B}}?ttl=60'       # shorter TTL (seconds, capped at 300)
  cmd 2>&1 | curl --data-binary @- '{{B}}?words=1'      # say-it-out-loud link (otter-maple-…)
  cmd 2>&1 | curl --data-binary @- '{{B}}?qr=1'         # push + print a scannable QR

PULL (machine B):
  curl {{B}}/<id>
  curl '{{B}}/<id>?qr'            # print a QR of the link — scan it with your phone

SHELL HELPER (bash or zsh, macOS or Linux — drop into ~/.bashrc / ~/.zshrc):
  eval "$(curl -s {{B}}/shell)"     # the /shell path has no '?', so no zsh quoting
  cmd | p                 # push, prints the URL
  cmd | p my-slot         # push to a named slot
  p get my-slot           # pull a slot / id
  cmd | p -e              # END-TO-END ENCRYPT: prints {{B}}/#<id>~<key>
  p open '{{B}}/#<id>~<key>'   # pull + decrypt (quote it — the # is a shell comment)
  p -e -f photo.png       # a FILE whose name, size and sha256 are sealed INSIDE the link
  cmd | p -e -n log.txt   # same, naming piped data
  p save '{{B}}/#<id>~<key>' [dir]   # decrypt to dir/<sealed name>, checked, never overwriting
  cmd | p -e -m kind=build -m repo=x   # any key=value rides inside too (open metadata)

ENCRYPT WITH ONE LINE (no helper, just curl + openssl — pick any password):
  echo 'my secret' | openssl enc -aes256 -pbkdf2 -k PASS | curl -s --data-binary @- {{B}}
  # → {{B}}/oCwOc4q4    ... then on the other machine, SAME password:
  curl -s {{B}}/oCwOc4q4 | openssl enc -d -aes256 -pbkdf2 -k PASS
  The server only ever sees a scrambled blob — never your text or password.
  Wrong password just prints "bad decrypt". A whole file: add -in file.jpg.
  Hide the password from shell history: drop "-k PASS" and openssl prompts.

END-TO-END ENCRYPTION, browser-openable link (one flag: -e, via the helper):
  echo 's3cr3t' | p -e
  # → {{B}}/#Xq7k2aPb~2f9c…   (open in ANY browser to decrypt, or: p open '<link>')
  The key rides in the URL's #fragment, which curl/browsers NEVER send to the
  server, so the server stores only ciphertext and a passive ISP never sees it.
  With -f/-n the file's name, size and sha256 travel INSIDE the encrypted payload
  (the server never sees them), so a reader needs nothing passed on the side:
  the browser shows the name + a download button, and p open / p save check it.

KNOW WHEN IT'S READ (?notify):
  W=$(echo secret | curl -sD - --data-binary @- '{{B}}/?notify=1' | awk 'tolower($1)=="x-pipe-watch:"{print $2}' | tr -d '\r')
  curl -s "$W"      # long-polls; returns {"read":true,"readAt":...} the moment it's opened

RICHER CLIENT — wormhole + universal clipboard (one install):
  curl -s {{B}}/install | sh
  echo hi | pipe send       # prints a short code (otter-maple-…); share it
  pipe recv <code>          # fetch + decrypt on another machine (one-time)
  pipe pc  /  pipe pp        # copy here, paste there (end-to-end clipboard)

BROWSER:
  Open {{B}} in a browser for an in-page encrypt/paste app, or to "Ask someone
  for a secret" — they fill a form, it's sealed to you, only you can read it.

Notes:
  * --data-binary @- streams stdin verbatim; plain -d would mangle newlines.
  * Max body 10 MiB. Served as text/plain, never executed.
  * Anyone with the URL can read it within the TTL — use ?burn=1 for secrets,
    or encrypt (above) so the server never sees the plaintext.
  * ?words links are shorter to say but lower-entropy — pair with ?burn or -e.
  * zsh "no matches found"? Quote any URL with a ?  e.g. '{{B}}/?shell=1'.
`

// shellHelper returns a sourceable helper that works identically in bash and
// zsh, on macOS (LibreSSL) and Linux (OpenSSL). The encrypt/decrypt scheme
// (AES-256-CTR + HMAC-SHA256, encrypt-then-MAC, key in the URL #fragment) is
// byte-for-byte the same one the browser app uses, so a link made here opens
// in the browser and vice-versa. Only POSIX tools + openssl are used:
// openssl, od, dd, cmp, mktemp, sed, tr, printf, curl.
func shellHelper(base string) string {
	return strings.ReplaceAll(shellHelperTmpl, "{{B}}", base)
}

// shellHelperTmpl is the helper; {{B}} is the public base. Envelope versions: 1 is the plain
// payload, 3 carries a header sealed inside it (file name, size, sha256) so a link describes
// its own file: plaintext = uint32be(len) | JSON | bytes, all under the same MAC.
const shellHelperTmpl = `# pipe shell helper — eval "$(curl -s {{B}}/shell)"
# bash/zsh, macOS/Linux. Override the endpoint with PIPE_URL, openssl with PIPE_OPENSSL.
PIPE_URL="${PIPE_URL:-{{B}}}"

_pipe_enc() { # $1=keyhex [$2=envelope version 1|3] ; stdin plaintext -> stdout base64 envelope
  local key="$1" ver="${2:-1}" O="${PIPE_OPENSSL:-openssl}" e m d iv
  e=$(printf '%s' "${key}:enc" | "$O" dgst -sha256 | sed 's/^.*= //')
  m=$(printf '%s' "${key}:mac" | "$O" dgst -sha256 | sed 's/^.*= //')
  d=$(mktemp -d) || return 1
  cat > "$d/pt"; "$O" rand 16 > "$d/iv"
  iv=$(od -An -tx1 -v "$d/iv" | tr -d ' \n')
  "$O" enc -aes-256-ctr -K "$e" -iv "$iv" -in "$d/pt" -out "$d/ct"
  cat "$d/iv" "$d/ct" | "$O" dgst -sha256 -hmac "$m" -binary > "$d/mac"
  printf "\\00$ver" > "$d/v"
  cat "$d/v" "$d/iv" "$d/mac" "$d/ct" | "$O" base64 -A
  rm -rf "$d"
}
_pipe_safename() { # $1=name -> a file name that cannot leave its directory or hide
  local n
  n=$(printf '%s' "${1##*/}" | LC_ALL=C tr -c 'A-Za-z0-9._ -' '_' | sed 's/^[. ]*//' | cut -c1-100)
  printf '%s' "${n:-download}"
}
_pipe_json_str() { # $1=text -> JSON string body: control characters dropped, \ and " escaped
  printf '%s' "$1" | LC_ALL=C tr -d '\000-\037\177' | sed 's/\\/\\\\/g; s/"/\\"/g'
}
_pipe_meta_extra() { # $1="k=v" lines -> the JSON fragment for them (,"k":"v"...); fails on a bad key
  # Run this BEFORE the upload pipeline: an error inside a pipeline stage would not stop it.
  local l k v extra=""
  while IFS= read -r l; do
    [ -n "$l" ] || continue
    k="${l%%=*}"; v="${l#*=}"
    case "$k" in
      ""|*[!A-Za-z0-9_.-]*) echo "pipe: bad metadata key '$k' (use letters, digits, _ . -)" >&2; return 1 ;;
      name|size|sha256) echo "pipe: metadata key '$k' is set by the helper" >&2; return 1 ;;
    esac
    [ ${#k} -le 32 ] || { echo "pipe: metadata key too long: $k" >&2; return 1; }
    extra="$extra,\"$k\":\"$(_pipe_json_str "$v")\""
  done <<PIPE_KV
$1
PIPE_KV
  if [ ${#extra} -gt 3800 ]; then echo "pipe: metadata is too big (limit about 3800 bytes)" >&2; return 1; fi
  printf '%s' "$extra"
}
_pipe_meta_wrap() { # $1=file name (may be empty) $2=extra JSON fragment from _pipe_meta_extra ; stdin body -> header+body
  # The header is open: any extra key=value rides along. name, size and sha256 are the only
  # keys readers act on (and verify); the rest is data for the receiving agent to use or ignore.
  local O="${PIPE_OPENSSL:-openssl}" d sz sum json len extra="$2" nm=""
  d=$(mktemp -d) || return 1
  cat > "$d/b"
  [ -z "$1" ] || nm="\"name\":\"$(_pipe_safename "$1")\","
  sz=$(wc -c < "$d/b" | tr -d ' ')
  sum=$("$O" dgst -sha256 "$d/b" | sed 's/^.*= //')
  json="{${nm}\"size\":$sz,\"sha256\":\"$sum\"$extra}"
  len=${#json}
  if [ "$len" -gt 4096 ]; then echo "pipe: metadata is over 4096 bytes" >&2; rm -rf "$d"; return 1; fi
  printf "$(printf '\\%03o\\%03o\\%03o\\%03o' $((len>>24&255)) $((len>>16&255)) $((len>>8&255)) $((len&255)))"
  printf '%s' "$json"
  cat "$d/b"
  rm -rf "$d"
}
_pipe_dec() { # $1=keyhex [$2=dir [$3=fallback name]] ; stdin base64 envelope -> stdout plaintext
  # A version 3 payload is checked against its sealed size and sha256, its header is dropped
  # (reported on stderr), and with a dir it is saved there under its sealed name, never over a file.
  local key="$1" dir="$2" O="${PIPE_OPENSSL:-openssl}" e m d iv v n name size sum got out
  e=$(printf '%s' "${key}:enc" | "$O" dgst -sha256 | sed 's/^.*= //')
  m=$(printf '%s' "${key}:mac" | "$O" dgst -sha256 | sed 's/^.*= //')
  d=$(mktemp -d) || return 1
  "$O" base64 -d -A > "$d/env"
  v=$(od -An -tx1 -j0 -N1 -v "$d/env" | tr -d ' \n')
  if [ "$v" != "01" ] && [ "$v" != "03" ]; then echo "pipe: not an encrypted pipe" >&2; rm -rf "$d"; return 1; fi
  dd if="$d/env" of="$d/iv"  bs=1 skip=1  count=16 2>/dev/null
  dd if="$d/env" of="$d/mac" bs=1 skip=17 count=32 2>/dev/null
  tail -c +50 "$d/env" > "$d/ct"
  cat "$d/iv" "$d/ct" | "$O" dgst -sha256 -hmac "$m" -binary > "$d/mac2"
  if ! cmp -s "$d/mac" "$d/mac2"; then echo "pipe: authentication failed (wrong key or tampered)" >&2; rm -rf "$d"; return 1; fi
  iv=$(od -An -tx1 -v "$d/iv" | tr -d ' \n')
  "$O" enc -d -aes-256-ctr -K "$e" -iv "$iv" -in "$d/ct" -out "$d/pt"
  name="$3"
  if [ "$v" = "03" ]; then
    set -- $(od -An -tu1 -v -N4 "$d/pt")
    n=$(( ($1<<24) + ($2<<16) + ($3<<8) + $4 ))
    if [ "$n" -gt 4096 ] || [ "$n" -gt $(( $(wc -c < "$d/pt") - 4 )) ]; then
      echo "pipe: bad metadata header" >&2; rm -rf "$d"; return 1; fi
    tail -c +5 "$d/pt" | head -c "$n" > "$d/meta"
    tail -c +$((n+5)) "$d/pt" > "$d/body"
    name=$(sed -n 's/.*"name":"\([^"\\]*\)".*/\1/p' "$d/meta")
    size=$(sed -n 's/.*"size":\([0-9][0-9]*\).*/\1/p' "$d/meta")
    sum=$(sed -n 's/.*"sha256":"\([0-9a-fA-F]*\)".*/\1/p' "$d/meta" | tr 'A-F' 'a-f')
    got=$("$O" dgst -sha256 "$d/body" | sed 's/^.*= //')
    if { [ -n "$size" ] && [ "$size" != "$(wc -c < "$d/body" | tr -d ' ')" ]; } || { [ -n "$sum" ] && [ "$sum" != "$got" ]; }; then
      echo "pipe: the file does not match the size/checksum sealed inside it" >&2; rm -rf "$d"; return 1; fi
    echo "pipe: file name=${name:-?} size=$(wc -c < "$d/body" | tr -d ' ') sha256=$got" >&2
    # Every other key is the sender's data: shown (control characters dropped), never acted on.
    grep -o '"[A-Za-z0-9_.-]*":\("\([^"\\]\|\\.\)*"\|[0-9][0-9]*\)' "$d/meta" | sed 's/^"\([^"]*\)":/\1=/; s/="\(.*\)"$/=\1/' \
      | LC_ALL=C tr -d '\000-\010\013-\037\177' | grep -v -E '^(name|size|sha256)=' | sed 's/^/pipe: meta /' >&2
  else
    cp "$d/pt" "$d/body"
  fi
  if [ -n "$dir" ]; then
    out="$dir/$(_pipe_safename "${name:-pipe-download}")"
    if [ -e "$out" ] || [ -L "$out" ]; then echo "pipe: $out exists; not replacing it" >&2; rm -rf "$d"; return 1; fi
    cp "$d/body" "$out" && chmod 600 "$out" && echo "saved $out"
  else
    cat "$d/body"
  fi
  rm -rf "$d"
}
p() { # push | push named | -e [-f FILE | -n NAME] [-m key=value]... encrypt | get <id|url> [key] | open <url> | save <url> [dir]
  local base="$PIPE_URL" O="${PIPE_OPENSSL:-openssl}" key id resp frag name src kv extra
  case "$1" in
    get|g) shift
      # Accept a bare id, a full plain URL, or a full E2E link.
      case "$1" in
        *"#"*"~"*) # quoted E2E link passed to get → behave like open
          frag="${1#*#}"; id="${frag%%~*}"; key="${frag#*~}"
          curl -fsS "$base/$id" | _pipe_dec "$key" ;;
        *) id="${1##*/}" # last path segment: works for id and full URL alike
          if [ -n "$2" ]; then curl -fsS "$base/$id" | _pipe_dec "$2"; else curl -fsS "$base/$id"; fi ;;
      esac ;;
    open|o) shift
      frag="${1#*#}"; id="${frag%%~*}"; key="${frag#*~}"
      if [ "$id" = "$key" ]; then echo "pipe: no key in URL (expected .../#id~key)" >&2; return 1; fi
      curl -fsS "$base/$id" | _pipe_dec "$key" ;;
    save|s) shift # decrypt to a file named by what the sender sealed inside (dir default: .)
      frag="${1#*#}"; id="${frag%%~*}"; key="${frag#*~}"
      if [ "$id" = "$key" ]; then echo "pipe: no key in URL (expected .../#id~key)" >&2; return 1; fi
      curl -fsS "$base/$id" | _pipe_dec "$key" "${2:-.}" "pipe-$id" ;;
    -e|e) shift
      name=""; src=""; kv=""
      while :; do case "$1" in
        -n) name="$2"; shift 2 ;;             # seal this file name (stdin is the body)
        -f) src="$2"; name="${name:-${2##*/}}"; shift 2 ;; # read FILE, seal its name
        -m) kv="$kv
$2"; shift 2 ;;                               # seal any key=value (repeatable)
        *) break ;; esac; done
      if [ -n "$src" ] && [ ! -f "$src" -o ! -r "$src" ]; then echo "pipe: cannot read $src" >&2; return 1; fi
      extra=$(_pipe_meta_extra "$kv") || return 1
      key=$("$O" rand -hex 32)
      if [ -n "$name" ] || [ -n "$kv" ]; then # name, size, sha256 and any -m key=value travel inside; readers need none of it on the side
        if [ -n "$src" ]; then resp=$(_pipe_meta_wrap "$name" "$extra" < "$src" | _pipe_enc "$key" 3 | curl -fsS --data-binary @- "$base/$1") || return 1
        else resp=$(_pipe_meta_wrap "$name" "$extra" | _pipe_enc "$key" 3 | curl -fsS --data-binary @- "$base/$1") || return 1; fi
      else
        resp=$(_pipe_enc "$key" | curl -fsS --data-binary @- "$base/$1") || return 1
      fi
      printf '%s/#%s~%s\n' "$base" "${resp##*/}" "$key" ;;
    *) curl -fsS --data-binary @- "$base/$1" ;;
  esac
}
`
