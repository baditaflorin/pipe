package main

import (
	"net/http"

	qrcode "github.com/skip2/go-qrcode"
)

// QR codes (?qr) — turn a link into something you scan with a phone.
//
//	cmd | curl --data-binary @- 'https://pipe.0exec.com/?qr'   # push + print a
//	                                                            # scannable QR
//	curl 'https://pipe.0exec.com/<id>?qr'                       # QR for an id
//	curl 'https://pipe.0exec.com/<id>?qr=png' > link.png        # PNG instead
//
// The magic: push from a headless box, then scan the code straight off your
// terminal with your phone — no typing a URL. The server can only build a QR
// for links it can see (plain ids); for end-to-end links the key lives in the
// #fragment, so those QRs are drawn client-side by the browser app.
//
// Encoding is github.com/skip2/go-qrcode (MIT).

// qrFormat returns the requested QR format ("text"/"png") or "" if ?qr absent.
// "?qr=png" asks for a 512x512 PNG; any other value (or a bare ?qr) for text.
func qrFormat(r *http.Request) string {
	v, ok := r.URL.Query()["qr"]
	if !ok {
		return ""
	}
	if len(v) > 0 && v[0] == "png" {
		return "png"
	}
	return "text"
}

// writeQR renders content as a QR in the given format ("text"/"png").
func writeQR(w http.ResponseWriter, format, content string) {
	if format == "png" {
		png, err := qrcode.Encode(content, qrcode.Medium, 512)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "qr encode failed")
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(png)
		return
	}
	text := qrTextString(content)
	if text == "" {
		httpError(w, http.StatusInternalServerError, "qr encode failed")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(text))
}

// qrTextString returns the half-block QR art for content, or "" on error.
func qrTextString(content string) string {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return ""
	}
	return q.ToSmallString(false)
}
