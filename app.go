package main

// appHTML is the self-contained browser single-page app served for GET /
// when the client is a browser (Accept: text/html). curl/non-browser clients
// still get the plain-text usage page.
//
// Two modes, both fully client-side:
//   - compose: encrypt the message in-browser (AES-256-CTR + HMAC-SHA256,
//     key from crypto.getRandomValues), POST only the ciphertext, then show a
//     link of the form  {origin}/#<id>~<keyhex>.
//   - read: when location.hash is present, fetch the ciphertext from /<id> and
//     decrypt it in-browser using the key carried in the URL fragment.
//
// The decryption key lives in the URL fragment (after '#'), which the browser
// NEVER sends to the server — so the server only ever stores ciphertext and a
// passive network observer never sees the key. The crypto here is the exact
// same scheme the shell helper (/?shell=1) uses, so a link made in the
// terminal opens here and vice-versa.
//
// Untrusted bytes are written with textContent (never innerHTML), so a paste
// can never execute as HTML/JS in this page.
const appHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>pipe — ephemeral encrypted paste</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
         max-width: 720px; margin: 0 auto; padding: 24px 16px 60px; }
  h1 { font-size: 20px; margin: 0 0 2px; }
  h1 .lock { opacity: .7; }
  .sub { opacity: .65; margin: 0 0 20px; font-size: 13px; }
  textarea { width: 100%; min-height: 220px; padding: 12px; border-radius: 10px;
             border: 1px solid rgba(128,128,128,.4); background: transparent; color: inherit;
             font: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; resize: vertical; }
  .row { display: flex; flex-wrap: wrap; gap: 16px 20px; align-items: center; margin: 14px 0; }
  label { display: inline-flex; align-items: center; gap: 7px; cursor: pointer; user-select: none; }
  input[type=number] { width: 76px; padding: 5px 7px; border-radius: 7px;
                       border: 1px solid rgba(128,128,128,.4); background: transparent; color: inherit; }
  button { font: inherit; font-weight: 600; padding: 9px 18px; border-radius: 9px; border: 0;
           background: #2563eb; color: #fff; cursor: pointer; }
  button.ghost { background: transparent; border: 1px solid rgba(128,128,128,.5); color: inherit; font-weight: 500; }
  button:disabled { opacity: .5; cursor: default; }
  .hint { opacity: .6; font-size: 12.5px; }
  pre { white-space: pre-wrap; word-break: break-word; padding: 14px; border-radius: 10px;
        border: 1px solid rgba(128,128,128,.35); background: rgba(128,128,128,.06); overflow: auto; margin: 0; }
  .out { margin-top: 18px; }
  .link { display: flex; gap: 8px; align-items: center; margin: 10px 0; }
  .link input { flex: 1; min-width: 0; padding: 9px 11px; border-radius: 9px;
                border: 1px solid rgba(128,128,128,.4); background: transparent; color: inherit;
                font: 12.5px ui-monospace, Menlo, monospace; }
  .ok { color: #16a34a; } .err { color: #dc2626; } .muted { opacity: .6; }
  a { color: #2563eb; }
  footer { margin-top: 34px; font-size: 12px; opacity: .55; }
</style>
</head>
<body>
<h1><span class="lock">&#128274;</span> pipe</h1>
<p class="sub">Ephemeral encrypted paste. In-RAM, &le;5&nbsp;min. The key stays in the link&rsquo;s <code>#fragment</code> &mdash; it never reaches the server.</p>
<div id="app"></div>
<footer>
  No account, no tracking. Encrypted in your browser; the server stores only ciphertext.
  CLI: <code>eval "$(curl -s <span id="host"></span>/shell)"</code> &middot;
  <a href="https://github.com/baditaflorin/pipe">source</a>
</footer>
<script>
"use strict";
(function () {
  var subtle = (crypto && crypto.subtle) || null;
  var ORIGIN = location.origin;
  var app = document.getElementById("app");
  var hostEl = document.getElementById("host"); if (hostEl) hostEl.textContent = location.origin;
  var enc = new TextEncoder(), dec = new TextDecoder();

  function hex(buf){ var b=new Uint8Array(buf), s=""; for(var i=0;i<b.length;i++) s+=b[i].toString(16).padStart(2,"0"); return s; }
  function unhex(h){ var a=new Uint8Array(h.length/2); for(var i=0;i<a.length;i++) a[i]=parseInt(h.substr(i*2,2),16); return a; }
  function b64enc(u){ var s=""; for(var i=0;i<u.length;i++) s+=String.fromCharCode(u[i]); return btoa(s); }
  function b64dec(s){ var bin=atob(s.replace(/\s+/g,"")); var a=new Uint8Array(bin.length); for(var i=0;i<bin.length;i++) a[i]=bin.charCodeAt(i); return a; }
  function sha256hex(s){ return subtle.digest("SHA-256", enc.encode(s)).then(hex); }

  function keys(k){
    return Promise.all([sha256hex(k+":enc"), sha256hex(k+":mac")]).then(function(h){
      return Promise.all([
        subtle.importKey("raw", unhex(h[0]), {name:"AES-CTR"}, false, ["encrypt","decrypt"]),
        subtle.importKey("raw", enc.encode(h[1]), {name:"HMAC",hash:"SHA-256"}, false, ["sign","verify"])
      ]);
    });
  }
  function encrypt(k, ptBytes){
    return keys(k).then(function(kk){
      var iv = crypto.getRandomValues(new Uint8Array(16));
      return subtle.encrypt({name:"AES-CTR",counter:iv,length:128}, kk[0], ptBytes).then(function(ctb){
        var ct=new Uint8Array(ctb), msg=new Uint8Array(16+ct.length); msg.set(iv); msg.set(ct,16);
        return subtle.sign("HMAC", kk[1], msg).then(function(macb){
          var mac=new Uint8Array(macb), e=new Uint8Array(1+16+32+ct.length);
          e[0]=1; e.set(iv,1); e.set(mac,17); e.set(ct,49); return b64enc(e);
        });
      });
    });
  }
  // Envelope versions: 1 = plain payload; 3 = payload with a header (the sender's file name,
  // size and sha256) sealed inside, so the link alone describes the file:
  //   plaintext = uint32be(metaLen) | meta JSON | file bytes     (the MAC covers all of it)
  function parseMeta(p){
    if(p.length<4) throw new Error("the metadata header is cut short");
    var n=((p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3])>>>0;
    if(n>4096||n>p.length-4) throw new Error("the metadata header is not valid");
    var m; try{ m=JSON.parse(dec.decode(p.slice(4,4+n))); }catch(e){ throw new Error("the metadata is not valid"); }
    return {meta:m, bytes:p.slice(4+n)};
  }
  function decrypt(k, envB64){
    return keys(k).then(function(kk){
      var e=b64dec(envB64), v=e[0]; if(v!==1&&v!==3) throw new Error("not an encrypted pipe");
      var iv=e.slice(1,17), mac=e.slice(17,49), ct=e.slice(49), msg=new Uint8Array(16+ct.length);
      msg.set(iv); msg.set(ct,16);
      return subtle.verify("HMAC", kk[1], mac, msg).then(function(ok){
        if(!ok) throw new Error("authentication failed — wrong key or tampered");
        return subtle.decrypt({name:"AES-CTR",counter:iv,length:128}, kk[0], ct);
      }).then(function(p){ p=new Uint8Array(p); return v===3 ? parseMeta(p) : {bytes:p, meta:null}; });
    });
  }
  function safeName(n){
    n=String(n||"").replace(/\\/g,"/").split("/").pop().replace(/[^\w.\- ]+/g,"_").replace(/^[. ]+/,"");
    return n.slice(0,100)||"download";
  }
  function human(n){ return n>=1048576?(n/1048576).toFixed(1)+" MB":n>=1024?(n/1024).toFixed(1)+" KB":n+" bytes"; }
  var IMG={png:"image/png",jpg:"image/jpeg",jpeg:"image/jpeg",gif:"image/gif",webp:"image/webp"};
  // Show a decrypted result. With sealed metadata: check size and checksum, name the file, and
  // offer a download (and an image preview for plain image types); text still shows inline.
  function showResult(status, out, r){
    var m=r.meta, bytes=r.bytes, text=null;
    try{ text=new TextDecoder("utf-8",{fatal:true}).decode(bytes); if(/[\u0000-\u0008\u000e-\u001f]/.test(text)) text=null; }catch(e){ text=null; }
    function finish(note){
      status.className="ok"; status.textContent="Decrypted in your browser ✓"+(note?" — "+note:"");
      if(text!==null){ out.textContent=text; } else { out.parentNode.removeChild(out); }
      if(!m) return;
      var name=safeName(m.name), ext=(name.split(".").pop()||"").toLowerCase();
      var info=el("p",{class:"hint",text:(m.name?"File "+name+", ":"")+human(bytes.length)+(m.sha256?", sha256 "+m.sha256.slice(0,12)+"…":"")});
      status.parentNode.insertBefore(info, status.nextSibling);
      var last=info;
      function after(n){ last.parentNode.insertBefore(n, last.nextSibling); last=n; }
      // Open metadata: every other key is the sender's data. Shown as text, never acted on.
      Object.keys(m).filter(function(k){ return !/^(name|size|sha256)$/.test(k) && /^[\w.\-]{1,32}$/.test(k); }).forEach(function(k){
        var v=m[k]; if(typeof v!=="string"&&typeof v!=="number") return;
        after(el("p",{class:"hint",text:k+": "+String(v).replace(/[\u0000-\u001f\u007f]/g," ").slice(0,300)}));
      });
      if(!m.name) return;
      if(IMG[ext]){
        var img=el("img",{alt:name}); img.style.maxWidth="100%"; img.style.borderRadius="10px";
        img.src=URL.createObjectURL(new Blob([bytes],{type:IMG[ext]})); after(img);
      }
      var b=el("button",{text:"Download "+name});
      b.addEventListener("click",function(){
        var a=document.createElement("a"); a.href=URL.createObjectURL(new Blob([bytes],{type:"application/octet-stream"}));
        a.download=name; document.body.appendChild(a); a.click(); a.remove();
      });
      after(b);
    }
    if(!m) return finish("");
    return subtle.digest("SHA-256", bytes).then(function(d){
      if(typeof m.size==="number" && m.size!==bytes.length) throw new Error("the file does not match the size sealed inside it");
      if(m.sha256 && hex(d)!==String(m.sha256).toLowerCase()) throw new Error("the file does not match the checksum sealed inside it");
      finish("checksum matches");
    });
  }

  // ---- ask-me-a-secret: ECDH P-256 sealed box ----
  // A request link carries the requester's PUBLIC key; the replier's browser
  // seals a secret to it (ephemeral ECDH → SHA-256 → AES-256-GCM) and uploads
  // only ciphertext. The requester's private inbox link decrypts it. The
  // server (and any link-holder) only ever sees the sealed envelope.
  function b64uEnc(u){ return b64enc(u).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,""); }
  function b64uDec(s){ s=s.replace(/-/g,"+").replace(/_/g,"/"); while(s.length%4) s+="="; return b64dec(s); }
  function genEC(){ return subtle.generateKey({name:"ECDH",namedCurve:"P-256"}, true, ["deriveBits"]); }
  function expRaw(k){ return subtle.exportKey("raw", k).then(function(b){ return new Uint8Array(b); }); }
  function expP8(k){ return subtle.exportKey("pkcs8", k).then(function(b){ return new Uint8Array(b); }); }
  function impPub(raw){ return subtle.importKey("raw", raw, {name:"ECDH",namedCurve:"P-256"}, false, []); }
  function impPriv(p8){ return subtle.importKey("pkcs8", p8, {name:"ECDH",namedCurve:"P-256"}, false, ["deriveBits"]); }
  function ecdhKey(priv, pub){
    return subtle.deriveBits({name:"ECDH",public:pub}, priv, 256)
      .then(function(bits){ return subtle.digest("SHA-256", bits); })
      .then(function(h){ return subtle.importKey("raw", h, {name:"AES-GCM"}, false, ["encrypt","decrypt"]); });
  }
  function seal(recipientPubRaw, ptBytes){
    return Promise.all([genEC(), impPub(recipientPubRaw)]).then(function(a){
      var eph=a[0], rpub=a[1];
      return Promise.all([expRaw(eph.publicKey), ecdhKey(eph.privateKey, rpub)]).then(function(b){
        var ephPub=b[0], aesKey=b[1], iv=crypto.getRandomValues(new Uint8Array(12));
        return subtle.encrypt({name:"AES-GCM",iv:iv}, aesKey, ptBytes).then(function(ctb){
          var ct=new Uint8Array(ctb), env=new Uint8Array(1+65+12+ct.length);
          env[0]=2; env.set(ephPub,1); env.set(iv,66); env.set(ct,78); return b64enc(env);
        });
      });
    });
  }
  function unseal(privP8, envB64){
    return impPriv(privP8).then(function(priv){
      var env=b64dec(envB64); if(env[0]!==2) throw new Error("not an ask reply");
      var ephPub=env.slice(1,66), iv=env.slice(66,78), ct=env.slice(78);
      return impPub(ephPub).then(function(ep){ return ecdhKey(priv, ep); }).then(function(aesKey){
        return subtle.decrypt({name:"AES-GCM",iv:iv}, aesKey, ct);
      }).then(function(p){ return new Uint8Array(p); });
    });
  }

  function el(tag, attrs, kids){
    var n=document.createElement(tag); attrs=attrs||{};
    for(var k in attrs){ if(k==="class") n.className=attrs[k]; else if(k==="text") n.textContent=attrs[k]; else n.setAttribute(k,attrs[k]); }
    (kids||[]).forEach(function(c){ n.appendChild(c); }); return n;
  }
  function clear(){ while(app.firstChild) app.removeChild(app.firstChild); }

  // ---- read mode: #<id>~<keyhex>  (key optional: plain view) ----
  function readMode(frag){
    var sep=frag.indexOf("~"), id=sep<0?frag:frag.slice(0,sep), key=sep<0?"":frag.slice(sep+1);
    clear();
    var status=el("p",{class:"muted",text:"Fetching…"}), out=el("pre");
    app.appendChild(status); app.appendChild(out);
    app.appendChild(el("p",{class:"hint"},[ (function(){var a=el("a",{href:ORIGIN,text:"← new paste"});return a;})() ]));
    if(!subtle && key){ status.textContent=""; status.className="err"; status.textContent="This browser blocks WebCrypto (needs HTTPS)."; return; }
    fetch(ORIGIN+"/"+encodeURIComponent(id), {headers:{Accept:"text/plain"}}).then(function(r){
      if(r.status===404) throw new Error("gone — wrong id, already burned, or expired");
      if(!r.ok) throw new Error("server error "+r.status);
      return r.text();
    }).then(function(body){
      if(!key){ status.textContent="Plain (unencrypted) paste:"; out.textContent=body; return; }
      return decrypt(key, body).then(function(r){ return showResult(status, out, r); });
    }).catch(function(e){ status.className="err"; status.textContent=String(e.message||e); });
  }

  // ---- compose mode ----
  function composeMode(){
    clear();
    var ta=el("textarea",{placeholder:"Type or paste… (encrypted in your browser before it leaves)",autofocus:"true"});
    var e2e=el("input",{type:"checkbox"}); e2e.checked=true;
    var burn=el("input",{type:"checkbox"});
    var ttl=el("input",{type:"number",min:"5",max:"300",value:"300"});
    var go=el("button",{text:"Create link"});
    var out=el("div",{class:"out"});
    app.appendChild(ta);
    app.appendChild(el("div",{class:"row"},[
      el("label",{},[e2e, el("span",{text:"End-to-end encrypt"})]),
      el("label",{},[burn, el("span",{text:"Burn after read"})]),
      el("label",{},[el("span",{text:"TTL"}), ttl, el("span",{class:"hint",text:"sec (≤300)"})])
    ]));
    var ask=el("button",{class:"ghost",text:"Ask someone for a secret"});
    ask.onclick=function(){ startAsk(out, fail); };
    app.appendChild(go); app.appendChild(ask); app.appendChild(out);

    function showLink(url, encrypted){
      while(out.firstChild) out.removeChild(out.firstChild);
      var field=el("input",{readonly:"true",value:url}), copy=el("button",{class:"ghost",text:"Copy"});
      copy.onclick=function(){ field.select(); navigator.clipboard&&navigator.clipboard.writeText(url); copy.textContent="Copied"; setTimeout(function(){copy.textContent="Copy";},1200); };
      out.appendChild(el("p",{class:"ok",text: encrypted?"Encrypted ✓ share this link (the key after # never hit the server):":"Link (not encrypted — anyone with it can read):"}));
      out.appendChild(el("div",{class:"link"},[field, copy]));
      out.appendChild(el("p",{class:"hint",text:"Opens & decrypts in any browser. From a terminal: "+(encrypted?("p open '"+url+"'"):("curl "+url))}));
      field.focus(); field.select();
    }
    function fail(msg){ while(out.firstChild) out.removeChild(out.firstChild); out.appendChild(el("p",{class:"err",text:msg})); }

    go.onclick=function(){
      var text=ta.value; if(!text){ fail("Nothing to send."); return; }
      var qs=[]; if(burn.checked) qs.push("burn=1");
      var t=parseInt(ttl.value,10); if(t>0 && t<300) qs.push("ttl="+t);
      var q=qs.length?("?"+qs.join("&")):"";
      go.disabled=true; go.textContent="Working…";
      var done=function(){ go.disabled=false; go.textContent="Create link"; };
      var post=function(body){ return fetch(ORIGIN+"/"+q,{method:"POST",body:body}).then(function(r){
        if(r.status===429) throw new Error("rate limited — slow down"); if(!r.ok) throw new Error("server error "+r.status); return r.text(); }); };
      if(e2e.checked){
        if(!subtle){ fail("This browser blocks WebCrypto (needs HTTPS)."); done(); return; }
        var key=hex(crypto.getRandomValues(new Uint8Array(32)));
        encrypt(key, enc.encode(text)).then(post).then(function(urlText){
          var id=urlText.trim().split("/").pop(); showLink(ORIGIN+"/#"+id+"~"+key, true); done();
        }).catch(function(e){ fail(String(e.message||e)); done(); });
      } else {
        post(text).then(function(urlText){ showLink(urlText.trim(), false); done(); })
                  .catch(function(e){ fail(String(e.message||e)); done(); });
      }
    };
  }

  function linkRow(label, url){
    var wrap=el("div"); wrap.appendChild(el("p",{class:"hint",text:label}));
    var field=el("input",{readonly:"true",value:url}), copy=el("button",{class:"ghost",text:"Copy"});
    copy.onclick=function(){ field.select(); navigator.clipboard&&navigator.clipboard.writeText(url); copy.textContent="Copied"; setTimeout(function(){copy.textContent="Copy";},1200); };
    wrap.appendChild(el("div",{class:"link"},[field, copy])); return wrap;
  }

  // ---- ask: requester mints a request link + a private inbox link ----
  function startAsk(out, fail){
    if(!subtle){ fail("This browser blocks WebCrypto (needs HTTPS)."); return; }
    var slot=hex(crypto.getRandomValues(new Uint8Array(8)));
    genEC().then(function(kp){ return Promise.all([expRaw(kp.publicKey), expP8(kp.privateKey)]); }).then(function(a){
      var reqUrl=ORIGIN+"/#ask="+slot+"."+b64uEnc(a[0]);
      var inboxUrl=ORIGIN+"/#inbox="+slot+"."+b64uEnc(a[1]);
      while(out.firstChild) out.removeChild(out.firstChild);
      out.appendChild(el("p",{class:"ok",text:"Ask created. Send the request link; keep the inbox link private."}));
      out.appendChild(linkRow("Request link — share this:", reqUrl));
      out.appendChild(linkRow("Inbox link — keep secret, it decrypts replies:", inboxUrl));
    }).catch(function(e){ fail(String(e.message||e)); });
  }

  // ---- ask reply: someone seals a secret to the requester ----
  function askReplyMode(payload){
    clear();
    var dot=payload.indexOf("."), slot=payload.slice(0,dot), pub=b64uDec(payload.slice(dot+1));
    app.appendChild(el("h1",{},[document.createTextNode("\u{1F510} Send a secret")]));
    app.appendChild(el("p",{class:"sub",text:"Only the person who asked can read this — it's encrypted in your browser to their key."}));
    var ta=el("textarea",{placeholder:"Type the secret to send back…"});
    var go=el("button",{text:"Send securely"}), out=el("div",{class:"out"});
    app.appendChild(ta); app.appendChild(go); app.appendChild(out);
    function fail(m){ while(out.firstChild) out.removeChild(out.firstChild); out.appendChild(el("p",{class:"err",text:m})); }
    go.onclick=function(){
      if(!ta.value){ fail("Nothing to send."); return; }
      if(!subtle){ fail("This browser blocks WebCrypto (needs HTTPS)."); return; }
      go.disabled=true; go.textContent="Sending…";
      seal(pub, enc.encode(ta.value)).then(function(envB64){
        return fetch(ORIGIN+"/"+encodeURIComponent(slot)+"?replace=1", {method:"POST", body:envB64});
      }).then(function(r){ if(!r.ok) throw new Error("server error "+r.status);
        while(out.firstChild) out.removeChild(out.firstChild);
        out.appendChild(el("p",{class:"ok",text:"Sent ✓ — only the requester can decrypt it. You can close this tab."}));
        ta.value="";
      }).catch(function(e){ fail(String(e.message||e)); }).then(function(){ go.disabled=false; go.textContent="Send securely"; });
    };
  }

  // ---- inbox: requester opens the sealed reply ----
  function inboxMode(payload){
    clear();
    var dot=payload.indexOf("."), slot=payload.slice(0,dot), priv=b64uDec(payload.slice(dot+1));
    app.appendChild(el("h1",{},[document.createTextNode("\u{1F4E5} Your inbox")]));
    var status=el("p",{class:"muted",text:"Checking for a reply…"}), pre=el("pre");
    app.appendChild(status); app.appendChild(pre);
    app.appendChild(el("p",{class:"hint"},[el("a",{href:ORIGIN,text:"← new"})]));
    if(!subtle){ status.className="err"; status.textContent="This browser blocks WebCrypto (needs HTTPS)."; return; }
    fetch(ORIGIN+"/"+encodeURIComponent(slot)).then(function(r){
      if(r.status===404){ status.textContent="No reply yet — keep this link and check back within 5 minutes."; return null; }
      if(!r.ok) throw new Error("server error "+r.status); return r.text();
    }).then(function(body){
      if(body===null) return;
      return unseal(priv, body).then(function(b){ status.className="ok"; status.textContent="Decrypted in your browser ✓"; pre.textContent=dec.decode(b); });
    }).catch(function(e){ status.className="err"; status.textContent=String(e.message||e); });
  }

  function route(){
    var frag=decodeURIComponent((location.hash||"").replace(/^#/,""));
    if(frag.indexOf("ask=")===0) askReplyMode(frag.slice(4));
    else if(frag.indexOf("inbox=")===0) inboxMode(frag.slice(6));
    else if(frag) readMode(frag);
    else composeMode();
  }
  // Re-route when the fragment changes in-place (e.g. pasting a new link into
  // the same tab) — each mode clear()s first, so the page just re-renders.
  window.addEventListener("hashchange", route);
  route();
})();
</script>
</body>
</html>
`
