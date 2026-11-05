// The lookout's admin sign-in (from gnoshop's web/admin.js). Adena signs a one-time code from the server (SignArbitrary); the server checks the
// signature and that the wallet is an admin, and sets the cookie (admin.go, wallet.go). gnomail's wallet.js does
// the same steps.
(function () {
  "use strict";

  var button = document.getElementById("sign-in"); // not id="adena": an element's id is a window property, and Adena is window.adena
  var status = document.getElementById("status");
  var getAdena = document.getElementById("get-adena");
  if (!button || !status || !window.fetch) return;

  var READ_MS = 25000, HUMAN_MS = 180000; // a call Adena answers by itself; one you approve, maybe on a Ledger

  function within(p, ms) {
    return Promise.race([Promise.resolve(p), new Promise(function (_, reject) {
      setTimeout(function () {
        reject(new Error("Adena didn't answer. If its window is open, approve it there and try again."));
      }, ms);
    })]);
  }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  // 4001 is both ALREADY_CONNECTED and NETWORK_TIMEOUT in Adena's codes; the type says which.
  function connected(e) {
    return !!e && (e.code === 0 || e.type === "CONNECTION_SUCCESS" || e.type === "ALREADY_CONNECTED" ||
      (e.type === undefined && e.code === 4001));
  }

  // The document exactly as Adena signed it: keys sorted (sortedJsonStringify), then <, > and & escaped
  // (encodeCharacterSet). The server checks the signature over these bytes.
  function sorted(v) {
    if (Array.isArray(v)) return v.map(sorted);
    if (v && typeof v === "object") {
      var o = {};
      Object.keys(v).sort().forEach(function (k) { o[k] = sorted(v[k]); });
      return o;
    }
    return v;
  }
  function signBytes(doc) {
    return JSON.stringify(sorted(doc)).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026");
  }

  function say(text, problem) {
    status.textContent = text;
    status.classList.toggle("info", !problem);
  }

  async function post(path, body) {
    var res = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: body ? { "Content-Type": "application/json", "Accept": "application/json" } : { "Accept": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    var out = {};
    try { out = await res.json(); } catch (e) { /* nginx's own error pages are not JSON */ }
    if (!res.ok || !out.ok) throw new Error(out.message || "The server said no (" + res.status + "). Try again.");
    return out;
  }

  // Adena puts window.adena on the page a moment after it loads.
  async function wallet() {
    for (var i = 0; i < 20 && !window.adena; i++) await sleep(100);
    return window.adena;
  }

  async function signIn() {
    var a = await wallet();
    if (!a) {
      say("", true);
      getAdena.hidden = false;
      return;
    }
    if (typeof a.SignArbitrary !== "function") throw new Error("This Adena can't sign a message. Update it to 1.22.2 or later, then reload this page.");
    say("Connecting to Adena...");
    var est = await within(a.AddEstablish(location.hostname), HUMAN_MS);
    if (!connected(est)) throw new Error((est && est.message) || "Adena didn't connect.");
    var acct = await within(a.GetAccount(), READ_MS);
    if (!acct || acct.code !== 0 || !acct.data || !acct.data.address) throw new Error((acct && acct.message) || "Adena has no account selected.");
    var addr = acct.data.address;
    var ch = await post("/admin/challenge");
    say("Approve the signature in Adena. A Ledger account asks on the device too.");
    var r = await within(a.SignArbitrary({ signer: addr, data: ch.words }), HUMAN_MS);
    if (r && r.type === "ACCOUNT_MISMATCH") throw new Error("Adena's selected account isn't " + addr + ". Select that account in Adena (not a session key) and try again.");
    if (!r || r.status !== "success" || !r.data || !r.data.signed) throw new Error((r && r.message) || "Adena didn't sign.");
    var sig = r.data.signature || {};
    say("Checking the signature...");
    await post("/admin/login", { id: ch.id, addr: addr, pub: (sig.pubKey || {}).value, sig: sig.signature, doc: signBytes(r.data.signed) });
    say("Signed in.");
    location.replace("/admin");
  }

  button.addEventListener("click", function () {
    button.disabled = true;
    getAdena.hidden = true;
    signIn().catch(function (e) { say(e && e.message ? e.message : String(e), true); })
      .then(function () { button.disabled = false; });
  });
})();
