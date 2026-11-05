// node scripts/lookout-browser.js LOOKOUT OUTDIR: the lookout's page end to end in headless Chrome, against a
// throwaway lookout (the autopatch-lookout binary LOOKOUT) this script starts on localhost:18795, with a fleet of two
// machines it can't reach. A stand-in for Adena (from gnoshop's tools/admin.js) signs what Adena signs: Node's
// secp256k1 signs, and the document and the answer are shaped as Adena's SignArbitrary shapes them, so the server's
// checks run as they do for the real wallet. It signs in, checks the cookie, screenshots the page at desktop and phone
// width in light and dark, downloads the policy and the reports, signs out (which ends a second browser's session
// too), and tries a wallet that isn't an admin, a wallet showing another account, and a browser with no Adena. Any
// console message, page error, failed request or failed check makes it exit 1. Needs puppeteer (NODE_PATH).
"use strict";
const { spawn } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const puppeteer = require("puppeteer");

const [bin, out = path.join(os.tmpdir(), "lookout-shots")] = process.argv.slice(2);
if (!bin) { console.error("usage: node scripts/lookout-browser.js LOOKOUT OUTDIR"); process.exit(2); }
fs.mkdirSync(out, { recursive: true });
const BASE = "http://localhost:18795";

// A wallet: a secp256k1 key and its g1 address, RIPEMD160(SHA256(compressed key)) in bech32 under "g". This is a
// second implementation of the server's address; if the two disagree, signing in fails.
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function polymod(values) {
  const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= gen[i];
  }
  return chk;
}
function bech32(hrp, bytes) {
  const five = [];
  let acc = 0, bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b; bits += 8;
    while (bits >= 5) { bits -= 5; five.push((acc >> bits) & 31); }
  }
  if (bits > 0) five.push((acc << (5 - bits)) & 31);
  const expand = [...hrp].map((c) => c.charCodeAt(0) >> 5).concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31));
  const pm = polymod(expand.concat(five, [0, 0, 0, 0, 0, 0])) ^ 1;
  const check = [0, 1, 2, 3, 4, 5].map((i) => (pm >> (5 * (5 - i))) & 31);
  return hrp + "1" + five.concat(check).map((x) => CHARSET[x]).join("");
}
function newWallet() {
  const keys = crypto.generateKeyPairSync("ec", { namedCurve: "secp256k1" });
  const jwk = keys.publicKey.export({ format: "jwk" });
  const x = Buffer.from(jwk.x, "base64url"), y = Buffer.from(jwk.y, "base64url");
  const pub = Buffer.concat([Buffer.from([y[31] % 2 === 0 ? 2 : 3]), x]);
  const hash = crypto.createHash("ripemd160").update(crypto.createHash("sha256").update(pub).digest()).digest();
  return {
    pub: pub.toString("base64"),
    addr: bech32("g", hash),
    sign: (doc) => crypto.sign("sha256", Buffer.from(doc, "utf8"), { key: keys.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64"),
  };
}

// The stand-in for Adena, put on each page before its scripts run. mode "mismatch" answers SignArbitrary the way
// Adena does when its selected account isn't the one the page asked to sign for.
async function giveAdena(page, wallet, mode) {
  await page.exposeFunction("__walletSign", (doc) => ({ sig: wallet.sign(doc), pub: wallet.pub }));
  await page.evaluateOnNewDocument((addr, mode) => {
    const b64 = (s) => btoa(String.fromCharCode(...new TextEncoder().encode(s)));
    const sorted = (v) => Array.isArray(v) ? v.map(sorted) : v && typeof v === "object"
      ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sorted(v[k])])) : v;
    const signBytes = (doc) => JSON.stringify(sorted(doc)).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026");
    window.adena = {
      AddEstablish: async () => ({ code: 0, status: "success", type: "CONNECTION_SUCCESS" }),
      GetAccount: async () => ({ code: 0, status: "success", type: "GET_ACCOUNT_SUCCESS", data: { address: addr, chainId: "gnoland1" } }),
      SignArbitrary: async ({ signer, data }) => {
        if (mode === "mismatch") return { code: 1, status: "failure", type: "ACCOUNT_MISMATCH", message: "Account mismatch" };
        const signed = { chain_id: "gnoland1", account_number: "0", sequence: "0", fee: { amount: [], gas: "0" },
          msgs: [{ type: "sign/MsgSignData", value: { signer, data: b64(data) } }], memo: "" };
        const r = await window.__walletSign(signBytes(signed));
        return { code: 0, status: "success", type: "SIGN_ARBITRARY", data: { signed,
          signature: { pubKey: { typeUrl: "/tm.PubKeySecp256k1", value: r.pub }, signature: r.sig } } };
      },
    };
  }, wallet.addr, mode || "");
}

// The canonical policy (as the Go policy package writes it) of a fleet of two machines in one tier.
const policy = '{"fleet":"browsertest","replaces":"","delay_seconds":86400,"signers":{"me":{"name":"owner",' +
  '"key":"02db41e6e79a9f5fc6813df46202e996d245ef327e5ff3cc47c11bdb46071ab08e"}},' +
  '"tiers":[{"name":"A","hosts":["mail","web"],"admit":["me"]}]}';

const desktop = { width: 1280, height: 900, deviceScaleFactor: 1 };
const phone = { width: 390, height: 844, deviceScaleFactor: 2, isMobile: true, hasTouch: true };
let problems = 0;
function check(ok, what) {
  console.log((ok ? "ok    " : "FAILED ") + what);
  if (!ok) problems++;
}

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lookout-browser-"));
  for (const f of ["report.key", "intake.key", "known_hosts"]) fs.writeFileSync(path.join(dir, f), "", { mode: 0o600 });
  fs.writeFileSync(path.join(dir, "policy.json"), policy);
  // The kernel's new network flaws, as the feeds command keeps them for the page.
  fs.mkdirSync(path.join(dir, "state", "feeds"), { recursive: true });
  fs.writeFileSync(path.join(dir, "state", "feeds", "kernel-new.json"), JSON.stringify([{ id: "CVE-2026-98432",
    title: "ipv4: free inet_opt and ireq_opt after an RCU grace period", files: ["net/ipv4/af_inet.c", "net/ipv4/tcp_ipv4.c"],
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", introduced: "4.4", mainline: "7.3",
    fixed: { "5.10": "5.10.272", "5.15": "5.15.223", "6.1": "6.1.190", "6.6": "6.6.159", "6.12": "6.12.113", "6.18": "6.18.56", "7.2": "7.2.10" },
    first_seen: new Date(Date.now() - 3 * 3600 * 1000).toISOString() }]));
  fs.writeFileSync(path.join(dir, "lookout.json"), JSON.stringify({ state: path.join(dir, "state"), policy: path.join(dir, "policy.json"),
    report_key: path.join(dir, "report.key"), intake_key: path.join(dir, "intake.key"), known_hosts: path.join(dir, "known_hosts"), hosts: {} }));
  const admin = newWallet(), stranger = newWallet();
  const server = spawn(bin, ["serve", "-config", path.join(dir, "lookout.json"), "-listen", "127.0.0.1:18795", "-admin", admin.addr],
    { stdio: ["ignore", "ignore", "inherit"] });
  let browser;
  try {
    for (let i = 0; ; i++) {
      try { if ((await fetch(BASE + "/admin")).ok) break; } catch (e) { /* not up yet */ }
      if (i > 100) throw new Error("the lookout did not start");
      await new Promise((r) => setTimeout(r, 100));
    }
    browser = await puppeteer.launch({ args: ["--no-sandbox"] });

    // allow is a console message the scenario expects, such as Chrome noting the 403 that refuses a stranger.
    async function open(ctx, viewport, scheme, wallet, mode, allow) {
      const page = await ctx.newPage();
      page.on("console", (m) => {
        if (allow && allow.test(m.text())) return console.log(`[console ${m.type()}, expected] ${m.text()}`);
        console.log(`[console ${m.type()}] ${m.text()}`);
        problems++;
      });
      page.on("pageerror", (e) => { console.log(`[pageerror] ${e.message}`); problems++; });
      page.on("requestfailed", (r) => { console.log(`[requestfailed] ${r.url()} ${r.failure() && r.failure().errorText}`); problems++; });
      await page.setViewport(viewport);
      await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: scheme }]);
      if (wallet) await giveAdena(page, wallet, mode);
      return page;
    }
    async function shot(page, name) {
      await page.evaluate(() => document.fonts.ready);
      await new Promise((r) => setTimeout(r, 150));
      await page.screenshot({ path: path.join(out, name + ".png"), fullPage: true });
      console.log("shot", name);
    }
    const text = (page, sel) => page.$eval(sel, (el) => el.textContent.trim()).catch(() => "");
    const wide = (page) => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);

    // The admin signs in.
    const ctx = await browser.createBrowserContext();
    const page = await open(ctx, desktop, "light", admin);
    await page.goto(BASE + "/admin", { waitUntil: "networkidle0" });
    check((await text(page, "#sign-in")) === "Sign in with Adena" && !(await page.content()).includes("browsertest"),
      "before signing in, the page shows only the sign-in");
    await shot(page, "signin-desktop-light");
    await Promise.all([page.waitForNavigation({ waitUntil: "networkidle0" }), page.click("#sign-in")]);
    check((await text(page, "h1")).includes("the lookout for fleet browsertest"), "the admin's wallet signs in and lands on the page");
    check((await page.content()).includes("Signed in as " + admin.addr.slice(0, 6) + "..." + admin.addr.slice(-4)), "the page names the wallet signed in");
    const ck = (await ctx.cookies()).find((c) => c.name === "__Host-autopatch-admin");
    check(ck && ck.httpOnly && ck.secure && ck.sameSite === "Lax" && ck.path === "/", "the session cookie is HttpOnly, Secure, SameSite=Lax, path /");
    const body = await page.content();
    check(body.includes("<td>mail</td>") && body.includes("<td>web</td>") && body.includes("no agent key in the policy yet"),
      "both machines of the policy are on the page, each without an agent key yet");
    check(body.includes("New kernel flaws a network can reach") && body.includes("6.1.190, 6.6.159") && body.includes("mainline 7.3"),
      "the kernel's new network flaws are on the page, their fixes in order");
    await shot(page, "page-desktop-light");

    // A guard file uploaded through the page's form is kept; the form with no file says so.
    const guardFile = path.join(path.dirname(__dirname), "guard", "testdata", "cve-2026-98432-ipopt.json");
    await (await page.$('input[type="file"]')).uploadFile(guardFile);
    await Promise.all([page.waitForNavigation({ waitUntil: "networkidle0" }), page.click('form[action="/admin/upload"] button')]);
    check((await text(page, ".note")).startsWith("Kept"), "a guard uploaded through the form is kept: " + (await text(page, ".note")));
    const files = await page.evaluate(async () => {
      const p = await fetch("/admin/policy.json"), t = await fetch("/admin/reports.tar");
      return { policy: p.status === 200 ? await p.text() : "status " + p.status, tar: t.status, tarType: t.headers.get("content-type") };
    });
    check(files.policy.trim() === policy, "the policy downloads, byte for byte");
    check(files.tar === 200, "the signed reports download for autopatch-sign");

    for (const [vp, scheme, name] of [[desktop, "dark", "page-desktop-dark"], [phone, "light", "page-phone-light"], [phone, "dark", "page-phone-dark"]]) {
      const p = await open(ctx, vp, scheme);
      await p.goto(BASE + "/admin", { waitUntil: "networkidle0" });
      check(await wide(p), name + ": nothing runs off the side");
      await shot(p, name);
      await p.close();
    }
    const sp = await open(await browser.createBrowserContext(), phone, "dark");
    await sp.goto(BASE + "/admin", { waitUntil: "networkidle0" });
    check(await wide(sp), "the sign-in at phone width: nothing runs off the side");
    await shot(sp, "signin-phone-dark");

    // A second browser signed in as the admin; signing out in the first ends its session too.
    const ctx2 = await browser.createBrowserContext();
    const page2 = await open(ctx2, desktop, "light", admin);
    await page2.goto(BASE + "/admin", { waitUntil: "networkidle0" });
    await Promise.all([page2.waitForNavigation({ waitUntil: "networkidle0" }), page2.click("#sign-in")]);
    check((await text(page2, "h1")).includes("browsertest"), "a second browser signs in too");
    await Promise.all([page.waitForNavigation({ waitUntil: "networkidle0" }), page.click('form[action="/admin/logout"] button')]);
    check((await text(page, "#sign-in")) === "Sign in with Adena", "signing out returns to the sign-in");
    check(!(await ctx.cookies()).some((c) => c.name === "__Host-autopatch-admin" && c.value), "signing out clears the cookie");
    await page2.reload({ waitUntil: "networkidle0" });
    check((await text(page2, "#sign-in")) === "Sign in with Adena", "signing out ended the second browser's session too");
    const after = await page2.evaluate(async () => {
      const r = await fetch("/admin/policy.json");
      return { url: r.url, signin: (await r.text()).includes("Sign in with Adena") };
    });
    check(after.url.endsWith("/admin") && after.signin, "after signing out, the files send you to sign in");

    // A wallet that isn't an admin is refused, and told so.
    const sctx = await browser.createBrowserContext();
    const strangerPage = await open(sctx, desktop, "light", stranger, "", /status of 403/);
    await strangerPage.goto(BASE + "/admin", { waitUntil: "networkidle0" });
    await strangerPage.click("#sign-in");
    await strangerPage.waitForFunction(() => /not an admin/.test(document.getElementById("status").textContent), { timeout: 10000 });
    check((await text(strangerPage, "#status")).includes(stranger.addr.slice(0, 6)), "a wallet that isn't an admin is refused, by its address");
    check(!(await sctx.cookies()).some((c) => c.name === "__Host-autopatch-admin"), "the refused wallet gets no cookie");
    await shot(strangerPage, "refused-stranger");

    // Adena showing another account than the one the page asked to sign for.
    const mctx = await browser.createBrowserContext();
    const mm = await open(mctx, desktop, "light", admin, "mismatch");
    await mm.goto(BASE + "/admin", { waitUntil: "networkidle0" });
    await mm.click("#sign-in");
    await mm.waitForFunction(() => /selected account/.test(document.getElementById("status").textContent), { timeout: 10000 });
    check((await text(mm, "#status")).includes("Select that account in Adena"), "an Adena on another account is told what to do");

    // No Adena at all.
    const nctx = await browser.createBrowserContext();
    const na = await open(nctx, desktop, "light");
    await na.goto(BASE + "/admin", { waitUntil: "networkidle0" });
    await na.click("#sign-in");
    await na.waitForSelector("#get-adena:not([hidden])", { timeout: 10000 });
    check(true, "a browser without Adena is pointed to it");
    await shot(na, "no-adena");
  } catch (e) {
    console.log("FAILED", e && e.stack ? e.stack : e);
    problems++;
  } finally {
    if (browser) await browser.close();
    server.kill();
    fs.rmSync(dir, { recursive: true, force: true });
  }
  console.log(problems ? `${problems} problem(s)` : "all checks passed");
  process.exit(problems ? 1 : 0);
})();
