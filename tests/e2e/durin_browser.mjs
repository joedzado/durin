// End-to-end test of Durin through a real proxy, in a headless Chromium with a virtual authenticator.
// No dependencies (Node 22+). Chromium sends every *.<suffix> host to the proxy's address and trusts
// the proxy's certificate by its public key (pass the intermediate, or a self-signed leaf; Chromium
// ignores the flag for a root), so this needs no DNS or keychain changes.
//
//   DURIN_SETUP_CODE=... DURIN_AUTH_HOST=auth.example.com E2E_APPS=a.example.com,b.example.com,c.example.com \
//     node tests/e2e/durin_browser.mjs <chromium> <cert.pem> [proxy address[:port], default 127.0.0.1]
//
// E2E_APPS: three gated app hosts behind the proxy (the third only gets a forged code, from a stranger).
// Run against an empty Durin database: it creates the first account (owner) and an invited one.
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [, , CHROME, CA_CRT, ADDR = "127.0.0.1"] = process.argv;
const SETUP = process.env.DURIN_SETUP_CODE || "";
const AUTH = process.env.DURIN_AUTH_HOST || "";
const [APP1, APP2, APP3] = (process.env.E2E_APPS || "").split(",");
if (!AUTH || !APP3) { console.log("set DURIN_AUTH_HOST and E2E_APPS (three hosts)"); process.exit(2); }
const SUFFIX = AUTH.slice(AUTH.indexOf(".") + 1);
const DEBUG_PORT = 9334;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
const check = (ok, what, extra = "") => { console.log(`${ok ? "PASS" : "FAIL"}  ${what}${extra ? "  " + extra : ""}`); if (!ok) failures++; };

const spki = execFileSync("sh", ["-c",
  `openssl x509 -in "${CA_CRT}" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`]).toString().trim();
const profile = mkdtempSync(join(tmpdir(), "durin-e2e-"));
const chrome = spawn(CHROME, ["--headless=new", `--remote-debugging-port=${DEBUG_PORT}`, `--user-data-dir=${profile}`,
  "--no-first-run", "--no-default-browser-check", "--disable-gpu",
  `--host-resolver-rules=MAP *.${SUFFIX} ${ADDR}`, `--ignore-certificate-errors-spki-list=${spki}`, "about:blank"], { stdio: "ignore" });

async function connect() {
  for (let i = 0; i < 50; i++) {
    try { return (await (await fetch(`http://127.0.0.1:${DEBUG_PORT}/json/version`)).json()).webSocketDebuggerUrl; } catch { await sleep(200); }
  }
  throw new Error("Chrome did not start");
}
const ws = new WebSocket(await connect());
await new Promise((r) => (ws.onopen = r));
let nextId = 1; const pending = new Map();
let onPaused = null;
ws.onmessage = (m) => {
  const msg = JSON.parse(m.data);
  if (msg.method === "Fetch.requestPaused" && onPaused) onPaused(msg.params);
  if (msg.id && pending.has(msg.id)) { const { res, rej } = pending.get(msg.id); pending.delete(msg.id); msg.error ? rej(new Error(JSON.stringify(msg.error))) : res(msg.result); }
};
const send = (method, params = {}, sessionId) => new Promise((res, rej) => {
  const id = nextId++; pending.set(id, { res, rej });
  ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
});
const { targetId } = await send("Target.createTarget", { url: "about:blank" });
const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
const cdp = (m, p) => send(m, p, sessionId);
await cdp("Page.enable"); await cdp("Runtime.enable"); await cdp("Network.enable"); await cdp("WebAuthn.enable");
const { authenticatorId } = await cdp("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal",
  hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });

const ev = async (expr) => {
  const r = await cdp("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.text + " " + JSON.stringify(r.exceptionDetails.exception?.description));
  return r.result.value;
};
const here = async () => { try { return await ev("location.host + location.pathname"); } catch { return ""; } };
const until = async (expr, what, ms = 10000) => {
  const t = Date.now();
  while (Date.now() - t < ms) { try { if (await ev(expr)) return true; } catch {} await sleep(150); }
  console.log("  timed out waiting for:", what, "at", await here()); return false;
};
const goto = async (url) => { await cdp("Page.navigate", { url }); await sleep(300); await until(`document.readyState === "complete"`, "load"); };
const cookies = async (url) => (await cdp("Network.getCookies", { urls: [url] })).cookies;
const status = () => ev(`document.getElementById("durin-status")?.textContent ?? ""`);

try {
  // 1. An app host sends a stranger to the auth host, carrying the address
  await goto(`https://${APP1}/review?x=1`);
  check(await ev("location.host") === `${AUTH}`, `${APP1} without a session lands on ${AUTH}`, await here());
  check((await ev("location.search")).includes(encodeURIComponent(`https://${APP1}/review?x=1`)), "with the original address in rd");
  check(await ev(`typeof PublicKeyCredential === "function"`), `${AUTH} is a secure context with WebAuthn (cert trusted)`);

  // 2. Sign-up needs the setup code
  check(await ev(`!!document.querySelector("[data-durin=setup]")`), "empty database: setup form shown");
  check(await ev(`document.getElementById("setup-name").value`) === "", "the first-account form has no preset name");
  await ev(`document.getElementById("setup-name").value = "owner"`);
  await ev(`document.getElementById("setup-code").value = "wrong"`);
  await ev(`document.querySelector("[data-durin=setup]").click()`);
  await until(`document.getElementById("durin-status").textContent.includes("setup code")`, "wrong code message");
  check((await status()).includes("Wrong setup code"), "a wrong setup code is refused", `status="${await status()}"`);
  check((await cdp("WebAuthn.getCredentials", { authenticatorId })).credentials.length === 0, "and no passkey was made");

  // 3. First account, then straight on to the app
  await ev(`document.getElementById("setup-code").value = ${JSON.stringify(SETUP)}`);
  await ev(`document.querySelector("[data-durin=setup]").click()`);
  check(await until(`location.host === "${APP1}"`, `back on ${APP1}`), `creating the passkey signs in and returns to ${APP1}`, await here());
  check(await ev("location.pathname + location.search") === "/review?x=1", "at the original path", await ev("location.pathname + location.search"));
  const fc = (await cookies(`https://${APP1}/`)).find((c) => c.name === "__Host-durin");
  check(!!fc && fc.secure && fc.httpOnly && fc.domain === `${APP1}` && fc.session, `${APP1} has a host-only Secure HttpOnly session cookie`, JSON.stringify(fc && { d: fc.domain, s: fc.secure, h: fc.httpOnly, session: fc.session }));
  check(!(await cookies(`https://${APP1}/`)).some((c) => c.name === "_csrf"), "no Durin CSRF cookie planted on the app host");

  // 4. One sign-in covers a second app, with no prompt
  await goto(`https://${APP2}/`);
  check(await until(`location.host === "${APP2}"`, `on ${APP2}`), `${APP2} opens without signing in again`, await here());
  check(await ev(`document.title`) !== "Sign in", "and shows the app", await ev("document.title"));

  // 5. The account page lists both, and refuses an open redirect
  await goto(`https://${AUTH}/`);
  check(await ev(`document.body.innerText.includes("Signed in as owner")`), `${AUTH} shows the signed-in user`);
  check(await ev(`document.body.innerText.includes("${APP1}") && document.body.innerText.includes("${APP2}")`), "lists the apps opened");
  const hdrs = await ev(`fetch(location.href).then((r) => [r.headers.get("cache-control"), r.headers.get("referrer-policy"), r.headers.get("x-frame-options"), (r.headers.get("content-security-policy") || "").includes("frame-ancestors 'none'")].join("|"))`);
  check(hdrs === "no-store|no-referrer|DENY|true", "pages are not cached, framed or sent as a referrer", hdrs);
  await goto(`https://${AUTH}/?rd=` + encodeURIComponent("https://evil.example/"));
  check(await ev("location.host") === `${AUTH}`, "rd to another domain is ignored", await here());
  await goto(`https://${AUTH}/?rd=` + encodeURIComponent(`https://${APP1}@evil.example/`));
  check(await ev("location.host") === `${AUTH}`, "rd with userinfo is ignored", await here());

  // 7. Sign out ends every app session
  await goto(`https://${AUTH}/`);
  await ev(`[...document.querySelectorAll("form button, form input[type=submit]")].find((b) => (b.textContent || b.value) === "Sign out").click()`);
  await until(`document.querySelector("[data-durin=signin]")`, "sign-in page");
  await goto(`https://${APP1}/`);
  check(await ev("location.host") === `${AUTH}`, `after sign-out, ${APP1}'s old cookie no longer works`, await here());

  // 8. Sign in with the passkey, remembered
  check(!(await ev(`!!document.querySelector("[data-durin=setup]")`)), "setup form gone once an account exists");
  await ev(`document.getElementById("remember").checked = true`);
  const before = (await cdp("WebAuthn.getCredentials", { authenticatorId })).credentials[0]?.signCount ?? -1;
  await ev(`document.querySelector("[data-durin=signin]").click()`);
  check(await until(`location.host === "${APP1}"`, `back on ${APP1}`), `passkey sign-in returns to ${APP1}`, `${await here()} status="${await status().catch(() => "")}"`);
  const fc2 = (await cookies(`https://${APP1}/`)).find((c) => c.name === "__Host-durin");
  check(!!fc2 && !fc2.session && fc2.expires - Date.now() / 1000 > 20 * 86400, "remember me: the app cookie lasts weeks", fc2 && String(Math.round((fc2.expires - Date.now() / 1000) / 86400)) + " days");
  const after = (await cdp("WebAuthn.getCredentials", { authenticatorId })).credentials[0]?.signCount ?? -1;
  check(after > before, "authenticator counter advanced", `${before} -> ${after}`);

  // 9. Owner controls: the first account is the owner, invites make one account each, owners remove people
  await goto(`https://${AUTH}/`);
  check(await ev(`!!document.getElementById("owner-panel")`), "the first account is the owner (owner panel shown)");
  await ev(`[...document.querySelectorAll("#owner-panel button")].find((b) => b.textContent === "New invite link").click()`);
  await until(`document.getElementById("invite-link")`, "invite link");
  const link = await ev(`document.getElementById("invite-link").value`);
  check(link.startsWith(`https://${AUTH}/?invite=`), "owner gets an invite link", link.slice(0, 32) + "…");

  // A second, separate browser (its own cookies and authenticator) for the invited person
  const { browserContextId } = await send("Target.createBrowserContext");
  const g = await send("Target.createTarget", { url: "about:blank", browserContextId });
  const gsid = (await send("Target.attachToTarget", { targetId: g.targetId, flatten: true })).sessionId;
  const gcdp = (m, p) => send(m, p, gsid);
  await gcdp("Page.enable"); await gcdp("Runtime.enable"); await gcdp("WebAuthn.enable");
  await gcdp("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal",
    hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  const gev = async (expr) => {
    const r = await gcdp("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text + " " + JSON.stringify(r.exceptionDetails.exception?.description));
    return r.result.value;
  };
  const guntil = async (expr, what, ms = 10000) => {
    const t = Date.now();
    while (Date.now() - t < ms) { try { if (await gev(expr)) return true; } catch {} await sleep(150); }
    console.log("  timed out waiting for:", what); return false;
  };
  const ggoto = async (url) => { await gcdp("Page.navigate", { url }); await sleep(300); await guntil(`document.readyState === "complete"`, "load"); };
  const gpost = (url, body) => gev(`fetch(${JSON.stringify(url)}, { method: "POST", headers: { "content-type": "application/json",
    "x-csrf-token": document.querySelector("[data-csrf]").dataset.csrf }, body: ${JSON.stringify(JSON.stringify(body))} }).then((r) => r.status)`);

  await gcdp("Network.enable");
  await ggoto(`https://${APP3}/.durin/callback?code=madeup&rd=/`);
  check(await gev("location.host") === AUTH, "a forged code sends a stranger to sign in", await gev("location.host"));
  check((await gcdp("Network.getCookies", { urls: [`https://${APP3}/`] })).cookies.every((c) => c.name !== "__Host-durin"), "and sets no cookie");
  await ggoto(`https://${AUTH}/`);
  check(!(await gev(`!!document.querySelector("[data-durin=setup], [data-durin=join]")`)), "no sign-up form without an invite");
  check(await gpost("/passkey/register/options", { name: "late", setup_code: SETUP }) === 403, "the setup code no longer makes accounts");
  check(await gpost("/passkey/register/options", { name: "late", invite: "forged" }) === 403, "a forged invite is refused");
  await ggoto(link);
  check(await gev(`!!document.querySelector("[data-durin=join]")`), "the invite link shows the new-account form");
  await gev(`document.getElementById("setup-name").value = "guest"`);
  await gev(`document.querySelector("[data-durin=join]").click()`);
  check(await guntil(`document.querySelector("h1")?.textContent === "Signed in as guest"`, "guest signed in"), "the invite makes an account and signs it in");
  check(!(await gev(`!!document.getElementById("owner-panel")`)), "an invited account is not an owner");
  check(await gpost("/people/invite", {}) === 403, "a non-owner cannot make invites");

  await gcdp("Network.clearBrowserCookies");
  await ggoto(link);
  check(await gev(`document.body.textContent.includes("was used")`), "an invite works only once");

  // A code made for one browser's nonce does not sign another browser in (login CSRF): hold back the
  // hand-off the signed-in owner's browser is sent on, and open it in the signed-out guest's browser.
  const caught = [];
  onPaused = (p) => { caught.push(p.request.url); send("Fetch.failRequest", { requestId: p.requestId, errorReason: "Aborted" }, sessionId); };
  await cdp("Fetch.enable", { patterns: [{ urlPattern: "*/.durin/callback*", requestStage: "Request" }] });
  await cdp("Page.navigate", { url: `https://${AUTH}/?rd=${encodeURIComponent(`https://${APP3}/x`)}&n=${"a".repeat(64)}` });
  for (let i = 0; i < 40 && caught.length === 0; i++) await sleep(150);
  await cdp("Fetch.disable"); onPaused = null;
  check(caught.length === 1 && caught[0].startsWith(`https://${APP3}/.durin/callback?code=`), "a signed-in browser is handed a code for the nonce hash it was given", caught[0]);
  await ggoto(caught[0]);
  check(await gev("location.host") === AUTH, "that code signs nobody in elsewhere: the other browser lands on sign-in", await gev("location.host"));
  check((await gcdp("Network.getCookies", { urls: [`https://${APP3}/`] })).cookies.every((c) => c.name !== "__Host-durin"), "and gets no session cookie");

  await goto(`https://${AUTH}/`);
  check(await ev(`document.getElementById("owner-panel").textContent.includes("guest")`), "the owner sees the new account");
  await ev(`window.confirm = () => true`);
  await ev(`[...document.querySelectorAll("#owner-panel .row")].find((r) => r.textContent.includes("guest")).querySelector("button").click()`);
  check(await until(`!document.getElementById("owner-panel").textContent.includes("guest")`, "guest gone"), "the owner removes the account");
  check(!(await ev(`[...document.querySelectorAll("#owner-panel .row")].some((r) => r.textContent.includes("owner") && r.querySelector("button"))`)),
    "the owner's own row has no Remove button");
  await send("Target.disposeBrowserContext", { browserContextId });
} catch (e) {
  console.log("ERROR", e.message); failures++;
} finally {
  ws.close(); chrome.kill();
}
console.log(failures === 0 ? "ALL DURIN CHECKS PASSED" : `${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
