// Passkey sign-in, joining by link and "add a passkey". No libraries.
// Buttons carry data-durin="signin" | "join" | "add" | "copy"; messages go to #durin-status.
(function () {
  "use strict";

  const enc = (buf) =>
    btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const dec = (s) => {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
  };
  const say = (msg) => {
    const el = document.getElementById("durin-status");
    if (el) el.textContent = msg;
  };
  const val = (id) => {
    const el = document.getElementById(id);
    return el ? el.value.trim() : "";
  };

  async function post(url, body) {
    const res = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json", "x-csrf-token": document.querySelector("[data-csrf]").dataset.csrf },
      body: JSON.stringify(body),
    });
    let json = {};
    try { json = await res.json(); } catch (_) {}
    return { ok: res.ok, json };
  }

  const reasons = {
    invite: "This link was used, cancelled or has expired.",
    bad_name: "Name: lower-case letters, digits, . _ - only.",
    name_taken: "That name is taken.",
    credential_taken: "That passkey is already registered.",
  };

  async function register(extra) {
    const start = await post("/passkey/register/options", extra);
    if (!start.ok) throw new Error(reasons[start.json.error] || "Could not start. Try again.");
    const o = start.json.options;
    const cred = await navigator.credentials.create({
      publicKey: {
        ...o,
        challenge: dec(o.challenge),
        user: { ...o.user, id: dec(o.user.id) },
        excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: dec(c.id) })),
      },
    });
    const done = await post("/passkey/register/finish", {
      ...extra,
      challenge_id: start.json.challenge_id,
      client_data_json: enc(cred.response.clientDataJSON),
      attestation_object: enc(cred.response.attestationObject),
      label: navigator.platform || "Passkey",
    });
    if (!done.ok) throw new Error(reasons[done.json.error] || "Could not save the passkey.");
  }

  async function signIn() {
    const start = await post("/passkey/login/options", {});
    if (!start.ok) throw new Error("Could not start. Try again.");
    const o = start.json.options;
    const cred = await navigator.credentials.get({ publicKey: { ...o, challenge: dec(o.challenge) } });
    const r = cred.response;
    const remember = document.getElementById("remember");
    const done = await post("/passkey/login/finish", {
      challenge_id: start.json.challenge_id,
      credential_id: enc(cred.rawId),
      client_data_json: enc(r.clientDataJSON),
      authenticator_data: enc(r.authenticatorData),
      signature: enc(r.signature),
      user_handle: r.userHandle ? enc(r.userHandle) : "",
      remember: remember && remember.checked ? "1" : "0",
    });
    if (!done.ok) throw new Error("Sign-in failed.");
  }

  async function run(kind) {
    if (kind === "copy") {
      const box = document.getElementById("invite-link");
      if (box) { box.select(); try { await navigator.clipboard.writeText(box.value); say("Link copied."); } catch (_) { say("Select the link and copy it."); } }
      return;
    }
    if (!window.PublicKeyCredential) return say("This browser does not support passkeys.");
    say("Waiting for your device…");
    try {
      if (kind === "signin") {
        await signIn();
        location.reload(); // keeps ?rd=, so the server sends us on to the app
      } else if (kind === "join") {
        await register({ name: val("join-name"), invite: val("invite-code") });
        location.reload(); // keeps ?rd=; a used ?invite= is ignored once signed in
      } else {
        await register({});
        say("Passkey added.");
        if (window.htmx) htmx.ajax("GET", "/passkeys", { target: "#passkey-list", swap: "outerHTML" });
      }
    } catch (e) {
      say(e && e.name === "NotAllowedError" ? "Cancelled."
        : e && e.name === "InvalidStateError" ? "This device already has a passkey here."
        : (e && e.message) || "Something went wrong.");
    }
  }

  // #invite= is not sent to the proxy, so the code never lands in an access log. Drop it before anything else.
  const hash = new URLSearchParams(location.hash.startsWith("#") ? location.hash.slice(1) : "");
  const invited = (hash.get("invite") || "").trim();
  if (hash.has("invite")) history.replaceState(null, "", location.pathname + location.search);
  if (invited) {
    const block = document.getElementById("join-block");
    const field = document.getElementById("invite-code");
    if (block && field) {
      field.value = invited;
      block.hidden = false;
    }
  }

  document.addEventListener("durin-note", (ev) => say(ev.detail && ev.detail.value));
  document.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-durin]");
    if (btn) {
      ev.preventDefault();
      run(btn.dataset.durin);
    }
  });
})();
