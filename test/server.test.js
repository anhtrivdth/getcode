import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

let baseUrl;
let server;
let tempDirectory;
let adminCookie;
let csrfToken;
let getkeyCookie;
let getkeyCsrfToken;
let accessKeyId;
let publicAccessKey;
const linkedAdminKey = "admin-link-key-0001";
const otherLinkedAdminKey = "other-link-key-0002";

before(async () => {
  tempDirectory = await mkdtemp(path.join(tmpdir(), "netflix-mail-admin-"));
  process.env.ADMIN_USERNAME = "test-admin";
  process.env.ADMIN_PASSWORD = "test-password-12345";
  process.env.DATA_ENCRYPTION_KEY = "test-encryption-key-with-at-least-32-characters";
  process.env.NETFLIX_SESSION_FILE = path.join(tempDirectory, "session.json");
  process.env.ACCESS_KEYS_FILE = path.join(tempDirectory, "access-keys.json");
  process.env.PUBLIC_RATE_LIMIT = "100";

  await writeFile(
    process.env.NETFLIX_SESSION_FILE,
    JSON.stringify({
      activeSessionId: "linked-session",
      sessions: [
        {
          id: "linked-session",
          key: linkedAdminKey,
          cookie: "NetflixId=test-secret-value; SecureNetflixId=second-secret-value",
          cookieFormat: "cookie_header",
          cookieCount: 2,
          rejectedCount: 0,
          updatedAt: new Date().toISOString(),
          lastCheck: null,
          imap: { user: "test@example.com", pass: "test-app-password" },
        },
        {
          id: "other-linked-session",
          key: otherLinkedAdminKey,
          cookie: "",
          cookieFormat: "cookie_header",
          cookieCount: 0,
          rejectedCount: 0,
          updatedAt: new Date().toISOString(),
          lastCheck: null,
          imap: { user: "other@example.com", pass: "other-app-password" },
        },
      ],
    }),
    "utf8"
  );

  const module = await import(`../server.js?test=${Date.now()}`);
  server = await module.startServer({ host: "127.0.0.1", port: 0 });
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  if (tempDirectory) await rm(tempDirectory, { recursive: true, force: true });
});

test("health endpoint is public and returns security headers", async () => {
  const response = await fetch(`${baseUrl}/api/health`);
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.ok, true);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
});

test("admin API rejects missing credentials", async () => {
  const response = await fetch(`${baseUrl}/api/netflix/sessions`);
  assert.equal(response.status, 401);
});

test("admin login rejects invalid credentials", async () => {
  const response = await fetch(`${baseUrl}/api/admin/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "test-admin", password: "wrong-password" }),
  });
  assert.equal(response.status, 401);
});

test("admin login creates an HttpOnly session", async () => {
  const response = await fetch(`${baseUrl}/api/admin/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "test-admin", password: "test-password-12345" }),
  });
  const payload = await response.json();
  const setCookie = response.headers.get("set-cookie") || "";
  assert.equal(response.status, 200);
  assert.equal(payload.authenticated, true);
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /SameSite=Strict/i);
  adminCookie = setCookie.split(";", 1)[0];
  csrfToken = payload.csrfToken;
  assert.ok(adminCookie);
  assert.ok(csrfToken);
});

test("admin API accepts a valid session and does not expose raw secrets", async () => {
  const response = await fetch(`${baseUrl}/api/netflix/sessions`, {
    headers: { Cookie: adminCookie },
  });
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.sessions.length, 2);
  assert.equal(payload.sessions[0].key, linkedAdminKey);
  assert.equal(JSON.stringify(payload).includes("cookie\":"), false);
  assert.equal(JSON.stringify(payload).includes("pass\":"), false);
});

test("getkey uses its own IMAP-linked-key session without an admin password", async () => {
  const invalidFormat = await fetch(`${baseUrl}/api/getkey/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sourceKey: "short" }),
  });
  assert.equal(invalidFormat.status, 400);

  const unlinked = await fetch(`${baseUrl}/api/getkey/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sourceKey: "missing-admin-key-0001" }),
  });
  assert.equal(unlinked.status, 403);

  const response = await fetch(`${baseUrl}/api/getkey/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sourceKey: linkedAdminKey }),
  });
  const payload = await response.json();
  const setCookie = response.headers.get("set-cookie") || "";
  assert.equal(response.status, 200);
  assert.equal(payload.authenticated, true);
  assert.match(setCookie, /^getkey_session=/);
  assert.match(setCookie, /HttpOnly/i);
  getkeyCookie = setCookie.split(";", 1)[0];
  getkeyCsrfToken = payload.csrfToken;
});

test("admin session alone cannot access the key registry", async () => {
  const response = await fetch(`${baseUrl}/api/keys`, {
    headers: { Cookie: adminCookie },
  });
  assert.equal(response.status, 401);
});

test("getkey creates a random public key linked to an Admin key without storing plaintext", async () => {
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const response = await fetch(`${baseUrl}/api/keys`, {
    method: "POST",
    headers: {
      Cookie: getkeyCookie,
      "X-CSRF-Token": getkeyCsrfToken,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      label: "Integration test key",
      expiresAt,
    }),
  });
  const payload = await response.json();
  assert.equal(response.status, 201);
  assert.match(payload.rawKey, /^sk-[A-Za-z0-9_-]{12}$/);
  assert.notEqual(payload.rawKey, linkedAdminKey);
  assert.equal(payload.key.status, "active");
  assert.equal(payload.key.linkedKeyPreview, "admin-lin…-0001");
  accessKeyId = payload.key.id;
  publicAccessKey = payload.rawKey;

  const rawStore = await readFile(path.join(tempDirectory, "access-keys.json"), "utf8");
  const store = JSON.parse(rawStore);
  assert.equal(rawStore.includes(publicAccessKey), false);
  assert.equal(rawStore.includes(linkedAdminKey), false);
  assert.match(store.keys[0].keyHash, /^[a-f0-9]{64}$/);
  assert.match(store.keys[0].linkedSessionKey, /^enc:v1:/);
});

test("key registration requires a future expiry", async () => {
  const response = await fetch(`${baseUrl}/api/keys`, {
    method: "POST",
    headers: {
      Cookie: getkeyCookie,
      "X-CSRF-Token": getkeyCsrfToken,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      label: "Expired key",
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
    }),
  });
  assert.equal(response.status, 400);
});

test("getkey session can rename and extend its active key", async () => {
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  const response = await fetch(`${baseUrl}/api/keys/${encodeURIComponent(accessKeyId)}`, {
    method: "PATCH",
    headers: {
      Cookie: getkeyCookie,
      "X-CSRF-Token": getkeyCsrfToken,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ label: "Extended test key", expiresAt }),
  });
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.key.label, "Extended test key");
  assert.equal(payload.key.expiresAt, expiresAt);
});

test("key registry list never returns the plaintext key", async () => {
  const response = await fetch(`${baseUrl}/api/keys`, {
    headers: { Cookie: getkeyCookie },
  });
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.keys.length, 1);
  assert.equal(JSON.stringify(payload).includes(linkedAdminKey), false);
  assert.match(payload.keys[0].preview, /…/);
  assert.match(payload.keys[0].linkedKeyPreview, /…/);

  const adminResponse = await fetch(`${baseUrl}/api/netflix/sessions`, {
    headers: { Cookie: adminCookie },
  });
  const adminPayload = await adminResponse.json();
  const linkedSession = adminPayload.sessions.find((session) => session.key === linkedAdminKey);
  assert.equal(adminResponse.status, 200);
  assert.deepEqual(linkedSession.accessKeyStats, {
    total: 1,
    active: 1,
    expired: 0,
    revoked: 0,
    usageCount: 0,
  });
});

test("a GetKey session only sees keys belonging to its linked IMAP", async () => {
  const login = await fetch(`${baseUrl}/api/getkey/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sourceKey: otherLinkedAdminKey }),
  });
  const session = await login.json();
  const cookie = (login.headers.get("set-cookie") || "").split(";", 1)[0];
  assert.equal(login.status, 200);

  const response = await fetch(`${baseUrl}/api/keys`, { headers: { Cookie: cookie } });
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.deepEqual(payload.keys, []);

  const logout = await fetch(`${baseUrl}/api/getkey/logout`, {
    method: "POST",
    headers: { Cookie: cookie, "X-CSRF-Token": session.csrfToken },
  });
  assert.equal(logout.status, 200);
});

test("session secrets are encrypted before being persisted", async () => {
  const response = await fetch(`${baseUrl}/api/netflix/session`, {
    method: "POST",
    headers: {
      Cookie: adminCookie,
      "X-CSRF-Token": csrfToken,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      key: linkedAdminKey,
      cookie: "NetflixId=test-secret-value; SecureNetflixId=second-secret-value",
    }),
  });
  assert.equal(response.status, 200);

  const rawStore = await readFile(path.join(tempDirectory, "session.json"), "utf8");
  const store = JSON.parse(rawStore);
  assert.match(store.sessions[0].cookie, /^enc:v1:/);
  assert.equal(rawStore.includes("test-secret-value"), false);
  assert.equal(rawStore.includes("second-secret-value"), false);
  assert.equal(rawStore.includes("test-app-password"), false);
  assert.equal(rawStore.includes("other-app-password"), false);
});

test("admin mutation rejects a missing CSRF token", async () => {
  const response = await fetch(`${baseUrl}/api/netflix/session/select`, {
    method: "POST",
    headers: {
      Cookie: adminCookie,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ sessionId: "missing" }),
  });
  assert.equal(response.status, 403);
});

test("public API validates input without contacting external services", async () => {
  const response = await fetch(`${baseUrl}/api/get-code`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  const payload = await response.json();
  assert.equal(response.status, 400);
  assert.equal(payload.ok, false);
});

test("public API rejects an unregistered key", async () => {
  const response = await fetch(`${baseUrl}/api/get-code`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key: "sk-UnregKey0001", type: "login_code" }),
  });
  const payload = await response.json();
  assert.equal(response.status, 403);
  assert.match(payload.message, /chưa được đăng ký/);
});

test("unknown API returns JSON 404", async () => {
  const response = await fetch(`${baseUrl}/api/not-found`);
  assert.equal(response.status, 404);
  assert.match(response.headers.get("content-type") || "", /application\/json/);
});

test("revoked key is rejected immediately", async () => {
  const listResponse = await fetch(`${baseUrl}/api/keys`, {
    headers: { Cookie: getkeyCookie },
  });
  const listPayload = await listResponse.json();
  const keyId = listPayload.keys[0].id;
  const revoke = await fetch(`${baseUrl}/api/keys/${encodeURIComponent(keyId)}`, {
    method: "DELETE",
    headers: { Cookie: getkeyCookie, "X-CSRF-Token": getkeyCsrfToken },
  });
  assert.equal(revoke.status, 200);

  const useRevoked = await fetch(`${baseUrl}/api/get-code`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key: publicAccessKey, type: "login_code" }),
  });
  const payload = await useRevoked.json();
  assert.equal(useRevoked.status, 403);
  assert.match(payload.message, /thu hồi/);
});

test("getkey logout invalidates only the key-management session", async () => {
  const logout = await fetch(`${baseUrl}/api/getkey/logout`, {
    method: "POST",
    headers: { Cookie: getkeyCookie, "X-CSRF-Token": getkeyCsrfToken },
  });
  assert.equal(logout.status, 200);

  const afterLogout = await fetch(`${baseUrl}/api/keys`, {
    headers: { Cookie: getkeyCookie },
  });
  assert.equal(afterLogout.status, 401);

  const adminStillActive = await fetch(`${baseUrl}/api/netflix/sessions`, {
    headers: { Cookie: adminCookie },
  });
  assert.equal(adminStillActive.status, 200);
});

test("logout invalidates the admin session", async () => {
  const logout = await fetch(`${baseUrl}/api/admin/logout`, {
    method: "POST",
    headers: { Cookie: adminCookie, "X-CSRF-Token": csrfToken },
  });
  assert.equal(logout.status, 200);

  const afterLogout = await fetch(`${baseUrl}/api/netflix/sessions`, {
    headers: { Cookie: adminCookie },
  });
  assert.equal(afterLogout.status, 401);
});
