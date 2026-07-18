import express from "express";
import "dotenv/config";
import helmet from "helmet";
import { rateLimit } from "express-rate-limit";
import path from "path";
import { fileURLToPath } from "url";
import { mkdir, readFile, rename, unlink, writeFile } from "fs/promises";
import { createHash, randomBytes, randomUUID, timingSafeEqual, createCipheriv, createDecipheriv } from "crypto";
import { ImapFlow } from "imapflow";
import { simpleParser } from "mailparser";

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const NETFLIX_SESSION_FILE = path.resolve(
  __dirname,
  process.env.NETFLIX_SESSION_FILE || path.join("data", "netflix-session.json")
);
const ACCESS_KEYS_FILE = path.resolve(
  __dirname,
  process.env.ACCESS_KEYS_FILE || path.join("data", "access-keys.json")
);
const ADMIN_USERNAME = String(process.env.ADMIN_USERNAME || "admin").trim();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "");
const DATA_ENCRYPTION_KEY = String(process.env.DATA_ENCRYPTION_KEY || "");
const SECRET_PREFIX = "enc:v1";
const ADMIN_SESSION_COOKIE = "admin_session";
const ADMIN_SESSION_TTL_MS = Math.max(
  15 * 60 * 1000,
  Number(process.env.ADMIN_SESSION_HOURS || 8) * 60 * 60 * 1000
);
const ADMIN_COOKIE_SECURE = process.env.ADMIN_COOKIE_SECURE === "true";
const adminSessions = new Map();
const GETKEY_SESSION_COOKIE = "getkey_session";
const getkeySessions = new Map();
const NETFLIX_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
const NETFLIX_ACCEPT =
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";

const DEFAULT_IMAP = {
  host: process.env.IMAP_HOST || "imap.gmail.com",
  port: Number(process.env.IMAP_PORT || 993),
  secure: process.env.IMAP_SECURE
    ? process.env.IMAP_SECURE !== "false"
    : true,
};

const LABEL_TYPE = {
  HOME_UPDATE: "home_update",
  TEMP_ACCESS: "temp_access",
  LOGIN_CODE: "login_code",
};
const TV_CODE_INVALID_OR_USED_MESSAGE =
  "Mã TV không đúng hoặc đã được sử dụng. Vui lòng thử lại.\nLưu ý: liên hệ seller nếu bạn chắc chắn mã nhập đúng nhưng vẫn lỗi.";

const netflixStore = {
  activeSessionId: null,
  sessions: [],
};
const accessKeyStore = { keys: [] };

app.disable("x-powered-by");
if (process.env.TRUST_PROXY === "true") app.set("trust proxy", 1);
app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'", "https://fonts.googleapis.com"],
        "font-src": ["'self'", "https://fonts.gstatic.com", "data:"],
        "connect-src": ["'self'"],
        "img-src": ["'self'", "data:"],
        "object-src": ["'none'"],
        "base-uri": ["'self'"],
        "frame-ancestors": ["'none'"],
      },
    },
    referrerPolicy: { policy: "no-referrer" },
  })
);
app.use(express.json({ limit: "1mb" }));
app.use("/api", (_req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: Number(process.env.ADMIN_RATE_LIMIT || 500),
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { ok: false, message: "Quá nhiều yêu cầu quản trị. Vui lòng thử lại sau." },
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: Number(process.env.ADMIN_LOGIN_RATE_LIMIT || 10),
  standardHeaders: "draft-8",
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { ok: false, message: "Đăng nhập sai quá nhiều lần. Vui lòng thử lại sau." },
});

const publicApiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: Number(process.env.PUBLIC_RATE_LIMIT || 30),
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { ok: false, message: "Bạn thao tác quá nhanh. Vui lòng thử lại sau." },
});

function safeEqual(left, right) {
  const leftHash = createHash("sha256").update(String(left)).digest();
  const rightHash = createHash("sha256").update(String(right)).digest();
  return timingSafeEqual(leftHash, rightHash);
}

function hashSessionToken(token) {
  return createHash("sha256").update(String(token || "")).digest("hex");
}

function readCookie(req, name) {
  const header = String(req.headers.cookie || "");
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(separator + 1).trim());
    } catch {
      return "";
    }
  }
  return "";
}

function sessionCookie(value, maxAgeSeconds, name = ADMIN_SESSION_COOKIE) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`,
  ];
  if (ADMIN_COOKIE_SECURE) parts.push("Secure");
  return parts.join("; ");
}

function pruneAdminSessions() {
  const now = Date.now();
  for (const [key, session] of adminSessions) {
    if (session.expiresAt <= now) adminSessions.delete(key);
  }
}

function createAdminSession() {
  pruneAdminSessions();
  const token = randomBytes(32).toString("base64url");
  const csrfToken = randomBytes(24).toString("base64url");
  const expiresAt = Date.now() + ADMIN_SESSION_TTL_MS;
  adminSessions.set(hashSessionToken(token), {
    username: ADMIN_USERNAME,
    csrfToken,
    expiresAt,
  });
  return { token, csrfToken, expiresAt };
}

function createGetkeySession(linkedSessionKey) {
  const token = randomBytes(32).toString("base64url");
  const csrfToken = randomBytes(24).toString("base64url");
  const expiresAt = Date.now() + ADMIN_SESSION_TTL_MS;
  getkeySessions.set(hashSessionToken(token), { linkedSessionKey, csrfToken, expiresAt });
  return { token, csrfToken, expiresAt };
}

function getAdminSession(req) {
  const token = readCookie(req, ADMIN_SESSION_COOKIE);
  if (!token) return null;
  const tokenHash = hashSessionToken(token);
  const session = adminSessions.get(tokenHash);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    adminSessions.delete(tokenHash);
    return null;
  }
  return { ...session, tokenHash };
}

function getGetkeySession(req) {
  const token = readCookie(req, GETKEY_SESSION_COOKIE);
  if (!token) return null;
  const tokenHash = hashSessionToken(token);
  const session = getkeySessions.get(tokenHash);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    getkeySessions.delete(tokenHash);
    return null;
  }
  return { ...session, tokenHash };
}

function requireAdmin(req, res, next) {
  const session = getAdminSession(req);
  if (!session) return res.status(401).json({ ok: false, message: "Phiên quản trị đã hết hạn hoặc chưa đăng nhập." });
  req.adminSession = session;
  return next();
}

function requireCsrf(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const submitted = String(req.headers["x-csrf-token"] || "");
  if (!req.adminSession || !safeEqual(submitted, req.adminSession.csrfToken)) {
    return res.status(403).json({ ok: false, message: "CSRF token không hợp lệ. Hãy tải lại trang." });
  }
  return next();
}

function requireGetkey(req, res, next) {
  const session = getGetkeySession(req);
  if (!session) return res.status(401).json({ ok: false, message: "Phiên quản lý key đã hết hạn hoặc chưa đăng nhập." });
  req.getkeySession = session;
  return next();
}

function requireGetkeyCsrf(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const submitted = String(req.headers["x-csrf-token"] || "");
  if (!req.getkeySession || !safeEqual(submitted, req.getkeySession.csrfToken)) {
    return res.status(403).json({ ok: false, message: "CSRF token quản lý key không hợp lệ." });
  }
  return next();
}

function encryptionKey() {
  if (!DATA_ENCRYPTION_KEY) return null;
  return createHash("sha256").update(DATA_ENCRYPTION_KEY).digest();
}

function encryptSecret(value) {
  const plaintext = String(value || "");
  if (!plaintext) return "";
  const key = encryptionKey();
  if (!key) throw new Error("Server chưa cấu hình DATA_ENCRYPTION_KEY.");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [SECRET_PREFIX, iv.toString("base64url"), tag.toString("base64url"), encrypted.toString("base64url")].join(":");
}

function decryptSecret(value) {
  const stored = String(value || "");
  if (!stored || !stored.startsWith(`${SECRET_PREFIX}:`)) return stored;
  const key = encryptionKey();
  if (!key) throw new Error("Cần DATA_ENCRYPTION_KEY để đọc dữ liệu session đã mã hóa.");
  const parts = stored.split(":");
  if (parts.length !== 5) throw new Error("Dữ liệu session mã hóa không đúng định dạng.");
  const iv = Buffer.from(parts[2], "base64url");
  const tag = Buffer.from(parts[3], "base64url");
  const encrypted = Buffer.from(parts[4], "base64url");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
}

function hashAccessKey(value) {
  return createHash("sha256").update(String(value || "")).digest("hex");
}

function normalizeAccessKey(value) {
  return String(value || "").trim();
}

function isValidAccessKey(value) {
  return /^sk-[A-Za-z0-9_-]{12}$/.test(normalizeAccessKey(value));
}

function accessKeyPreview(value) {
  const key = String(value || "");
  if (key.length <= 14) return `${key.slice(0, 4)}…`;
  return `${key.slice(0, 9)}…${key.slice(-5)}`;
}

function accessKeyStatus(entry, now = Date.now()) {
  if (entry.revokedAt) return "revoked";
  if (new Date(entry.expiresAt).getTime() <= now) return "expired";
  return "active";
}

function buildAccessKeySummary(entry) {
  return {
    id: entry.id,
    label: entry.label,
    preview: entry.preview,
    linkedKeyPreview: accessKeyPreview(entry.linkedSessionKey),
    status: accessKeyStatus(entry),
    createdAt: entry.createdAt,
    expiresAt: entry.expiresAt,
    revokedAt: entry.revokedAt || null,
    lastUsedAt: entry.lastUsedAt || null,
    usageCount: Number(entry.usageCount) || 0,
  };
}

function validateRegisteredAccessKey(value) {
  const key = normalizeAccessKey(value);
  if (!isValidAccessKey(key)) {
    return { ok: false, message: "Access Key phải có dạng sk- và 12 ký tự ngẫu nhiên." };
  }
  const entry = accessKeyStore.keys.find((item) => item.keyHash === hashAccessKey(key));
  if (!entry) return { ok: false, message: "Access Key chưa được đăng ký." };
  const status = accessKeyStatus(entry);
  if (status === "expired") return { ok: false, message: "Key đã hết hạn sử dụng." };
  if (status === "revoked") return { ok: false, message: "Key đã bị admin thu hồi." };
  return { ok: true, key, entry };
}

let accessKeySaveQueue = Promise.resolve();

async function persistAccessKeysToDisk() {
  await mkdir(path.dirname(ACCESS_KEYS_FILE), { recursive: true });
  const temporaryFile = `${ACCESS_KEYS_FILE}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  const payload = {
    version: 2,
    keys: accessKeyStore.keys.map((entry) => ({
      ...entry,
      linkedSessionKey: encryptSecret(entry.linkedSessionKey),
    })),
  };
  try {
    await writeFile(temporaryFile, JSON.stringify(payload, null, 2), {
      encoding: "utf8",
      mode: 0o600,
    });
    await rename(temporaryFile, ACCESS_KEYS_FILE);
  } catch (error) {
    await unlink(temporaryFile).catch(() => {});
    throw error;
  }
}

function saveAccessKeysToDisk() {
  const task = accessKeySaveQueue.then(() => persistAccessKeysToDisk());
  accessKeySaveQueue = task.catch(() => {});
  return task;
}

async function loadAccessKeysFromDisk() {
  try {
    const parsed = JSON.parse(await readFile(ACCESS_KEYS_FILE, "utf8"));
    accessKeyStore.keys = Array.isArray(parsed?.keys)
      ? parsed.keys
          .filter((entry) => entry && typeof entry.keyHash === "string")
          .map((entry) => ({
            id: String(entry.id || randomUUID()),
            label: normalizeText(entry.label, 80) || "Không có tên",
            keyHash: String(entry.keyHash),
            preview: String(entry.preview || "key…"),
            linkedSessionKey: normalizeSessionKey(decryptSecret(entry.linkedSessionKey)),
            createdAt: String(entry.createdAt || new Date().toISOString()),
            expiresAt: String(entry.expiresAt || new Date(0).toISOString()),
            revokedAt: entry.revokedAt ? String(entry.revokedAt) : null,
            lastUsedAt: entry.lastUsedAt ? String(entry.lastUsedAt) : null,
            usageCount: Number(entry.usageCount) || 0,
          }))
      : [];
  } catch (error) {
    if (error?.code === "ENOENT") {
      accessKeyStore.keys = [];
      return;
    }
    throw new Error(`Không thể đọc dữ liệu access key: ${error?.message || error}`);
  }
}

async function markAccessKeyUsed(entry) {
  entry.lastUsedAt = new Date().toISOString();
  entry.usageCount = (Number(entry.usageCount) || 0) + 1;
  await saveAccessKeysToDisk();
}

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "netflix-mail-admin", uptimeSeconds: Math.floor(process.uptime()) });
});

app.post("/api/admin/login", loginLimiter, (req, res) => {
  if (!ADMIN_PASSWORD) {
    return res.status(503).json({ ok: false, message: "Server chưa cấu hình ADMIN_PASSWORD." });
  }
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  if (!safeEqual(username, ADMIN_USERNAME) || !safeEqual(password, ADMIN_PASSWORD)) {
    return res.status(401).json({ ok: false, message: "Tên đăng nhập hoặc mật khẩu không đúng." });
  }
  const session = createAdminSession();
  res.set("Set-Cookie", sessionCookie(session.token, ADMIN_SESSION_TTL_MS / 1000));
  return res.json({
    ok: true,
    authenticated: true,
    username: ADMIN_USERNAME,
    csrfToken: session.csrfToken,
    expiresAt: new Date(session.expiresAt).toISOString(),
  });
});

app.get("/api/admin/session", (req, res) => {
  const session = getAdminSession(req);
  if (!session) return res.json({ ok: true, authenticated: false });
  return res.json({
    ok: true,
    authenticated: true,
    username: session.username,
    csrfToken: session.csrfToken,
    expiresAt: new Date(session.expiresAt).toISOString(),
  });
});

app.post("/api/admin/logout", requireAdmin, requireCsrf, (req, res) => {
  adminSessions.delete(req.adminSession.tokenHash);
  res.set("Set-Cookie", sessionCookie("", 0));
  return res.json({ ok: true, authenticated: false });
});

app.post("/api/getkey/login", loginLimiter, (req, res) => {
  const sourceKey = normalizeSessionKey(req.body?.sourceKey);
  if (!isValidSessionKey(sourceKey)) {
    return res.status(400).json({ ok: false, message: "Key liên kết IMAP/Netflix phải có từ 16 đến 80 ký tự." });
  }
  const linkedSession = getSessionByKey(sourceKey);
  if (!linkedSession?.imap?.user || !linkedSession?.imap?.pass) {
    return res.status(403).json({ ok: false, message: "Key này chưa được liên kết với IMAP trong Admin." });
  }
  const session = createGetkeySession(sourceKey);
  const cookie = sessionCookie(session.token, ADMIN_SESSION_TTL_MS / 1000, GETKEY_SESSION_COOKIE);
  res.set("Set-Cookie", cookie);
  return res.json({
    ok: true,
    authenticated: true,
    linkedKeyPreview: accessKeyPreview(sourceKey),
    csrfToken: session.csrfToken,
    expiresAt: new Date(session.expiresAt).toISOString(),
  });
});

app.get("/api/getkey/session", (req, res) => {
  const session = getGetkeySession(req);
  if (!session) return res.json({ ok: true, authenticated: false });
  return res.json({
    ok: true,
    authenticated: true,
    linkedKeyPreview: accessKeyPreview(session.linkedSessionKey),
    csrfToken: session.csrfToken,
    expiresAt: new Date(session.expiresAt).toISOString(),
  });
});

app.post("/api/getkey/logout", requireGetkey, requireGetkeyCsrf, (req, res) => {
  getkeySessions.delete(req.getkeySession.tokenHash);
  const cookie = sessionCookie("", 0, GETKEY_SESSION_COOKIE);
  res.set("Set-Cookie", cookie);
  return res.json({ ok: true, authenticated: false });
});

app.use(["/api/imap", "/api/netflix"], adminLimiter, requireAdmin, requireCsrf);
app.use("/api/keys", adminLimiter, requireGetkey, requireGetkeyCsrf);
app.use(["/api/get-code", "/api/submit-tv-code"], publicApiLimiter);

app.get("/api/keys", (req, res) => {
  const keys = accessKeyStore.keys
    .filter((entry) => normalizeSessionLookupKey(entry.linkedSessionKey) === normalizeSessionLookupKey(req.getkeySession.linkedSessionKey))
    .map((entry) => buildAccessKeySummary(entry))
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  return res.json({ ok: true, keys });
});

app.post("/api/keys", async (req, res) => {
  const label = normalizeText(req.body?.label, 80);
  const sourceKey = req.getkeySession.linkedSessionKey;
  const expiresAtMs = new Date(req.body?.expiresAt).getTime();
  if (!label) return res.status(400).json({ ok: false, message: "Vui lòng nhập tên hoặc ghi chú cho key." });
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {
    return res.status(400).json({ ok: false, message: "Hạn sử dụng phải là thời điểm trong tương lai." });
  }
  if (!isValidSessionKey(sourceKey)) {
    return res.status(400).json({ ok: false, message: "Key liên kết từ Admin phải có từ 16 đến 80 ký tự." });
  }
  const linkedSession = getSessionByKey(sourceKey);
  if (!linkedSession) {
    return res.status(404).json({ ok: false, message: "Không tìm thấy tài khoản được liên kết với key Admin này." });
  }
  if (!linkedSession.imap?.user || !linkedSession.imap?.pass) {
    return res.status(400).json({ ok: false, message: "Key Admin này chưa được cấu hình IMAP." });
  }

  const rawKey = `sk-${randomBytes(9).toString("base64url")}`;
  const keyHash = hashAccessKey(rawKey);
  if (accessKeyStore.keys.some((entry) => entry.keyHash === keyHash)) {
    return res.status(409).json({ ok: false, message: "Key này đã được đăng ký trước đó." });
  }
  const entry = {
    id: randomUUID(),
    label,
    keyHash,
    preview: accessKeyPreview(rawKey),
    linkedSessionKey: sourceKey,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(expiresAtMs).toISOString(),
    revokedAt: null,
    lastUsedAt: null,
    usageCount: 0,
  };
  accessKeyStore.keys.push(entry);
  await saveAccessKeysToDisk();
  return res.status(201).json({
    ok: true,
    key: buildAccessKeySummary(entry),
    rawKey,
    message: "Đã tạo Access Key ngẫu nhiên. Giá trị đầy đủ chỉ được trả về trong lần này.",
  });
});

app.patch("/api/keys/:keyId", async (req, res) => {
  const entry = accessKeyStore.keys.find(
    (item) => item.id === String(req.params.keyId || "") &&
      normalizeSessionLookupKey(item.linkedSessionKey) === normalizeSessionLookupKey(req.getkeySession.linkedSessionKey)
  );
  if (!entry) return res.status(404).json({ ok: false, message: "Không tìm thấy key." });
  if (entry.revokedAt) return res.status(409).json({ ok: false, message: "Key đã thu hồi không thể kích hoạt lại." });
  const label = normalizeText(req.body?.label, 80);
  const expiresAtMs = new Date(req.body?.expiresAt).getTime();
  if (!label) return res.status(400).json({ ok: false, message: "Tên key không được để trống." });
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {
    return res.status(400).json({ ok: false, message: "Hạn sử dụng mới phải ở trong tương lai." });
  }
  entry.label = label;
  entry.expiresAt = new Date(expiresAtMs).toISOString();
  await saveAccessKeysToDisk();
  return res.json({ ok: true, key: buildAccessKeySummary(entry), message: "Đã cập nhật key." });
});

app.delete("/api/keys/:keyId", async (req, res) => {
  const entry = accessKeyStore.keys.find(
    (item) => item.id === String(req.params.keyId || "") &&
      normalizeSessionLookupKey(item.linkedSessionKey) === normalizeSessionLookupKey(req.getkeySession.linkedSessionKey)
  );
  if (!entry) return res.status(404).json({ ok: false, message: "Không tìm thấy key." });
  if (!entry.revokedAt) {
    entry.revokedAt = new Date().toISOString();
    await saveAccessKeysToDisk();
  }
  return res.json({ ok: true, key: buildAccessKeySummary(entry), message: "Đã thu hồi key." });
});

function normalizeText(input, maxLength = 600) {
  if (!input) return "";
  return String(input).replace(/\s+/g, " ").trim().slice(0, maxLength);
}

function normalizeLookupText(input) {
  return String(input || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/đ/g, "d")
    .replace(/Đ/g, "D")
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();
}

function detectNetflixLabelType(label) {
  const text = normalizeLookupText(label);
  if (!text) return null;

  const isHomeUpdate =
    text.includes("luu y quan trong") &&
    text.includes("cap nhat") &&
    text.includes("ho gia dinh netflix");
  if (isHomeUpdate) return LABEL_TYPE.HOME_UPDATE;

  const isTempAccess =
    text.includes("ma truy cap netflix tam thoi") ||
    (text.includes("truy cap") && text.includes("tam thoi") && text.includes("netflix"));
  if (isTempAccess) return LABEL_TYPE.TEMP_ACCESS;

  const isLoginCode =
    (text.includes("ma dang nhap") || text.includes("login code")) &&
    text.includes("netflix");
  if (isLoginCode) return LABEL_TYPE.LOGIN_CODE;

  return null;
}

function normalizeCookieHeaderString(cookie) {
  const raw = String(cookie || "")
    .trim()
    .replace(/[\r\n]+/g, " ")
    .replace(/\s{2,}/g, " ");
  if (!raw) return "";

  const byName = new Map();
  for (const item of raw.split(";")) {
    const part = String(item || "").trim();
    if (!part) continue;
    const idx = part.indexOf("=");
    if (idx <= 0) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!name) continue;
    byName.set(name, `${name}=${value}`);
  }

  return Array.from(byName.values()).join("; ");
}

function normalizeCookieDomain(domain) {
  const d = String(domain || "").trim().toLowerCase();
  if (!d) return "";
  return d.startsWith(".") ? d.slice(1) : d;
}

function matchesCookieDomain(targetHost, domain, hostOnly) {
  const normalizedDomain = normalizeCookieDomain(domain);
  if (!normalizedDomain) return true;
  if (hostOnly) return targetHost === normalizedDomain;
  return (
    targetHost === normalizedDomain || targetHost.endsWith(`.${normalizedDomain}`)
  );
}

function extractCookiePairsFromJson(entries, targetHost) {
  const nowSec = Date.now() / 1000;
  const byName = new Map();
  let rejectedCount = 0;

  for (const entry of entries) {
    if (!entry || typeof entry !== "object") {
      rejectedCount += 1;
      continue;
    }

    const name = String(entry.name || "").trim();
    if (!name) {
      rejectedCount += 1;
      continue;
    }

    const expirationDate = Number(entry.expirationDate);
    if (Number.isFinite(expirationDate) && expirationDate <= nowSec) {
      rejectedCount += 1;
      continue;
    }

    const hostOnly = Boolean(entry.hostOnly);
    if (!matchesCookieDomain(targetHost, entry.domain, hostOnly)) {
      rejectedCount += 1;
      continue;
    }

    const value =
      entry.value === undefined || entry.value === null ? "" : String(entry.value);
    byName.set(name, `${name}=${value}`);
  }

  return {
    pairs: Array.from(byName.values()),
    rejectedCount,
  };
}

function parseCookieInput(rawCookie, options = {}) {
  const targetHost = String(options.targetHost || "www.netflix.com")
    .trim()
    .toLowerCase();

  const hasInput =
    rawCookie !== undefined &&
    rawCookie !== null &&
    (typeof rawCookie !== "string" || rawCookie.trim().length > 0);

  if (!hasInput) {
    return {
      hasInput: false,
      cookie: "",
      format: "empty",
      acceptedCount: 0,
      rejectedCount: 0,
      parseError: null,
    };
  }

  if (Array.isArray(rawCookie)) {
    const extracted = extractCookiePairsFromJson(rawCookie, targetHost);
    return {
      hasInput: true,
      cookie: extracted.pairs.join("; "),
      format: "json_array",
      acceptedCount: extracted.pairs.length,
      rejectedCount: extracted.rejectedCount,
      parseError: null,
    };
  }

  if (typeof rawCookie === "object") {
    if (Array.isArray(rawCookie.cookies)) {
      return parseCookieInput(rawCookie.cookies, options);
    }
    if ("name" in rawCookie && "value" in rawCookie) {
      return parseCookieInput([rawCookie], options);
    }
    return {
      hasInput: true,
      cookie: "",
      format: "json_object",
      acceptedCount: 0,
      rejectedCount: 1,
      parseError: "Cấu trúc JSON cookie không đúng.",
    };
  }

  let rawText = String(rawCookie).trim();
  if (!rawText) {
    return {
      hasInput: false,
      cookie: "",
      format: "empty",
      acceptedCount: 0,
      rejectedCount: 0,
      parseError: null,
    };
  }

  const tryParseNestedJson = (text) => {
    let candidate = String(text || "").trim();
    for (let i = 0; i < 3; i += 1) {
      if (!candidate) break;

      if (/^[\[{]/.test(candidate)) {
        try {
          return JSON.parse(candidate);
        } catch {
          // continue
        }
      }

      if (
        (candidate.startsWith('"') && candidate.endsWith('"')) ||
        (candidate.startsWith("'") && candidate.endsWith("'"))
      ) {
        const unwrapped = candidate.slice(1, -1).trim();
        if (unwrapped) candidate = unwrapped;
      }

      try {
        const parsed = JSON.parse(candidate);
        if (typeof parsed === "string") {
          candidate = parsed.trim();
          continue;
        }
        return parsed;
      } catch {
        // continue
      }

      // Best-effort unescape for payloads like:
      // [{\"name\":\"NetflixId\",\"value\":\"...\"}]
      if (/\\["\\/bfnrtu]/.test(candidate)) {
        const unescaped = candidate
          .replace(/\\\\/g, "\\")
          .replace(/\\"/g, '"')
          .replace(/\\r/g, "\r")
          .replace(/\\n/g, "\n")
          .replace(/\\t/g, "\t");
        if (unescaped !== candidate) {
          candidate = unescaped.trim();
          continue;
        }
      }
    }
    return null;
  };

  const nestedParsed = tryParseNestedJson(rawText);
  if (nestedParsed !== null) {
    return parseCookieInput(nestedParsed, options);
  }

  if (/^[\[{]/.test(rawText)) {
    try {
      const parsed = JSON.parse(rawText);
      return parseCookieInput(parsed, options);
    } catch {
      // try to recover a JSON array/object inside noisy pasted text
      const firstArray = rawText.indexOf("[");
      const lastArray = rawText.lastIndexOf("]");
      if (firstArray >= 0 && lastArray > firstArray) {
        const slice = rawText.slice(firstArray, lastArray + 1);
        try {
          const parsedSlice = JSON.parse(slice);
          return parseCookieInput(parsedSlice, options);
        } catch {
          // ignore and continue to final error
        }
      }

      const firstObj = rawText.indexOf("{");
      const lastObj = rawText.lastIndexOf("}");
      if (firstObj >= 0 && lastObj > firstObj) {
        const slice = rawText.slice(firstObj, lastObj + 1);
        try {
          const parsedSlice = JSON.parse(slice);
          return parseCookieInput(parsedSlice, options);
        } catch {
          // ignore and continue to final error
        }
      }

      return {
        hasInput: true,
        cookie: "",
        format: "json_text",
        acceptedCount: 0,
        rejectedCount: 0,
        parseError: "JSON cookie không hợp lệ.",
      };
    }
  }

  const normalized = normalizeCookieHeaderString(rawText);
  // Reject obvious non-cookie payload (eg. pasted JSON that failed to parse).
  if (!normalized && /[{[\]}",:]/.test(rawText)) {
    return {
      hasInput: true,
      cookie: "",
      format: "unknown_text",
      acceptedCount: 0,
      rejectedCount: 0,
      parseError:
        "Không nhận diện được cookie hợp lệ. Hãy dán JSON cookie chuẩn hoặc chuỗi header name=value; ...",
    };
  }
  const acceptedCount = normalized ? normalized.split(";").length : 0;
  return {
    hasInput: true,
    cookie: normalized,
    format: "cookie_header",
    acceptedCount,
    rejectedCount: 0,
    parseError: null,
  };
}

function normalizeCookie(cookie) {
  return parseCookieInput(cookie).cookie;
}

function assertCookieHeaderSafe(cookie) {
  const value = String(cookie || "").trim();
  if (!value) return;
  try {
    // Undici's own validation catches illegal header chars.
    new Headers({ Cookie: value });
  } catch {
    throw new Error(
      "Cookie không đúng chuẩn header. Hãy dán JSON cookie export hoặc chuỗi name=value; ..."
    );
  }
}

function maskCookie(cookie) {
  const value = normalizeCookie(cookie);
  if (!value) return "";
  if (value.length <= 12) return `${value.slice(0, 4)}...`;
  return `${value.slice(0, 8)}...${value.slice(-8)}`;
}

function normalizeSessionKey(input) {
  return String(input || "")
    .trim()
    .replace(/\s+/g, " ")
    .slice(0, 80);
}

function normalizeSessionLookupKey(input) {
  return normalizeSessionKey(input).toLowerCase();
}

function isValidSessionKey(input) {
  const key = normalizeSessionKey(input);
  return key.length >= 16 && key.length <= 80;
}

function createSessionId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function buildNetflixHeaders(cookie) {
  const headers = {
    "User-Agent": NETFLIX_USER_AGENT,
    Accept: NETFLIX_ACCEPT,
  };
  if (cookie) headers.Cookie = cookie;
  return headers;
}

function mergeCookieHeaders(...cookieHeaders) {
  const byName = new Map();
  for (const header of cookieHeaders) {
    const normalized = normalizeCookieHeaderString(header);
    if (!normalized) continue;
    for (const item of normalized.split(";")) {
      const part = String(item || "").trim();
      if (!part) continue;
      const idx = part.indexOf("=");
      if (idx <= 0) continue;
      const name = part.slice(0, idx).trim();
      const value = part.slice(idx + 1).trim();
      if (!name) continue;
      byName.set(name, `${name}=${value}`);
    }
  }
  return Array.from(byName.values()).join("; ");
}

function extractCookieHeaderFromResponse(response) {
  const setCookieHeaders =
    typeof response?.headers?.getSetCookie === "function"
      ? response.headers.getSetCookie()
      : [];

  if (!Array.isArray(setCookieHeaders) || !setCookieHeaders.length) {
    return "";
  }

  const cookiePairs = [];
  for (const setCookie of setCookieHeaders) {
    const pair = String(setCookie || "").split(";")[0]?.trim() || "";
    if (pair.includes("=")) cookiePairs.push(pair);
  }

  return normalizeCookieHeaderString(cookiePairs.join("; "));
}

function ensureActiveSession() {
  if (!netflixStore.sessions.length) {
    netflixStore.activeSessionId = null;
    return null;
  }

  let active = netflixStore.sessions.find(
    (session) => session.id === netflixStore.activeSessionId
  );
  if (!active) {
    active = netflixStore.sessions[0];
    netflixStore.activeSessionId = active.id;
  }
  return active;
}

function getActiveSession() {
  return ensureActiveSession();
}

function getSessionById(sessionId) {
  return netflixStore.sessions.find((session) => session.id === sessionId) || null;
}

function getSessionByKey(sessionKey) {
  const lookup = normalizeSessionLookupKey(sessionKey);
  if (!lookup) return null;
  return (
    netflixStore.sessions.find(
      (session) => normalizeSessionLookupKey(session.key) === lookup
    ) || null
  );
}

function buildSessionAccessKeyStats(sessionKey) {
  const lookup = normalizeSessionLookupKey(sessionKey);
  if (!lookup) {
    return { total: 0, active: 0, expired: 0, revoked: 0, usageCount: 0 };
  }
  const entries = accessKeyStore.keys.filter(
    (entry) => normalizeSessionLookupKey(entry.linkedSessionKey) === lookup
  );
  const stats = {
    total: entries.length,
    active: 0,
    expired: 0,
    revoked: 0,
    usageCount: 0,
  };
  for (const entry of entries) {
    const status = accessKeyStatus(entry);
    stats[status] += 1;
    stats.usageCount += Number(entry.usageCount) || 0;
  }
  return stats;
}

function buildSessionSummary(session) {
  if (!session) {
    return {
      id: null,
      key: null,
      hasCookie: false,
      cookiePreview: "",
      cookieFormat: "none",
      cookieCount: 0,
      rejectedCount: 0,
      updatedAt: null,
      lastCheck: null,
      accessKeyStats: buildSessionAccessKeyStats(""),
    };
  }

  return {
    id: session.id,
    key: session.key,
    hasCookie: Boolean(session.cookie),
    cookiePreview: maskCookie(session.cookie),
    cookieFormat: session.cookieFormat || "none",
    cookieCount: Number(session.cookieCount) || 0,
    rejectedCount: Number(session.rejectedCount) || 0,
    updatedAt: session.updatedAt || null,
    lastCheck: session.lastCheck || null,
    accessKeyStats: buildSessionAccessKeyStats(session.key),
  };
}

function getSessionCookieFromBody(rawCookie, sessionId, sessionKey) {
  const provided = parseCookieInput(rawCookie);
  if (provided.hasInput) return provided;

  const requestedId = String(sessionId || "").trim();
  if (requestedId) {
    const requestedSession = getSessionById(requestedId);
    if (!requestedSession) {
      return {
        hasInput: false,
        cookie: "",
        format: "session",
        acceptedCount: 0,
        rejectedCount: 0,
        parseError: "Session được chọn không tồn tại.",
        source: "session",
        sessionId: requestedId,
        sessionKey: null,
      };
    }
    const requested = parseCookieInput(requestedSession.cookie);
    return {
      ...requested,
      source: "session",
      hasInput: false,
      sessionId: requestedSession.id,
      sessionKey: requestedSession.key,
    };
  }

  const requestedKey = normalizeSessionKey(sessionKey);
  if (requestedKey) {
    const requestedSession = getSessionByKey(requestedKey);
    if (!requestedSession) {
      return {
        hasInput: false,
        cookie: "",
        format: "session",
        acceptedCount: 0,
        rejectedCount: 0,
        parseError: "Không tìm thấy session Netflix theo key yêu cầu.",
        source: "session",
        sessionId: null,
        sessionKey: requestedKey,
      };
    }
    const requested = parseCookieInput(requestedSession.cookie);
    return {
      ...requested,
      source: "session",
      hasInput: false,
      sessionId: requestedSession.id,
      sessionKey: requestedSession.key,
    };
  }

  const selected = getActiveSession();
  const stored = parseCookieInput(selected?.cookie || "");
  return {
    ...stored,
    source: "session",
    hasInput: false,
    sessionId: selected?.id || null,
    sessionKey: selected?.key || null,
  };
}

function getNetflixSessionPayload() {
  const active = getActiveSession();
  const activeSummary = buildSessionSummary(active);
  const sessions = netflixStore.sessions.map((session) => buildSessionSummary(session));

  return {
    ok: true,
    activeSessionId: activeSummary.id,
    activeSessionKey: activeSummary.key,
    sessions,
    hasCookie: activeSummary.hasCookie,
    cookiePreview: activeSummary.cookiePreview,
    cookieFormat: activeSummary.cookieFormat,
    cookieCount: activeSummary.cookieCount,
    rejectedCount: activeSummary.rejectedCount,
    updatedAt: activeSummary.updatedAt,
    lastCheck: activeSummary.lastCheck,
  };
}

let saveQueue = Promise.resolve();

async function persistNetflixSessionToDisk() {
  const payload = {
    activeSessionId: netflixStore.activeSessionId,
    sessions: netflixStore.sessions.map((session) => ({
      id: session.id,
      key: session.key,
      cookie: encryptSecret(session.cookie),
      cookieFormat: session.cookieFormat,
      cookieCount: session.cookieCount,
      rejectedCount: session.rejectedCount,
      updatedAt: session.updatedAt,
      lastCheck: session.lastCheck,
      imap: session.imap
        ? { user: session.imap.user, pass: encryptSecret(session.imap.pass) }
        : null,
    })),
  };
  await mkdir(path.dirname(NETFLIX_SESSION_FILE), { recursive: true });
  const temporaryFile = `${NETFLIX_SESSION_FILE}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    await writeFile(temporaryFile, JSON.stringify(payload, null, 2), {
      encoding: "utf8",
      mode: 0o600,
    });
    await rename(temporaryFile, NETFLIX_SESSION_FILE);
  } catch (error) {
    await unlink(temporaryFile).catch(() => {});
    throw error;
  }
}

function saveNetflixSessionToDisk() {
  const task = saveQueue.then(() => persistNetflixSessionToDisk());
  saveQueue = task.catch(() => {});
  return task;
}

async function loadNetflixSessionFromDisk() {
  try {
    const raw = await readFile(NETFLIX_SESSION_FILE, "utf8");
    const parsed = JSON.parse(raw);
    netflixStore.sessions = [];

    if (Array.isArray(parsed?.sessions)) {
      for (const item of parsed.sessions) {
        const key = normalizeSessionKey(item?.key);
        const cookie = normalizeCookie(decryptSecret(item?.cookie));
        if (!key) continue;
        // Cho phép session chỉ có IMAP mà chưa có cookie
        if (!cookie && !item?.imap) continue;
        netflixStore.sessions.push({
          id: String(item?.id || createSessionId()),
          key,
          cookie: cookie || "",
          cookieFormat:
            typeof item?.cookieFormat === "string" ? item.cookieFormat : "cookie_header",
          cookieCount: Number(item?.cookieCount) || 0,
          rejectedCount: Number(item?.rejectedCount) || 0,
          updatedAt: typeof item?.updatedAt === "string" ? item.updatedAt : null,
          lastCheck:
            item?.lastCheck && typeof item.lastCheck === "object" ? item.lastCheck : null,
          imap:
            item?.imap && typeof item.imap === "object"
              ? { user: String(item.imap.user || ""), pass: decryptSecret(item.imap.pass) }
              : null,
        });
      }
    } else if (parsed?.cookie) {
      // Backward compatibility with old single-session format
      const fallbackCookie = normalizeCookie(decryptSecret(parsed.cookie));
      if (fallbackCookie) {
        netflixStore.sessions.push({
          id: createSessionId(),
          key: "default",
          cookie: fallbackCookie,
          cookieFormat:
            typeof parsed?.cookieFormat === "string" ? parsed.cookieFormat : "cookie_header",
          cookieCount: Number(parsed?.cookieCount) || 0,
          rejectedCount: Number(parsed?.rejectedCount) || 0,
          updatedAt: typeof parsed?.updatedAt === "string" ? parsed.updatedAt : null,
          lastCheck:
            parsed?.lastCheck && typeof parsed.lastCheck === "object"
              ? parsed.lastCheck
              : null,
        });
      }
    }

    const rawActiveId = String(parsed?.activeSessionId || "").trim();
    netflixStore.activeSessionId = rawActiveId || null;
    ensureActiveSession();
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw new Error(`Không thể đọc dữ liệu session: ${error?.message || error}`);
  }
}

function upsertNetflixSession(cookie, key, meta = {}) {
  const normalizedCookie = normalizeCookie(cookie);
  const normalizedKey = normalizeSessionKey(key);
  if (!normalizedCookie || !normalizedKey) return null;

  let session =
    netflixStore.sessions.find(
      (item) => item.key.toLowerCase() === normalizedKey.toLowerCase()
    ) || null;

  if (!session) {
    session = {
      id: createSessionId(),
      key: normalizedKey,
      cookie: "",
      cookieFormat: "cookie_header",
      cookieCount: 0,
      rejectedCount: 0,
      updatedAt: null,
      lastCheck: null,
      imap: null,
    };
    netflixStore.sessions.push(session);
  }

  session.key = normalizedKey;
  session.cookie = normalizedCookie;
  session.cookieFormat = String(meta.format || "cookie_header");
  session.cookieCount = Number(meta.acceptedCount) || 0;
  session.rejectedCount = Number(meta.rejectedCount) || 0;
  session.updatedAt = new Date().toISOString();
  session.lastCheck = null;

  netflixStore.activeSessionId = session.id;
  return session;
}

function updateSessionImap(key, imapUser, imapPass) {
  const normalizedKey = normalizeSessionKey(key);
  if (!normalizedKey || !imapUser || !imapPass) return null;
  let session =
    netflixStore.sessions.find(
      (item) => item.key.toLowerCase() === normalizedKey.toLowerCase()
    ) || null;

  if (!session) {
    // Tạo session mới chỉ với IMAP (chưa có cookie)
    session = {
      id: createSessionId(),
      key: normalizedKey,
      cookie: "",
      cookieFormat: "cookie_header",
      cookieCount: 0,
      rejectedCount: 0,
      updatedAt: null,
      lastCheck: null,
      imap: null,
    };
    netflixStore.sessions.push(session);
  }

  session.imap = { user: imapUser, pass: imapPass };
  return session;
}

function removeNetflixSession(sessionId) {
  const id = String(sessionId || "").trim();
  const index = netflixStore.sessions.findIndex((session) => session.id === id);
  if (index < 0) return false;
  netflixStore.sessions.splice(index, 1);
  if (netflixStore.activeSessionId === id) {
    netflixStore.activeSessionId = netflixStore.sessions[0]?.id || null;
  }
  return true;
}

function setActiveNetflixSession(sessionId) {
  const id = String(sessionId || "").trim();
  const session = getSessionById(id);
  if (!session) return null;
  netflixStore.activeSessionId = session.id;
  return session;
}

async function syncActiveNetflixSessionByKey(sessionKey) {
  const matched = getSessionByKey(sessionKey);
  if (!matched) return null;
  if (matched.id !== netflixStore.activeSessionId) {
    netflixStore.activeSessionId = matched.id;
    await saveNetflixSessionToDisk();
  }
  return matched;
}

function updateNetflixSessionCheck(checkResult, sessionId) {
  const session =
    (sessionId ? getSessionById(sessionId) : null) ||
    (netflixStore.activeSessionId ? getSessionById(netflixStore.activeSessionId) : null);
  if (!session) return;
  session.lastCheck = {
    ...checkResult,
    checkedAt: new Date().toISOString(),
  };
}

async function checkNetflixCookieStatus(cookie) {
  const normalized = normalizeCookie(cookie);
  if (!normalized) throw new Error("Cookie không hợp lệ.");
  assertCookieHeaderSafe(normalized);

  const response = await fetch("https://www.netflix.com/browse", {
    method: "GET",
    redirect: "manual",
    headers: buildNetflixHeaders(normalized),
  });

  const location = response.headers.get("location") || "";
  // With redirect:"manual", a 3xx opaque redirect means Netflix redirected us
  // (likely to login). response.text() returns empty for opaque redirects.
  const isOpaqueRedirect = response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400);
  const text = isOpaqueRedirect ? "" : await response.text();
  const redirectedToLogin = isOpaqueRedirect || /login/i.test(location) || /sign in/i.test(text);
  const looksLikeBrowsePage = !isOpaqueRedirect && /netflix/i.test(text) && /browse/i.test(text);
  const live = !redirectedToLogin && response.status < 300 && looksLikeBrowsePage;
  const account = live ? await fetchNetflixAccountSnapshot(normalized) : null;

  return {
    status: live ? "LIVE" : "DIE",
    httpStatus: response.status,
    redirectedTo: location || null,
    account,
    note: live
      ? "Cookie có vẻ còn sống."
      : "Cookie có thể đã die/expired hoặc bị Netflix chặn.",
  };
}

function getRegexMatch(input, regexes) {
  const raw = String(input || "");
  for (const regex of regexes) {
    const match = raw.match(regex);
    const value = String(match?.[1] || "").trim();
    if (value) return value;
  }
  return null;
}

function maskSensitiveValue(value) {
  const raw = String(value || "").trim();
  if (!raw) return null;
  if (raw.length <= 10) return `${raw.slice(0, 3)}...`;
  return `${raw.slice(0, 6)}...${raw.slice(-4)}`;
}

function extractNetflixIdentityFromCookie(cookie) {
  const header = normalizeCookieHeaderString(cookie);
  if (!header) return null;

  const map = new Map();
  for (const pair of header.split(";")) {
    const part = String(pair || "").trim();
    if (!part) continue;
    const index = part.indexOf("=");
    if (index <= 0) continue;
    map.set(part.slice(0, index).trim(), part.slice(index + 1).trim());
  }

  const netflixId = map.get("NetflixId");
  const secureNetflixId = map.get("SecureNetflixId");
  if (!netflixId && !secureNetflixId) return null;

  return {
    netflixIdHint: maskSensitiveValue(netflixId),
    secureNetflixIdHint: maskSensitiveValue(secureNetflixId),
  };
}

async function fetchNetflixAccountSnapshot(cookie) {
  try {
    const response = await fetch("https://www.netflix.com/YourAccount", {
      method: "GET",
      redirect: "follow",
      headers: buildNetflixHeaders(cookie),
    });

    const html = await response.text();
    const text = stripHtmlToText(html);
    const title = normalizeText(
      getRegexMatch(html, [/<title[^>]*>([\s\S]*?)<\/title>/i]) || "",
      180
    );
    const emailHint = getRegexMatch(text, [
      /\b([A-Za-z0-9._%+\-*]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/,
    ]);
    const profileNameHint = getRegexMatch(html, [
      /"profileName"\s*:\s*"([^"]{1,80})"/i,
      /"firstName"\s*:\s*"([^"]{1,80})"/i,
    ]);
    const memberSinceHint = getRegexMatch(text, [
      /Member since[^0-9A-Za-z]*([0-9A-Za-z,\s]{4,40})/i,
    ]);

    return {
      finalUrl: response.url || "https://www.netflix.com/YourAccount",
      httpStatus: response.status,
      title: title || null,
      emailHint: emailHint || null,
      profileNameHint: profileNameHint || null,
      memberSinceHint: memberSinceHint || null,
    };
  } catch {
    return null;
  }
}

function validateAuth(body) {
  const user = String(body?.user || "").trim();
  const pass = String(body?.pass || "");
  if (!user || !pass) return null;
  return { user, pass };
}

function validateImapRequest(body) {
  const auth = validateAuth(body);
  const key = normalizeSessionKey(body?.key);
  if (!auth || !isValidSessionKey(key)) return null;
  return { auth, key };
}

function buildImapClient(auth) {
  return new ImapFlow({
    host: DEFAULT_IMAP.host,
    port: DEFAULT_IMAP.port,
    secure: DEFAULT_IMAP.secure,
    auth,
    logger: false,
  });
}

async function safeLogout(client) {
  try {
    await client.logout();
  } catch {
    // ignore
  }
}

async function getFilteredLabels(client) {
  const list = await client.list();
  return list
    .map((mailbox) => mailbox.path)
    .filter(Boolean)
    .filter((label) => Boolean(detectNetflixLabelType(label)))
    .sort((a, b) => a.localeCompare(b, "vi"));
}

function extractOneTimeCode(text) {
  if (!text) return null;
  const raw = normalizeLookupText(text);
  const patterns = [
    /\b(\d{4,8})\b/g,
    /\bcode[:\s-]*(\d{4,8})\b/gi,
    /\botp[:\s-]*(\d{4,8})\b/gi,
    /\bma[:\s-]*(\d{4,8})\b/gi,
  ];

  for (const pattern of patterns) {
    const match = pattern.exec(raw);
    if (match?.[1]) return match[1];
  }
  return null;
}

function extractLoginCode4(text) {
  if (!text) return null;
  const raw = normalizeLookupText(text);
  const patterns = [
    /\b(?:ma|code|otp|login|dang nhap|xac minh)\b[^0-9]{0,24}(\d{4})\b/gi,
    /\b(\d{4})\b[^0-9]{0,24}\b(?:ma|code|otp|login|dang nhap|xac minh)\b/gi,
    /\b(\d{4})\b/g,
  ];

  for (const pattern of patterns) {
    const match = pattern.exec(raw);
    if (match?.[1]) return match[1];
  }
  return null;
}

function isAllowedNetflixUrl(rawUrl) {
  try {
    const parsed = new URL(String(rawUrl || "").trim());
    if (parsed.protocol !== "https:") return false;
    if (
      parsed.hostname === "netflix.com" ||
      parsed.hostname.endsWith(".netflix.com")
    ) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

function stripHtmlToText(html) {
  const withoutScript = String(html || "")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ");

  return withoutScript
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, " ")
    .trim();
}

function normalizeSearchText(input) {
  return normalizeLookupText(input);
}

function extractHtmlAttributeValue(tag, attribute) {
  const pattern = new RegExp(
    `\\b${attribute}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`,
    "i"
  );
  const match = String(tag || "").match(pattern);
  if (!match) return "";
  return String(match[1] || match[2] || match[3] || "").trim();
}

function extractHiddenInputValues(html) {
  const values = {};
  const raw = String(html || "");
  const inputRegex = /<input\b[^>]*>/gi;
  let match;

  while ((match = inputRegex.exec(raw)) !== null) {
    const tag = match[0];
    const type = normalizeSearchText(extractHtmlAttributeValue(tag, "type"));
    if (type !== "hidden") continue;
    const name = extractHtmlAttributeValue(tag, "name");
    if (!name) continue;
    values[name] = extractHtmlAttributeValue(tag, "value");
  }

  return values;
}

function hasNamedInputField(html, fieldName) {
  const pattern = new RegExp(
    `\\bname\\s*=\\s*(?:"${fieldName}"|'${fieldName}'|${fieldName})\\b`,
    "i"
  );
  return pattern.test(String(html || ""));
}

function resolveHtmlFormActionUrl(action, baseUrl) {
  const rawAction = String(action || "").trim();
  const fallbackUrl = String(baseUrl || "https://www.netflix.com/tv2").trim();

  if (!rawAction) return fallbackUrl;

  try {
    return new URL(rawAction, fallbackUrl).toString();
  } catch {
    return fallbackUrl;
  }
}

function extractTvCodeSubmitForm(html, pageUrl) {
  const raw = String(html || "");
  const formRegex = /<form\b[^>]*>[\s\S]*?<\/form>/gi;
  let match;

  while ((match = formRegex.exec(raw)) !== null) {
    const formHtml = match[0];
    const openTagMatch = formHtml.match(/<form\b[^>]*>/i);
    if (!openTagMatch) continue;

    const hiddenValues = extractHiddenInputValues(formHtml);
    const hasTvCodeField = hasNamedInputField(formHtml, "tvLoginRendezvousCode");
    const hasLegacyPinField = hasNamedInputField(formHtml, "pin");
    const looksLikeTvCodeForm =
      hasTvCodeField ||
      hasLegacyPinField ||
      Boolean(hiddenValues.authURL) ||
      /tv2|enter code|ma tv|ma truy cap/i.test(stripHtmlToText(formHtml));

    if (!looksLikeTvCodeForm) continue;

    const action = extractHtmlAttributeValue(openTagMatch[0], "action");

    return {
      actionUrl: resolveHtmlFormActionUrl(action, pageUrl),
      hiddenValues,
      hasTvCodeField,
      hasLegacyPinField,
    };
  }

  return null;
}

function hasConfirmUpdateButton(html) {
  const target = normalizeSearchText("Xac nhan cap nhat");
  const raw = String(html || "");

  const buttonRegex = /<button\b[^>]*>([\s\S]*?)<\/button>/gi;
  let buttonMatch;
  while ((buttonMatch = buttonRegex.exec(raw)) !== null) {
    const buttonText = normalizeSearchText(stripHtmlToText(buttonMatch[1] || ""));
    if (buttonText.includes(target)) return true;
  }

  const inputRegex = /<input\b[^>]*>/gi;
  let inputMatch;
  while ((inputMatch = inputRegex.exec(raw)) !== null) {
    const tag = inputMatch[0];
    const type = normalizeSearchText(extractHtmlAttributeValue(tag, "type"));
    if (type && type !== "submit" && type !== "button") continue;

    const inputText = normalizeSearchText(
      `${extractHtmlAttributeValue(tag, "value")} ${extractHtmlAttributeValue(tag, "aria-label")} ${extractHtmlAttributeValue(tag, "title")}`
    );
    if (inputText.includes(target)) return true;
  }

  return false;
}

function extractFourDigitCodesFromText(text) {
  const unique = new Set();
  const allCodes = String(text || "").match(/\b\d{4}\b/g) || [];
  for (const code of allCodes) {
    unique.add(code);
    if (unique.size >= 10) break;
  }
  return Array.from(unique);
}

/**
 * Kiểm tra trang Netflix có phải trang "link hết hạn / không còn hiệu lực" không.
 * Netflix thường hiển thị các cụm từ này khi link đã expire.
 */
function detectNetflixExpiredPage(text) {
  const normalized = normalizeLookupText(text);
  const expiredPhrases = [
    "lien ket nay khong con hieu luc",
    "lien ket da het han",
    "link is no longer valid",
    "link has expired",
    "this link has expired",
    "link expired",
    "lien ket het han",
    "ma nay da het han",
    "code has expired",
    "this code has expired",
    "request has expired",
    "yeu cau da het han",
    "khong con hieu luc",
    "no longer valid",
    "session expired",
    "phien da het han",
    "sorry, the request",
    "please try again",
  ];
  return expiredPhrases.some((phrase) => normalized.includes(phrase));
}

/**
 * Gộp các chữ số cách nhau bằng khoảng trắng đơn thành chuỗi liền.
 * Ví dụ: "1 8 6 8" → "1868", nhưng không gộp "abc 1 2 xyz" tùy tiện
 * (chỉ gộp khi thấy pattern N chữ số đơn cách nhau bằng space, N >= 3).
 */
function compactSpacedDigits(text) {
  return String(text || "").replace(/\b(\d)(?:\s+(\d)){2,5}\b/g, (match) => {
    return match.replace(/\s+/g, "");
  });
}

/**
 * Trích xuất mã truy cập tạm thời Netflix (4 chữ số) từ HTML trang final.
 * Chỉ lấy mã khi có context rõ ràng — không nhặt bừa số 4 chữ số.
 * Trả về: { code, expired, contextText }
 */
function extractTempAccessCode(html, plainText) {
  // Loại bỏ URL khỏi text trước mọi phân tích (tránh nhặt số từ UUID/URL)
  const cleanText = plainText.replace(/https?:\/\/[^\s<>"')\]]+/gi, " ");

  // 1. Kiểm tra link hết hạn trước — ưu tiên tuyệt đối
  if (detectNetflixExpiredPage(cleanText)) {
    return { code: null, expired: true, contextText: null };
  }

  // 2. Gộp chữ số cách nhau: "1 8 6 8" → "1868"
  const compactedText = compactSpacedDigits(cleanText);
  const normalized = normalizeLookupText(compactedText);

  // Loại bỏ thêm các chuỗi số dài (UUID, token) — chỉ giữ số đứng riêng 4 chữ số
  // Xóa mọi chuỗi số >= 5 chữ số liền nhau
  const noLongNumbers = normalized.replace(/\d{5,}/g, " ");

  // 3. Tìm mã có context rõ ràng của Netflix (tiếng Anh + tiếng Việt)
  const contextPhrases = [
    // Tiếng Anh - Netflix thật sự dùng
    "use this code",
    "enter this code",
    "temporary access",
    "watch on your tv",
    "on the requesting tv",
    "this code expires",
    "your access code",
    "your code is",
    // Tiếng Việt
    "su dung ma nay",
    "nhap ma nay",
    "ma nay het han sau",
    "ma cua ban la",
    "ma truy cap la",
    "ma xac nhan la",
    "ma xem tren tv",
  ];

  // Duyệt từng context phrase, tìm mã 4 chữ số gần đó
  for (const phrase of contextPhrases) {
    const idx = noLongNumbers.indexOf(phrase);
    if (idx < 0) continue;
    const windowStart = Math.max(0, idx - 30);
    const windowEnd = Math.min(noLongNumbers.length, idx + phrase.length + 200);
    const window = noLongNumbers.slice(windowStart, windowEnd);
    const codeMatch = window.match(/\b(\d{4})\b/);
    if (codeMatch?.[1]) {
      return { code: codeMatch[1], expired: false, contextText: null };
    }
  }

  // 4. Tìm mã trong HTML — trong thẻ nổi bật, hỗ trợ "1 8 6 8"
  const prominentTagPatterns = [
    /<h[123][^>]*>\s*(\d[\s\d]*\d)\s*<\/h[123]>/i,
    /<strong[^>]*>\s*(\d[\s\d]*\d)\s*<\/strong>/i,
    /<b[^>]*>\s*(\d[\s\d]*\d)\s*<\/b>/i,
    /<(?:p|div|span)[^>]*class="[^"]*(?:code|pin|otp|access|temp)[^"]*"[^>]*>([\s\S]*?)<\/(?:p|div|span)>/i,
  ];

  for (const pattern of prominentTagPatterns) {
    const match = html.match(pattern);
    if (match?.[1]) {
      const digits = match[1].replace(/[^0-9]/g, "");
      if (/^\d{4}$/.test(digits)) {
        return { code: digits, expired: false, contextText: null };
      }
    }
  }

  // 5. Fallback: HTML có "số space số space số space số" trong thẻ độc lập
  const spacedDigitInTag = html.match(
    /<(?:h[1-3]|p|div|td|span)[^>]*>\s*(\d\s+\d\s+\d\s+\d)\s*<\/(?:h[1-3]|p|div|td|span)>/i
  );
  if (spacedDigitInTag?.[1]) {
    const digits = spacedDigitInTag[1].replace(/\s+/g, "");
    if (/^\d{4}$/.test(digits)) {
      return { code: digits, expired: false, contextText: null };
    }
  }

  // 6. Không tìm thấy mã hợp lệ — trả về null, KHÔNG nhặt bừa
  return { code: null, expired: false, contextText: normalizeText(cleanText, 400) };
}

function buildConfirmReviewMessage(hasButton) {
  if (hasButton) return "Tìm thấy nút Xác nhận cập nhật.";
  return "Liên kết không còn hiệu lực, vui lòng xác nhận lại.";
}

function buildCodeReviewMessage(result) {
  if (result.expired) return "Liên kết này không còn hiệu lực.";
  if (result.code) return `Mã truy cập: ${result.code}`;
  return "Không tìm thấy mã — trang không hiển thị mã rõ ràng.";
}

app.post("/api/imap/login", async (req, res) => {
  const imapRequest = validateImapRequest(req.body);
  if (!imapRequest) {
    return res.status(400).json({
      ok: false,
      message: "Thiếu thông tin đăng nhập hoặc key ngắn hơn 16 ký tự.",
    });
  }
  const { auth, key } = imapRequest;

  const client = buildImapClient(auth);
  try {
    await client.connect();
    const labels = await getFilteredLabels(client);
    // Lưu IMAP credentials vào session theo key
    updateSessionImap(key, auth.user, auth.pass);
    await saveNetflixSessionToDisk();
    const linkedSession = await syncActiveNetflixSessionByKey(key);
    return res.json({
      ok: true,
      message: "Đăng nhập IMAP thành công.",
      key,
      linkedNetflixSessionId: linkedSession?.id || null,
      linkedNetflixSessionKey: linkedSession?.key || null,
      labels,
      imapDefaults: DEFAULT_IMAP,
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error?.message || "Đăng nhập IMAP thất bại.",
    });
  } finally {
    await safeLogout(client);
  }
});

app.post("/api/imap/labels", async (req, res) => {
  const imapRequest = validateImapRequest(req.body);
  if (!imapRequest) {
    return res.status(400).json({
      ok: false,
      message: "Thiếu thông tin đăng nhập hoặc key ngắn hơn 16 ký tự.",
    });
  }
  const { auth, key } = imapRequest;

  const client = buildImapClient(auth);
  try {
    await client.connect();
    const labels = await getFilteredLabels(client);
    const linkedSession = await syncActiveNetflixSessionByKey(key);
    return res.json({
      ok: true,
      key,
      linkedNetflixSessionId: linkedSession?.id || null,
      linkedNetflixSessionKey: linkedSession?.key || null,
      labels,
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error?.message || "Không thể lấy danh sách nhãn.",
    });
  } finally {
    await safeLogout(client);
  }
});

app.post("/api/imap/fetch-mails", async (req, res) => {
  const imapRequest = validateImapRequest(req.body);
  const mailbox = String(req.body?.mailbox || "").trim();
  const mailboxType = detectNetflixLabelType(mailbox);
  const limit = Math.min(Math.max(Number(req.body?.limit) || 50, 1), 200);

  if (!imapRequest) {
    return res.status(400).json({
      ok: false,
      message: "Thiếu thông tin đăng nhập hoặc key ngắn hơn 16 ký tự.",
    });
  }
  const { auth, key } = imapRequest;
  if (!mailbox) {
    return res.status(400).json({
      ok: false,
      message: "Thiếu nhãn/hộp thư cần lọc.",
    });
  }
  if (!mailboxType) {
    return res.status(400).json({
      ok: false,
      message: "Nhãn không hợp lệ. Chỉ cho phép 3 nhãn Netflix đã cấu hình.",
    });
  }

  const client = buildImapClient(auth);
  let lock = null;

  try {
    await client.connect();
    const linkedSession = await syncActiveNetflixSessionByKey(key);
    lock = await client.getMailboxLock(mailbox);

    const exists = client.mailbox.exists || 0;
    const messages = [];

    if (exists > 0) {
      const start = Math.max(exists - limit + 1, 1);
      const range = `${start}:${exists}`;

      for await (const msg of client.fetch(range, {
        envelope: true,
        source: true,
        internalDate: true,
      })) {
        const parsed = await simpleParser(msg.source);
        const text =
          parsed.text || normalizeText(parsed.html ? parsed.html.toString() : "");
        const content = normalizeText(parsed.text || text, 15000);
        const from =
          msg.envelope?.from?.map((f) => f.address).filter(Boolean).join(", ") || "";
        const subject = msg.envelope?.subject || "";
        const snippet = normalizeText(content, 240);
        const codeSource = `${subject}\n${content}\n${parsed.html ? parsed.html.toString() : ""}`;
        // Strip URL khỏi codeSource để tránh nhặt số từ UUID/token trong URL
        const cleanCodeSource = codeSource.replace(/https?:\/\/[^\s<>"')\]]+/gi, " ");
        const code =
          mailboxType === LABEL_TYPE.LOGIN_CODE
            ? extractLoginCode4(cleanCodeSource)
            : extractOneTimeCode(cleanCodeSource);
        const messageDate = parsed.date || msg.internalDate || null;

        messages.push({
          uid: msg.uid,
          date: messageDate,
          from,
          subject,
          code,
          snippet,
          content,
        });
      }
    }

    messages.sort((a, b) => {
      const timeA = a?.date ? new Date(a.date).getTime() : 0;
      const timeB = b?.date ? new Date(b.date).getTime() : 0;
      const safeA = Number.isFinite(timeA) ? timeA : 0;
      const safeB = Number.isFinite(timeB) ? timeB : 0;
      if (safeA !== safeB) return safeB - safeA;
      return Number(b?.uid || 0) - Number(a?.uid || 0);
    });

    return res.json({
      ok: true,
      key,
      linkedNetflixSessionId: linkedSession?.id || null,
      linkedNetflixSessionKey: linkedSession?.key || null,
      mailbox,
      total: messages.length,
      messages,
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error?.message || "Không thể tải thư của nhãn đã chọn.",
    });
  } finally {
    if (lock) lock.release();
    await safeLogout(client);
  }
});

app.get("/api/netflix/session", async (_req, res) => {
  return res.json(getNetflixSessionPayload());
});

app.post("/api/netflix/session", async (req, res) => {
  const key = normalizeSessionKey(req.body?.key);
  const parsedCookie = parseCookieInput(req.body?.cookie);

  if (!isValidSessionKey(key)) {
    return res.status(400).json({
      ok: false,
      message: "Key định danh phải có từ 16 đến 80 ký tự.",
    });
  }
  if (!parsedCookie.cookie) {
    const reason =
      parsedCookie.parseError ||
      "Không đọc được cookie hợp lệ từ dữ liệu nhập (chuỗi hoặc JSON).";
    return res.status(400).json({
      ok: false,
      message: reason,
    });
  }

  try {
    const saved = upsertNetflixSession(parsedCookie.cookie, key, parsedCookie);
    if (!saved) {
      return res.status(400).json({
        ok: false,
        message: "Không thể lưu phiên: cookie hoặc key không hợp lệ.",
      });
    }
    await saveNetflixSessionToDisk();
    return res.json({
      ...getNetflixSessionPayload(),
      savedSessionId: saved.id,
      savedSessionKey: saved.key,
      acceptedCount: parsedCookie.acceptedCount,
      rejectedCount: parsedCookie.rejectedCount,
      inputFormat: parsedCookie.format,
      message: "Đã lưu phiên Netflix trên server.",
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error?.message || "Không thể lưu phiên Netflix.",
    });
  }
});

app.post("/api/netflix/session/select", async (req, res) => {
  const sessionId = String(req.body?.sessionId || "").trim();
  if (!sessionId) {
    return res.status(400).json({
      ok: false,
      message: "Thiếu sessionId cần chọn.",
    });
  }

  const selected = setActiveNetflixSession(sessionId);
  if (!selected) {
    return res.status(404).json({
      ok: false,
      message: "Không tìm thấy session để chọn.",
    });
  }

  try {
    await saveNetflixSessionToDisk();
    return res.json({
      ...getNetflixSessionPayload(),
      message: `Đã chọn session: ${selected.key}`,
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error?.message || "Không thể chọn session Netflix.",
    });
  }
});

app.get("/api/netflix/sessions", async (_req, res) => {
  return res.json(getNetflixSessionPayload());
});

app.delete("/api/netflix/session/:sessionId", async (req, res) => {
  const sessionId = String(req.params?.sessionId || "").trim();
  if (!sessionId) {
    return res.status(400).json({
      ok: false,
      message: "Thiếu sessionId cần xóa.",
    });
  }

  const removed = removeNetflixSession(sessionId);
  if (!removed) {
    return res.status(404).json({
      ok: false,
      message: "Không tìm thấy session để xóa.",
    });
  }

  try {
    await saveNetflixSessionToDisk();
    return res.json({
      ...getNetflixSessionPayload(),
      message: "Đã xóa session Netflix.",
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error?.message || "Không thể xóa session Netflix.",
    });
  }
});

app.delete("/api/netflix/session", async (_req, res) => {
  try {
    netflixStore.sessions = [];
    netflixStore.activeSessionId = null;
    await saveNetflixSessionToDisk();
    return res.json({
      ...getNetflixSessionPayload(),
      message: "Đã xóa toàn bộ phiên Netflix.",
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error?.message || "Không thể xóa toàn bộ phiên Netflix.",
    });
  }
});

app.post("/api/netflix/analyze-link", async (req, res) => {
  const url = String(req.body?.url || "").trim();
  const analysisMode = String(req.body?.analysisMode || "confirm_button")
    .trim()
    .toLowerCase();
  const requestedSessionId = String(req.body?.sessionId || "").trim();
  const requestedSessionKey = normalizeSessionKey(req.body?.sessionKey);
  const cookieState = getSessionCookieFromBody(
    req.body?.cookie,
    requestedSessionId,
    requestedSessionKey
  );
  const cookie = cookieState.cookie;

  if (!isAllowedNetflixUrl(url)) {
    return res.status(400).json({
      ok: false,
      message: "Chỉ cho phép phân tích link HTTPS thuộc domain netflix.com.",
    });
  }
  if (!["confirm_button", "code4_final_html"].includes(analysisMode)) {
    return res.status(400).json({
      ok: false,
      message: "analysisMode không hợp lệ.",
    });
  }

  const requiresAuth = /\/account\//i.test(url);
  if (requiresAuth && !cookie) {
    const reason =
      cookieState.parseError ||
      (cookieState.hasInput
        ? "Cookie nhập vào không đúng định dạng (có thể đang dán JSON lỗi)."
        : "Link này cần phiên Netflix. Hãy vào tab 'Phiên Netflix' để lưu cookie trước khi phân tích.");
    return res.status(400).json({
      ok: false,
      message: reason,
    });
  }
  if (cookie) {
    try {
      assertCookieHeaderSafe(cookie);
    } catch (error) {
      return res.status(400).json({
        ok: false,
        message: error?.message || "Cookie không đúng chuẩn header.",
      });
    }
  }

  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "follow",
      headers: buildNetflixHeaders(cookie),
    });

    const html = await response.text();
    const text = stripHtmlToText(html);
    const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    const title = titleMatch ? normalizeText(stripHtmlToText(titleMatch[1]), 180) : "";
    const hasConfirmButton =
      analysisMode === "confirm_button" ? hasConfirmUpdateButton(html) : null;

    // code4_final_html: dùng logic chặt chẽ, không nhặt bừa số
    let codeResult = null;
    let codeCandidates = [];
    let bestCode = null;
    if (analysisMode === "code4_final_html") {
      codeResult = extractTempAccessCode(html, text);
      bestCode = codeResult.code || null;
      codeCandidates = bestCode ? [bestCode] : [];
    }

    const review =
      analysisMode === "code4_final_html"
        ? buildCodeReviewMessage(codeResult)
        : buildConfirmReviewMessage(Boolean(hasConfirmButton));

    return res.json({
      ok: true,
      analysisMode,
      status: response.status,
      finalUrl: response.url || url,
      redirected: Boolean(response.redirected),
      title,
      hasConfirmUpdateButton: hasConfirmButton,
      codeCandidates,
      bestCode,
      expired: codeResult?.expired ?? null,
      review,
      textPreview: normalizeText(text, 2000),
      usedSessionCookie: Boolean(cookie),
      cookieFormat: cookieState.format || null,
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error?.message || "Không thể truy cập link để phân tích.",
    });
  }
});

app.post("/api/netflix/check-cookie", async (req, res) => {
  const requestedSessionId = String(req.body?.sessionId || "").trim();
  const requestedSessionKey = normalizeSessionKey(req.body?.sessionKey);
  const cookieState = getSessionCookieFromBody(
    req.body?.cookie,
    requestedSessionId,
    requestedSessionKey
  );
  const cookie = cookieState.cookie;
  const usedSessionCookie = !cookieState.hasInput;
  if (!cookie) {
    const reason =
      cookieState.parseError ||
      (cookieState.hasInput
        ? "Cookie nhập vào không đúng định dạng (chuỗi header hoặc JSON array)."
        : "Chưa có cookie. Hãy lưu phiên Netflix trước.");
    return res.status(400).json({
      ok: false,
      message: reason,
    });
  }

  try {
    const check = await checkNetflixCookieStatus(cookie);
    const identity = extractNetflixIdentityFromCookie(cookie);

    if (usedSessionCookie) {
      updateNetflixSessionCheck(check, cookieState.sessionId || null);
      await saveNetflixSessionToDisk();
    }

    return res.json({
      ok: true,
      ...check,
      identity,
      usedSessionCookie,
      cookieFormat: cookieState.format || null,
      acceptedCount: Number(cookieState.acceptedCount || 0),
      rejectedCount: Number(cookieState.rejectedCount || 0),
      session: getNetflixSessionPayload(),
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error?.message || "Không thể kiểm tra cookie Netflix.",
    });
  }
});

// === USER API: Lấy mã truy cập cho user ===
app.post("/api/get-code", async (req, res) => {
  const key = String(req.body?.key || "").trim();
  const type = String(req.body?.type || "login_code").trim();

  const keyAccess = validateRegisteredAccessKey(key);
  if (!keyAccess.ok) {
    return res.status(isValidAccessKey(key) ? 403 : 400).json({ ok: false, message: keyAccess.message });
  }
  if (!["login_code", "temp_access", "home_update"].includes(type)) {
    return res.status(400).json({ ok: false, message: "Loại mã không hợp lệ." });
  }

  const session = getSessionByKey(keyAccess.entry.linkedSessionKey);
  if (!session) {
    return res.status(404).json({ ok: false, message: "Access Key chưa liên kết với tài khoản hợp lệ." });
  }
  await markAccessKeyUsed(keyAccess.entry);

  const cookie = session.cookie || "";

  // === TEMP_ACCESS: dùng cookie vào /tv2 — không cần IMAP ===
  if (type === "temp_access") {
    if (!cookie) {
      return res.status(400).json({ ok: false, message: "Chưa có cookie Netflix. Admin cần lưu cookie trước." });
    }
    try {
      const tv2Response = await fetch("https://www.netflix.com/tv2", {
        method: "GET",
        redirect: "follow",
        headers: buildNetflixHeaders(cookie),
      });

      const tv2Html = await tv2Response.text();
      const tv2Text = stripHtmlToText(tv2Html);
      const redirectedToLogin = /login|sign.?in/i.test(tv2Response.url);

      if (redirectedToLogin || tv2Response.status >= 400) {
        return res.json({
          ok: true,
          step: "error",
          message: "Cookie không hợp lệ hoặc đã hết hạn.",
        });
      }

      const isCodePage = /nhập mã|enter.*code|tv.*code/i.test(tv2Text) ||
        tv2Response.url.includes("/tv2");

      return res.json({
        ok: true,
        step: "input_code",
        message: isCodePage ? "Sẵn sàng nhập mã TV." : "Trang TV đã tải.",
        finalUrl: tv2Response.url,
      });
    } catch (error) {
      return res.status(500).json({ ok: false, message: error?.message || "Lỗi kết nối Netflix TV." });
    }
  }

  // === LOGIN_CODE & HOME_UPDATE: cần IMAP ===
  if (!session.imap || !session.imap.user || !session.imap.pass) {
    return res.status(400).json({ ok: false, message: "Tài khoản chưa được cấu hình IMAP." });
  }

  const client = buildImapClient({ user: session.imap.user, pass: session.imap.pass });
  let lock = null;

  try {
    await client.connect();
    const labels = await getFilteredLabels(client);

    // Tìm nhãn phù hợp với loại yêu cầu
    const targetLabelType =
      type === "login_code" ? LABEL_TYPE.LOGIN_CODE : LABEL_TYPE.HOME_UPDATE;

    const targetLabel = labels.find(
      (label) => detectNetflixLabelType(label) === targetLabelType
    );

    if (!targetLabel) {
      return res.json({ ok: true, code: null, expired: false, message: "Không tìm thấy nhãn phù hợp trong hộp thư." });
    }

    lock = await client.getMailboxLock(targetLabel);
    const exists = client.mailbox.exists || 0;

    if (exists === 0) {
      return res.json({ ok: true, code: null, expired: false, message: "Không có thư nào." });
    }

    // Lấy mail mới nhất
    const range = `${exists}:${exists}`;
    let latestContent = "";
    let latestHtml = "";
    let latestSubject = "";
    let latestDate = null;

    for await (const msg of client.fetch(range, { envelope: true, source: true, internalDate: true })) {
      const parsed = await simpleParser(msg.source);
      latestContent = parsed.text || "";
      latestHtml = parsed.html ? parsed.html.toString() : "";
      latestSubject = msg.envelope?.subject || "";
      latestDate = parsed.date || msg.internalDate || null;
    }

    lock.release();
    lock = null;
    await safeLogout(client);

    // === LOGIN_CODE: lấy mã 4 số trực tiếp từ nội dung mail ===
    if (type === "login_code") {
      const codeSource = `${latestSubject}\n${latestContent}\n${latestHtml}`;
      const cleanSource = codeSource.replace(/https?:\/\/[^\s<>"')\]]+/gi, " ");
      const code = extractLoginCode4(cleanSource);
      return res.json({
        ok: true,
        code: code || null,
        expired: false,
        date: latestDate || null,
        message: code ? null : "Không tìm thấy mã đăng nhập trong thư mới nhất.",
      });
    }

    // === HOME_UPDATE: cần fetch link từ mail ===
    const mailText = `${latestContent}\n${latestHtml}`;
    const linkPatterns = [
      /https:\/\/www\.netflix\.com\/account\/travel\/verify[^\s<>"')\]]*/i,
      /https:\/\/www\.netflix\.com\/account\/update-primary-location[^\s<>"')\]]*/i,
      /https:\/\/www\.netflix\.com\/account\/[^\s<>"')\]]*/i,
    ];

    let netflixLink = "";
    for (const pattern of linkPatterns) {
      const match = mailText.match(pattern);
      if (match?.[0]) {
        netflixLink = match[0];
        break;
      }
    }

    if (!netflixLink) {
      return res.json({ ok: true, code: null, expired: false, message: "Không tìm thấy link Netflix trong thư." });
    }

    // Fetch link Netflix
    const response = await fetch(netflixLink, {
      method: "GET",
      redirect: "follow",
      headers: buildNetflixHeaders(cookie),
    });

    const html = await response.text();
    const text = stripHtmlToText(html);

    // === HOME_UPDATE: kiểm tra nút xác nhận ===
    if (type === "home_update") {
      const expired = detectNetflixExpiredPage(text);
      if (expired) {
        return res.json({ ok: true, confirmed: false, expired: true, message: "Liên kết không còn hiệu lực." });
      }
      const confirmed = hasConfirmUpdateButton(html);
      return res.json({
        ok: true,
        confirmed,
        expired: false,
        message: confirmed ? "Tìm thấy nút xác nhận." : "Không tìm thấy nút xác nhận.",
      });
    }
  } catch (error) {
    return res.status(500).json({ ok: false, message: error?.message || "Lỗi khi lấy mã." });
  } finally {
    if (lock) lock.release();
    await safeLogout(client);
  }
});

// === USER API: Submit mã TV ===
app.post("/api/submit-tv-code", async (req, res) => {
  const key = String(req.body?.key || "").trim();
  const code = String(req.body?.code || "")
    .replace(/\D+/g, "")
    .slice(0, 8);

  if (!key || !code) {
    return res.status(400).json({ ok: false, message: "Thiếu key hoặc mã TV." });
  }
  const keyAccess = validateRegisteredAccessKey(key);
  if (!keyAccess.ok) {
    return res.status(isValidAccessKey(key) ? 403 : 400).json({ ok: false, message: keyAccess.message });
  }

  if (code.length !== 8) {
    return res.status(400).json({ ok: false, message: "Mã TV phải đủ 8 số." });
  }

  const session = getSessionByKey(keyAccess.entry.linkedSessionKey);
  if (!session || !session.cookie) {
    return res.status(400).json({ ok: false, message: "Access Key chưa liên kết với session hoặc cookie hợp lệ." });
  }
  await markAccessKeyUsed(keyAccess.entry);

  const cookie = session.cookie;

  try {
    const tv2Response = await fetch("https://www.netflix.com/tv2", {
      method: "GET",
      redirect: "follow",
      headers: buildNetflixHeaders(cookie),
    });

    const tv2Html = await tv2Response.text();
    const tv2Text = stripHtmlToText(tv2Html);
    const tv2Form = extractTvCodeSubmitForm(tv2Html, tv2Response.url || "https://www.netflix.com/tv2");
    const flowCookie = extractCookieHeaderFromResponse(tv2Response);
    const submitCookie = mergeCookieHeaders(cookie, flowCookie);

    if (
      !tv2Response.ok ||
      /login|sign.?in/i.test(tv2Response.url) ||
      /sign in|log in/i.test(normalizeLookupText(tv2Text))
    ) {
      return res.json({
        ok: true,
        success: false,
        message: "Cookie Netflix không còn hợp lệ để đăng nhập TV.",
      });
    }

    if (!tv2Form) {
      return res.json({
        ok: true,
        success: false,
        message: "Netflix đã đổi form nhập mã TV, không tìm được form submit.",
        finalUrl: tv2Response.url,
      });
    }

    const submitUrl = isAllowedNetflixUrl(tv2Form.actionUrl)
      ? tv2Form.actionUrl
      : (tv2Response.url || "https://www.netflix.com/tv2");
    const usesLegacyPinFlow =
      tv2Form.hasLegacyPinField ||
      /\/tv2\/pin(?:[/?#]|$)/i.test(submitUrl);

    if (!usesLegacyPinFlow && !tv2Form.hiddenValues.authURL) {
      return res.json({
        ok: true,
        success: false,
        message: "Netflix đã đổi form nhập mã TV, không đọc được authURL để submit.",
        finalUrl: submitUrl,
      });
    }

    const form = new URLSearchParams();
    for (const [name, value] of Object.entries(tv2Form.hiddenValues || {})) {
      form.set(name, value ?? "");
    }

    if (usesLegacyPinFlow) {
      form.set("pin", code);
    }

    if (tv2Form.hasTvCodeField || !usesLegacyPinFlow) {
      if (!form.has("flow")) form.set("flow", "websiteSignUp");
      if (!form.has("flowMode")) form.set("flowMode", "enterTvLoginRendezvousCode");
      if (!form.has("withFields")) form.set("withFields", "tvLoginRendezvousCode,isTvUrl2");
      if (!form.has("isTvUrl2")) form.set("isTvUrl2", "true");
      if (!form.has("action")) form.set("action", "nextAction");
      form.set("tvLoginRendezvousCode", code);
    }

    const submitResponse = await fetch(submitUrl, {
      method: "POST",
      redirect: "follow",
      headers: {
        ...buildNetflixHeaders(submitCookie),
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: "https://www.netflix.com",
        Referer: tv2Response.url || "https://www.netflix.com/tv2",
      },
      body: form.toString(),
    });

    const resultHtml = await submitResponse.text();
    const resultText = stripHtmlToText(resultHtml);
    const resultForm = extractTvCodeSubmitForm(resultHtml, submitResponse.url || submitUrl);
    const normalizedResultText = normalizeLookupText(resultText);
    const normalizedFinalUrl = normalizeLookupText(submitResponse.url || "");
    const hasRetryForm = Boolean(resultForm);
    const explicitSuccess =
      /success|thành công|đăng nhập thành công|đã kết nối|connected|signed in|sign in complete|device.*added|your tv is now signed in|you can now watch/i.test(resultText) ||
      normalizedResultText.includes("now signed in") ||
      normalizedResultText.includes("ready to watch") ||
      normalizedResultText.includes("tv is now signed in");
    const successByUrl =
      submitResponse.url.includes("/browse") ||
      submitResponse.url.includes("/tv2/success") ||
      submitResponse.url.includes("/tv/out/success");
    const explicitInvalid =
      /invalid|không hợp lệ|sai mã|incorrect|try again|thử lại/i.test(resultText) ||
      normalizedResultText.includes("that code wasn't right") ||
      normalizedResultText.includes("that code wasnt right") ||
      normalizedResultText.includes("that code was not right") ||
      normalizedResultText.includes("code entry failed") ||
      normalizedResultText.includes("failed to retrieve tv login rendezvous code");
    const invalidByUrl =
      normalizedFinalUrl.includes("/notfound") ||
      normalizedFinalUrl.includes("prev=https%3a%2f%2fwww.netflix.com%2ftv2%2fpin") ||
      normalizedFinalUrl.includes("prev=https://www.netflix.com/tv2/pin");
    const stillWaitingForCode =
      hasRetryForm &&
      (
        normalizedResultText.includes("enter code") ||
        normalizedResultText.includes("enter the code") ||
        normalizedResultText.includes("tvloginrendezvouscode") ||
        normalizedResultText.includes("ma tv") ||
        normalizedResultText.includes("ma truy cap") ||
        normalizedResultText.includes("nhap ma") ||
        normalizedResultText.includes("watch on your tv")
      );

    // Kiểm tra kết quả: ưu tiên success rõ ràng trước, tránh false negative
    const isSuccess = explicitSuccess || successByUrl;
    const isInvalidCode = !isSuccess && (explicitInvalid || invalidByUrl || stillWaitingForCode);

    if (isSuccess) {
      return res.json({
        ok: true,
        success: true,
        message: "Đã đăng nhập TV thành công!",
      });
    }

    if (isInvalidCode) {
      return res.json({
        ok: true,
        success: false,
        message: TV_CODE_INVALID_OR_USED_MESSAGE,
      });
    }

    return res.json({
      ok: true,
      success: false,
      message: TV_CODE_INVALID_OR_USED_MESSAGE,
      finalUrl: submitResponse.url,
      preview: normalizeText(resultText, 240),
    });
  } catch (error) {
    return res.status(500).json({ ok: false, message: error?.message || "Lỗi khi gửi mã TV." });
  }
});

app.use("/p8xK29panel", express.static(path.join(__dirname, "public", "p8xK29panel")));
app.use(express.static(path.join(__dirname, "public")));

app.use("/api", (_req, res) => {
  res.status(404).json({ ok: false, message: "Không tìm thấy API." });
});

app.use((_req, res) => {
  // Admin SPA fallback
  if (_req.path.startsWith("/p8xK29panel")) {
    return res.sendFile(path.join(__dirname, "public", "p8xK29panel", "index.html"));
  }
  // User page fallback
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

function validateRuntimeConfig() {
  const problems = [];
  if (ADMIN_PASSWORD.length < 12) problems.push("ADMIN_PASSWORD phải có ít nhất 12 ký tự");
  if (DATA_ENCRYPTION_KEY.length < 32) problems.push("DATA_ENCRYPTION_KEY phải có ít nhất 32 ký tự");
  if (problems.length) throw new Error(`Cấu hình không hợp lệ: ${problems.join("; ")}`);
}

export async function startServer(options = {}) {
  validateRuntimeConfig();
  await loadAccessKeysFromDisk();
  await saveAccessKeysToDisk();
  await loadNetflixSessionFromDisk();
  // Re-save once at startup to migrate legacy plaintext data to encrypted storage.
  await saveNetflixSessionToDisk();
  const port = options.port ?? Number(process.env.PORT || 3000);
  const host = options.host ?? process.env.HOST ?? "127.0.0.1";
  return new Promise((resolve, reject) => {
    const server = app.listen(port, host, () => {
      const address = server.address();
      const actualPort = typeof address === "object" && address ? address.port : port;
      console.log(`Server running at http://${host}:${actualPort}`);
      resolve(server);
    });
    server.once("error", reject);
  });
}

export { app };

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  await startServer();
}
