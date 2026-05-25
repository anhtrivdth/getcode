import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { mkdir, readFile, writeFile } from "fs/promises";
import { ImapFlow } from "imapflow";
import { simpleParser } from "mailparser";

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const NETFLIX_SESSION_FILE = path.join(
  __dirname,
  "data",
  "netflix-session.json"
);
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

const netflixStore = {
  activeSessionId: null,
  sessions: [],
};

app.use(express.json({ limit: "1mb" }));

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

async function saveNetflixSessionToDisk() {
  const payload = {
    activeSessionId: netflixStore.activeSessionId,
    sessions: netflixStore.sessions.map((session) => ({
      id: session.id,
      key: session.key,
      cookie: session.cookie,
      cookieFormat: session.cookieFormat,
      cookieCount: session.cookieCount,
      rejectedCount: session.rejectedCount,
      updatedAt: session.updatedAt,
      lastCheck: session.lastCheck,
      imap: session.imap || null,
    })),
  };
  await mkdir(path.dirname(NETFLIX_SESSION_FILE), { recursive: true });
  await writeFile(NETFLIX_SESSION_FILE, JSON.stringify(payload, null, 2), "utf8");
}

async function loadNetflixSessionFromDisk() {
  try {
    const raw = await readFile(NETFLIX_SESSION_FILE, "utf8");
    const parsed = JSON.parse(raw);
    netflixStore.sessions = [];

    if (Array.isArray(parsed?.sessions)) {
      for (const item of parsed.sessions) {
        const key = normalizeSessionKey(item?.key);
        const cookie = normalizeCookie(item?.cookie);
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
          imap: item?.imap && typeof item.imap === "object" ? item.imap : null,
        });
      }
    } else if (parsed?.cookie) {
      // Backward compatibility with old single-session format
      const fallbackCookie = normalizeCookie(parsed.cookie);
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
    if (error?.code !== "ENOENT") {
      console.error("Failed to load Netflix session:", error?.message || error);
    }
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
  if (!auth || !key) return null;
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
      message: "Thiếu thông tin đăng nhập: email, app password và key.",
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
      message: "Thiếu thông tin đăng nhập: email, app password và key.",
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
      message: "Thiếu thông tin đăng nhập: email, app password và key.",
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

  if (!key) {
    return res.status(400).json({
      ok: false,
      message: "Thiếu key định danh cho phiên Netflix.",
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

  if (!key) {
    return res.status(400).json({ ok: false, message: "Vui lòng nhập key tài khoản." });
  }
  if (!["login_code", "temp_access", "home_update"].includes(type)) {
    return res.status(400).json({ ok: false, message: "Loại mã không hợp lệ." });
  }

  const session = getSessionByKey(key);
  if (!session) {
    return res.status(404).json({ ok: false, message: "Không tìm thấy tài khoản với key này." });
  }

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
  const code = String(req.body?.code || "").trim();

  if (!key || !code) {
    return res.status(400).json({ ok: false, message: "Thiếu key hoặc mã TV." });
  }

  const session = getSessionByKey(key);
  if (!session || !session.cookie) {
    return res.status(400).json({ ok: false, message: "Không tìm thấy session hoặc cookie." });
  }

  const cookie = session.cookie;

  try {
    // Netflix /tv2 submit flow: POST to /tv2/pin with the code
    const submitResponse = await fetch("https://www.netflix.com/tv2/pin", {
      method: "POST",
      redirect: "follow",
      headers: {
        ...buildNetflixHeaders(cookie),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `pin=${encodeURIComponent(code)}`,
    });

    const resultHtml = await submitResponse.text();
    const resultText = stripHtmlToText(resultHtml);

    // Kiểm tra kết quả
    const isSuccess = /success|thành công|đã kết nối|connected|signed in|device.*added/i.test(resultText) ||
      submitResponse.url.includes("/browse") ||
      submitResponse.url.includes("/tv2/success");
    const isInvalidCode = /invalid|không hợp lệ|sai mã|incorrect|try again|thử lại/i.test(resultText);

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
        message: "Mã không hợp lệ. Vui lòng kiểm tra lại mã trên TV.",
      });
    }

    return res.json({
      ok: true,
      success: false,
      message: "Không xác định được kết quả. Vui lòng thử lại.",
      finalUrl: submitResponse.url,
    });
  } catch (error) {
    return res.status(500).json({ ok: false, message: error?.message || "Lỗi khi gửi mã TV." });
  }
});

await loadNetflixSessionFromDisk();

app.use("/admin", express.static(path.join(__dirname, "public", "admin")));
app.use(express.static(path.join(__dirname, "public")));

app.use((_req, res) => {
  // Admin SPA fallback
  if (_req.path.startsWith("/admin")) {
    return res.sendFile(path.join(__dirname, "public", "admin", "index.html"));
  }
  // User page fallback
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log(`Admin UI running at http://localhost:${port}`);
});

