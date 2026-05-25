const LABEL_TYPE = {
  HOME_UPDATE: "home_update",
  TEMP_ACCESS: "temp_access",
  LOGIN_CODE: "login_code",
};

const tabButtons = Array.from(document.querySelectorAll(".tab-btn"));
const panels = {
  imap: document.getElementById("tab-imap"),
  netflix: document.getElementById("tab-netflix"),
};

for (const btn of tabButtons) {
  btn.addEventListener("click", () => {
    for (const b of tabButtons) b.classList.remove("active");
    btn.classList.add("active");
    const tab = btn.dataset.tab;
    Object.entries(panels).forEach(([key, panel]) => {
      panel.classList.toggle("active", key === tab);
    });
  });
}

const qs = (id) => document.getElementById(id);
const DISPLAY_TIMEZONE = "Asia/Ho_Chi_Minh";
const state = {
  user: "",
  pass: "",
  key: "",
  loggedIn: false,
  selectedLabel: "",
};

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
  if (
    text.includes("luu y quan trong") &&
    text.includes("cap nhat") &&
    text.includes("ho gia dinh netflix")
  ) {
    return LABEL_TYPE.HOME_UPDATE;
  }
  if (
    text.includes("ma truy cap netflix tam thoi") ||
    (text.includes("truy cap") && text.includes("tam thoi") && text.includes("netflix"))
  ) {
    return LABEL_TYPE.TEMP_ACCESS;
  }
  if ((text.includes("ma dang nhap") || text.includes("login code")) && text.includes("netflix")) {
    return LABEL_TYPE.LOGIN_CODE;
  }
  return null;
}

function formatDateTime(value, fallback = "không rõ") {
  if (!value) return fallback;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return fallback;

  const parts = new Intl.DateTimeFormat("vi-VN", {
    timeZone: DISPLAY_TIMEZONE,
    hour12: false,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).formatToParts(date);

  const map = {};
  parts.forEach((part) => {
    if (part.type !== "literal") map[part.type] = part.value;
  });
  return `${map.hour}:${map.minute}:${map.second} ${map.day}/${map.month}/${map.year}`;
}

function setStatus(text) {
  qs("imap-test-result").textContent = text;
}

function saveImapConfig() {
  const config = {
    user: qs("imap-user").value.trim(),
    pass: qs("imap-pass").value,
    key: qs("imap-key").value.trim(),
  };
  localStorage.setItem("admin.imap.config", JSON.stringify(config));
}

function loadImapConfig() {
  const raw = localStorage.getItem("admin.imap.config");
  if (!raw) return;
  try {
    const config = JSON.parse(raw);
    qs("imap-user").value = config.user || "";
    qs("imap-pass").value = config.pass || "";
    qs("imap-key").value = config.key || "";
  } catch {
    // Bỏ qua cache lỗi
  }
}

// --- IMAP Account List (saved accounts) ---
const IMAP_ACCOUNTS_KEY = "admin.imap.accounts";

function loadImapAccounts() {
  try {
    const raw = localStorage.getItem(IMAP_ACCOUNTS_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveImapAccounts(accounts) {
  localStorage.setItem(IMAP_ACCOUNTS_KEY, JSON.stringify(accounts));
}

function upsertImapAccount(user, pass, key) {
  if (!user || !pass || !key) return;
  const accounts = loadImapAccounts();
  const idx = accounts.findIndex((a) => a.user.toLowerCase() === user.toLowerCase() && a.key.toLowerCase() === key.toLowerCase());
  const entry = { user, pass, key, savedAt: new Date().toISOString() };
  if (idx >= 0) {
    accounts[idx] = entry;
  } else {
    accounts.unshift(entry);
  }
  // Giữ tối đa 20 tài khoản
  saveImapAccounts(accounts.slice(0, 20));
}

function deleteImapAccount(user, key) {
  const accounts = loadImapAccounts().filter(
    (a) => !(a.user.toLowerCase() === user.toLowerCase() && a.key.toLowerCase() === key.toLowerCase())
  );
  saveImapAccounts(accounts);
}

function fillImapForm(account) {
  qs("imap-user").value = account.user || "";
  qs("imap-pass").value = account.pass || "";
  qs("imap-key").value = account.key || "";
  saveImapConfig();
}

function renderImapAccountList() {
  const root = qs("imap-account-list");
  if (!root) return;
  const accounts = loadImapAccounts();
  root.innerHTML = "";

  if (!accounts.length) {
    root.innerHTML = '<div class="imap-account-empty">Chưa có tài khoản nào được lưu.</div>';
    return;
  }

  for (const account of accounts) {
    const item = document.createElement("div");
    item.className = "imap-account-item";

    const savedAt = account.savedAt ? formatDateTime(account.savedAt, "") : "";
    item.innerHTML = `
      <button class="imap-account-btn" type="button">
        <span class="imap-account-user">${escapeHtml(account.user)}</span>
        <span class="imap-account-key">${escapeHtml(account.key)}</span>
        ${savedAt ? `<span class="imap-account-time">${escapeHtml(savedAt)}</span>` : ""}
      </button>
      <button class="imap-account-del" type="button" title="Xóa tài khoản này" data-user="${escapeAttr(account.user)}" data-key="${escapeAttr(account.key)}">✕</button>
    `;

    item.querySelector(".imap-account-btn").addEventListener("click", async () => {
      fillImapForm(account);
      // Tự động đăng nhập luôn
      qs("btn-imap-login").click();
    });

    item.querySelector(".imap-account-del").addEventListener("click", (e) => {
      e.stopPropagation();
      deleteImapAccount(account.user, account.key);
      renderImapAccountList();
    });

    root.appendChild(item);
  }
}

qs("btn-imap-accounts-clear")?.addEventListener("click", () => {
  saveImapAccounts([]);
  renderImapAccountList();
});

function escapeHtml(input) {
  return String(input || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function escapeAttr(input) {
  return String(input || "")
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function extractPrimaryLocationLink(text) {
  const raw = String(text || "");
  const patterns = [
    /https:\/\/www\.netflix\.com\/account\/update-primary-location[^\s<>"')\]]*/i,
    /https:\/\/www\.netflix\.com\/account\/[^\s<>"')\]]*/i,
    /https:\/\/www\.netflix\.com\/[^\s<>"')\]]*/i,
  ];
  for (const pattern of patterns) {
    const match = raw.match(pattern);
    if (match?.[0]) return match[0];
  }
  return "";
}

async function postJson(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.message || `Yeu cau that bai: ${response.status}`);
  return data;
}

async function getJson(url) {
  const response = await fetch(url);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.message || `Yeu cau that bai: ${response.status}`);
  return data;
}

async function deleteJson(url) {
  const response = await fetch(url, { method: "DELETE" });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.message || `Yeu cau that bai: ${response.status}`);
  return data;
}

function setSelectedLabel(label) {
  state.selectedLabel = label;
  qs("selected-label").textContent = label
    ? `Nhãn đang chọn: ${label}`
    : "Chưa chọn nhãn.";
  for (const btn of document.querySelectorAll(".label-btn")) {
    btn.classList.toggle("active", btn.dataset.label === label);
  }
}

function renderLabels(labels) {
  const root = qs("label-list");
  root.innerHTML = "";

  if (!labels.length) {
    root.innerHTML =
      '<div class="mail-item">Không tìm thấy nhãn phù hợp trong tài khoản mail.</div>';
    setSelectedLabel("");
    return;
  }

  for (const label of labels) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "label-btn";
    btn.dataset.label = label;
    btn.textContent = label;
    btn.addEventListener("click", async () => {
      setSelectedLabel(label);
      await fetchMailsByLabel(label);
    });
    root.appendChild(btn);
  }

  if (!state.selectedLabel || !labels.includes(state.selectedLabel)) {
    setSelectedLabel(labels[0]);
  } else {
    setSelectedLabel(state.selectedLabel);
  }
}

async function analyzeLink(url, resultEl) {
  const selectedLabelType = detectNetflixLabelType(state.selectedLabel);
  const analysisMode =
    selectedLabelType === LABEL_TYPE.TEMP_ACCESS ? "code4_final_html" : "confirm_button";
  resultEl.textContent =
    analysisMode === "code4_final_html"
      ? "Đang truy cập link final và phân tích HTML để tìm mã 4 chữ số..."
      : "Đang truy cập link final và kiểm tra nút Xác nhận cập nhật...";

  try {
    const cookie = cookieInput.value.trim();
    const payload = { url, cookie, analysisMode };
    if (!cookie && netflixState.activeSessionId) {
      payload.sessionId = netflixState.activeSessionId;
    }
    if (!cookie && state.key) {
      payload.sessionKey = state.key;
    }
    const data = await postJson("/api/netflix/analyze-link", payload);
    const hasConfirmText = data.hasConfirmUpdateButton ? "CÓ" : "KHÔNG";
    const codeText =
      data.codeCandidates && data.codeCandidates.length > 0
        ? data.codeCandidates.join(", ")
        : "Không có";
    const reviewText = data.review || "";
    const sessionText = data.usedSessionCookie
      ? "Có dùng cookie phiên Netflix."
      : "Không dùng cookie phiên.";

    const commonFlow =
      "Luồng thao tác:\n" +
      '1) Bấm nút "Phân tích link final" ngay dưới email.\n' +
      "2) Hệ thống lấy link từ email đó.\n" +
      `3) Server mở link gốc: ${url}\n` +
      `4) Server theo redirect và ra link cuối: ${data.finalUrl}\n`;

    if (analysisMode === "code4_final_html") {
      // Hết hạn
      if (data.expired) {
        resultEl.textContent =
          `⛔ Liên kết này không còn hiệu lực.\n\n` +
          `Final URL: ${data.finalUrl}\n` +
          `HTTP: ${data.status}\n` +
          `Title: ${data.title || "(trống)"}\n\n` +
          `Preview:\n${data.textPreview || "(không có nội dung)"}`;
        return;
      }
      // Có mã
      if (data.bestCode) {
        resultEl.textContent =
          `✅ Mã truy cập: ${data.bestCode}\n\n` +
          `Final URL: ${data.finalUrl}\n` +
          `HTTP: ${data.status}\n` +
          `Title: ${data.title || "(trống)"}\n\n` +
          `Preview:\n${data.textPreview || "(không có nội dung)"}`;
        return;
      }
      // Không tìm thấy mã rõ ràng — hiển thị nội dung trang để user tự đọc
      resultEl.textContent =
        `⚠️ Không tìm thấy mã rõ ràng trong trang.\n\n` +
        `Final URL: ${data.finalUrl}\n` +
        `HTTP: ${data.status}\n` +
        `Title: ${data.title || "(trống)"}\n\n` +
        `Nội dung trang:\n${data.textPreview || "(không có nội dung)"}`;
      return;
    }

    resultEl.textContent =
      `${commonFlow}5) Kiểm tra nút Xác nhận cập nhật: ${hasConfirmText}\n\n` +
      `Review: ${reviewText}\n` +
      `Có nút Xác nhận cập nhật: ${hasConfirmText}\n` +
      `HTTP: ${data.status}\n` +
      `Final URL: ${data.finalUrl}\n` +
      `Title: ${data.title || "(trống)"}\n` +
      `${sessionText}\n\n` +
      `Preview:\n${data.textPreview || "(không có nội dung)"}`;
  } catch (error) {
    resultEl.textContent = `Lỗi phân tích link: ${error.message}`;
  }
}

function renderMails(items) {
  const root = qs("mail-list");
  root.innerHTML = "";
  const sortedItems = [...items].sort((a, b) => {
    const timeA = a?.date ? new Date(a.date).getTime() : 0;
    const timeB = b?.date ? new Date(b.date).getTime() : 0;
    const safeA = Number.isFinite(timeA) ? timeA : 0;
    const safeB = Number.isFinite(timeB) ? timeB : 0;
    if (safeA !== safeB) return safeB - safeA;
    return Number(b?.uid || 0) - Number(a?.uid || 0);
  });

  if (!sortedItems.length) {
    root.innerHTML = '<div class="mail-item">Không có thư trong nhãn này.</div>';
    return;
  }

  sortedItems.forEach((item, index) => {
    const d = formatDateTime(item.date, "không rõ thời gian");
    const selectedLabelType = detectNetflixLabelType(state.selectedLabel);
    const isLoginCodeLabel = selectedLabelType === LABEL_TYPE.LOGIN_CODE;
    const isHomeUpdateLabel =
      selectedLabelType === LABEL_TYPE.HOME_UPDATE ||
      selectedLabelType === LABEL_TYPE.TEMP_ACCESS;

    const div = document.createElement("article");
    div.className = "mail-item";

    // --- LOGIN_CODE: chỉ hiển thị mã, gọn ---
    if (isLoginCodeLabel) {
      div.className = "mail-item mail-item-code";
      div.innerHTML = `
        <div class="code-card">
          <div class="code-card-left">
            ${item.code
              ? `<span class="code-display">${escapeHtml(item.code)}</span>`
              : `<span class="code-display code-display-empty">—</span>`
            }
            <span class="code-label">${item.code ? "Mã đăng nhập" : "Không có mã"}</span>
          </div>
          <div class="code-card-right">
            <span class="code-meta-time">${escapeHtml(d)}</span>
            <span class="code-meta-from">${escapeHtml(item.from || "-")}</span>
          </div>
        </div>
      `;
      root.appendChild(div);
      return;
    }

    // --- HOME_UPDATE / TEMP_ACCESS: hiển thị link + nút phân tích ---
    const codePill = item.code
      ? `<span class="pill code">MÃ ${item.code}</span>`
      : `<span class="pill no-code">KHÔNG CÓ MÃ</span>`;
    const primaryLocationUrl = extractPrimaryLocationLink(item.content || item.snippet || "");
    const resultId = `analyze-result-${item.uid || "u"}-${index}`;
    const summaryText = isHomeUpdateLabel ? "Đường dẫn cập nhật" : "Xem nội dung thư";
    const content = isHomeUpdateLabel
      ? escapeHtml(primaryLocationUrl || "Không tìm thấy đường dẫn cập nhật.")
      : escapeHtml(item.content || item.snippet || "(Không có nội dung)");

    const analyzeBlock =
      isHomeUpdateLabel && primaryLocationUrl
        ? `
        <div class="analyze-wrap">
          <a class="mail-link" href="${escapeAttr(primaryLocationUrl)}" target="_blank" rel="noreferrer">
            ${escapeHtml(primaryLocationUrl)}
          </a>
          <button class="analyze-link-btn" data-url="${escapeAttr(primaryLocationUrl)}" data-result-id="${resultId}">
            Phân tích link final
          </button>
          <pre id="${resultId}" class="analyze-result"></pre>
        </div>
      `
        : "";

    div.innerHTML = `
      <div class="mail-head">
        ${codePill}
        <span class="pill">UID ${item.uid}</span>
      </div>
      <div class="meta"><strong>Người gửi:</strong> ${escapeHtml(item.from || "-")}</div>
      <div class="meta"><strong>Tiêu đề:</strong> ${escapeHtml(item.subject || "-")}</div>
      <div class="meta"><strong>Ngày giờ:</strong> ${d}</div>
      <details class="mail-content" open>
        <summary>${summaryText}</summary>
        <pre>${content}</pre>
      </details>
      ${analyzeBlock}
    `;
    root.appendChild(div);
  });

  for (const button of root.querySelectorAll(".analyze-link-btn")) {
    button.addEventListener("click", async () => {
      const url = button.dataset.url;
      const resultId = button.dataset.resultId;
      const resultEl = document.getElementById(resultId);
      if (!url || !resultEl) return;
      await analyzeLink(url, resultEl);
    });
  }
}

async function fetchMailsByLabel(label) {
  if (!state.loggedIn) {
    setStatus("Bạn cần đăng nhập IMAP trước.");
    return;
  }

  setStatus(`Đang tải thư của nhãn "${label}"...`);
  try {
    const data = await postJson("/api/imap/fetch-mails", {
      user: state.user,
      pass: state.pass,
      key: state.key,
      mailbox: label,
    });
    renderMails(data.messages || []);
    setStatus(`Đã tải ${data.total} thư của nhãn "${label}".`);
  } catch (error) {
    renderMails([]);
    setStatus(`Lỗi tải thư: ${error.message}`);
  }
}

qs("btn-imap-login").addEventListener("click", async () => {
  setStatus("Đang đăng nhập IMAP...");
  saveImapConfig();

  try {
    const auth = {
      user: qs("imap-user").value.trim(),
      pass: qs("imap-pass").value,
      key: qs("imap-key").value.trim(),
    };
    const data = await postJson("/api/imap/login", auth);

    state.user = auth.user;
    state.pass = auth.pass;
    state.key = auth.key;
    state.loggedIn = true;
    // Lưu tài khoản vào danh sách truy cập nhanh
    upsertImapAccount(auth.user, auth.pass, auth.key);
    renderImapAccountList();
    if (state.key) {
      cookieKeyInput.value = state.key;
    }

    try {
      const link = await autoActivateLinkedSession();
      if (link.linked) {
        cookieKeyInput.value = link.linked.key || cookieKeyInput.value || "";
      }
    } catch {
      // ignore linking error, IMAP flow should continue
    }
    await loadNetflixSession();

    const labels = Array.isArray(data.labels) ? data.labels : [];
    renderLabels(labels);
    setStatus("Đăng nhập thành công.");

    if (labels.length > 0) {
      await fetchMailsByLabel(labels[0]);
    }
  } catch (error) {
    state.loggedIn = false;
    renderLabels([]);
    setStatus(`Lỗi: ${error.message}`);
  }
});

qs("imap-user").addEventListener("input", saveImapConfig);
qs("imap-pass").addEventListener("input", saveImapConfig);
qs("imap-key").addEventListener("input", saveImapConfig);

const cookieInput = qs("nf-cookie");
const cookieKeyInput = qs("nf-key");
const cookieResult = qs("cookie-result");
const saveCookieBtn = qs("btn-cookie-save");
const checkSavedSessionBtn = qs("btn-cookie-check");
const clearAllSessionsBtn = qs("btn-cookie-clear-all");
const sessionListRoot = qs("nf-session-list");
const netflixState = {
  activeSessionId: null,
  sessions: [],
};

function formatSessionInfo(session) {
  if (!session || !session.hasCookie) {
    const total = Array.isArray(session?.sessions) ? session.sessions.length : 0;
    return `Phiên hiện tại: CHƯA CÓ COOKIE\nTổng phiên đã lưu: ${total}`;
  }

  const updatedAt = session.updatedAt ? formatDateTime(session.updatedAt) : "không rõ";
  const lastCheck = session.lastCheck || null;
  const liveDie = lastCheck?.status || "CHƯA KIỂM TRA";
  const checkedAt = lastCheck?.checkedAt ? formatDateTime(lastCheck.checkedAt) : "chưa có";
  const cookieMeta = `${session.cookieFormat || "unknown"} / ${session.cookieCount || 0} cookie`;

  return (
    `Phiên active: ${session.activeSessionKey || "(không key)"}\n` +
    `Phiên hiện tại: ĐÃ CÓ COOKIE (${session.cookiePreview || "ẩn"})\n` +
    `Múi giờ hiển thị: Asia/Ho_Chi_Minh (UTC+7)\n` +
    `Định dạng lưu: ${cookieMeta}\n` +
    `Tổng phiên đã lưu: ${(session.sessions || []).length}\n` +
    `Cập nhật lúc: ${updatedAt}\n` +
    `Live/Die gần nhất: ${liveDie}\n` +
    `Kiểm tra lúc: ${checkedAt}`
  );
}

function applySessionPayload(payload) {
  netflixState.activeSessionId = payload?.activeSessionId || null;
  netflixState.sessions = Array.isArray(payload?.sessions) ? payload.sessions : [];
}

function renderSessionList() {
  sessionListRoot.innerHTML = "";
  if (!netflixState.sessions.length) {
    sessionListRoot.innerHTML =
      '<tr><td colspan="4">Chưa có phiên nào được lưu.</td></tr>';
    return;
  }

  const linkedSession = findLinkedSessionByImap();

  netflixState.sessions.forEach((session) => {
    const row = document.createElement("tr");
    row.className = "";
    if (session.id && session.id === netflixState.activeSessionId) {
      row.classList.add("session-row-active");
    }

    const rawStatus = String(session.lastCheck?.status || "").toUpperCase();
    const statusText =
      rawStatus === "LIVE"
        ? "LIVE"
        : rawStatus === "DIE"
          ? "DIE"
          : "CHƯA KIỂM TRA";
    const statusClass =
      rawStatus === "LIVE" ? "live" : rawStatus === "DIE" ? "die" : "unknown";
    const lastCheckedAt = session.lastCheck?.checkedAt
      ? formatDateTime(session.lastCheck.checkedAt)
      : "chưa check";

    const linkBadge = state.loggedIn
      ? session.id === linkedSession?.id
        ? '<span class="pill">ACTIVE</span>'
        : '<span class="pill">WAIT</span>'
      : session.id === netflixState.activeSessionId
        ? '<span class="pill">ACTIVE</span>'
        : '<span class="pill">SAVED</span>';

    row.innerHTML = `
      <td>${escapeHtml(session.key || "(không key)")} ${linkBadge}</td>
      <td>${escapeHtml(lastCheckedAt)}</td>
      <td><span class="session-status ${statusClass}">${statusText}</span></td>
      <td><button class="session-delete-btn" type="button" data-action="delete" data-id="${escapeAttr(session.id || "")}">Xóa</button></td>
    `;
    sessionListRoot.appendChild(row);
  });

  sessionListRoot.querySelectorAll("button[data-action='delete']").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const sessionId = String(btn.dataset.id || "").trim();
      if (!sessionId) return;
      try {
        const data = await deleteJson(`/api/netflix/session/${encodeURIComponent(sessionId)}`);
        applySessionPayload(data);
        renderSessionList();
        cookieKeyInput.value = data.activeSessionKey || "";
        cookieResult.textContent =
          `${data.message || "Đã xóa session."}\n` +
          `${formatSessionInfo(data)}`;
      } catch (error) {
        cookieResult.textContent = `Lỗi xóa session: ${error.message}`;
      }
    });
  });
}

function formatAccountHints(data) {
  const lines = [];
  const account = data?.account || null;
  const identity = data?.identity || null;
  if (account) {
    if (account.emailHint) lines.push(`Email hint: ${account.emailHint}`);
    if (account.profileNameHint) lines.push(`Profile hint: ${account.profileNameHint}`);
    if (account.memberSinceHint) lines.push(`Member since: ${account.memberSinceHint}`);
    if (account.title) lines.push(`Title: ${account.title}`);
    if (account.finalUrl) lines.push(`Account URL: ${account.finalUrl}`);
  }
  if (identity?.netflixIdHint || identity?.secureNetflixIdHint) {
    lines.push(
      `Cookie ID hint: ${identity.netflixIdHint || "-"} | ${identity.secureNetflixIdHint || "-"}`
    );
  }
  return lines.length ? lines.join("\n") : "Không đọc được hint tài khoản từ phản hồi Netflix.";
}

function formatCheckStatus(data) {
  if (data.status === "LIVE") {
    return "TRẠNG THÁI: LIVE (cookie hợp lệ)";
  }
  if (data.status === "DIE") {
    return "TRẠNG THÁI: DIE (cookie không hợp lệ hoặc đã hết hạn)";
  }
  return `TRẠNG THÁI: ${data.status || "Không xác định"}`;
}

function normalizeLookupKey(input) {
  return String(input || "")
    .trim()
    .toLowerCase();
}

function findLinkedSessionByImap() {
  if (!state.loggedIn || !state.key) return null;
  const lookup = normalizeLookupKey(state.key);
  return (
    netflixState.sessions.find((session) => normalizeLookupKey(session.key) === lookup) || null
  );
}

async function autoActivateLinkedSession() {
  const linked = findLinkedSessionByImap();
  if (!linked) return { linked: null, switched: false };
  if (linked.id && linked.id !== netflixState.activeSessionId) {
    const data = await postJson("/api/netflix/session/select", { sessionId: linked.id });
    applySessionPayload(data);
    return { linked: findLinkedSessionByImap(), switched: true };
  }
  return { linked, switched: false };
}

async function loadNetflixSession() {
  try {
    let session = await getJson("/api/netflix/session");
    applySessionPayload(session);
    if (state.loggedIn) {
      try {
        await autoActivateLinkedSession();
        session = await getJson("/api/netflix/session");
        applySessionPayload(session);
      } catch {
        // Vẫn render dù link sync thất bại
      }
    }
    renderSessionList();
    cookieKeyInput.value = session.activeSessionKey || state.key || "";
    cookieResult.textContent = formatSessionInfo(session);
  } catch (error) {
    cookieResult.textContent = `Không thể tải phiên Netflix: ${error.message}`;
  }
}

saveCookieBtn.addEventListener("click", async () => {
  const cookie = cookieInput.value.trim();
  const key = cookieKeyInput.value.trim();
  if (!cookie) {
    cookieResult.textContent = "Vui lòng dán cookie trước khi lưu.";
    return;
  }

  if (!key) {
    cookieResult.textContent = "Vui lòng nhập key định danh trước khi lưu phiên.";
    return;
  }

  cookieResult.textContent = "Đang kiểm tra cookie rồi lưu phiên...";

  try {
    const check = await postJson("/api/netflix/check-cookie", { cookie });
    const statusText = formatCheckStatus(check);
    if (String(check.status || "").toUpperCase() !== "LIVE") {
      cookieResult.textContent =
        `${statusText}\n` +
        `HTTP: ${check.httpStatus}\n` +
        `Redirect: ${check.redirectedTo || "Không có"}\n` +
        `${check.note || ""}\n\n` +
        "Cookie không LIVE nên chưa lưu.";
      return;
    }

    const data = await postJson("/api/netflix/session", { cookie, key });
    applySessionPayload(data);
    renderSessionList();
    cookieKeyInput.value = data.activeSessionKey || key;
    const accepted = Number(data.acceptedCount || 0);
    const rejected = Number(data.rejectedCount || 0);
    const accountHints = formatAccountHints(check);
    cookieResult.textContent =
      `${data.message || "Đã lưu phiên Netflix."}\n` +
      `${statusText}\n` +
      `Đã nhận: ${accepted} cookie, bỏ qua: ${rejected}\n` +
      `${accountHints}\n\n` +
      `${formatSessionInfo(data)}`;
  } catch (error) {
    cookieResult.textContent = `Lỗi: ${error.message}`;
  }
});

checkSavedSessionBtn.addEventListener("click", async () => {
  if (!netflixState.sessions.length) {
    cookieResult.textContent = "Chưa có session đã lưu để kiểm tra.";
    return;
  }

  cookieResult.textContent = "Đang kiểm tra toàn bộ session đã lưu...";

  try {
    const summaries = [];
    let latestPayload = null;
    const sessionsCopy = [...netflixState.sessions];
    for (const session of sessionsCopy) {
      cookieResult.textContent = `Đang kiểm tra: ${session.key}...`;
      const data = await postJson("/api/netflix/check-cookie", { sessionId: session.id });
      latestPayload = data.session || latestPayload;
      const statusLabel = String(data.status || "UNKNOWN").toUpperCase();
      summaries.push(`${session.key}: ${statusLabel}`);
      // Cập nhật UI sau mỗi session để hiển thị tiến trình
      if (latestPayload) {
        applySessionPayload(latestPayload);
        renderSessionList();
      }
    }
    if (latestPayload) {
      cookieKeyInput.value = latestPayload.activeSessionKey || cookieKeyInput.value || "";
    }
    cookieResult.textContent =
      "Kết quả kiểm tra session đã lưu:\n" +
      summaries.join("\n") +
      "\n\n" +
      formatSessionInfo(latestPayload || null);
  } catch (error) {
    cookieResult.textContent = `Lỗi: ${error.message}`;
  }
});

clearAllSessionsBtn.addEventListener("click", async () => {
  cookieResult.textContent = "Đang xóa toàn bộ phiên đã lưu...";
  try {
    const data = await deleteJson("/api/netflix/session");
    applySessionPayload(data);
    renderSessionList();
    cookieKeyInput.value = "";
    cookieResult.textContent =
      `${data.message || "Đã xóa toàn bộ phiên."}\n` +
      `${formatSessionInfo(data)}`;
  } catch (error) {
    cookieResult.textContent = `Lỗi xóa toàn bộ phiên: ${error.message}`;
  }
});

loadImapConfig();
loadNetflixSession();
renderImapAccountList();



