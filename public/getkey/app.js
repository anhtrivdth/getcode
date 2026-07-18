const app = document.getElementById("key-app");
const form = document.getElementById("key-create-form");
const list = document.getElementById("key-list");
const listMessage = document.getElementById("key-list-message");
const formError = document.getElementById("key-form-error");
const result = document.getElementById("new-key-result");
const rawKeyOutput = document.getElementById("new-key-value");
const state = { csrfToken: "", keys: [] };
const loginScreen = document.getElementById("getkey-login");
const loginForm = document.getElementById("getkey-login-form");
const linkedKeyInput = document.getElementById("getkey-linked-key");
const loginError = document.getElementById("getkey-login-error");

function showGetkeyLogin(message = "") {
  state.csrfToken = "";
  app.hidden = true;
  loginScreen.hidden = false;
  loginError.textContent = message;
  linkedKeyInput.value = "";
  window.setTimeout(() => linkedKeyInput.focus(), 0);
}

async function showGetkeyApp(session) {
  state.csrfToken = String(session.csrfToken || "");
  loginScreen.hidden = true;
  app.hidden = false;
  await loadKeys();
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function toLocalInput(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

function formatDate(value) {
  if (!value) return "Chưa có";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Không rõ"
    : new Intl.DateTimeFormat("vi-VN", { dateStyle: "short", timeStyle: "short" }).format(date);
}

function setDefaultExpiry(days = 30) {
  const date = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
  document.getElementById("key-expiry").value = toLocalInput(date);
}

async function api(url, options = {}) {
  const method = String(options.method || "GET").toUpperCase();
  const headers = new Headers(options.headers || {});
  if (!["GET", "HEAD"].includes(method)) headers.set("X-CSRF-Token", state.csrfToken);
  const response = await fetch(url, { ...options, method, headers, credentials: "same-origin" });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401) {
    showGetkeyLogin("Phiên quản lý key đã hết hạn. Vui lòng nhập lại key liên kết IMAP/Netflix.");
    throw new Error("Phiên đăng nhập đã hết hạn.");
  }
  if (!response.ok) throw new Error(data.message || `Yêu cầu thất bại: ${response.status}`);
  return data;
}

function renderStats() {
  document.getElementById("stat-total").textContent = state.keys.length;
  for (const status of ["active", "expired", "revoked"]) {
    document.getElementById(`stat-${status}`).textContent = state.keys.filter((key) => key.status === status).length;
  }
}

function statusLabel(status) {
  return { active: "Hoạt động", expired: "Hết hạn", revoked: "Đã thu hồi" }[status] || status;
}

function renderKeys() {
  renderStats();
  list.innerHTML = "";
  listMessage.textContent = state.keys.length ? "" : "Chưa có key nào được đăng ký.";
  if (!state.keys.length) {
    list.innerHTML = '<div class="empty-state">Tạo key đầu tiên bằng biểu mẫu phía trên.</div>';
    return;
  }

  for (const key of state.keys) {
    const disabled = key.status === "revoked" ? "disabled" : "";
    const card = document.createElement("article");
    card.className = "key-card";
    card.dataset.keyId = key.id;
    card.innerHTML = `
      <div class="key-identity">
        <strong>${escapeHtml(key.label)}</strong>
        <code>${escapeHtml(key.preview)}</code>
      </div>
      <div class="key-meta">
        <span class="status status-${escapeHtml(key.status)}">${escapeHtml(statusLabel(key.status))}</span><br />
        Liên kết Admin: <code>${escapeHtml(key.linkedKeyPreview)}</code><br />
        Tạo: ${escapeHtml(formatDate(key.createdAt))}<br />
        Dùng gần nhất: ${escapeHtml(formatDate(key.lastUsedAt))} · ${Number(key.usageCount) || 0} lượt
      </div>
      <div class="key-edit">
        <input class="edit-label" value="${escapeHtml(key.label)}" maxlength="80" aria-label="Tên key ${escapeHtml(key.preview)}" ${disabled} />
        <input class="edit-expiry" type="datetime-local" value="${escapeHtml(toLocalInput(key.expiresAt))}" aria-label="Hạn key ${escapeHtml(key.preview)}" ${disabled} />
      </div>
      <div class="key-actions">
        <button class="save-key button-secondary" type="button" ${disabled}>Lưu / Gia hạn</button>
        <button class="revoke-key button-danger" type="button" ${disabled}>Thu hồi</button>
      </div>
    `;
    list.appendChild(card);
  }
}

async function loadKeys() {
  listMessage.textContent = "Đang tải danh sách key...";
  try {
    const data = await api("/api/keys");
    state.keys = Array.isArray(data.keys) ? data.keys : [];
    renderKeys();
  } catch (error) {
    listMessage.textContent = error.message;
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  formError.textContent = "";
  const submit = document.getElementById("key-create-submit");
  const label = document.getElementById("key-label").value.trim();
  const expiryValue = document.getElementById("key-expiry").value;
  if (!label || !expiryValue) {
    formError.textContent = "Vui lòng nhập tên và hạn sử dụng.";
    return;
  }
  submit.disabled = true;
  submit.textContent = "Đang tạo Access Key...";
  try {
    const data = await api("/api/keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ label, expiresAt: new Date(expiryValue).toISOString() }),
    });
    rawKeyOutput.textContent = data.rawKey;
    result.hidden = false;
    form.reset();
    setDefaultExpiry(30);
    await loadKeys();
    result.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (error) {
    formError.textContent = error.message;
  } finally {
    submit.disabled = false;
    submit.textContent = "Tạo Access Key ngẫu nhiên";
  }
});

list.addEventListener("click", async (event) => {
  const card = event.target.closest(".key-card");
  if (!card) return;
  const keyId = card.dataset.keyId;
  try {
    if (event.target.closest(".save-key")) {
      const label = card.querySelector(".edit-label").value.trim();
      const expiresAt = card.querySelector(".edit-expiry").value;
      await api(`/api/keys/${encodeURIComponent(keyId)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label, expiresAt: new Date(expiresAt).toISOString() }),
      });
      await loadKeys();
    }
    if (event.target.closest(".revoke-key")) {
      if (!window.confirm("Thu hồi key này? Key sẽ ngừng hoạt động ngay và không thể kích hoạt lại.")) return;
      await api(`/api/keys/${encodeURIComponent(keyId)}`, { method: "DELETE" });
      await loadKeys();
    }
  } catch (error) {
    listMessage.textContent = error.message;
  }
});

document.querySelectorAll("[data-days]").forEach((button) => {
  button.addEventListener("click", () => setDefaultExpiry(Number(button.dataset.days)));
});

document.getElementById("copy-new-key").addEventListener("click", async () => {
  const button = document.getElementById("copy-new-key");
  try {
    await navigator.clipboard.writeText(rawKeyOutput.textContent);
    button.textContent = "Đã sao chép";
    window.setTimeout(() => (button.textContent = "Sao chép Key"), 1600);
  } catch {
    window.getSelection()?.selectAllChildren(rawKeyOutput);
    button.textContent = "Hãy nhấn Ctrl+C";
  }
});

document.getElementById("refresh-keys").addEventListener("click", loadKeys);

document.getElementById("key-logout").addEventListener("click", async () => {
  try {
    await api("/api/getkey/logout", { method: "POST" });
  } finally {
    showGetkeyLogin("Bạn đã thoát trình quản lý key.");
  }
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  loginError.textContent = "";
  const submit = document.getElementById("getkey-login-submit");
  const sourceKey = linkedKeyInput.value.trim();
  if (sourceKey.length < 16) {
    loginError.textContent = "Key liên kết IMAP/Netflix phải có ít nhất 16 ký tự.";
    return;
  }
  submit.disabled = true;
  submit.textContent = "Đang xác thực...";
  try {
    const response = await fetch("/api/getkey/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ sourceKey }),
    });
    const session = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(session.message || "Không thể truy cập GetKey.");
    linkedKeyInput.value = "";
    await showGetkeyApp(session);
  } catch (error) {
    loginError.textContent = error.message;
    linkedKeyInput.select();
  } finally {
    submit.disabled = false;
    submit.textContent = "Truy cập GetKey";
  }
});

async function bootstrap() {
  setDefaultExpiry(30);
  try {
    const response = await fetch("/api/getkey/session", { credentials: "same-origin" });
    const session = await response.json().catch(() => ({}));
    if (!response.ok || !session.authenticated) {
      showGetkeyLogin();
      return;
    }
    await showGetkeyApp(session);
  } catch {
    showGetkeyLogin("Không thể kết nối tới server.");
  }
}

bootstrap();
