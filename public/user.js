const keyInput = document.getElementById("user-key");
const btn = document.getElementById("btn-get-code");
const resultArea = document.getElementById("result");
const typeBtns = Array.from(document.querySelectorAll(".type-btn"));

let selectedType = "login_code";

function formatTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const parts = new Intl.DateTimeFormat("vi-VN", {
    timeZone: "Asia/Ho_Chi_Minh",
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
  }).formatToParts(date);
  const m = {};
  parts.forEach((p) => { if (p.type !== "literal") m[p.type] = p.value; });
  return `${m.hour}:${m.minute} ${m.day}/${m.month}/${m.year}`;
}

for (const tb of typeBtns) {
  tb.addEventListener("click", () => {
    for (const b of typeBtns) b.classList.remove("active");
    tb.classList.add("active");
    selectedType = tb.dataset.type;
    resultArea.innerHTML = "";
  });
}

function showLoading(text) {
  resultArea.innerHTML = `<div class="result-loading">${text || "Đang xử lý..."}</div>`;
}

function showCode(code, label) {
  resultArea.innerHTML = `
    <div class="result-code">
      <div class="code-value">${code}</div>
      <div class="code-status">${label || ""}</div>
    </div>
  `;
}

function showExpired() {
  resultArea.innerHTML = `
    <div class="result-expired">
      <div class="expired-icon">⛔</div>
      <div class="expired-text">Liên kết không còn hiệu lực</div>
      <div class="expired-hint">Vui lòng yêu cầu gửi lại mã mới</div>
    </div>
  `;
}

function showConfirmed() {
  resultArea.innerHTML = `
    <div class="result-code">
      <div class="code-value" style="font-size:28px;letter-spacing:0">✅ Đã xác nhận</div>
      <div class="code-status">Hộ gia đình đã được cập nhật thành công</div>
    </div>
  `;
}

function showNotConfirmed() {
  resultArea.innerHTML = `
    <div class="result-expired">
      <div class="expired-icon">⚠️</div>
      <div class="expired-text">Chưa xác nhận được</div>
      <div class="expired-hint">Link có thể đã hết hạn hoặc cần thao tác thủ công</div>
    </div>
  `;
}

function showTvSuccess() {
  resultArea.innerHTML = `
    <div class="result-code">
      <div class="code-value" style="font-size:28px;letter-spacing:0">✅ Thành công</div>
      <div class="code-status">Đã đăng nhập TV thành công!</div>
    </div>
  `;
}

function normalizeTvCode(input) {
  return String(input || "").replace(/\D+/g, "").slice(0, 8);
}

function formatTvCode(input) {
  const digits = normalizeTvCode(input);
  if (digits.length <= 4) return digits;
  return `${digits.slice(0, 4)}-${digits.slice(4)}`;
}

function showTvCodeInput() {
  resultArea.innerHTML = `
    <div class="tv-code-form">
      <p class="tv-code-title">Nhập mã hiển thị trên TV</p>
      <div class="tv-code-input-group">
        <input id="tv-code-input" type="text" maxlength="9" inputmode="numeric" placeholder="1234-5678" autocomplete="off" />
        <button id="tv-code-submit">Xác nhận</button>
      </div>
      <div id="tv-code-status" class="tv-code-status"></div>
    </div>
  `;

  const tvInput = document.getElementById("tv-code-input");
  const tvSubmit = document.getElementById("tv-code-submit");
  const tvStatus = document.getElementById("tv-code-status");

  tvSubmit.addEventListener("click", async () => {
    const code = normalizeTvCode(tvInput.value);
    tvInput.value = formatTvCode(code);
    if (!code) {
      tvStatus.textContent = "Vui lòng nhập mã TV.";
      tvStatus.className = "tv-code-status error";
      return;
    }

    if (code.length !== 8) {
      tvStatus.textContent = "Mã TV phải đủ 8 số, ví dụ 4094-1021.";
      tvStatus.className = "tv-code-status error";
      return;
    }

    tvSubmit.disabled = true;
    tvStatus.textContent = "Đang gửi mã...";
    tvStatus.className = "tv-code-status";

    try {
      const key = keyInput.value.trim();
      const response = await fetch("/api/submit-tv-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key, code }),
      });
      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        tvStatus.textContent = data.message || "Lỗi gửi mã.";
        tvStatus.className = "tv-code-status error";
        return;
      }

      if (data.success) {
        showTvSuccess();
      } else {
        tvStatus.textContent =
          data.message ||
          "Mã TV không đúng hoặc đã được sử dụng. Vui lòng thử lại.\nLưu ý: liên hệ seller nếu bạn chắc chắn mã nhập đúng nhưng vẫn lỗi.";
        tvStatus.className = "tv-code-status error";
      }
    } catch (error) {
      tvStatus.textContent = `Lỗi: ${error.message}`;
      tvStatus.className = "tv-code-status error";
    } finally {
      tvSubmit.disabled = false;
    }
  });

  tvInput.addEventListener("input", () => {
    const formatted = formatTvCode(tvInput.value);
    if (tvInput.value !== formatted) {
      tvInput.value = formatted;
    }
  });

  tvInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") tvSubmit.click();
  });

  tvInput.focus();
}

function showError(message) {
  resultArea.innerHTML = `<div class="result-error">${message}</div>`;
}

btn.addEventListener("click", async () => {
  const key = keyInput.value.trim();
  if (!/^sk-[A-Za-z0-9_-]{12}$/.test(key)) {
    showError("Access Key phải có dạng sk- và 12 ký tự ngẫu nhiên.");
    return;
  }

  btn.disabled = true;
  showLoading(selectedType === "temp_access" ? "Đang kết nối Netflix TV..." : "Đang lấy mã...");

  try {
    const response = await fetch("/api/get-code", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key, type: selectedType }),
    });
    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      showError(data.message || "Không thể lấy mã.");
      return;
    }

    // TEMP_ACCESS: flow TV 2 bước
    if (selectedType === "temp_access") {
      if (data.step === "input_code") {
        showTvCodeInput();
      } else if (data.step === "error") {
        showError(data.message || "Không thể truy cập trang TV.");
      } else {
        showError(data.message || "Lỗi không xác định.");
      }
      return;
    }

    if (data.expired) {
      showExpired();
      return;
    }

    // HOME_UPDATE
    if (selectedType === "home_update") {
      if (data.confirmed) {
        showConfirmed();
      } else {
        showNotConfirmed();
      }
      return;
    }

    // LOGIN_CODE
    if (data.code) {
      showCode(data.code, formatTime(data.date));
    } else {
      showError(data.message || "Không tìm thấy mã.");
    }
  } catch (error) {
    showError(`Lỗi kết nối: ${error.message}`);
  } finally {
    btn.disabled = false;
  }
});

keyInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") btn.click();
});
