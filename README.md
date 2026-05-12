# Get Code Service

Dịch vụ tra mã theo `KEY` với giao diện người dùng và trang quản trị.

## Chạy nhanh

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload
```

## URL

- Dashboard: `http://127.0.0.1:8000/`
- Admin Panel: `http://127.0.0.1:8000/admin`
- Health check: `GET /healthz`

## Public API

- `POST /api/code/resolve`: tra mã tổng quát theo key.
- `POST /api/code/login-codes`: lấy mã đăng nhập mới nhất.
- `POST /api/code/family-link`: lấy mã hộ gia đình (đọc từ link Netflix bằng session cookie).

Ví dụ request:

```json
{ "key": "your-team-key" }
```

## Admin API

Header bắt buộc:

- `X-Admin-Token: <ADMIN_TOKEN>`

Nhóm endpoint:

- `GET/POST/PATCH/DELETE /api/admin/mailboxes`
- `GET/POST/PATCH/DELETE /api/admin/rules`
- `GET/POST/PATCH/DELETE /api/admin/keys`
- `GET /api/admin/audit`
- `POST /api/admin/simple/setup`
- `GET /api/admin/simple/list`
- `POST /api/admin/simple/netflix-login-manual/start`
- `GET /api/admin/simple/netflix-login-manual/{job_id}`
- `POST /api/admin/simple/netflix-session-check`

## Ghi chú triển khai

- Bảo mật key bằng hash HMAC-SHA256.
- Mật khẩu app email và session Netflix được mã hóa khi lưu.
- Tab `Xác minh hộ gia đình cho TV` hiện ở trạng thái `COMMING SOON`.

