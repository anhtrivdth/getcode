import { access, appendFile, readFile, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { randomBytes } from "node:crypto";
import path from "node:path";

const envPath = path.resolve(process.cwd(), ".env");

try {
  await access(envPath, constants.F_OK);
  const current = await readFile(envPath, "utf8");
  const existingKeys = new Set(
    current
      .split(/\r?\n/)
      .filter((line) => line && !line.startsWith("#") && line.includes("="))
      .map((line) => line.slice(0, line.indexOf("=")))
  );
  const safeDefaults = {
    ADMIN_SESSION_HOURS: "8",
    ADMIN_LOGIN_RATE_LIMIT: "10",
    ADMIN_COOKIE_SECURE: "false",
    ACCESS_KEYS_FILE: "data/access-keys.json",
  };
  const additions = Object.entries(safeDefaults)
    .filter(([key]) => !existingKeys.has(key))
    .map(([key, value]) => `${key}=${value}`);
  if (additions.length) {
    await appendFile(envPath, `\n${additions.join("\n")}\n`, "utf8");
    console.log(`Đã bổ sung ${additions.length} cấu hình session admin còn thiếu vào .env.`);
  } else {
    console.log(".env đã tồn tại và có đủ cấu hình session admin.");
  }
} catch {
  const adminPassword = randomBytes(18).toString("base64url");
  const encryptionKey = randomBytes(32).toString("base64url");
  const content = [
    "NODE_ENV=development",
    "HOST=127.0.0.1",
    "PORT=3000",
    "",
    "ADMIN_USERNAME=admin",
    `ADMIN_PASSWORD=${adminPassword}`,
    `DATA_ENCRYPTION_KEY=${encryptionKey}`,
    "ADMIN_SESSION_HOURS=8",
    "ADMIN_LOGIN_RATE_LIMIT=10",
    "ADMIN_COOKIE_SECURE=false",
    "",
    "IMAP_HOST=imap.gmail.com",
    "IMAP_PORT=993",
    "IMAP_SECURE=true",
    "TRUST_PROXY=false",
    "ADMIN_RATE_LIMIT=500",
    "PUBLIC_RATE_LIMIT=30",
    "NETFLIX_SESSION_FILE=data/netflix-session.json",
    "ACCESS_KEYS_FILE=data/access-keys.json",
    "",
  ].join("\n");
  await writeFile(envPath, content, { encoding: "utf8", mode: 0o600, flag: "wx" });
  console.log("Đã tạo .env với mật khẩu admin và khóa mã hóa ngẫu nhiên.");
  console.log("Mở file .env để xem hoặc thay đổi ADMIN_PASSWORD trước khi sử dụng.");
}
