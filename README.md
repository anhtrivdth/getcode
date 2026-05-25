# Netflix Mail Admin UI (MVP)

Web admin panel for:

- IMAP login check
- Filtering mails inside a specified mailbox/label
- Netflix session cookie save (server-side) and LIVE/DIE check
  - Accepts cookie header string or JSON cookie array export
  - Recommended flow: verify account first, then save session
  - Supports saved-session list with custom key labels and active-session switching
  - IMAP key auto-sync: IMAP requests require `key` and auto-link to Netflix session with same key

## Run

```bash
npm install
npm start
```

Open:

`http://localhost:3000`

## Notes

- For Gmail IMAP, use App Password instead of main account password.
- IMAP APIs (`/api/imap/login`, `/api/imap/labels`, `/api/imap/fetch-mails`) now require `user`, `pass`, and `key`.
- Mailbox/label value depends on provider (for Gmail often `INBOX`, `[Gmail]/All Mail`, or custom label path).
- Netflix cookie LIVE/DIE check is heuristic and can fail when Netflix changes anti-bot behavior.
- Saved Netflix session is persisted at `data/netflix-session.json`.
