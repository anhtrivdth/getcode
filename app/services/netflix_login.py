import re
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx


@dataclass
class NetflixLoginResult:
    ok: bool
    message: str


def _extract_auth_url(html: str) -> str | None:
    match = re.search(r'name=["\']authURL["\']\s+value=["\']([^"\']+)["\']', html, flags=re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r'"authURL"\s*:\s*"([^"]+)"', html, flags=re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip())


def _is_code_challenge_page(html: str) -> bool:
    text = _normalize_space(re.sub(r"<[^>]+>", " ", html)).lower()
    markers = (
        "enter the code we sent",
        "nhap ma chung toi da gui",
        "4-digit code",
        "sign-in code",
    )
    return any(marker in text for marker in markers)


def _find_link_by_text(html: str, terms: tuple[str, ...]) -> str | None:
    for match in re.finditer(r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html, flags=re.IGNORECASE | re.DOTALL):
        href = match.group(1).strip()
        anchor_text = _normalize_space(re.sub(r"<[^>]+>", " ", match.group(2))).lower()
        if not href:
            continue
        if any(term in anchor_text for term in terms):
            return href
    return None


def _is_success(client: httpx.Client, response: httpx.Response) -> bool:
    final_url = str(response.url).lower()
    body = response.text.lower()
    has_session_cookie = bool(client.cookies.get("NetflixId") or client.cookies.get("SecureNetflixId"))
    is_login_screen = "/login" in final_url or "/signin" in final_url or 'name="authurl"' in body
    success_paths = ("/browse", "/profiles", "/switchprofile", "/youraccount", "/account")
    is_success_path = any(path in final_url for path in success_paths)
    return has_session_cookie and is_success_path and not is_login_screen


def _post_password(client: httpx.Client, email: str, password: str, page_html: str, page_url: str) -> httpx.Response | None:
    auth_url = _extract_auth_url(page_html)
    if not auth_url:
        return None
    payload = {
        "userLoginId": email,
        "password": password,
        "rememberMe": "true",
        "flow": "websiteSignUp",
        "mode": "login",
        "action": "loginAction",
        "authURL": auth_url,
        "nextPage": "",
    }
    return client.post(urljoin(page_url, "/login"), data=payload)


def _handle_code_page_to_password_page(client: httpx.Client, current_page: httpx.Response) -> httpx.Response | None:
    page_html = current_page.text
    page_url = str(current_page.url)

    # Netflix Help says: Get Help -> Use password instead.
    help_link = _find_link_by_text(
        page_html,
        ("get help", "nhan tro giup", "trợ giúp", "help"),
    )
    if help_link:
        help_page = client.get(urljoin(page_url, help_link))
        use_password_link = _find_link_by_text(
            help_page.text,
            ("use password instead", "dung mat khau", "mật khẩu", "password instead"),
        )
        if use_password_link:
            return client.get(urljoin(str(help_page.url), use_password_link))

    # Sometimes the "Use password instead" link is already in source.
    direct_password_link = _find_link_by_text(
        page_html,
        ("use password instead", "dung mat khau", "mật khẩu", "password instead"),
    )
    if direct_password_link:
        return client.get(urljoin(page_url, direct_password_link))

    return None


def attempt_netflix_login(email: str, password: str) -> NetflixLoginResult:
    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    )
    headers = {"User-Agent": user_agent}

    try:
        with httpx.Client(follow_redirects=True, timeout=25.0, headers=headers) as client:
            # Step 1: open Vietnam login page as requested.
            login_page = client.get("https://www.netflix.com/vn/login")
            if login_page.status_code >= 400:
                return NetflixLoginResult(False, "Khong mo duoc trang dang nhap Netflix.")

            # Step 2: submit password flow directly (fast path).
            first_submit = _post_password(client, email, password, login_page.text, str(login_page.url))
            if not first_submit:
                return NetflixLoginResult(False, "Khong lay duoc auth token dang nhap Netflix.")

            if _is_success(client, first_submit):
                return NetflixLoginResult(True, "Dang nhap Netflix thanh cong.")

            body_lower = first_submit.text.lower()
            credential_error_markers = (
                "incorrect password",
                "incorrect email",
                "does not match an account",
                "wrong password",
            )
            if any(marker in body_lower for marker in credential_error_markers):
                return NetflixLoginResult(False, "Sai email hoac mat khau Netflix.")
            if "recaptcha" in body_lower or "not a bot" in body_lower:
                return NetflixLoginResult(False, "Netflix yeu cau reCAPTCHA, chua the dang nhap tu dong.")

            # Step 3: if code page appears, follow Get Help -> Use password instead.
            challenge_page = first_submit
            if _is_code_challenge_page(challenge_page.text):
                password_page = _handle_code_page_to_password_page(client, challenge_page)
                if password_page:
                    second_submit = _post_password(client, email, password, password_page.text, str(password_page.url))
                    if second_submit and _is_success(client, second_submit):
                        return NetflixLoginResult(True, "Dang nhap Netflix thanh cong.")
                    if second_submit:
                        second_body = second_submit.text.lower()
                        if any(marker in second_body for marker in credential_error_markers):
                            return NetflixLoginResult(False, "Sai email hoac mat khau Netflix.")
                        if "recaptcha" in second_body or "not a bot" in second_body:
                            return NetflixLoginResult(False, "Netflix yeu cau reCAPTCHA, chua the dang nhap tu dong.")

            return NetflixLoginResult(False, "Dang nhap Netflix that bai.")
    except Exception as exc:
        return NetflixLoginResult(False, f"Loi ket noi Netflix: {exc}")
