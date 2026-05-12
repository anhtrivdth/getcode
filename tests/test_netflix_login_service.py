from app.services.netflix_login import attempt_netflix_login


class _FakeResponse:
    def __init__(self, status_code: int, url: str, text: str):
        self.status_code = status_code
        self.url = url
        self.text = text


class _FakeCookies(dict):
    def get(self, key, default=None):
        return super().get(key, default)


def test_attempt_netflix_login_not_false_positive_on_login_page(monkeypatch):
    class FakeClient:
        def __init__(self, *args, **kwargs):
            self.cookies = _FakeCookies({"NetflixId": "guest-cookie"})

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url):
            return _FakeResponse(
                200,
                "https://www.netflix.com/login",
                '<input name="authURL" value="token-1" />',
            )

        def post(self, url, data):
            return _FakeResponse(
                200,
                "https://www.netflix.com/login",
                '<input name="authURL" value="token-2" />',
            )

    monkeypatch.setattr("app.services.netflix_login.httpx.Client", FakeClient)
    result = attempt_netflix_login("user@example.com", "wrong-pass")
    assert result.ok is False


def test_attempt_netflix_login_success_on_browse(monkeypatch):
    class FakeClient:
        def __init__(self, *args, **kwargs):
            self.cookies = _FakeCookies({"SecureNetflixId": "real-cookie"})

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url):
            return _FakeResponse(
                200,
                "https://www.netflix.com/login",
                '<input name="authURL" value="token-1" />',
            )

        def post(self, url, data):
            return _FakeResponse(
                200,
                "https://www.netflix.com/browse",
                "<html><body>browse page</body></html>",
            )

    monkeypatch.setattr("app.services.netflix_login.httpx.Client", FakeClient)
    result = attempt_netflix_login("user@example.com", "correct-pass")
    assert result.ok is True


def test_attempt_netflix_login_code_page_then_use_password(monkeypatch):
    class FakeClient:
        def __init__(self, *args, **kwargs):
            self.cookies = _FakeCookies()
            self._post_count = 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url):
            if url.endswith("/vn/login"):
                return _FakeResponse(
                    200,
                    "https://www.netflix.com/vn/login",
                    '<input name="authURL" value="token-login" />',
                )
            if "help-link" in url:
                return _FakeResponse(
                    200,
                    "https://www.netflix.com/help-link",
                    '<a href="/password-page">Use password instead</a>',
                )
            if "password-page" in url:
                return _FakeResponse(
                    200,
                    "https://www.netflix.com/password-page",
                    '<input name="authURL" value="token-password" />',
                )
            return _FakeResponse(200, "https://www.netflix.com/login", "")

        def post(self, url, data):
            self._post_count += 1
            if self._post_count == 1:
                return _FakeResponse(
                    200,
                    "https://www.netflix.com/login",
                    """
                    <h1>Enter the code we sent to your email</h1>
                    <a href="/help-link">Get Help</a>
                    """,
                )
            self.cookies["SecureNetflixId"] = "session-cookie"
            return _FakeResponse(
                200,
                "https://www.netflix.com/browse",
                "<html><body>browse page</body></html>",
            )

    monkeypatch.setattr("app.services.netflix_login.httpx.Client", FakeClient)
    result = attempt_netflix_login("user@example.com", "correct-pass")
    assert result.ok is True
