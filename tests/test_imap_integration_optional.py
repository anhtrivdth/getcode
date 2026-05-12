import os

import pytest

from app.services.imap_client import ImapClient


pytestmark = pytest.mark.skipif(
    not (os.getenv("IMAP_TEST_EMAIL") and os.getenv("IMAP_TEST_APP_PASSWORD")),
    reason="Set IMAP_TEST_EMAIL and IMAP_TEST_APP_PASSWORD to run integration test.",
)


def test_imap_gmail_connection_and_fetch():
    client = ImapClient(
        host=os.getenv("IMAP_TEST_SERVER", "imap.gmail.com"),
        port=int(os.getenv("IMAP_TEST_PORT", "993")),
        username=os.environ["IMAP_TEST_EMAIL"],
        password=os.environ["IMAP_TEST_APP_PASSWORD"],
    )
    mails = client.fetch_recent_mails(max_messages=5, since_minutes=120)
    assert isinstance(mails, list)
