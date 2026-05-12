from datetime import datetime

import pytest

from app.services.imap_client import ImapMail
from app.services.resolve_service import ResolveError, cache, resolve_code
from tests.helpers import create_seed


@pytest.mark.asyncio
async def test_rate_limit_one_request_per_180_minutes(db_session, monkeypatch):
    create_seed(db_session)
    cache._store.clear()

    def fake_fetch_recent_mails(self, max_messages=30, since_minutes=60):
        return [
            ImapMail(
                body="Your OTP: 999888",
                sender="no-reply@example.com",
                subject="Your OTP",
                received_at=datetime.utcnow(),
            )
        ]

    monkeypatch.setattr(
        "app.services.imap_client.ImapClient.fetch_recent_mails",
        fake_fetch_recent_mails,
    )

    first = await resolve_code(db_session, key_plain="team-secret-key", ip="127.0.0.1")
    assert first.code == "999888"

    with pytest.raises(ResolveError) as err:
        await resolve_code(db_session, key_plain="team-secret-key", ip="127.0.0.1")
    assert err.value.code == "rate_limited"
    assert err.value.ttl_hint is not None
    assert err.value.ttl_hint > 0
