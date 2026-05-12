import asyncio
from contextlib import suppress

from sqlalchemy import select
from sqlalchemy.orm import joinedload

from app.config import get_settings
from app.database import SessionLocal
from app.models import AccessKey
from app.services.resolve_service import cache, fetch_latest_code_for_entity


settings = get_settings()


class CachePoller:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> None:
        if settings.poll_interval_seconds <= 0:
            return
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task

    async def _loop(self) -> None:
        while self._running:
            await self._poll_once()
            await asyncio.sleep(settings.poll_interval_seconds)

    async def _poll_once(self) -> None:
        db = SessionLocal()
        try:
            keys = db.execute(
                select(AccessKey)
                .where(AccessKey.active.is_(True))
                .options(joinedload(AccessKey.mailbox), joinedload(AccessKey.parser_rule))
            ).scalars().all()
            for key in keys:
                if not key.mailbox.active or not key.parser_rule.active:
                    continue
                if cache.get(key.id):
                    continue
                latest = fetch_latest_code_for_entity(key)
                if latest:
                    code, received_at, source_label = latest
                    cache.set(
                        key.id,
                        code=code,
                        received_at=received_at,
                        source_label=source_label,
                        ttl_seconds=settings.cache_ttl_seconds,
                    )
        finally:
            db.close()
