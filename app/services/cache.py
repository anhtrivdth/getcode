from dataclasses import dataclass
from datetime import datetime, timedelta
import asyncio


@dataclass
class CacheItem:
    code: str
    received_at: datetime
    source_label: str
    expires_at: datetime


class ResolveCache:
    def __init__(self) -> None:
        self._store: dict[int, CacheItem] = {}

    def get(self, key_id: int) -> CacheItem | None:
        item = self._store.get(key_id)
        if not item:
            return None
        if item.expires_at < datetime.utcnow():
            self._store.pop(key_id, None)
            return None
        return item

    def set(self, key_id: int, code: str, received_at: datetime, source_label: str, ttl_seconds: int) -> None:
        self._store[key_id] = CacheItem(
            code=code,
            received_at=received_at,
            source_label=source_label,
            expires_at=datetime.utcnow() + timedelta(seconds=ttl_seconds),
        )


class KeyLockRegistry:
    def __init__(self) -> None:
        self._locks: dict[int, asyncio.Lock] = {}
        self._meta_lock = asyncio.Lock()

    async def lock_for(self, key_id: int) -> asyncio.Lock:
        async with self._meta_lock:
            if key_id not in self._locks:
                self._locks[key_id] = asyncio.Lock()
            return self._locks[key_id]
