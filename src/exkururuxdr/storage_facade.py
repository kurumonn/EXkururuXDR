from __future__ import annotations

from typing import Any

from .storage import XdrStorage


class XdrReadStorage:
    def __init__(self, storage: XdrStorage) -> None:
        self._storage = storage

    def __getattr__(self, name: str) -> Any:
        return getattr(self._storage, name)


class XdrWriteStorage(XdrReadStorage):
    pass
