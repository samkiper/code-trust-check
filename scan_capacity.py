"""Bound interactive work on the single-process free-beta scanner.

The permit belongs to the synchronous worker, not the HTTP connection: client
cancellation must not admit a second job while the first worker is still running.
This is a per-process bound; revisit before increasing Uvicorn workers/instances.
"""
from functools import wraps
from threading import BoundedSemaphore
from fastapi import HTTPException

_INTERACTIVE_SCAN_SLOT = BoundedSemaphore(1)


def limit_scan_capacity(function):
    @wraps(function)
    def limited(*args, **kwargs):
        if not _INTERACTIVE_SCAN_SLOT.acquire(blocking=False):
            raise HTTPException(
                status_code=429,
                detail="The scanner is busy completing another audit. Your scan has not started. Retry shortly.",
                headers={"Retry-After": "10", "Cache-Control": "no-store"},
            )
        try:
            return function(*args, **kwargs)
        finally:
            _INTERACTIVE_SCAN_SLOT.release()
    return limited
