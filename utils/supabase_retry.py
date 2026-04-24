"""
Retry transient HTTP failures on Supabase PostgREST (.execute()).
Mitigates httpx/httpcore RemoteProtocolError: Server disconnected (often HTTP/2 + parallel requests).
"""
import time
from typing import Callable, Tuple, Type, TypeVar

T = TypeVar("T")


def _transient_error_types() -> Tuple[Type[BaseException], ...]:
    types_list: list[Type[BaseException]] = []
    try:
        import httpx

        types_list.extend(
            [
                httpx.RemoteProtocolError,
                httpx.ConnectError,
                httpx.ReadTimeout,
                httpx.WriteTimeout,
                httpx.PoolTimeout,
            ]
        )
    except ImportError:
        pass
    try:
        import httpcore

        types_list.append(httpcore.RemoteProtocolError)
    except ImportError:
        pass
    return tuple(types_list)


_TRANSIENT = _transient_error_types()


def execute_with_retry(fn: Callable[[], T], *, retries: int = 4, base_delay: float = 0.12) -> T:
    if not _TRANSIENT:
        return fn()

    for attempt in range(retries):
        try:
            return fn()
        except _TRANSIENT:
            if attempt >= retries - 1:
                raise
            time.sleep(base_delay * (2**attempt))

    raise RuntimeError("execute_with_retry: unreachable")
