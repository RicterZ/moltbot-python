import asyncio
import uuid
from typing import Any, Callable, Optional

from .client import GatewayWebSocketClient


def _extract_text(message: Any) -> Optional[str]:
    """Best-effort: pull out text from message.content[]."""
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    if not isinstance(content, list):
        return None
    parts: list[str] = []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            text = item.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "\n".join(parts) if parts else None


async def status_async(
    *,
    url: str | None = None,
    token: str | None = None,
    password: str | None = None,
    scopes: Optional[list[str]] = None,
) -> Any:
    client = GatewayWebSocketClient(
        url=url,
        token=token,
        password=password,
        scopes=scopes,
    )
    await client.connect()
    try:
        return await client.status()
    finally:
        await client.close()


def status_sync(
    *,
    url: str | None = None,
    token: str | None = None,
    password: str | None = None,
    scopes: Optional[list[str]] = None,
) -> Any:
    return asyncio.run(status_async(url=url, token=token, password=password, scopes=scopes))


async def chat_once_async(
    *,
    session_key: str,
    message: str,
    url: str | None = None,
    token: str | None = None,
    password: str | None = None,
    scopes: Optional[list[str]] = None,
    thinking: Optional[str] = None,
    deliver: Optional[bool] = None,
    timeout_ms: Optional[int] = None,
    wait_timeout: Optional[float] = 60,
    idempotency_key: Optional[str] = None,
    on_event: Optional[Callable[[dict[str, Any]], None]] = None,
) -> dict[str, Any]:
    """Send once; stream chat events; return final payload and full transcript."""
    events: list[dict[str, Any]] = []
    done = asyncio.Event()
    run_id = idempotency_key or str(uuid.uuid4())
    final_payload: Optional[dict[str, Any]] = None
    final_state: str | None = None

    def _on_event(evt: dict[str, Any]) -> None:
        nonlocal final_payload, final_state
        if evt.get("event") != "chat":
            return
        payload = evt.get("payload") or {}
        if payload.get("runId") != run_id:
            return
        events.append(payload)
        if on_event:
            on_event(payload)
        state = payload.get("state")
        if state in {"final", "error", "aborted"}:
            final_payload = payload
            final_state = state
            done.set()

    client = GatewayWebSocketClient(
        url=url,
        token=token,
        password=password,
        scopes=scopes,
        on_event=_on_event,
    )
    await client.connect()
    try:
        ack = await client.send_chat(
            session_key=session_key,
            message=message,
            thinking=thinking,
            deliver=deliver,
            timeout_ms=timeout_ms,
            idempotency_key=run_id,
        )
        if wait_timeout and wait_timeout > 0:
            try:
                await asyncio.wait_for(done.wait(), timeout=wait_timeout)
            except asyncio.TimeoutError:
                pass
        final_text = _extract_text(final_payload.get("message")) if final_payload else None
        return {
            "runId": run_id,
            "ack": ack.get("response"),
            "events": events,
            "final": final_payload,
            "final_text": final_text,
            "state": final_state or ("timeout" if wait_timeout else None),
        }
    finally:
        await client.close()


def chat_once_sync(
    *,
    session_key: str,
    message: str,
    url: str | None = None,
    token: str | None = None,
    password: str | None = None,
    scopes: Optional[list[str]] = None,
    thinking: Optional[str] = None,
    deliver: Optional[bool] = None,
    timeout_ms: Optional[int] = None,
    wait_timeout: Optional[float] = 60,
    idempotency_key: Optional[str] = None,
    on_event: Optional[Callable[[dict[str, Any]], None]] = None,
) -> dict[str, Any]:
    return asyncio.run(
        chat_once_async(
            session_key=session_key,
            message=message,
            url=url,
            token=token,
            password=password,
            scopes=scopes,
            thinking=thinking,
            deliver=deliver,
            timeout_ms=timeout_ms,
            wait_timeout=wait_timeout,
            idempotency_key=idempotency_key,
            on_event=on_event,
        )
    )
