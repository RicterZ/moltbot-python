import asyncio
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass
import logging
from typing import Any, Callable, Dict, Optional

import websockets
from websockets.client import WebSocketClientProtocol
from websockets.exceptions import ConnectionClosed

from .auth_store import clear_device_token, load_device_token, store_device_token
from .device import DeviceIdentity, load_or_create_identity, public_key_base64url, sign_payload

PROTOCOL_VERSION = 3
MAX_PAYLOAD_BYTES = 25 * 1024 * 1024

GatewayEventFrame = Dict[str, Any]


class GatewayError(Exception):
    pass


@dataclass
class _PendingRequest:
    future: asyncio.Future
    expect_final: bool


def _build_device_auth_payload(
    *,
    device_id: str,
    client_id: str,
    client_mode: str,
    role: str,
    scopes: list[str],
    signed_at_ms: int,
    token: Optional[str],
    nonce: Optional[str],
) -> str:
    version = "v2" if nonce else "v1"
    scope_str = ",".join(scopes)
    base = [
        version,
        device_id,
        client_id,
        client_mode,
        role,
        scope_str,
        str(signed_at_ms),
        token or "",
    ]
    if version == "v2":
        base.append(nonce or "")
    return "|".join(base)


def _json_dumps(data: Any) -> str:
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False)


class GatewayWebSocketClient:
    def __init__(
        self,
        *,
        url: str | None = None,
        token: str | None = None,
        password: str | None = None,
        scopes: Optional[list[str]] = None,
        role: str = "operator",
        client_id: str = "gateway-client",
        client_mode: str = "backend",
        client_version: str = "python-sdk",
        client_display_name: str = "moltbot-python-sdk",
        caps: Optional[list[str]] = None,
        commands: Optional[list[str]] = None,
        permissions: Optional[dict[str, bool]] = None,
        device_identity: Optional[DeviceIdentity] = None,
        on_event: Optional[Callable[[GatewayEventFrame], None]] = None,
        on_gap: Optional[Callable[[dict[str, int]], None]] = None,
        on_close: Optional[Callable[[int, str], None]] = None,
        path_env: Optional[str] = None,
    ) -> None:
        self.url = url or "ws://127.0.0.1:18789"
        self.token = token
        self.password = password
        self.scopes = scopes or ["operator.admin"]
        self.role = role
        self.client_id = client_id
        self.client_mode = client_mode
        self.client_version = client_version
        self.client_display_name = client_display_name
        self.caps = caps or []
        self.commands = commands or []
        self.permissions = permissions or {}
        self.device_identity = device_identity or load_or_create_identity()
        self.on_event = on_event
        self.on_gap = on_gap
        self.on_close = on_close
        self.path_env = path_env or os.environ.get("PATH")

        self._ws: Optional[WebSocketClientProtocol] = None
        self._pending: dict[str, _PendingRequest] = {}
        self._reader: Optional[asyncio.Task] = None
        self._hello: Optional[dict[str, Any]] = None
        self._last_seq: Optional[int] = None
        self._closed = False
        self._log = logging.getLogger("moltbot.client")

    async def connect(self, timeout: float = 15.0) -> dict[str, Any]:
        if self._ws and not self._ws.closed:
            return self._hello or {}
        self._closed = False
        self._ws = await websockets.connect(
            self.url,
            max_size=MAX_PAYLOAD_BYTES,
        )
        self._log.debug("gateway websocket opened url=%s", self.url)
        hello = await self._handshake(timeout=timeout)
        self._reader = asyncio.create_task(self._read_loop())
        return hello

    async def close(self) -> None:
        self._closed = True
        if self._reader:
            self._reader.cancel()
        if self._ws and not self._ws.closed:
            self._log.debug("closing gateway websocket")
            await self._ws.close()
        self._fail_pending(GatewayError("gateway connection closed"))

    async def request(
        self, method: str, params: Any | None = None, *, expect_final: bool = False
    ) -> Any:
        if not self._ws or self._ws.closed or not self._hello:
            raise GatewayError("gateway not connected")
        loop = asyncio.get_running_loop()
        req_id = str(uuid.uuid4())
        frame = {"type": "req", "id": req_id, "method": method, "params": params}
        future: asyncio.Future = loop.create_future()
        self._pending[req_id] = _PendingRequest(future=future, expect_final=expect_final)
        self._log.debug("sending req id=%s method=%s", req_id, method)
        await self._ws.send(_json_dumps(frame))
        return await future

    async def send_chat(
        self,
        *,
        session_key: str,
        message: str,
        thinking: Optional[str] = None,
        deliver: Optional[bool] = None,
        timeout_ms: Optional[int] = None,
        idempotency_key: Optional[str] = None,
    ) -> dict[str, Any]:
        run_id = idempotency_key or str(uuid.uuid4())
        payload: dict[str, Any] = {
            "sessionKey": session_key,
            "message": message,
            "idempotencyKey": run_id,
        }
        if isinstance(thinking, str):
            payload["thinking"] = thinking
        if isinstance(deliver, bool):
            payload["deliver"] = deliver
        if isinstance(timeout_ms, int):
            payload["timeoutMs"] = timeout_ms
        res = await self.request("chat.send", payload)
        return {"runId": run_id, "response": res}

    async def abort_chat(self, *, session_key: str, run_id: Optional[str] = None) -> Any:
        payload: dict[str, Any] = {"sessionKey": session_key}
        if run_id is not None:
            payload["runId"] = run_id
        return await self.request("chat.abort", payload)

    async def chat_history(self, *, session_key: str, limit: Optional[int] = None) -> Any:
        payload: dict[str, Any] = {"sessionKey": session_key}
        if limit is not None:
            payload["limit"] = limit
        return await self.request("chat.history", payload)

    async def sessions_list(self, *, limit: Optional[int] = None) -> Any:
        payload: dict[str, Any] = {}
        if limit is not None:
            payload["limit"] = limit
        return await self.request("sessions.list", payload)

    async def status(self) -> Any:
        return await self.request("status", {})

    async def _handshake(self, timeout: float) -> dict[str, Any]:
        assert self._ws
        nonce = await self._await_challenge(timeout)
        connect_id = str(uuid.uuid4())
        connect_frame = {
            "type": "req",
            "id": connect_id,
            "method": "connect",
            "params": self._build_connect_params(nonce),
        }
        self._log.debug("sending connect frame id=%s", connect_id)
        await self._ws.send(_json_dumps(connect_frame))
        hello = await self._await_connect_response(connect_id, timeout)
        self._hello = hello
        self._last_seq = None
        auth_info = hello.get("auth")
        if auth_info and isinstance(auth_info, dict):
            token = auth_info.get("deviceToken")
            role = auth_info.get("role") or self.role
            scopes = auth_info.get("scopes") or self.scopes
            if token:
                store_device_token(
                    self.device_identity.device_id,
                    role,
                    str(token),
                    scopes=[str(scope) for scope in scopes] if isinstance(scopes, list) else None,
                )
        return hello

    async def _await_challenge(self, timeout: float) -> Optional[str]:
        assert self._ws
        while True:
            raw = await asyncio.wait_for(self._ws.recv(), timeout=timeout)
            frame = self._parse_frame(raw)
            if not frame:
                continue
            if frame.get("type") == "event" and frame.get("event") == "connect.challenge":
                payload = frame.get("payload") or {}
                nonce = payload.get("nonce")
                self._log.debug("received connect.challenge nonce=%s", nonce)
                return nonce if isinstance(nonce, str) else None

    async def _await_connect_response(self, connect_id: str, timeout: float) -> dict[str, Any]:
        assert self._ws
        while True:
            raw = await asyncio.wait_for(self._ws.recv(), timeout=timeout)
            frame = self._parse_frame(raw)
            if not frame:
                continue
            if frame.get("type") == "res" and frame.get("id") == connect_id:
                if frame.get("ok"):
                    payload = frame.get("payload")
                    self._log.debug("connect ok")
                    return payload if isinstance(payload, dict) else {}
                error = frame.get("error") or {}
                message = error.get("message") if isinstance(error, dict) else None
                if self.device_identity and message and "token mismatch" in message:
                    clear_device_token(self.device_identity.device_id, self.role)
                raise GatewayError(message or "connect failed")
            if frame.get("type") == "event" and self.on_event:
                self.on_event(frame)

    def _build_connect_params(self, nonce: Optional[str]) -> dict[str, Any]:
        scopes = [scope for scope in self.scopes if scope]
        if not scopes:
            scopes = ["operator.admin"]
        stored = load_device_token(self.device_identity.device_id, self.role)
        raw_auth_token = stored.token if stored else self.token
        auth_token = raw_auth_token.strip() if isinstance(raw_auth_token, str) else None
        auth_password = self.password.strip() if isinstance(self.password, str) else None
        auth = None
        if auth_token or auth_password:
            auth = {}
            if auth_token:
                auth["token"] = auth_token
            if auth_password:
                auth["password"] = auth_password
        signed_at = int(time.time() * 1000)
        payload = _build_device_auth_payload(
            device_id=self.device_identity.device_id,
            client_id=self.client_id,
            client_mode=self.client_mode,
            role=self.role,
            scopes=scopes,
            signed_at_ms=signed_at,
            token=auth_token,
            nonce=nonce,
        )
        signature = sign_payload(self.device_identity, payload)
        device = {
            "id": self.device_identity.device_id,
            "publicKey": public_key_base64url(self.device_identity),
            "signature": signature,
            "signedAt": signed_at,
        }
        if nonce is not None:
            device["nonce"] = nonce
        params: dict[str, Any] = {
            "minProtocol": PROTOCOL_VERSION,
            "maxProtocol": PROTOCOL_VERSION,
            "client": {
                "id": self.client_id,
                "displayName": self.client_display_name,
                "version": self.client_version,
                "platform": sys.platform,
                "mode": self.client_mode,
                "instanceId": str(uuid.uuid4()),
            },
            "caps": self.caps,
            "role": self.role,
            "scopes": scopes,
            "device": device,
        }
        if self.commands:
            params["commands"] = self.commands
        if self.permissions:
            params["permissions"] = self.permissions
        if self.path_env:
            params["pathEnv"] = self.path_env
        if auth:
            params["auth"] = auth
        return params

    async def _read_loop(self) -> None:
        assert self._ws
        try:
            async for raw in self._ws:
                frame = self._parse_frame(raw)
                if not frame:
                    continue
                if frame.get("type") == "event":
                    self._handle_event(frame)
                elif frame.get("type") == "res":
                    self._handle_response(frame)
        except asyncio.CancelledError:
            return
        except ConnectionClosed as err:
            self._log.debug("gateway closed code=%s reason=%s", err.code, err.reason)
            self._fail_pending(GatewayError(f"gateway closed: {err.code} {err.reason}"))
            if self.on_close:
                self.on_close(err.code, err.reason or "")
        except Exception as err:
            self._log.debug("gateway read loop error: %s", err)
            self._fail_pending(GatewayError(str(err)))
        finally:
            if self._ws and not self._ws.closed:
                await self._ws.close()

    def _handle_event(self, frame: dict[str, Any]) -> None:
        seq = frame.get("seq")
        if isinstance(seq, int):
            if self._last_seq is not None and seq > self._last_seq + 1 and self.on_gap:
                self.on_gap({"expected": self._last_seq + 1, "received": seq})
            self._last_seq = seq
        self._log.debug("event=%s seq=%s", frame.get("event"), frame.get("seq"))
        if self.on_event:
            self.on_event(frame)

    def _handle_response(self, frame: dict[str, Any]) -> None:
        req_id = frame.get("id")
        if not isinstance(req_id, str):
            return
        pending = self._pending.get(req_id)
        if not pending:
            return
        self._log.debug("response for id=%s ok=%s", req_id, frame.get("ok"))
        if frame.get("ok"):
            payload = frame.get("payload")
            if pending.expect_final and isinstance(payload, dict):
                status = payload.get("status")
                if status == "accepted":
                    return
            pending.future.set_result(payload)
        else:
            error = frame.get("error") or {}
            message = error.get("message") if isinstance(error, dict) else None
            pending.future.set_exception(GatewayError(message or "gateway request failed"))
            if self.device_identity and message and "token mismatch" in message:
                clear_device_token(self.device_identity.device_id, self.role)
        self._pending.pop(req_id, None)

    def _fail_pending(self, err: Exception) -> None:
        self._log.debug("failing %d pending requests", len(self._pending))
        for pending in list(self._pending.values()):
            if not pending.future.done():
                pending.future.set_exception(err)
        self._pending.clear()

    @staticmethod
    def _parse_frame(raw: Any) -> Optional[dict[str, Any]]:
        try:
            if isinstance(raw, bytes):
                raw = raw.decode()
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return None
        return None
