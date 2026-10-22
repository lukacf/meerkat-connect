"""Mountable MCP callback transport for one retained authenticated host login.

The embedding host owns authentication, TLS, the registered URL and request
routing. It supplies the same retained login context to each admitted operation,
not context reconstructed from request JSON. This module owns no OAuth protocol,
credential store or server. The native client's exact hosted contract must be
bound separately; the released loopback-only native owner still refuses HTTPS.
Never expose this binding, its client or presenter to agent tools.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from .mcp_auth import (
    CleanupObservation, JoinedMcpLogin, McpLoginCustodian, McpTarget,
    RegisteredHttpsCallback, StartedMcpLogin, _origin, observe_mcp_auth,
)


class McpHostError(RuntimeError):
    """Fixed host diagnostic without callback, native or identity values."""


@dataclass(frozen=True)
class CallbackResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


_SCRIPT = """const query = window.location.search.slice(1);
history.replaceState(null, '', window.location.pathname);
const message = document.getElementById('message');
if (!query) {
  message.textContent = 'No sign-in callback was supplied.';
} else {
  fetch(window.location.pathname, {
    method: 'POST', credentials: 'same-origin', redirect: 'error',
    headers: {'Content-Type': 'application/json'}, body: JSON.stringify({query})
  }).then(response => {
    message.textContent = response.status === 202
      ? 'Callback received. Return to the application to check sign-in.'
      : 'Callback was not accepted. Return to the application to check sign-in.';
  }).catch(() => {
    message.textContent = 'Callback delivery is unconfirmed. Return to the application.';
  });
}
"""
_SCRIPT_HASH = base64.b64encode(hashlib.sha256(_SCRIPT.encode()).digest()).decode()
_LANDING = ("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<title>Sign-in callback</title><p id=\"message\">Returning sign-in callback...</p>"
            "<noscript>Return to the application. JavaScript is needed to deliver this callback."
            "</noscript><script>" + _SCRIPT + "</script></html>").encode()
_HEADERS = (("Cache-Control", "no-store"), ("Referrer-Policy", "no-referrer"),
            ("X-Content-Type-Options", "nosniff"))
_MAX_BODY = 65536


def _response(status: int) -> CallbackResponse:
    message = (b"Callback received. Check sign-in in the application.\n" if status == 202
               else b"Callback not accepted. Check sign-in in the application.\n")
    return CallbackResponse(status, _HEADERS + (("Content-Type", "text/plain; charset=utf-8"),),
                            message)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


class HostedMcpAuthBinding:
    """One host-owned attempt, mounted by Forge or another authenticated host.

    login_context is the host's retained ConsoleConnectLogin-like object with
    an origin and synchronous is_current(). The host must select this object
    from its authenticated request/session; a matching JSON identity is not
    accepted. GET is a fixed landing only. POST must carry the browser Origin
    and an already bounded, unmodified body. Never log callback URLs or bodies.

    shutdown() belongs to whole-host disposal, never panel/request disposal.
    Cancellation of a begin/wait caller leaves the existing custodian running.
    """

    def __init__(self, client: Any, target: McpTarget, *, login_context: Any,
                 redirect_uri: str,
                 protected_presenter: Callable[[str], Awaitable[None]] | None = None,
                 callback_timeout: float = 240, rpc_timeout: float = 10):
        invalid = False
        try:
            current = getattr(login_context, "is_current", None)
            if (not callable(current) or inspect.iscoroutinefunction(current)
                    or (protected_presenter is not None and not callable(protected_presenter))):
                raise ValueError
            origin = _origin(redirect_uri)
            if getattr(login_context, "origin", None) != origin:
                raise ValueError
        except Exception:
            invalid = True
        if invalid:
            raise McpHostError("invalid_host_composition")
        self._callback = RegisteredHttpsCallback(target, redirect_uri)
        self._custodian = McpLoginCustodian(client, target, callback=self._callback,
            callback_timeout=callback_timeout, rpc_timeout=rpc_timeout)
        self._client, self._target = client, target
        self._context, self._origin = login_context, origin
        self._redirect, self._presenter = redirect_uri, protected_presenter
        self._rpc_timeout, self._handle = rpc_timeout, None
        self._closed = False

    def __repr__(self):
        return "HostedMcpAuthBinding(<host-private>)"

    def _admit(self, context):
        accepted, cancelled = False, False
        if context is self._context:
            try:
                current = context.is_current()
                # Refuse an accidentally async host without admitting its truthiness.
                if inspect.iscoroutine(current):
                    current.close()
                accepted = current is True and context.origin == self._origin
            except asyncio.CancelledError:
                cancelled = True
            except Exception:
                pass
        if cancelled:
            raise asyncio.CancelledError("mcp_host_admission_cancelled")
        if not accepted:
            raise McpHostError("host_admission_unconfirmed")

    def _open(self):
        if self._closed:
            raise McpHostError("host_binding_closed")

    async def begin(self, context) -> str:
        self._admit(context)
        self._open()
        self._handle = await self._custodian.begin()
        self._admit(context)
        self._open()
        return "joined" if isinstance(self._handle, JoinedMcpLogin) else "started"

    async def present(self, context) -> bool:
        self._admit(context)
        self._open()
        if self._presenter is None:
            raise McpHostError("protected_presenter_unavailable")
        if not isinstance(self._handle, StartedMcpLogin):
            raise McpHostError("owned_login_unavailable")
        return await self._handle.present(self._presenter)

    async def handle_callback(self, context=None, *, method: str, redirect_uri: str,
                              origin: str | None = None, body: bytes = b"") -> CallbackResponse:
        """HTTP-shaped handler; no framework, cookies, TLS or OAuth is supplied.

        The mounted route supplies its fixed redirect_uri, never one from the
        request query. The public GET landing forwards the query by same-origin
        POST after navigation, when a Strict session cookie can be available.
        A 202 means received locally, not authenticated or installed.
        """
        if redirect_uri != self._redirect:
            return _response(404)
        if method == "GET":
            csp = ("default-src 'none'; script-src 'sha256-" + _SCRIPT_HASH
                   + "'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            return CallbackResponse(200, _HEADERS + (
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Security-Policy", csp)), _LANDING)
        if method != "POST":
            return _response(405)
        try:
            self._admit(context)
        except McpHostError:
            return _response(403)
        if origin != self._origin:
            return _response(403)
        if self._closed:
            return _response(410)
        if type(body) is not bytes or not 0 < len(body) <= _MAX_BODY:
            return _response(400)
        try:
            payload = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object)
            if type(payload) is not dict or set(payload) != {"query"}:
                return _response(400)
            query = payload["query"]
            accepted = self._callback.receive(redirect_uri=self._redirect, query=query)
        except (ValueError, UnicodeError, RecursionError):
            return _response(400)
        return _response(202 if accepted else 400)

    async def wait(self, context):
        self._admit(context)
        if not isinstance(self._handle, StartedMcpLogin):
            raise McpHostError("owned_login_unavailable")
        cancelled = False
        try:
            result = await self._handle.wait()
        except asyncio.CancelledError:
            cancelled = True
        if cancelled:
            raise asyncio.CancelledError("mcp_host_wait_cancelled")
        self._admit(context)
        return result

    async def observe(self, context):
        self._admit(context)
        result = await observe_mcp_auth(self._client, self._target, timeout=self._rpc_timeout)
        self._admit(context)
        return result

    async def close(self, context) -> CleanupObservation:
        self._admit(context)
        return await self.shutdown()

    async def shutdown(self) -> CleanupObservation:
        """Explicit host disposal, independent of browser session expiry."""
        self._closed = True
        return await self._custodian.close()
