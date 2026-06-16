"""SendByte Python SDK: the email API for Africa.

Zero runtime dependencies (stdlib urllib). Sync and async clients with the
same surface; errors carry the API's error shape (code, message, docs_url).

    from sendbyte import SendByte

    sendbyte = SendByte("sk_test_...")
    email = sendbyte.emails.send(
        from_="PayLink <receipts@paylink.ng>",
        to="amaka@halo.ng",
        subject="Receipt",
        html="<p>Thank you.</p>",
    )
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

__all__ = [
    "SendByte",
    "AsyncSendByte",
    "SendByteError",
    "verify_webhook_signature",
    "SIGNATURE_HEADER",
]

DEFAULT_BASE_URL = "https://api.sendbyte.africa"
SIGNATURE_HEADER = "sendbyte-signature"
_VERSION = "0.1.0"

# transport(method, url, headers, body) -> (status, response_text)
Transport = Callable[[str, str, Dict[str, str], Optional[bytes]], Tuple[int, str]]


class SendByteError(Exception):
    """An error returned by the SendByte API."""

    def __init__(self, code: str, message: str, status: int, docs_url: Optional[str] = None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.docs_url = docs_url


def _default_transport(
    method: str, url: str, headers: Dict[str, str], body: Optional[bytes]
) -> Tuple[int, str]:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as err:  # non-2xx still carries a JSON body
        return err.code, err.read().decode("utf-8")


class _Http:
    def __init__(self, api_key: str, base_url: str, transport: Optional[Transport]):
        if not api_key or not (api_key.startswith("sk_live_") or api_key.startswith("sk_test_")):
            raise SendByteError(
                "invalid_api_key",
                "API key must start with sk_live_ or sk_test_. "
                "Create one in the dashboard under API keys.",
                0,
            )
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.transport = transport or _default_transport

    def request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Any:
        headers = {
            "authorization": f"Bearer {self.api_key}",
            "user-agent": f"sendbyte-python/{_VERSION}",
        }
        payload: Optional[bytes] = None
        if body is not None:
            headers["content-type"] = "application/json"
            payload = json.dumps(body).encode("utf-8")

        status, text = self.transport(method, f"{self.base_url}{path}", headers, payload)
        data = json.loads(text) if text else {}

        if status >= 400:
            error = data.get("error", {}) if isinstance(data, dict) else {}
            raise SendByteError(
                error.get("code", "request_failed"),
                error.get("message", f"Request failed with status {status}"),
                status,
                error.get("docs_url"),
            )
        return data


def _build_send_body(
    from_: str,
    to: Union[str, List[str]],
    subject: str,
    **options: Any,
) -> Dict[str, Any]:
    body: Dict[str, Any] = {"from": from_, "to": to, "subject": subject}
    for key in (
        "html",
        "text",
        "cc",
        "bcc",
        "reply_to",
        "attachments",
        "tags",
        "headers",
        "scheduled_at",
        "template_id",
        "variables",
        "idempotency_key",
    ):
        value = options.pop(key, None)
        if value is not None:
            body[key] = value
    if options:
        raise TypeError(f"Unknown arguments: {', '.join(sorted(options))}")
    return body


def _list_query(limit: Optional[int], after: Optional[str], status: Optional[str]) -> str:
    params = {}
    if limit is not None:
        params["limit"] = str(limit)
    if after is not None:
        params["after"] = after
    if status is not None:
        params["status"] = status
    return f"?{urllib.parse.urlencode(params)}" if params else ""


class _Emails:
    def __init__(self, http: _Http):
        self._http = http

    def send(
        self, *, from_: str, to: Union[str, List[str]], subject: str, **options: Any
    ) -> Dict[str, Any]:
        return self._http.request("POST", "/v1/emails", _build_send_body(from_, to, subject, **options))

    def get(self, email_id: str) -> Dict[str, Any]:
        return self._http.request("GET", f"/v1/emails/{email_id}")

    def list(
        self,
        *,
        limit: Optional[int] = None,
        after: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self._http.request("GET", f"/v1/emails{_list_query(limit, after, status)}")


class _Domains:
    def __init__(self, http: _Http):
        self._http = http

    def create(self, domain: str) -> Dict[str, Any]:
        return self._http.request("POST", "/v1/domains", {"domain": domain})

    def list(self) -> Dict[str, Any]:
        return self._http.request("GET", "/v1/domains")

    def get(self, domain_id: str) -> Dict[str, Any]:
        return self._http.request("GET", f"/v1/domains/{domain_id}")

    def verify(self, domain_id: str) -> Dict[str, Any]:
        return self._http.request("POST", f"/v1/domains/{domain_id}/verify")


class _Webhooks:
    def __init__(self, http: _Http):
        self._http = http

    def create(self, url: str, events: Optional[List[str]] = None) -> Dict[str, Any]:
        body: Dict[str, Any] = {"url": url}
        if events is not None:
            body["events"] = events
        return self._http.request("POST", "/v1/webhooks", body)

    def list(self) -> Dict[str, Any]:
        return self._http.request("GET", "/v1/webhooks")

    def disable(self, endpoint_id: str) -> Dict[str, Any]:
        return self._http.request("DELETE", f"/v1/webhooks/{endpoint_id}")

    def replay(self, delivery_id: str) -> Dict[str, Any]:
        return self._http.request("POST", f"/v1/webhooks/deliveries/{delivery_id}/replay")


class SendByte:
    """Synchronous SendByte client."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        transport: Optional[Transport] = None,
    ):
        http = _Http(api_key, base_url, transport)
        self.emails = _Emails(http)
        self.domains = _Domains(http)
        self.webhooks = _Webhooks(http)


class AsyncSendByte:
    """Asynchronous SendByte client (same surface, awaitable methods).

    Transport runs in the default executor, keeping the SDK dependency-free
    while staying event-loop friendly.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        transport: Optional[Transport] = None,
    ):
        self._sync = SendByte(api_key, base_url=base_url, transport=transport)

    async def _run(self, fn: Callable[[], Any]) -> Any:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, fn)

    # Emails
    async def send_email(
        self, *, from_: str, to: Union[str, List[str]], subject: str, **options: Any
    ) -> Dict[str, Any]:
        return await self._run(
            lambda: self._sync.emails.send(from_=from_, to=to, subject=subject, **options)
        )

    async def get_email(self, email_id: str) -> Dict[str, Any]:
        return await self._run(lambda: self._sync.emails.get(email_id))

    async def list_emails(self, **params: Any) -> Dict[str, Any]:
        return await self._run(lambda: self._sync.emails.list(**params))

    # Domains
    async def create_domain(self, domain: str) -> Dict[str, Any]:
        return await self._run(lambda: self._sync.domains.create(domain))

    async def verify_domain(self, domain_id: str) -> Dict[str, Any]:
        return await self._run(lambda: self._sync.domains.verify(domain_id))

    async def list_domains(self) -> Dict[str, Any]:
        return await self._run(lambda: self._sync.domains.list())

    # Webhooks
    async def create_webhook(self, url: str, events: Optional[List[str]] = None) -> Dict[str, Any]:
        return await self._run(lambda: self._sync.webhooks.create(url, events))

    async def list_webhooks(self) -> Dict[str, Any]:
        return await self._run(lambda: self._sync.webhooks.list())


def verify_webhook_signature(
    secret: str,
    header: Optional[str],
    body: Union[str, bytes],
    *,
    tolerance_seconds: int = 300,
    now: Optional[int] = None,
) -> bool:
    """Verify a webhook request came from SendByte.

    The header format is ``t=<unix seconds>,v1=<hex hmac-sha256>`` over
    ``"<t>.<raw body>"``. Returns False for missing, malformed, stale, or
    forged signatures; never raises.
    """
    if not header:
        return False
    parts: Dict[str, str] = {}
    for piece in header.split(","):
        key, _, value = piece.partition("=")
        parts[key] = value
    timestamp_raw = parts.get("t", "")
    signature = parts.get("v1", "")
    if not timestamp_raw.isdigit() or not signature:
        return False

    timestamp = int(timestamp_raw)
    current = now if now is not None else int(time.time())
    if abs(current - timestamp) > tolerance_seconds:
        return False

    raw = body.encode("utf-8") if isinstance(body, str) else body
    expected = hmac.new(
        secret.encode("utf-8"), f"{timestamp}.".encode("utf-8") + raw, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
