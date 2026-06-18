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
import email.utils as email_utils
import hashlib
import hmac
import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlsplit

__all__ = [
    "SendByte",
    "AsyncSendByte",
    "SendByteError",
    "verify_webhook_signature",
    "SIGNATURE_HEADER",
]

DEFAULT_BASE_URL = "https://api.sendbyte.africa"
SIGNATURE_HEADER = "sendbyte-signature"
_VERSION = "0.2.0"
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_TIMEOUT_SECONDS = 30.0
_MAX_BACKOFF_SECONDS = 20.0

# transport(method, url, headers, body) -> (status, response_text). The default
# transport also exposes the response headers as a third tuple element so the
# retry policy can read Retry-After; a custom transport may return only
# (status, text), in which case headers are treated as absent.
Transport = Callable[..., Tuple]


class SendByteError(Exception):
    """An error returned by the SendByte API."""

    def __init__(self, code: str, message: str, status: int, docs_url: Optional[str] = None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.docs_url = docs_url


def _is_secure_base_url(base_url: str) -> bool:
    """https is required; http is tolerated only for localhost/loopback dev hosts."""
    parts = urlsplit(base_url)
    if parts.scheme == "https":
        return True
    host = parts.hostname or ""
    return host in ("localhost", "127.0.0.1", "::1")


def _is_retryable_status(status: int) -> bool:
    return status == 429 or 500 <= status < 600


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        parsed = email_utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed is None:
        return None
    return max(0.0, parsed.timestamp() - time.time())


def _backoff_delay(attempt: int, retry_after: Optional[str]) -> float:
    """Exponential backoff with full jitter, capped, honoring Retry-After.

    attempt is 1-based.
    """
    after = _parse_retry_after(retry_after)
    if after is not None:
        return min(after, _MAX_BACKOFF_SECONDS)
    base = min(_MAX_BACKOFF_SECONDS, 0.25 * (2 ** (attempt - 1)))
    return random.random() * base


def _default_transport(
    method: str, url: str, headers: Dict[str, str], body: Optional[bytes], timeout: float
) -> Tuple[int, str, Dict[str, str]]:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8"), dict(response.headers)
    except urllib.error.HTTPError as err:  # non-2xx still carries a JSON body
        return err.code, err.read().decode("utf-8"), dict(err.headers or {})


def _normalize_transport_result(result: Tuple) -> Tuple[int, str, Dict[str, str]]:
    """Accept (status, text) or (status, text, headers) from any transport."""
    if len(result) >= 3:
        status, text, raw = result[0], result[1], result[2]
        headers = {str(k).lower(): str(v) for k, v in (raw or {}).items()}
        return status, text, headers
    return result[0], result[1], {}


class _Http:
    def __init__(
        self,
        api_key: str,
        base_url: str,
        transport: Optional[Transport],
        max_attempts: int,
        timeout: float,
    ):
        if not api_key or not (api_key.startswith("sk_live_") or api_key.startswith("sk_test_")):
            raise SendByteError(
                "invalid_api_key",
                "API key must start with sk_live_ or sk_test_. "
                "Create one in the dashboard under API keys.",
                0,
            )
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.transport = transport
        self.max_attempts = max(1, max_attempts)
        self.timeout = max(0.001, timeout)

        # A live key over a non-https base URL would send the secret in cleartext.
        if api_key.startswith("sk_live_") and not _is_secure_base_url(self.base_url):
            raise SendByteError(
                "insecure_base_url",
                "Refusing to send a live API key (sk_live_) over an insecure base URL. "
                "Use https, or a test key for local http.",
                0,
            )

    def _call_transport(
        self, method: str, url: str, headers: Dict[str, str], payload: Optional[bytes]
    ) -> Tuple[int, str, Dict[str, str]]:
        if self.transport is not None:
            # A custom transport keeps the historical (method, url, headers, body)
            # signature; only the default transport receives the timeout.
            return _normalize_transport_result(self.transport(method, url, headers, payload))
        return _default_transport(method, url, headers, payload, self.timeout)

    def request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Any:
        # Auto-generate an idempotency key for sends and reuse it across retries
        # so a retried POST /v1/emails cannot double-send. Body-based, matching
        # the API.
        payload_body = body
        if (
            method == "POST"
            and path == "/v1/emails"
            and isinstance(payload_body, dict)
            and payload_body.get("idempotency_key") is None
        ):
            payload_body = {**payload_body, "idempotency_key": str(uuid.uuid4())}

        headers = {
            "authorization": f"Bearer {self.api_key}",
            "user-agent": f"sendbyte-python/{_VERSION}",
        }
        payload: Optional[bytes] = None
        if payload_body is not None:
            headers["content-type"] = "application/json"
            payload = json.dumps(payload_body).encode("utf-8")

        url = f"{self.base_url}{path}"
        last_error: Optional[SendByteError] = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                status, text, response_headers = self._call_transport(
                    method, url, headers, payload
                )
            except urllib.error.URLError as err:
                # Network or timeout error: retry if attempts remain.
                last_error = SendByteError(
                    "request_failed",
                    f"Could not reach the SendByte API: {err.reason}",
                    0,
                )
                if attempt < self.max_attempts:
                    time.sleep(_backoff_delay(attempt, None))
                    continue
                raise last_error

            if status >= 400:
                if _is_retryable_status(status) and attempt < self.max_attempts:
                    last_error = _parse_error(text, status)
                    time.sleep(_backoff_delay(attempt, response_headers.get("retry-after")))
                    continue
                raise _parse_error(text, status)

            # 2xx: parse the success body, guarding against a non-JSON proxy response.
            if not text:
                return {}
            try:
                return json.loads(text)
            except ValueError:
                raise SendByteError(
                    "invalid_response",
                    f"The API returned a 2xx response that was not valid JSON (status {status}).",
                    status,
                )

        raise last_error or SendByteError(
            "request_failed", "Request failed after exhausting retries.", 0
        )


def _parse_error(text: str, status: int) -> SendByteError:
    """Parse a non-2xx body into a typed error, never raising on non-JSON bodies."""
    data: Any = {}
    if text:
        try:
            data = json.loads(text)
        except ValueError:
            # A gateway/proxy 502/504 may return HTML or plain text.
            return SendByteError(
                "request_failed", f"Request failed with status {status}.", status
            )
    error = data.get("error", {}) if isinstance(data, dict) else {}
    return SendByteError(
        error.get("code", "request_failed"),
        error.get("message", f"Request failed with status {status}"),
        status,
        error.get("docs_url"),
    )


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
        "list_unsubscribe",
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
    """Synchronous SendByte client.

    Retries 429 and 5xx responses (and network errors) with exponential
    backoff plus jitter, honoring Retry-After, up to ``max_attempts``. Each
    attempt is bounded by ``timeout`` seconds. On POST /v1/emails an
    idempotency key is generated and reused across retries when the caller did
    not supply one, so a retried send cannot double-send.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        transport: Optional[Transport] = None,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        http = _Http(api_key, base_url, transport, max_attempts, timeout)
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
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self._sync = SendByte(
            api_key,
            base_url=base_url,
            transport=transport,
            max_attempts=max_attempts,
            timeout=timeout,
        )

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

    async def get_domain(self, domain_id: str) -> Dict[str, Any]:
        return await self._run(lambda: self._sync.domains.get(domain_id))

    async def verify_domain(self, domain_id: str) -> Dict[str, Any]:
        return await self._run(lambda: self._sync.domains.verify(domain_id))

    async def list_domains(self) -> Dict[str, Any]:
        return await self._run(lambda: self._sync.domains.list())

    # Webhooks
    async def create_webhook(self, url: str, events: Optional[List[str]] = None) -> Dict[str, Any]:
        return await self._run(lambda: self._sync.webhooks.create(url, events))

    async def list_webhooks(self) -> Dict[str, Any]:
        return await self._run(lambda: self._sync.webhooks.list())

    async def disable_webhook(self, endpoint_id: str) -> Dict[str, Any]:
        return await self._run(lambda: self._sync.webhooks.disable(endpoint_id))

    async def replay_webhook(self, delivery_id: str) -> Dict[str, Any]:
        return await self._run(lambda: self._sync.webhooks.replay(delivery_id))


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
