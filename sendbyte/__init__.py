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
from typing import Any, Awaitable, Callable, Dict, List, Literal, Optional, Tuple, TypedDict, Union
from urllib.parse import quote, urlsplit

__all__ = [
    "SendByte",
    "AsyncSendByte",
    "SendByteError",
    "verify_webhook_signature",
    "SIGNATURE_HEADER",
    "WEBHOOK_EVENT_TYPES",
    "ConversationItem",
    "DomainReceiving",
    "EmailConversation",
    "EmailReceivedEventData",
    "InboundRoute",
    "InboundRouteAction",
    "InboundRouteList",
    "InboundRouteMatchType",
    "MxRecord",
    "ReceivedAttachment",
    "ReceivedAttachmentLink",
    "ReceivedEmail",
    "ReceivedEmailContent",
    "ReceivedEmailDetail",
    "ReceivedEmailList",
    "ReceivedHeader",
    "ReceivedInReplyToEmail",
    "ReceivedRawLink",
    "ReceivedReply",
    "ReceivedStats",
    "ReceivedStatus",
    "ReceivedTruncated",
    "ReceivedWebhookDelivery",
    "ReceivingDomain",
    "ReceivingPreflight",
    "ReceivingSettings",
    "ReceivingStatus",
    "ReceivingTestResult",
    "ReceivingToggle",
]

DEFAULT_BASE_URL = "https://api.sendbyte.africa"
SIGNATURE_HEADER = "sendbyte-signature"
_VERSION = "0.3.0"
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_TIMEOUT_SECONDS = 30.0
_MAX_BACKOFF_SECONDS = 20.0

# transport(method, url, headers, body) -> (status, response_text). The default
# transport also exposes the response headers as a third tuple element so the
# retry policy can read Retry-After; a custom transport may return only
# (status, text), in which case headers are treated as absent.
Transport = Callable[..., Tuple]

ReceivingStatus = Literal["off", "pending", "active", "failing"]
ReceivedStatus = Literal["received", "delivered", "forwarded", "dropped", "held", "blocked"]
InboundRouteMatchType = Literal["exact", "prefix", "catch_all"]
InboundRouteAction = Literal["webhook", "forward", "drop"]

WEBHOOK_EVENT_TYPES = (
    "email.sent",
    "email.delivered",
    "email.opened",
    "email.clicked",
    "email.bounced",
    "email.complained",
    "email.unsubscribed",
    "email.failed",
    "email.received",
    "domain.verified",
    "domain.degraded",
    "suppression.removal.requested",
    "suppression.removal.verified",
    "suppression.removal.completed",
    "suppression.removal.expired",
    "suppression.removal.failed",
    "suppression.removal.cancelled",
    "suppression.removal.reverted",
)
"""Every event type a webhook endpoint can subscribe to."""


class MxRecord(TypedDict):
    """The MX record to publish so a receiving host routes mail to SendByte."""

    type: Literal["MX"]
    host: str
    name: str
    priority: int
    value: str


class DomainReceiving(TypedDict):
    """Receiving setup for one domain."""

    domain_id: str
    domain: str
    enabled: bool
    subdomain: str
    host: str
    status: ReceivingStatus
    checked_at: Optional[str]
    mx_record: MxRecord


class ReceivingDomain(DomainReceiving):
    """A domain in the receiving settings, with its sending verification state."""

    verified: bool


class ReceivingSettings(TypedDict):
    """Project receiving settings and every domain's receiving setup."""

    available: bool
    enabled: bool
    enabled_at: Optional[str]
    quota_notice: str
    test_host: Optional[str]
    content_days: int
    content_days_long: int
    domains: List[ReceivingDomain]


class ReceivingToggle(TypedDict, total=False):
    """Result of turning receiving on or off for the project."""

    enabled: bool
    test_host: Optional[str]
    quota_notice: str


class ReceivingTestResult(TypedDict):
    """Result of sending a test email to a receiving address."""

    sent: bool
    to: str


class ReceivingPreflight(TypedDict):
    """What enabling receiving on a subdomain would change, before it is enabled."""

    host: str
    root_provider: Optional[str]
    host_provider: Optional[str]
    mx_record: MxRecord


ReceivedEmail = TypedDict(
    "ReceivedEmail",
    {
        "id": str,
        "object": Literal["received_email"],
        "received_at": str,
        "status": ReceivedStatus,
        "status_reason": Optional[str],
        "from": str,
        "envelope_from": Optional[str],
        "to": List[str],
        "cc": List[str],
        "reply_to": List[str],
        "recipients": List[str],
        "subject": str,
        "tag": Optional[str],
        "message_id": Optional[str],
        "in_reply_to": Optional[str],
        "references": List[str],
        "thread_id": Optional[str],
        "in_reply_to_email_id": Optional[str],
        "domain_id": Optional[str],
        "route_id": Optional[str],
        "size": int,
        "spam": Optional[str],
        "virus": Optional[str],
        "spf": Optional[str],
        "dkim": Optional[str],
        "dmarc": Optional[str],
        "counted": bool,
        "content_available": bool,
        "content_expires_at": str,
        "attachment_count": int,
        "forwarded_email_ids": List[str],
        "action_at": Optional[str],
    },
)
"""A received email as it appears in a list."""


class ReceivedHeader(TypedDict):
    """One header line of a received email."""

    name: str
    value: str


class ReceivedTruncated(TypedDict, total=False):
    """Which bodies were cut short because they were too large."""

    text: bool
    html: bool
    stripped_text: bool


class ReceivedAttachment(TypedDict):
    """An attachment on a received email, with a short-lived download URL."""

    id: str
    filename: str
    content_type: str
    size: int
    content_id: Optional[str]
    disposition: str
    url: Optional[str]
    url_expires_at: Optional[str]


class InboundRoute(TypedDict):
    """A rule that decides what happens to mail arriving at matching addresses."""

    id: str
    domain_id: Optional[str]
    match_type: InboundRouteMatchType
    match_value: str
    action: InboundRouteAction
    endpoint_ids: Optional[List[str]]
    forward_to: List[str]
    allow_senders: List[str]
    block_senders: List[str]
    enabled: bool
    created_at: str
    updated_at: str


class ReceivedInReplyToEmail(TypedDict):
    """The sent email a received email replies to."""

    id: str
    subject: str
    to: List[str]
    status: str
    created_at: str


class ReceivedWebhookDelivery(TypedDict):
    """One webhook delivery made for a received email."""

    id: str
    endpoint_id: str
    url: str
    status: str
    attempts: List[Dict[str, Any]]
    created_at: str
    delivered_at: Optional[str]


ConversationItem = TypedDict(
    "ConversationItem",
    {
        "direction": Literal["sent", "received"],
        "id": str,
        "subject": str,
        "from": str,
        "to": List[str],
        "status": str,
        "at": str,
    },
)
"""One sent or received message in a conversation thread."""


class ReceivedEmailContent(ReceivedEmail):
    """A received email with its bodies, headers and attachments."""

    text: Optional[str]
    html: Optional[str]
    stripped_text: Optional[str]
    truncated: ReceivedTruncated
    headers: List[ReceivedHeader]
    attachments: List[ReceivedAttachment]


class ReceivedEmailDetail(ReceivedEmailContent):
    """A received email with content, its route, deliveries and conversation."""

    route: Optional[InboundRoute]
    in_reply_to_email: Optional[ReceivedInReplyToEmail]
    webhook_deliveries: List[ReceivedWebhookDelivery]
    webhook_payload: Optional[Dict[str, Any]]
    conversation: List[ConversationItem]


EmailReceivedEventData = ReceivedEmailContent
"""The ``data`` of an ``email.received`` webhook event."""


class ReceivedEmailList(TypedDict):
    """A page of received emails. Pass ``next_cursor`` as ``before`` for the next page."""

    data: List[ReceivedEmail]
    has_more: bool
    next_cursor: Optional[str]


class ReceivedStats(TypedDict):
    """Received email counts over a window of days."""

    days: int
    received: int
    spam: int
    held: int
    delivered: int
    blocked: int
    dropped: int
    forwarded: int
    counted: int


class ReceivedAttachmentLink(TypedDict):
    """A short-lived download URL for one attachment."""

    url: str
    filename: str
    content_type: str
    expires_at: str


class ReceivedRawLink(TypedDict):
    """A short-lived download URL for the original message as an .eml file."""

    url: str
    expires_at: str


class ReceivedReply(TypedDict):
    """The email sent as a reply to a received email."""

    id: str
    status: str
    thread_id: Optional[str]


class InboundRouteList(TypedDict):
    """Inbound routes for one domain, or for the test address."""

    data: List[InboundRoute]


class EmailConversation(TypedDict):
    """The thread a sent email belongs to and how many replies it received."""

    thread_id: Optional[str]
    replies: int
    data: List[ConversationItem]


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

    def conversation(self, email_id: str) -> EmailConversation:
        """The thread a sent email belongs to, with every sent and received message in it."""
        return self._http.request("GET", f"/v1/emails/{email_id}/conversation")



class _Brands:
    """Marketing brands: the container lists, campaigns and reports live in."""

    def __init__(self, http: _Http):
        self._http = http

    def create(self, name: str, **options: Any) -> Dict[str, Any]:
        return self._http.request("POST", "/v1/brands", {"name": name, **options})

    def list(self) -> Dict[str, Any]:
        return self._http.request("GET", "/v1/brands")

    def get(self, brand_id: str) -> Dict[str, Any]:
        return self._http.request("GET", f"/v1/brands/{brand_id}")

    def update(self, brand_id: str, **patch: Any) -> Dict[str, Any]:
        return self._http.request("PATCH", f"/v1/brands/{brand_id}", patch)

    def delete(self, brand_id: str) -> Dict[str, Any]:
        return self._http.request("DELETE", f"/v1/brands/{brand_id}")


class _Lists:
    def __init__(self, http: _Http):
        self._http = http

    def create(self, brand_id: str, name: str, **options: Any) -> Dict[str, Any]:
        return self._http.request("POST", f"/v1/brands/{brand_id}/lists", {"name": name, **options})

    def list(self, brand_id: str) -> Dict[str, Any]:
        return self._http.request("GET", f"/v1/brands/{brand_id}/lists")

    def get(self, brand_id: str, list_id: str) -> Dict[str, Any]:
        return self._http.request("GET", f"/v1/brands/{brand_id}/lists/{list_id}")

    def update(self, brand_id: str, list_id: str, **patch: Any) -> Dict[str, Any]:
        return self._http.request("PATCH", f"/v1/brands/{brand_id}/lists/{list_id}", patch)

    def delete(self, brand_id: str, list_id: str) -> Dict[str, Any]:
        return self._http.request("DELETE", f"/v1/brands/{brand_id}/lists/{list_id}")


class _Subscribers:
    def __init__(self, http: _Http):
        self._http = http

    def add(
        self,
        brand_id: str,
        list_id: str,
        email: str,
        *,
        name: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Add someone to a list.

        On a double opt-in list they land as ``unconfirmed`` and are never
        mailed until they confirm. Anyone who previously unsubscribed or
        bounced stays off: the response carries ``skipped_reason`` rather than
        the call failing, so a bulk caller can log it and move on.
        """
        body: Dict[str, Any] = {"email": email}
        if name is not None:
            body["name"] = name
        if attributes is not None:
            body["attributes"] = attributes
        return self._http.request(
            "POST", f"/v1/brands/{brand_id}/lists/{list_id}/subscribers", body
        )

    def list(self, brand_id: str, list_id: str, **params: Any) -> Dict[str, Any]:
        query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items() if v is not None)
        suffix = f"?{query}" if query else ""
        return self._http.request(
            "GET", f"/v1/brands/{brand_id}/lists/{list_id}/subscribers{suffix}"
        )

    def import_(
        self, brand_id: str, list_id: str, subscribers: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Batch import, up to 1,000 rows per call. Reports every rejected row."""
        return self._http.request(
            "POST", f"/v1/brands/{brand_id}/lists/{list_id}/import", {"subscribers": subscribers}
        )

    def set_status(
        self, brand_id: str, list_id: str, subscriber_id: str, status: str
    ) -> Dict[str, Any]:
        return self._http.request(
            "PATCH",
            f"/v1/brands/{brand_id}/lists/{list_id}/subscribers/{subscriber_id}",
            {"status": status},
        )

    def remove(self, brand_id: str, list_id: str, subscriber_id: str) -> Dict[str, Any]:
        return self._http.request(
            "DELETE", f"/v1/brands/{brand_id}/lists/{list_id}/subscribers/{subscriber_id}"
        )



class _Campaigns:
    def __init__(self, http: _Http):
        self._http = http

    def create(self, brand_id: str, name: str, subject: str, from_: str, **options: Any) -> Dict[str, Any]:
        body = {"name": name, "subject": subject, "from": from_, **options}
        return self._http.request("POST", f"/v1/brands/{brand_id}/campaigns", body)

    def list(self, brand_id: str, **params: Any) -> Dict[str, Any]:
        query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items() if v is not None)
        suffix = f"?{query}" if query else ""
        return self._http.request("GET", f"/v1/brands/{brand_id}/campaigns{suffix}")

    def get(self, brand_id: str, campaign_id: str) -> Dict[str, Any]:
        return self._http.request("GET", f"/v1/brands/{brand_id}/campaigns/{campaign_id}")

    def test(self, brand_id: str, campaign_id: str, to: str) -> Dict[str, Any]:
        return self._http.request(
            "POST", f"/v1/brands/{brand_id}/campaigns/{campaign_id}/test", {"to": to}
        )

    def send(
        self,
        brand_id: str,
        campaign_id: str,
        list_ids: List[str],
        *,
        segment_ids: Optional[List[str]] = None,
        scheduled_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Freeze the audience and send, or schedule it.

        The audience is snapshotted now: somebody who joins afterwards is not
        included, somebody who leaves before their turn is skipped, and a person
        on two of the chosen lists receives one email.
        """
        body: Dict[str, Any] = {"list_ids": list_ids}
        if segment_ids:
            body["segment_ids"] = segment_ids
        if scheduled_at:
            body["scheduled_at"] = scheduled_at
        return self._http.request(
            "POST", f"/v1/brands/{brand_id}/campaigns/{campaign_id}/send", body
        )

    def cancel(self, brand_id: str, campaign_id: str) -> Dict[str, Any]:
        return self._http.request("POST", f"/v1/brands/{brand_id}/campaigns/{campaign_id}/cancel")

    def report(self, brand_id: str, campaign_id: str) -> Dict[str, Any]:
        return self._http.request("GET", f"/v1/brands/{brand_id}/campaigns/{campaign_id}/report")


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


def _query(params: Dict[str, Any]) -> str:
    present = {k: str(v) for k, v in params.items() if v is not None}
    return f"?{urllib.parse.urlencode(present, safe=',')}" if present else ""


_ROUTE_CREATE_FIELDS = (
    "domain_id",
    "match_value",
    "action",
    "endpoint_ids",
    "forward_to",
    "allow_senders",
    "block_senders",
    "enabled",
)
_ROUTE_UPDATE_FIELDS = (
    "action",
    "endpoint_ids",
    "forward_to",
    "allow_senders",
    "block_senders",
    "enabled",
)


def _check_fields(given: Dict[str, Any], allowed: Tuple[str, ...]) -> None:
    unknown = sorted(set(given) - set(allowed))
    if unknown:
        raise TypeError(f"Unknown arguments: {', '.join(unknown)}")


class _Receiving:
    """Project receiving settings and per-domain receiving setup."""

    def __init__(self, http: _Http):
        self._http = http

    def get(self) -> ReceivingSettings:
        return self._http.request("GET", "/v1/receiving")

    def enable(self) -> ReceivingToggle:
        """Turn receiving on. Received emails count toward your monthly email quota."""
        return self._http.request("POST", "/v1/receiving/enable", {"acknowledge_quota": True})

    def disable(self) -> ReceivingToggle:
        return self._http.request("POST", "/v1/receiving/disable", {})

    def send_test(self, to: str) -> ReceivingTestResult:
        """Send a test email to one of the project's receiving addresses."""
        return self._http.request("POST", "/v1/receiving/test", {"to": to})

    def preflight(self, domain_id: str, subdomain: str = "inbound") -> ReceivingPreflight:
        """Check a receiving subdomain and return the MX record it needs, changing nothing."""
        return self._http.request(
            "GET",
            f"/v1/domains/{domain_id}/receiving/preflight{_query({'subdomain': subdomain})}",
        )

    def enable_domain(self, domain_id: str, subdomain: str = "inbound") -> DomainReceiving:
        return self._http.request(
            "POST", f"/v1/domains/{domain_id}/receiving", {"subdomain": subdomain}
        )

    def check_domain(self, domain_id: str) -> DomainReceiving:
        """Look up the domain's MX record now and return the updated receiving status."""
        return self._http.request("POST", f"/v1/domains/{domain_id}/receiving/check", {})

    def disable_domain(self, domain_id: str) -> DomainReceiving:
        return self._http.request("DELETE", f"/v1/domains/{domain_id}/receiving")


class _Received:
    """Received emails: list, read, download, and reply."""

    def __init__(self, http: _Http):
        self._http = http

    def list(
        self,
        *,
        status: Optional[Union[str, List[str]]] = None,
        domain_id: Optional[str] = None,
        search: Optional[str] = None,
        days: Optional[int] = None,
        limit: Optional[int] = None,
        before: Optional[str] = None,
    ) -> ReceivedEmailList:
        """List received emails, newest first. ``status`` takes a comma list or a list."""
        status_value = ",".join(status) if isinstance(status, list) else status
        query = _query(
            {
                "status": status_value,
                "domain_id": domain_id,
                "search": search,
                "days": days,
                "limit": limit,
                "before": before,
            }
        )
        return self._http.request("GET", f"/v1/received{query}")

    def get(self, received_id: str) -> ReceivedEmailDetail:
        return self._http.request("GET", f"/v1/received/{received_id}")

    def stats(self, days: int = 30, domain_id: Optional[str] = None) -> ReceivedStats:
        return self._http.request(
            "GET", f"/v1/received/stats{_query({'days': days, 'domain_id': domain_id})}"
        )

    def attachment(self, received_id: str, attachment_id: str) -> ReceivedAttachmentLink:
        return self._http.request(
            "GET", f"/v1/received/{received_id}/attachments/{attachment_id}"
        )

    def raw(self, received_id: str) -> ReceivedRawLink:
        return self._http.request("GET", f"/v1/received/{received_id}/raw")

    def reply(
        self,
        received_id: str,
        *,
        text: Optional[str] = None,
        html: Optional[str] = None,
        from_: Optional[str] = None,
        subject: Optional[str] = None,
        reply_all: Optional[bool] = None,
        idempotency_key: Optional[str] = None,
    ) -> ReceivedReply:
        """Reply in the same thread. Needs ``text`` or ``html``; retries never send twice."""
        if not text and not html:
            raise ValueError("Provide text or html for the reply.")
        body: Dict[str, Any] = {"idempotency_key": idempotency_key or str(uuid.uuid4())}
        for key, value in (
            ("from", from_),
            ("text", text),
            ("html", html),
            ("subject", subject),
            ("reply_all", reply_all),
        ):
            if value is not None:
                body[key] = value
        return self._http.request("POST", f"/v1/received/{received_id}/reply", body)


class _InboundRoutes:
    """Rules that decide what happens to mail arriving at matching addresses."""

    def __init__(self, http: _Http):
        self._http = http

    def list(self, domain_id: Optional[str] = None) -> InboundRouteList:
        """Routes for a domain, or the test address routes when ``domain_id`` is omitted."""
        return self._http.request("GET", f"/v1/inbound-routes{_query({'domain_id': domain_id})}")

    def create(self, match_type: InboundRouteMatchType, **options: Any) -> InboundRoute:
        _check_fields(options, _ROUTE_CREATE_FIELDS)
        body: Dict[str, Any] = {"match_type": match_type}
        body.update({k: v for k, v in options.items() if v is not None})
        return self._http.request("POST", "/v1/inbound-routes", body)

    def update(self, route_id: str, **patch: Any) -> InboundRoute:
        """Change only the fields given. A None value is sent as null."""
        _check_fields(patch, _ROUTE_UPDATE_FIELDS)
        return self._http.request("PATCH", f"/v1/inbound-routes/{route_id}", patch)

    def delete(self, route_id: str) -> None:
        self._http.request("DELETE", f"/v1/inbound-routes/{route_id}")


class SendByte:
    """Synchronous SendByte client.

    Retries 429 and 5xx responses (and network errors) with exponential
    backoff plus jitter, honoring Retry-After, up to ``max_attempts``. Each
    attempt by the built-in transport is bounded by ``timeout`` seconds; a
    custom ``transport`` you inject is responsible for its own timeout (it keeps
    the historical ``(method, url, headers, body)`` signature). On POST
    /v1/emails an idempotency key is generated and reused across retries when the
    caller did not supply one, so a retried send cannot double-send.
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
        self.brands = _Brands(http)
        self.lists = _Lists(http)
        self.subscribers = _Subscribers(http)
        self.campaigns = _Campaigns(http)
        self.webhooks = _Webhooks(http)
        self.receiving = _Receiving(http)
        self.received = _Received(http)
        self.inbound_routes = _InboundRoutes(http)


_Runner = Callable[[Callable[[], Any]], Awaitable[Any]]


class _AsyncReceiving:
    """Awaitable project receiving settings and per-domain receiving setup."""

    def __init__(self, sync: _Receiving, run: _Runner):
        self._sync = sync
        self._run = run

    async def get(self) -> ReceivingSettings:
        return await self._run(lambda: self._sync.get())

    async def enable(self) -> ReceivingToggle:
        """Turn receiving on. Received emails count toward your monthly email quota."""
        return await self._run(lambda: self._sync.enable())

    async def disable(self) -> ReceivingToggle:
        return await self._run(lambda: self._sync.disable())

    async def send_test(self, to: str) -> ReceivingTestResult:
        return await self._run(lambda: self._sync.send_test(to))

    async def preflight(self, domain_id: str, subdomain: str = "inbound") -> ReceivingPreflight:
        return await self._run(lambda: self._sync.preflight(domain_id, subdomain))

    async def enable_domain(self, domain_id: str, subdomain: str = "inbound") -> DomainReceiving:
        return await self._run(lambda: self._sync.enable_domain(domain_id, subdomain))

    async def check_domain(self, domain_id: str) -> DomainReceiving:
        return await self._run(lambda: self._sync.check_domain(domain_id))

    async def disable_domain(self, domain_id: str) -> DomainReceiving:
        return await self._run(lambda: self._sync.disable_domain(domain_id))


class _AsyncReceived:
    """Awaitable received emails: list, read, download, and reply."""

    def __init__(self, sync: _Received, run: _Runner):
        self._sync = sync
        self._run = run

    async def list(
        self,
        *,
        status: Optional[Union[str, List[str]]] = None,
        domain_id: Optional[str] = None,
        search: Optional[str] = None,
        days: Optional[int] = None,
        limit: Optional[int] = None,
        before: Optional[str] = None,
    ) -> ReceivedEmailList:
        return await self._run(
            lambda: self._sync.list(
                status=status,
                domain_id=domain_id,
                search=search,
                days=days,
                limit=limit,
                before=before,
            )
        )

    async def get(self, received_id: str) -> ReceivedEmailDetail:
        return await self._run(lambda: self._sync.get(received_id))

    async def stats(self, days: int = 30, domain_id: Optional[str] = None) -> ReceivedStats:
        return await self._run(lambda: self._sync.stats(days, domain_id))

    async def attachment(self, received_id: str, attachment_id: str) -> ReceivedAttachmentLink:
        return await self._run(lambda: self._sync.attachment(received_id, attachment_id))

    async def raw(self, received_id: str) -> ReceivedRawLink:
        return await self._run(lambda: self._sync.raw(received_id))

    async def reply(
        self,
        received_id: str,
        *,
        text: Optional[str] = None,
        html: Optional[str] = None,
        from_: Optional[str] = None,
        subject: Optional[str] = None,
        reply_all: Optional[bool] = None,
        idempotency_key: Optional[str] = None,
    ) -> ReceivedReply:
        """Reply in the same thread. Needs ``text`` or ``html``; retries never send twice."""
        if not text and not html:
            raise ValueError("Provide text or html for the reply.")
        return await self._run(
            lambda: self._sync.reply(
                received_id,
                text=text,
                html=html,
                from_=from_,
                subject=subject,
                reply_all=reply_all,
                idempotency_key=idempotency_key,
            )
        )


class _AsyncInboundRoutes:
    """Awaitable rules that decide what happens to mail arriving at matching addresses."""

    def __init__(self, sync: _InboundRoutes, run: _Runner):
        self._sync = sync
        self._run = run

    async def list(self, domain_id: Optional[str] = None) -> InboundRouteList:
        return await self._run(lambda: self._sync.list(domain_id))

    async def create(self, match_type: InboundRouteMatchType, **options: Any) -> InboundRoute:
        _check_fields(options, _ROUTE_CREATE_FIELDS)
        return await self._run(lambda: self._sync.create(match_type, **options))

    async def update(self, route_id: str, **patch: Any) -> InboundRoute:
        """Change only the fields given. A None value is sent as null."""
        _check_fields(patch, _ROUTE_UPDATE_FIELDS)
        return await self._run(lambda: self._sync.update(route_id, **patch))

    async def delete(self, route_id: str) -> None:
        await self._run(lambda: self._sync.delete(route_id))


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
        self.receiving = _AsyncReceiving(self._sync.receiving, self._run)
        self.received = _AsyncReceived(self._sync.received, self._run)
        self.inbound_routes = _AsyncInboundRoutes(self._sync.inbound_routes, self._run)

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

    async def get_email_conversation(self, email_id: str) -> EmailConversation:
        """The thread a sent email belongs to, with every sent and received message in it."""
        return await self._run(lambda: self._sync.emails.conversation(email_id))

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
