"""SDK tests: stdlib unittest, fake transport, no network."""

import asyncio
import hashlib
import hmac
import json
import unittest

from sendbyte import (
    WEBHOOK_EVENT_TYPES,
    AsyncSendByte,
    SendByte,
    SendByteError,
    verify_webhook_signature,
)

EMAIL = {
    "id": "em_1",
    "from": "a@b.ng",
    "to": ["c@d.ng"],
    "subject": "Hi",
    "status": "queued",
    "sandbox": True,
}


class FakeTransport:
    def __init__(self, status=200, body=None):
        self.status = status
        self.body = body if body is not None else EMAIL
        self.calls = []

    def __call__(self, method, url, headers, payload):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "body": json.loads(payload) if payload else None,
            }
        )
        return self.status, json.dumps(self.body)


class SequenceTransport:
    """Returns a scripted list of (status, text[, headers]) tuples, one per call."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, method, url, headers, payload):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "body": json.loads(payload) if payload else None,
            }
        )
        return self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]


class ClientTests(unittest.TestCase):
    def test_rejects_malformed_keys(self):
        with self.assertRaises(SendByteError) as ctx:
            SendByte("pk_live_nope")
        self.assertEqual(ctx.exception.code, "invalid_api_key")

    def test_sends_with_auth_and_body(self):
        transport = FakeTransport(201)
        client = SendByte("sk_test_abc", base_url="https://api.test", transport=transport)
        result = client.emails.send(
            from_="a@b.ng",
            to="c@d.ng",
            subject="Hi",
            html="<p>x</p>",
            idempotency_key="order-1",
        )
        self.assertEqual(result["id"], "em_1")
        call = transport.calls[0]
        self.assertEqual(call["url"], "https://api.test/v1/emails")
        self.assertEqual(call["headers"]["authorization"], "Bearer sk_test_abc")
        self.assertEqual(call["body"]["from"], "a@b.ng")
        self.assertEqual(call["body"]["idempotency_key"], "order-1")

    def test_rejects_unknown_send_kwargs(self):
        client = SendByte("sk_test_abc", transport=FakeTransport())
        with self.assertRaises(TypeError):
            client.emails.send(from_="a@b.ng", to="c@d.ng", subject="x", htlm="typo")

    def test_list_builds_query(self):
        transport = FakeTransport(200, {"data": [], "has_more": False})
        client = SendByte("sk_test_abc", base_url="https://api.test", transport=transport)
        client.emails.list(limit=5, status="delivered")
        self.assertEqual(transport.calls[0]["url"], "https://api.test/v1/emails?limit=5&status=delivered")

    def test_maps_api_errors(self):
        transport = FakeTransport(
            403,
            {
                "error": {
                    "code": "domain_not_verified",
                    "message": "paylink.ng is not verified.",
                    "docs_url": "https://docs.sendbyte.africa/errors/domain_not_verified",
                }
            },
        )
        client = SendByte("sk_live_abc", base_url="https://api.test", transport=transport)
        with self.assertRaises(SendByteError) as ctx:
            client.emails.send(from_="a@paylink.ng", to="c@d.ng", subject="x", text="x")
        self.assertEqual(ctx.exception.code, "domain_not_verified")
        self.assertEqual(ctx.exception.status, 403)
        self.assertIn("/errors/domain_not_verified", ctx.exception.docs_url)

    def test_domains_and_webhooks_surfaces(self):
        transport = FakeTransport(200, {"data": []})
        client = SendByte("sk_test_abc", base_url="https://api.test", transport=transport)
        client.domains.list()
        client.webhooks.list()
        urls = [c["url"] for c in transport.calls]
        self.assertEqual(urls, ["https://api.test/v1/domains", "https://api.test/v1/webhooks"])

    def test_async_client(self):
        transport = FakeTransport(201)
        client = AsyncSendByte("sk_test_abc", base_url="https://api.test", transport=transport)

        async def run():
            return await client.send_email(from_="a@b.ng", to="c@d.ng", subject="Hi", text="x")

        result = asyncio.run(run())
        self.assertEqual(result["id"], "em_1")

    def test_auto_idempotency_key_when_absent(self):
        transport = FakeTransport(201)
        client = SendByte("sk_test_abc", base_url="https://api.test", transport=transport)
        client.emails.send(from_="a@b.ng", to="c@d.ng", subject="Hi", text="x")
        key = transport.calls[0]["body"]["idempotency_key"]
        self.assertRegex(
            key,
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )

    def test_retries_429_and_reuses_idempotency_key(self):
        transport = SequenceTransport(
            [
                (429, json.dumps({"error": {"code": "rate_limited"}}), {"retry-after": "0"}),
                (201, json.dumps(EMAIL), {}),
            ]
        )
        client = SendByte("sk_test_abc", base_url="https://api.test", transport=transport)
        result = client.emails.send(from_="a@b.ng", to="c@d.ng", subject="Hi", text="x")
        self.assertEqual(result["id"], "em_1")
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(
            transport.calls[0]["body"]["idempotency_key"],
            transport.calls[1]["body"]["idempotency_key"],
        )

    def test_retries_5xx_then_raises_typed_error(self):
        transport = SequenceTransport(
            [(503, json.dumps({"error": {"code": "unavailable"}}), {})]
        )
        client = SendByte(
            "sk_test_abc", base_url="https://api.test", transport=transport, max_attempts=2
        )
        with self.assertRaises(SendByteError) as ctx:
            client.emails.send(from_="a@b.ng", to="c@d.ng", subject="x", text="x")
        self.assertEqual(ctx.exception.status, 503)
        self.assertEqual(len(transport.calls), 2)

    def test_non_json_error_body_raises_typed_error(self):
        transport = SequenceTransport([(502, "<html>502 Bad Gateway</html>", {})])
        client = SendByte(
            "sk_test_abc", base_url="https://api.test", transport=transport, max_attempts=1
        )
        with self.assertRaises(SendByteError) as ctx:
            client.emails.send(from_="a@b.ng", to="c@d.ng", subject="x", text="x")
        self.assertEqual(ctx.exception.code, "request_failed")
        self.assertEqual(ctx.exception.status, 502)

    def test_non_json_success_body_raises_invalid_response(self):
        transport = SequenceTransport([(200, "<html>not json</html>", {})])
        client = SendByte("sk_test_abc", base_url="https://api.test", transport=transport)
        with self.assertRaises(SendByteError) as ctx:
            client.emails.list()
        self.assertEqual(ctx.exception.code, "invalid_response")
        self.assertEqual(ctx.exception.status, 200)

    def test_list_unsubscribe_passes_through(self):
        transport = FakeTransport(201)
        client = SendByte("sk_test_abc", base_url="https://api.test", transport=transport)
        client.emails.send(
            from_="a@b.ng",
            to="c@d.ng",
            subject="Hi",
            text="x",
            list_unsubscribe={"url": "https://x.ng/u", "mailto": "unsub@x.ng"},
        )
        self.assertEqual(
            transport.calls[0]["body"]["list_unsubscribe"],
            {"url": "https://x.ng/u", "mailto": "unsub@x.ng"},
        )

    def test_refuses_live_key_over_insecure_base_url(self):
        with self.assertRaises(SendByteError) as ctx:
            SendByte("sk_live_abc", base_url="http://api.example.com")
        self.assertEqual(ctx.exception.code, "insecure_base_url")
        # http tolerated for localhost dev; test keys always allowed.
        SendByte("sk_live_abc", base_url="http://localhost:8080", transport=FakeTransport())
        SendByte("sk_test_abc", base_url="http://api.example.com", transport=FakeTransport())

    def test_async_parity_methods(self):
        transport = FakeTransport(200, {"id": "dom_1", "ses_verified": True})
        client = AsyncSendByte("sk_test_abc", base_url="https://api.test", transport=transport)

        async def run():
            # The methods missing before this fix: get_domain, disable_webhook, replay_webhook.
            await client.get_domain("dom_1")
            await client.disable_webhook("wh_1")
            await client.replay_webhook("evt_1")
            return [c["url"] for c in transport.calls]

        urls = asyncio.run(run())
        self.assertEqual(
            urls,
            [
                "https://api.test/v1/domains/dom_1",
                "https://api.test/v1/webhooks/wh_1",
                "https://api.test/v1/webhooks/deliveries/evt_1/replay",
            ],
        )


DOMAIN_ID = "11111111-1111-4111-8111-111111111111"
RECEIVED_ID = "22222222-2222-4222-8222-222222222222"
ROUTE_ID = "33333333-3333-4333-8333-333333333333"


def _client(transport):
    return SendByte("sk_test_abc", base_url="https://api.test", transport=transport)


class ReceivingTests(unittest.TestCase):
    def test_receiving_settings_and_project_toggle(self):
        transport = FakeTransport(200, {"enabled": True})
        client = _client(transport)
        client.receiving.get()
        client.receiving.enable()
        client.receiving.disable()
        client.receiving.send_test("hello@abc.in.sendbyte.africa")
        calls = [(c["method"], c["url"], c["body"]) for c in transport.calls]
        self.assertEqual(
            calls,
            [
                ("GET", "https://api.test/v1/receiving", None),
                ("POST", "https://api.test/v1/receiving/enable", {"acknowledge_quota": True}),
                ("POST", "https://api.test/v1/receiving/disable", {}),
                (
                    "POST",
                    "https://api.test/v1/receiving/test",
                    {"to": "hello@abc.in.sendbyte.africa"},
                ),
            ],
        )

    def test_enable_always_acknowledges_quota(self):
        transport = FakeTransport(200, {"enabled": True})
        _client(transport).receiving.enable()
        self.assertIs(transport.calls[0]["body"]["acknowledge_quota"], True)

    def test_domain_receiving_setup(self):
        transport = FakeTransport(200, {"domain_id": DOMAIN_ID, "status": "pending"})
        client = _client(transport)
        client.receiving.preflight(DOMAIN_ID)
        client.receiving.preflight(DOMAIN_ID, subdomain="mail-in")
        client.receiving.enable_domain(DOMAIN_ID)
        client.receiving.enable_domain(DOMAIN_ID, "replies")
        client.receiving.check_domain(DOMAIN_ID)
        client.receiving.disable_domain(DOMAIN_ID)
        base = f"https://api.test/v1/domains/{DOMAIN_ID}/receiving"
        calls = [(c["method"], c["url"], c["body"]) for c in transport.calls]
        self.assertEqual(
            calls,
            [
                ("GET", f"{base}/preflight?subdomain=inbound", None),
                ("GET", f"{base}/preflight?subdomain=mail-in", None),
                ("POST", base, {"subdomain": "inbound"}),
                ("POST", base, {"subdomain": "replies"}),
                ("POST", f"{base}/check", {}),
                ("DELETE", base, None),
            ],
        )

    def test_received_list_encodes_query_and_passes_status_lists(self):
        transport = FakeTransport(200, {"data": [], "has_more": False, "next_cursor": None})
        client = _client(transport)
        client.received.list()
        client.received.list(
            status="spam,held",
            domain_id=DOMAIN_ID,
            search="invoice 42",
            days=7,
            limit=10,
            before="cur_1",
        )
        client.received.list(status=["delivered", "forwarded"])
        urls = [c["url"] for c in transport.calls]
        self.assertEqual(
            urls,
            [
                "https://api.test/v1/received",
                (
                    "https://api.test/v1/received?status=spam,held"
                    f"&domain_id={DOMAIN_ID}&search=invoice+42&days=7&limit=10&before=cur_1"
                ),
                "https://api.test/v1/received?status=delivered,forwarded",
            ],
        )

    def test_received_reads(self):
        transport = FakeTransport(200, {"url": "https://s3.test/x"})
        client = _client(transport)
        client.received.get(RECEIVED_ID)
        client.received.stats()
        client.received.stats(days=7, domain_id=DOMAIN_ID)
        client.received.attachment(RECEIVED_ID, "0")
        client.received.raw(RECEIVED_ID)
        base = f"https://api.test/v1/received/{RECEIVED_ID}"
        calls = [(c["method"], c["url"]) for c in transport.calls]
        self.assertEqual(
            calls,
            [
                ("GET", base),
                ("GET", "https://api.test/v1/received/stats?days=30"),
                ("GET", f"https://api.test/v1/received/stats?days=7&domain_id={DOMAIN_ID}"),
                ("GET", f"{base}/attachments/0"),
                ("GET", f"{base}/raw"),
            ],
        )

    def test_reply_body(self):
        transport = FakeTransport(202, {"id": "em_2", "status": "queued", "thread_id": "th_1"})
        result = _client(transport).received.reply(
            RECEIVED_ID,
            text="Thanks",
            from_="support@paylink.ng",
            subject="Re: Help",
            reply_all=True,
            idempotency_key="reply-1",
        )
        self.assertEqual(result["thread_id"], "th_1")
        call = transport.calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["url"], f"https://api.test/v1/received/{RECEIVED_ID}/reply")
        self.assertEqual(
            call["body"],
            {
                "idempotency_key": "reply-1",
                "from": "support@paylink.ng",
                "text": "Thanks",
                "subject": "Re: Help",
                "reply_all": True,
            },
        )

    def test_reply_requires_text_or_html(self):
        transport = FakeTransport(202)
        with self.assertRaises(ValueError):
            _client(transport).received.reply(RECEIVED_ID)
        self.assertEqual(transport.calls, [])

    def test_reply_auto_idempotency_key_reused_across_retries(self):
        transport = SequenceTransport(
            [
                (503, json.dumps({"error": {"code": "unavailable"}}), {"retry-after": "0"}),
                (429, json.dumps({"error": {"code": "rate_limited"}}), {"retry-after": "0"}),
                (202, json.dumps({"id": "em_2", "status": "queued", "thread_id": None}), {}),
            ]
        )
        result = _client(transport).received.reply(RECEIVED_ID, html="<p>Thanks</p>")
        self.assertEqual(result["id"], "em_2")
        self.assertEqual(len(transport.calls), 3)
        keys = {c["body"]["idempotency_key"] for c in transport.calls}
        self.assertEqual(len(keys), 1)
        self.assertRegex(
            keys.pop(),
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )

    def test_async_reply_auto_idempotency_key_reused_across_retries(self):
        transport = SequenceTransport(
            [
                (500, json.dumps({"error": {"code": "internal"}}), {"retry-after": "0"}),
                (202, json.dumps({"id": "em_2", "status": "queued", "thread_id": None}), {}),
            ]
        )
        client = AsyncSendByte("sk_test_abc", base_url="https://api.test", transport=transport)
        asyncio.run(
            client.received.reply(RECEIVED_ID, text="Thanks")
        )
        self.assertEqual(len(transport.calls), 2)
        first, second = (c["body"]["idempotency_key"] for c in transport.calls)
        self.assertTrue(first)
        self.assertEqual(first, second)

    def test_separate_replies_get_separate_keys(self):
        transport = FakeTransport(202, {"id": "em_2", "status": "queued", "thread_id": None})
        client = _client(transport)
        client.received.reply(RECEIVED_ID, text="One")
        client.received.reply(RECEIVED_ID, text="Two")
        keys = [c["body"]["idempotency_key"] for c in transport.calls]
        self.assertNotEqual(keys[0], keys[1])

    def test_inbound_routes(self):
        transport = FakeTransport(201, {"id": ROUTE_ID, "match_type": "exact"})
        client = _client(transport)
        client.inbound_routes.list()
        client.inbound_routes.list(DOMAIN_ID)
        client.inbound_routes.create(
            "exact",
            domain_id=DOMAIN_ID,
            match_value="support",
            action="forward",
            forward_to=["team@paylink.ng"],
            endpoint_ids=None,
        )
        client.inbound_routes.update(ROUTE_ID, enabled=False, endpoint_ids=None)
        calls = [(c["method"], c["url"], c["body"]) for c in transport.calls]
        self.assertEqual(
            calls,
            [
                ("GET", "https://api.test/v1/inbound-routes", None),
                ("GET", f"https://api.test/v1/inbound-routes?domain_id={DOMAIN_ID}", None),
                (
                    "POST",
                    "https://api.test/v1/inbound-routes",
                    {
                        "match_type": "exact",
                        "domain_id": DOMAIN_ID,
                        "match_value": "support",
                        "action": "forward",
                        "forward_to": ["team@paylink.ng"],
                    },
                ),
                (
                    "PATCH",
                    f"https://api.test/v1/inbound-routes/{ROUTE_ID}",
                    {"enabled": False, "endpoint_ids": None},
                ),
            ],
        )

    def test_inbound_route_rejects_unknown_fields(self):
        client = _client(FakeTransport())
        with self.assertRaises(TypeError):
            client.inbound_routes.create("exact", match_valu="typo")
        with self.assertRaises(TypeError):
            client.inbound_routes.update(ROUTE_ID, match_type="prefix")

    def test_delete_route_handles_204(self):
        transport = SequenceTransport([(204, "", {})])
        result = _client(transport).inbound_routes.delete(ROUTE_ID)
        self.assertIsNone(result)
        self.assertEqual(transport.calls[0]["method"], "DELETE")
        self.assertEqual(
            transport.calls[0]["url"], f"https://api.test/v1/inbound-routes/{ROUTE_ID}"
        )

    def test_email_conversation(self):
        transport = FakeTransport(200, {"thread_id": "th_1", "replies": 1, "data": []})
        result = _client(transport).emails.conversation("em_1")
        self.assertEqual(result["replies"], 1)
        self.assertEqual(transport.calls[0]["url"], "https://api.test/v1/emails/em_1/conversation")

    def test_user_agent_version(self):
        transport = FakeTransport(200, {})
        _client(transport).receiving.get()
        self.assertEqual(transport.calls[0]["headers"]["user-agent"], "sendbyte-python/0.3.0")

    def test_webhook_event_types_include_received(self):
        self.assertIn("email.received", WEBHOOK_EVENT_TYPES)

    def test_async_client_has_every_receiving_method(self):
        transport = SequenceTransport([(200, json.dumps({"ok": True}), {})])
        client = AsyncSendByte("sk_test_abc", base_url="https://api.test", transport=transport)

        async def run():
            await client.receiving.get()
            await client.receiving.enable()
            await client.receiving.disable()
            await client.receiving.send_test("a@x.in.sendbyte.africa")
            await client.receiving.preflight(DOMAIN_ID, "mail-in")
            await client.receiving.enable_domain(DOMAIN_ID)
            await client.receiving.check_domain(DOMAIN_ID)
            await client.receiving.disable_domain(DOMAIN_ID)
            await client.received.list(status=["spam", "held"], limit=5)
            await client.received.get(RECEIVED_ID)
            await client.received.stats(days=14)
            await client.received.attachment(RECEIVED_ID, "1")
            await client.received.raw(RECEIVED_ID)
            await client.received.reply(RECEIVED_ID, text="Hi", idempotency_key="k1")
            await client.inbound_routes.list(DOMAIN_ID)
            await client.inbound_routes.create("catch_all", action="drop")
            await client.inbound_routes.update(ROUTE_ID, action="webhook")
            await client.inbound_routes.delete(ROUTE_ID)
            await client.get_email_conversation("em_1")

        asyncio.run(run())
        dbase = f"https://api.test/v1/domains/{DOMAIN_ID}/receiving"
        rbase = f"https://api.test/v1/received/{RECEIVED_ID}"
        calls = [(c["method"], c["url"], c["body"]) for c in transport.calls]
        self.assertEqual(
            calls,
            [
                ("GET", "https://api.test/v1/receiving", None),
                ("POST", "https://api.test/v1/receiving/enable", {"acknowledge_quota": True}),
                ("POST", "https://api.test/v1/receiving/disable", {}),
                ("POST", "https://api.test/v1/receiving/test", {"to": "a@x.in.sendbyte.africa"}),
                ("GET", f"{dbase}/preflight?subdomain=mail-in", None),
                ("POST", dbase, {"subdomain": "inbound"}),
                ("POST", f"{dbase}/check", {}),
                ("DELETE", dbase, None),
                ("GET", "https://api.test/v1/received?status=spam,held&limit=5", None),
                ("GET", rbase, None),
                ("GET", "https://api.test/v1/received/stats?days=14", None),
                ("GET", f"{rbase}/attachments/1", None),
                ("GET", f"{rbase}/raw", None),
                ("POST", f"{rbase}/reply", {"idempotency_key": "k1", "text": "Hi"}),
                ("GET", f"https://api.test/v1/inbound-routes?domain_id={DOMAIN_ID}", None),
                (
                    "POST",
                    "https://api.test/v1/inbound-routes",
                    {"match_type": "catch_all", "action": "drop"},
                ),
                (
                    "PATCH",
                    f"https://api.test/v1/inbound-routes/{ROUTE_ID}",
                    {"action": "webhook"},
                ),
                ("DELETE", f"https://api.test/v1/inbound-routes/{ROUTE_ID}", None),
                ("GET", "https://api.test/v1/emails/em_1/conversation", None),
            ],
        )


class WebhookSignatureTests(unittest.TestCase):
    SECRET = "whsec_secret"
    NOW = 1_750_000_000
    BODY = '{"type":"email.delivered"}'

    def sign(self, timestamp):
        digest = hmac.new(
            self.SECRET.encode(), f"{timestamp}.{self.BODY}".encode(), hashlib.sha256
        ).hexdigest()
        return f"t={timestamp},v1={digest}"

    def test_accepts_valid(self):
        self.assertTrue(
            verify_webhook_signature(self.SECRET, self.sign(self.NOW), self.BODY, now=self.NOW)
        )

    def test_rejects_tampered_stale_and_missing(self):
        self.assertFalse(
            verify_webhook_signature(self.SECRET, self.sign(self.NOW), '{"type":"x"}', now=self.NOW)
        )
        self.assertFalse(
            verify_webhook_signature(self.SECRET, self.sign(self.NOW - 301), self.BODY, now=self.NOW)
        )
        self.assertFalse(verify_webhook_signature(self.SECRET, None, self.BODY, now=self.NOW))
        self.assertFalse(verify_webhook_signature(self.SECRET, "garbage", self.BODY, now=self.NOW))


if __name__ == "__main__":
    unittest.main()
