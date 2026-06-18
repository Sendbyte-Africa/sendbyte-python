"""SDK tests: stdlib unittest, fake transport, no network."""

import asyncio
import hashlib
import hmac
import json
import unittest

from sendbyte import AsyncSendByte, SendByte, SendByteError, verify_webhook_signature

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

        result = asyncio.get_event_loop().run_until_complete(run())
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

        urls = asyncio.new_event_loop().run_until_complete(run())
        self.assertEqual(
            urls,
            [
                "https://api.test/v1/domains/dom_1",
                "https://api.test/v1/webhooks/wh_1",
                "https://api.test/v1/webhooks/deliveries/evt_1/replay",
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
