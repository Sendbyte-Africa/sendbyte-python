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
