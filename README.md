# sendbyte

The official Python SDK for [SendByte](https://sendbyte.africa), the email API for Africa. Zero runtime dependencies (standard library only), with both synchronous and asynchronous clients.

## Install

```bash
pip install sendbyte
```

Requires Python 3.8 or newer.

## Quickstart

```python
from sendbyte import SendByte

sendbyte = SendByte("sk_test_...")

email = sendbyte.emails.send(
    from_="PayLink <receipts@paylink.ng>",
    to="amaka@halo.ng",
    subject="Receipt for your payment",
    html="<p>Thank you. Your payment was received.</p>",
)

print(email["id"])
```

`from_` is spelled with a trailing underscore because `from` is a reserved word in Python. Keys that start with `sk_test_` run in the sandbox: every endpoint behaves the same, but nothing is actually delivered. Switch to an `sk_live_` key to send for real.

## Configuration

```python
sendbyte = SendByte("sk_live_...", base_url="https://api.sendbyte.africa")
```

## Async client

`AsyncSendByte` exposes the same surface with awaitable methods, running the transport in the default executor so the SDK stays dependency free.

```python
import asyncio
from sendbyte import AsyncSendByte

async def main():
    sendbyte = AsyncSendByte("sk_test_...")
    email = await sendbyte.send_email(
        from_="PayLink <receipts@paylink.ng>",
        to="amaka@halo.ng",
        subject="Receipt",
        html="<p>Thank you.</p>",
    )
    print(email["id"])

asyncio.run(main())
```

## API

### Emails

```python
sendbyte.emails.send(from_=..., to=..., subject=..., html=...)
sendbyte.emails.get("em_123")
sendbyte.emails.list(limit=20, status="delivered")
```

`to`, `cc`, `bcc`, and `reply_to` accept a single address or a list. Pass `idempotency_key` to make retries safe, `scheduled_at` for future sends, and `template_id` with `variables` to render a server side template.

### Domains

```python
domain = sendbyte.domains.create("paylink.ng")
# domain["dns_records"] lists the SPF, DKIM, and DMARC records to publish
sendbyte.domains.list()
sendbyte.domains.get(domain["id"])
sendbyte.domains.verify(domain["id"])
```

### Webhooks

```python
endpoint = sendbyte.webhooks.create(
    "https://example.com/hooks/sendbyte",
    ["email.delivered", "email.bounced"],
)
# endpoint["secret"] is shown once, store it now
sendbyte.webhooks.list()
sendbyte.webhooks.disable(endpoint["id"])
sendbyte.webhooks.replay("evt_123")
```

## Verifying webhook signatures

Every webhook request carries a `sendbyte-signature` header. Verify it against the raw request body before trusting the payload.

```python
from sendbyte import verify_webhook_signature

@app.post("/hooks/sendbyte")
def hooks(request):
    valid = verify_webhook_signature(
        secret=os.environ["SENDBYTE_WEBHOOK_SECRET"],
        header=request.headers.get("sendbyte-signature"),
        body=request.get_data(),  # the raw, unparsed body
    )
    if not valid:
        return "", 401
    # handle the event
    return "", 200
```

The check rejects missing, malformed, tampered, and stale signatures (default tolerance is 300 seconds) and never raises.

## Errors

Failed requests raise a `SendByteError` carrying the API error shape.

```python
from sendbyte import SendByteError

try:
    sendbyte.emails.send(from_=..., to=..., subject=..., html=...)
except SendByteError as err:
    print(err.code, err.status, err.docs_url)
```

## Links

- Documentation: https://docs.sendbyte.africa

## License

MIT
