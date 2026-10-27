# Architecture and protocol

## Message path

Cloudflare Email Routing invokes `src/index.mjs` for the configured `MAIL_RECIPIENT`. The Worker checks `MAIL_RECIPIENT` and `MAIL_RELAY` before inspecting mail, rejects unsupported recipients, parses MIME up to 10 MiB, and asks the `AI` binding to run `@cf/cloudflare/clef-flash`. The classifier receives `sender_domain` and `sender_name` (at most 200 characters) from the untrusted From header, subject, and at most 8,000 characters of plain text. HTML-only mail is not converted to text. A 15-second timeout bounds the AI call.

The Worker always calls `forward(MAIL_RELAY, headers)` for supported recipients after classification or a classification failure. It adds only an `X-Clef-Result` header for eligible scores; it does not edit the body. A `forward()` error propagates. Missing or malformed mail configuration throws before reject or forward. Parsing, AI, schema, timeout, or warning-token failure falls open to forwarding without a warning. A missing signing key also skips the warning header. Delivery remains subject to Cloudflare and mail server behavior.

## Signed header

For a valid spam probability at least 0.7, the Worker builds:

```text
X-Clef-Result: v1.<base64url(JSON payload)>.<base64url(HMAC-SHA256 of "v1." + payload)>
payload = {"version":1,"spam":0.8,"timestamp":<Unix seconds>,"message_id":"<id@example.invalid>"}
```

The key is `CLEF_SIGNING_KEY`. The MAC binds score, timestamp, and Message-ID. It does **not** bind the body, authenticate the sender, or make the message confidential. The Python verifier checks the exact payload fields, signature, Message-ID, score range, and time: at most 7 days old and at most 300 seconds in the future. It considers at most 8 candidate result headers; there is no replay database. Message-ID can be absent, in which case an empty string is signed.

At 0.7 through below 0.9, the filter inserts a Japanese warning and defangs common URL and address text in editable text/plain and text/html parts. It extracts readable text from HTML and escapes it into a fixed wrapper; sender tags, attributes, styling, and remote images are discarded. At 0.9 and above, it adds `X-Clef-Verified-Action: junk` and the sample maildrop rule routes to `.Junk` without changing the body. Signed or encrypted MIME skips body editing in the warning range, but a score at least 0.9 can still route it. Attachments and attached messages are left intact. The filter strips any incoming `X-Clef-Verified-Action` before verification, including when parsing or key access fails. It preserves Unix LF when rewriting through maildrop. Invalid tokens or MIME transformation failures pass through the original mail after that spoofed action removal.

The Worker uses the [Cloudflare Email handler API](https://developers.cloudflare.com/email-service/api/route-emails/email-handler/) and [clef-flash model](https://developers.cloudflare.com/workers-ai/models/clef-flash/). See [security and limitations](security.md) before deployment.
