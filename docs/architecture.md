# Architecture and protocol

## Message path

Cloudflare Email Routing invokes `src/index.mjs` for the configured `MAIL_RECIPIENT`. The Worker checks `MAIL_RECIPIENT` and `MAIL_RELAY` before inspecting mail, rejects unsupported recipients, parses MIME up to 10 MiB, and asks the `AI` binding to run `@cf/cloudflare/clef-flash`. The classifier receives `sender_domain` and `sender_name` (at most 200 characters) from the untrusted From header, subject, and at most 8,000 characters of plain text. HTML-only mail is not converted to text. A 15-second timeout bounds the AI call.

The Worker always calls `forward(MAIL_RELAY, headers)` for supported recipients after classification or a classification failure. It adds only an `X-Clef-Result` header for eligible scores; it does not edit the body. A `forward()` error propagates. Missing or malformed mail configuration throws before reject or forward. Parsing, AI, schema, timeout, or warning-token failure falls open to forwarding without a warning. A missing signing key also skips the warning header. Delivery remains subject to Cloudflare and mail server behavior.

## Signed header

For a valid spam probability at least 0.7, the Worker selects a version from the parsed Message-ID. A nonempty ID keeps the existing v1 exact-ID binding, with no body authentication:

```text
X-Clef-Result: v1.<base64url(JSON payload)>.<base64url(HMAC-SHA256 of "v1." + payload)>
payload = {"version":1,"spam":0.8,"timestamp":<Unix seconds>,"message_id":"<id@example.invalid>"}
```

Only an absent Message-ID header (zero headers) uses v2. An empty header does not enable this fallback:

```text
X-Clef-Result: v2.<base64url(JSON payload)>.<base64url(HMAC-SHA256 of "v2." + payload)>
payload = {"version":2,"spam":0.8,"timestamp":<Unix seconds>,"message_id":"","body_sha256":"<64 lowercase hexadecimal characters>"}
```

The key is `CLEF_SIGNING_KEY`. The HMAC covers the literal version prefix and encoded payload, separating the v1 and v2 signing domains. Both schemas reject duplicate JSON keys and require exactly the fields shown and a matching integer version. v2 requires `message_id: ''` and a lowercase hexadecimal SHA-256 digest. `body_sha256` hashes raw MIME body octets after the first `CRLFCRLF`, `LFLF`, or `CRCR` header/body separator, converting only CRLF and CR to LF. It does not decode MIME, transfer encoding, or character sets, trim whitespace, or add a final newline. Multipart boundaries, part headers, and encoded attachments within those body octets are included. Headers must use one uniform line-ending style (CRLF, LF, or CR) with an explicit blank separator line. Missing or mixed header line endings prevent v2 signing or verification; body line endings may still be mixed.

The Python verifier supports both versions. v1 still requires exact equality with the delivered Message-ID; its rules are not relaxed. v2 checks the canonical body hash and accepts zero or one delivered Message-ID, allowing one ID added by transport without trusting that ID as a binding. More than one Message-ID rejects result processing in either version. Previously stored v1 empty-ID messages are not repaired: adding an ID to them still invalidates their result.

Both versions retain signature, strict schema, score (0.7 through 1), time (at most 7 days old and 300 seconds in the future), and canonical unpadded base64url checks. More than 8 candidate result headers skips result processing. There is no replay database. v2 authenticates only the canonical body binding, score, and timestamp: it does **not** authenticate From, Subject, other top-level headers, or the sender, and does not prevent replay with the same canonical body within 7 days. Neither version provides confidentiality. Body/footer changes or transfer-encoding (CTE) and MIME rewrites that change those body octets beyond line endings invalidate v2 and fail open: no Clef warning or Junk action is applied, apart from stripping spoofed action headers.

At 0.7 through below 0.9, the filter inserts a Japanese warning and defangs common URL and address text in editable text/plain and text/html parts. It extracts readable text from HTML and escapes it into a fixed wrapper; sender tags, attributes, styling, and remote images are discarded. At 0.9 and above, it adds `X-Clef-Verified-Action: junk` and the sample maildrop rule routes to `.Junk` without changing the body. Signed or encrypted MIME skips body editing in the warning range, but a score at least 0.9 can still route it. Attachments and attached messages are left intact. The filter strips any incoming `X-Clef-Verified-Action` before verification, including when parsing or key access fails. It preserves Unix LF when rewriting through maildrop. Invalid tokens or MIME transformation failures pass through the original mail after that spoofed action removal.

The Worker uses the [Cloudflare Email handler API](https://developers.cloudflare.com/email-service/api/route-emails/email-handler/) and [clef-flash model](https://developers.cloudflare.com/workers-ai/models/clef-flash/). See [security and limitations](security.md) before deployment.
