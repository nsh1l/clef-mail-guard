"""Synthetic regressions for a transport-added Message-ID; Python 3.6 compatible."""
import base64
import hashlib
import hmac
import json
import unittest
from email import policy
from email.parser import BytesParser

import warn
from test_warn import KEY, NOW, sample, token


def signed(payload, prefix="v2"):
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    data = prefix + "." + encoded
    mac = base64.urlsafe_b64encode(hmac.new(KEY, data.encode(), hashlib.sha256).digest()).decode().rstrip("=")
    return data + "." + mac


def payload_for(raw, score=0.95):
    return {"version": 2, "spam": score, "timestamp": NOW, "message_id": "", "body_sha256": warn.body_digest(raw)}


def delivered(raw, payload=None, prefix="v2", added_id=True):
    result = signed(payload_for(raw) if payload is None else payload, prefix)
    headers = b"X-Clef-Result: " + result.encode() + b"\r\n"
    if added_id:
        headers += b"Message-ID: <transport-added@example.invalid>\r\n"
    return headers + raw


def missing_id_message():
    message = sample()
    del message["Message-ID"]
    return message


class TransportTests(unittest.TestCase):
    def test_missing_id_followed_by_transport_id_routes_junk_and_keeps_body(self):
        original = missing_id_message().as_bytes(policy=policy.SMTP)
        for added_id in (True, False):
            with self.subTest(added_id=added_id):
                raw = delivered(original, added_id=added_id)
                output = warn.transform(raw, KEY, NOW)
                parsed = BytesParser(policy=policy.SMTP).parsebytes(output)
                self.assertEqual(parsed.get("X-Clef-Verified-Action"), "junk")
                self.assertEqual(output.split(b"\r\n\r\n", 1)[1], raw.split(b"\r\n\r\n", 1)[1])
                attachment = next(part for part in parsed.walk() if part.get_filename() == "data.bin")
                self.assertEqual(attachment.get_payload(decode=True), b"\x00\xff\x10attachment")

    def test_v2_thresholds_and_warning_sanitization(self):
        message = missing_id_message()
        plain = message.get_body(preferencelist=("plain",))
        assert plain is not None
        plain.set_content("Body https://example.invalid/", cte="quoted-printable")
        original = message.as_bytes(policy=policy.SMTP)
        for score in (0.6999, 0.7, 0.8999, 0.9, 1):
            with self.subTest(score=score):
                raw = delivered(original, payload_for(original, score))
                output = warn.transform(raw, KEY, NOW)
                parsed = BytesParser(policy=policy.SMTP).parsebytes(output)
                self.assertEqual(parsed.get("X-Clef-Verified-Action"), "junk" if score >= 0.9 else None)
                plain = parsed.get_body(preferencelist=("plain",))
                assert plain is not None
                body = plain.get_content()
                self.assertEqual(warn.BANNER in body, 0.7 <= score < 0.9)
                if 0.7 <= score < 0.9:
                    self.assertIn("https[:]//example[.]invalid/", body)
                    self.assertNotIn(b"\r", output)
                if score < 0.7:
                    self.assertEqual(output, raw)

    def test_v2_tampered_body_and_attachment_reject_without_routing(self):
        original = missing_id_message().as_bytes(policy=policy.SMTP)
        raw = delivered(original)
        for changed in (raw.replace(b"Original plain body", b"Changed plain body"), raw + b"tampered attachment or footer"):
            with self.subTest(changed=changed[-30:]):
                self.assertNotEqual(changed, raw)
                self.assertEqual(warn.transform(changed, KEY, NOW), changed)

    def test_v2_invalid_mac_schema_version_score_and_time_reject(self):
        original = missing_id_message().as_bytes(policy=policy.SMTP)
        base = payload_for(original)
        invalid = [dict(base, version=True), dict(base, version=1), dict(base, version=3),
                   dict(base, message_id="<signed-id@example.invalid>"), dict(base, message_id=None),
                   dict(base, spam=True), dict(base, spam=float("nan")), dict(base, spam=1.01),
                   dict(base, timestamp=NOW - 7 * 86400 - 1), dict(base, timestamp=NOW + 301),
                   dict(base, timestamp=True), dict(base, body_sha256=None), dict(base, body_sha256="0" * 64),
                   dict(base, body_sha256=base["body_sha256"].upper()), dict(base, extra="unrecognized")]
        without_digest = dict(base)
        del without_digest["body_sha256"]
        invalid.append(without_digest)
        for payload in invalid:
            with self.subTest(fields=sorted(payload)):
                raw = delivered(original, payload)
                self.assertEqual(warn.transform(raw, KEY, NOW), raw)
        raw = delivered(original)
        self.assertEqual(warn.transform(raw, b"wrong-test-key", NOW), raw)
        for prefix in ("v1", "v3"):
            raw = delivered(original, base, prefix)
            self.assertEqual(warn.transform(raw, KEY, NOW), raw)

    def test_v2_body_digest_handles_wire_bytes_and_only_line_endings(self):
        canonical = b"\x00\xfffirst\nsecond\nthird\n"
        expected = hashlib.sha256(canonical).hexdigest()
        for newline in (b"\r\n", b"\n", b"\r"):
            raw = b"Subject: synthetic" + newline * 2 + canonical.replace(b"\n", newline)
            self.assertEqual(warn.body_digest(raw), expected)
        self.assertIsNone(warn.body_digest(b"Subject: no separator"))
        self.assertEqual(warn.body_digest(b"Subject: empty\r\n\r\n"), hashlib.sha256(b"").hexdigest())
        self.assertNotEqual(warn.body_digest(b"Subject: synthetic\n\nfirst \n"),
                            warn.body_digest(b"Subject: synthetic\n\nfirst\n"))
        self.assertNotEqual(warn.body_digest(b"Subject: synthetic\n\nfirst\n"),
                            warn.body_digest(b"Subject: synthetic\n\nfirst"))

    def test_v2_line_endings_folded_token_and_spoofed_action(self):
        original = missing_id_message().as_bytes(policy=policy.SMTP)
        raw = delivered(original)
        result = signed(payload_for(original)).encode()
        raw = raw.replace(result, result[:2] + b"\r\n " + result[2:])
        for newline in (b"\r\n", b"\n", b"\r"):
            with self.subTest(newline=newline):
                wire = raw.replace(b"\r\n", newline)
                wire = b"X-Clef-Verified-Action: forged" + newline + wire
                output = warn.transform(wire, KEY, NOW)
                parsed = BytesParser(policy=policy.SMTP).parsebytes(output)
                self.assertEqual(parsed.get_all("X-Clef-Verified-Action"), ["junk"])

    def test_v2_duplicate_ids_and_excess_result_headers_still_reject(self):
        original = missing_id_message().as_bytes(policy=policy.SMTP)
        raw = delivered(original)
        duplicates = b"Message-ID: <duplicate@example.invalid>\r\n" + raw
        self.assertEqual(warn.transform(duplicates, KEY, NOW), duplicates)
        excessive = (b"X-Clef-Result: garbage\r\n" * 8) + raw
        self.assertEqual(warn.transform(excessive, KEY, NOW), excessive)

    def test_v2_protected_mime_is_unedited_but_high_score_can_route(self):
        message = missing_id_message()
        message.clear_content()
        message.set_type("application/pkcs7-mime")
        message.set_payload("synthetic encrypted content")
        original = message.as_bytes(policy=policy.SMTP)
        raw = delivered(original, payload_for(original, 0.8))
        self.assertEqual(warn.transform(raw, KEY, NOW), raw)
        raw = delivered(original)
        output = warn.transform(raw, KEY, NOW)
        self.assertIn(b"X-Clef-Verified-Action: junk", output)
        self.assertEqual(output.split(b"\r\n\r\n", 1)[1], raw.split(b"\r\n\r\n", 1)[1])

    def test_v2_missing_or_mixed_header_boundaries_reject(self):
        self.assertIsNone(warn.body_digest(b"\r\nbody"))
        for raw in (b"Subject: no separator", b"Subject: one\n\r\nbody\n\nlate",
                    b"Subject: one\r\n\nbody", b"Subject: one\r\r\nbody",
                    b"Subject: one\n\rbody", b"Subject: one\r\nX-Test: two\n\nbody"):
            with self.subTest(raw=raw):
                self.assertIsNone(warn.body_digest(raw))
                payload = {"version": 2, "spam": 0.95, "timestamp": NOW, "message_id": "",
                           "body_sha256": hashlib.sha256(b"body").hexdigest()}
                wire = delivered(raw, payload)
                self.assertEqual(warn.transform(wire, KEY, NOW), wire)

    def test_signed_duplicate_json_fields_are_rejected(self):
        original = missing_id_message().as_bytes(policy=policy.SMTP)
        base = payload_for(original)
        for field in base:
            text = "{" + json.dumps(field) + ":" + json.dumps(base[field]) + "," + json.dumps(base)[1:]
            encoded = base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")
            data = "v2." + encoded
            mac = base64.urlsafe_b64encode(hmac.new(KEY, data.encode(), hashlib.sha256).digest()).decode().rstrip("=")
            raw = b"X-Clef-Result: " + (data + "." + mac).encode() + b"\r\n" + original
            self.assertEqual(warn.transform(raw, KEY, NOW), raw)

    def test_v1_id_binding_is_not_relaxed(self):
        raw = sample(token(message_id="", spam=0.95)).as_bytes(policy=policy.SMTP)
        self.assertEqual(warn.transform(raw, KEY, NOW), raw)
        raw = sample(token(message_id="<different@example.invalid>", spam=0.95)).as_bytes(policy=policy.SMTP)
        self.assertEqual(warn.transform(raw, KEY, NOW), raw)
        raw = sample(token(spam=0.95)).as_bytes(policy=policy.SMTP)
        self.assertIn(b"X-Clef-Verified-Action: junk", warn.transform(raw, KEY, NOW))


if __name__ == "__main__":
    unittest.main()
