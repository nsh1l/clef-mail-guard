"""Run with: python3 -m unittest discover -s xserver -p 'test_*.py'."""
import base64
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
import hashlib
import hmac
import json
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from pathlib import Path

import warn
from warn import BANNER, ReadableHTML, readable_html, strip_action, transform

KEY = b"test-only-shared-key"
NOW = int(time.time())


def token(message_id="<test@example.invalid>", spam=0.8, timestamp=NOW):
    payload = json.dumps({"version": 1, "spam": spam, "timestamp": timestamp, "message_id": message_id}, separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    signed = "v1." + encoded
    mac = base64.urlsafe_b64encode(hmac.new(KEY, signed.encode(), hashlib.sha256).digest()).decode().rstrip("=")
    return signed + "." + mac


def sample(result=None):
    message = EmailMessage()
    message["From"] = "sender@example.invalid"
    message["To"] = "recipient@example.invalid"
    message["Message-ID"] = "<test@example.invalid>"
    if result:
        message["X-Clef-Result"] = result
    message.set_content("Original plain body", cte="quoted-printable")
    message.add_alternative("<p>Original HTML body</p>", subtype="html", cte="base64")
    message.add_attachment(b"\x00\xff\x10attachment", maintype="application", subtype="octet-stream", filename="data.bin")
    return message


class WarningTests(unittest.TestCase):
    def test_maildrop_warning_output_keeps_unix_lf_for_forwarding(self):
        # maildrop is a Unix filter pipeline, not an SMTP wire transport.
        raw = sample(token()).as_bytes(policy=policy.default)
        self.assertNotIn(b"\r", raw)
        output = transform(raw, KEY, NOW)
        self.assertNotIn(b"\r", output)
        parsed = BytesParser(policy=policy.default).parsebytes(output)
        self.assertFalse(parsed.defects)
        self.assertTrue(parsed.get_body(preferencelist=("plain",)).get_content().startswith(BANNER))
        self.assertIn(BANNER, parsed.get_body(preferencelist=("html",)).get_content())
        attachment = next(part for part in parsed.walk() if part.get_filename() == "data.bin")
        self.assertEqual(attachment.get_payload(decode=True), b"\x00\xff\x10attachment")

    def test_signed_result_warns_both_alternatives_and_preserves_attachment(self):
        raw = sample(token()).as_bytes(policy=policy.SMTP)
        output = transform(raw, KEY, NOW)
        self.assertNotEqual(output, raw)
        parsed = BytesParser(policy=policy.SMTP).parsebytes(output)
        parts = list(parsed.walk())
        plain = next(part for part in parts if part.get_content_type() == "text/plain")
        rich = next(part for part in parts if part.get_content_type() == "text/html")
        attachment = next(part for part in parts if part.get_filename() == "data.bin")
        self.assertTrue(plain.get_content().startswith(BANNER))
        self.assertIn("Original plain body", plain.get_content())
        self.assertIn(BANNER, rich.get_content())
        self.assertIn("Original HTML body", rich.get_content())
        self.assertEqual(plain["Content-Transfer-Encoding"], "quoted-printable")
        self.assertEqual(rich["Content-Transfer-Encoding"], "base64")
        self.assertEqual(attachment.get_payload(decode=True), b"\x00\xff\x10attachment")
        original_attachment = next(part for part in BytesParser(policy=policy.SMTP).parsebytes(raw).walk() if part.get_filename() == "data.bin")
        self.assertEqual(attachment.get_payload().replace("\r\n", "\n"), original_attachment.get_payload().replace("\r\n", "\n"))

    def test_warning_defangs_links_and_rebuilds_html_as_escaped_text(self):
        message = sample(token())
        plain = message.get_body(preferencelist=("plain",))
        rich = message.get_body(preferencelist=("html",))
        plain.set_content("本文 https://example.invalid/path と www.example.invalid、ftp://files.example.invalid、"
                          "mailto:help@example.invalid、help@example.invalid", cte="quoted-printable")
        rich.set_content('''<p onclick="evil()">日本語の案内 <a href="javascript:evil()">確認先</a>
            https&#58;//example.invalid/go &amp; www.example.invalid</p>
            <script>alert(1)</script><style>body{background:url(https://evil.invalid)}</style>
            <img src="https://tracker.invalid/pixel"><iframe src="https://evil.invalid"></iframe>
            <form action="https://evil.invalid"><input autofocus></form>
            <svg onload="evil()"><script>evil()</script></svg><math href="data:text/html,evil"></math>
            <div><b>続き</b> &lt;script&gt;文字列&lt;/script&gt; h<b>ttps://example.invalid/join</b></div>''',
                         subtype="html", cte="base64")
        parsed = BytesParser(policy=policy.default).parsebytes(transform(message.as_bytes(policy=policy.default), KEY, NOW))
        plain_text = parsed.get_body(preferencelist=("plain",)).get_content()
        html_text = parsed.get_body(preferencelist=("html",)).get_content()
        for value in (plain_text, html_text):
            self.assertIn(BANNER, value)
            self.assertIn("https[:]//example[.]invalid", value)
            self.assertIn("www[.]example[.]invalid", value)
            self.assertNotIn("https://example.invalid", value)
        self.assertIn("mailto[:]help[@]example[.]invalid", plain_text)
        self.assertIn("help[@]example[.]invalid", plain_text)
        self.assertIn("日本語の案内", html_text)
        self.assertIn("確認先", html_text)
        self.assertIn("続き", html_text)
        self.assertIn("&lt;script&gt;文字列&lt;/script&gt;", html_text)
        self.assertNotIn("<script", html_text)
        for active in ("onclick", "javascript:", "<a ", "<img", "<iframe", "<form", "<svg", "<math", "tracker.invalid", "evil.invalid"):
            self.assertNotIn(active, html_text)

    def test_warning_defangs_email_after_local_part_punctuation_run(self):
        message = sample(token())
        dots = "." * 256
        message.get_body(preferencelist=("plain",)).set_content(
            dots + "a@example.invalid;first+tag@example.invalid,second@example.invalid " + dots,
            cte="quoted-printable")
        output = transform(message.as_bytes(policy=policy.default), KEY, NOW)
        plain = BytesParser(policy=policy.default).parsebytes(output).get_body(preferencelist=("plain",)).get_content()
        self.assertIn("[.]" * 256 + "a[@]example[.]invalid", plain)
        self.assertIn("first+tag[@]example[.]invalid,second[@]example[.]invalid", plain)
        self.assertTrue(plain.rstrip().endswith(dots))

    def test_html_parser_error_escapes_and_defangs_literal_source(self):
        message = sample(token())
        source = '<script src="https://evil.invalid/x">alert(1)</script><p>本文</p>'
        message.get_body(preferencelist=("html",)).set_content(source, subtype="html", cte="base64")
        raw = message.as_bytes(policy=policy.default)
        for method in ("feed", "close"):
            with self.subTest(method=method):
                with patch.object(ReadableHTML, method, side_effect=ValueError("synthetic parser failure")):
                    output = transform(raw, KEY, NOW)
                self.assertNotEqual(output, raw)
                rich = BytesParser(policy=policy.default).parsebytes(output).get_body(preferencelist=("html",)).get_content()
                self.assertIn(BANNER, rich)
                self.assertIn('&lt;script src=&quot;https[:]//evil[.]invalid/x&quot;&gt;', rich)
                self.assertIn("&lt;/script&gt;&lt;p&gt;本文&lt;/p&gt;", rich)
                self.assertNotIn("<script", rich)
                self.assertNotIn("<p>", rich)
                self.assertNotIn("https://evil.invalid", rich)

    def test_warning_escapes_malformed_html_and_preserves_attached_message_bytes(self):
        message = sample(token())
        message.get_body(preferencelist=("html",)).set_content(
            '<p>読める本文 <script src="https://evil.invalid/x" <b>壊れたタグ</p>\n'
            '<a href="data:text/html,evil">表示名</a> https&#58;//example.invalid/encoded', subtype="html")
        nested = EmailMessage()
        nested.set_content("Attached https://example.invalid/kept")
        message.add_attachment(nested)
        raw = message.as_bytes(policy=policy.default)
        original = BytesParser(policy=policy.default).parsebytes(raw)
        parsed = BytesParser(policy=policy.default).parsebytes(transform(raw, KEY, NOW))
        html_text = parsed.get_body(preferencelist=("html",)).get_content()
        self.assertIn("読める本文", html_text)
        self.assertNotIn("<script", html_text)
        self.assertNotIn("<a ", html_text)
        original_attached = next(part for part in original.walk() if part.get_content_type() == "message/rfc822")
        attached = next(part for part in parsed.walk() if part.get_content_type() == "message/rfc822")
        self.assertEqual(attached.get_payload()[0].as_bytes(policy=policy.default),
                         original_attached.get_payload()[0].as_bytes(policy=policy.default))
        self.assertIn("https://example.invalid/kept", attached.as_string())

    def test_hidden_html_unmatched_closes_do_not_scan_stack(self):
        class CountedStack(list):
            membership_scans = 0
            slice_scans = 0

            def __contains__(self, value):
                self.membership_scans += 1
                return super().__contains__(value)

            def __getitem__(self, index):
                if isinstance(index, slice):
                    self.slice_scans += 1
                return super().__getitem__(index)

        parser = ReadableHTML()
        stack = CountedStack()
        parser.hidden = stack
        parser.feed("<svg>" + "<a>" * 4000 + "</b>" * 4000 + "hidden</svg>" + "visible")
        parser.close()
        self.assertEqual(stack.membership_scans, 0)
        self.assertEqual(stack.slice_scans, 0)
        self.assertEqual("".join(parser.text), "visible")
        self.assertEqual(readable_html("before<svg><a><b>secret</a>after</b></svg>end"), "beforeend")
        self.assertEqual(readable_html("<style>secret<script>secret</style>shown"), "shown")

    def test_large_hidden_html_is_sanitized_in_real_transform(self):
        message = sample(token())
        message.get_body(preferencelist=("html",)).set_content(
            "<svg>" + "<a>" * 4000 + "</b>" * 4000 + "secret</svg><p>Visible https://example.invalid</p>",
            subtype="html", cte="base64")
        parsed = BytesParser(policy=policy.default).parsebytes(transform(message.as_bytes(policy=policy.default), KEY, NOW))
        rich = parsed.get_body(preferencelist=("html",)).get_content()
        self.assertIn("Visible https[:]//example[.]invalid", rich)
        self.assertNotIn("secret", rich)
        self.assertNotIn("<svg", rich)

    def test_invalid_inputs_pass_exact_bytes(self):
        for bad in (None, "garbage", token(spam=0.6999), token(timestamp=NOW - 8 * 86400),
                    token(timestamp=NOW + 301), token(message_id="<other@example.invalid>"),
                    token()[:-1] + ("A" if token()[-1] != "A" else "B")):
            with self.subTest(bad=bad):
                raw = sample(bad).as_bytes(policy=policy.SMTP)
                self.assertEqual(transform(raw, KEY, NOW), raw)

    def test_unreadable_charset_passes_exact_bytes(self):
        raw = (b"Message-ID: <test@example.invalid>\r\nX-Clef-Result: " + token().encode()
               + b"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\ninvalid \xff body")
        self.assertEqual(transform(raw, KEY, NOW), raw)

    def test_representable_charset_is_kept(self):
        message = EmailMessage()
        message["Message-ID"] = "<test@example.invalid>"
        message["X-Clef-Result"] = token()
        message.set_content("元の本文", charset="iso-2022-jp", cte="base64")
        parsed = BytesParser(policy=policy.SMTP).parsebytes(transform(message.as_bytes(policy=policy.SMTP), KEY, NOW))
        self.assertEqual(parsed.get_content_charset(), "iso-2022-jp")
        self.assertIn("元の本文", parsed.get_content())
        self.assertTrue(parsed.get_content().startswith(BANNER))

    def test_duplicate_headers_find_valid_token_and_fake_marker_does_not_suppress(self):
        message = sample("garbage")
        message["X-Clef-Result"] = token()
        message["X-Clef-Warned"] = "yes"
        raw = message.as_bytes(policy=policy.SMTP)
        self.assertIn(BANNER, BytesParser(policy=policy.SMTP).parsebytes(transform(raw, KEY, NOW)).get_body(preferencelist=("plain",)).get_content())
        for _ in range(8):
            message["X-Clef-Result"] = "garbage"
        raw = message.as_bytes(policy=policy.SMTP)
        self.assertEqual(transform(raw, KEY, NOW), raw)

    def test_folded_signed_header(self):
        raw = sample(token()).as_bytes(policy=policy.SMTP)
        marker = ("X-Clef-Result: " + token()).encode()
        folded = marker[:70] + b"\r\n " + marker[70:]
        self.assertIn(BANNER, BytesParser(policy=policy.SMTP).parsebytes(transform(raw.replace(marker, folded), KEY, NOW)).get_body(preferencelist=("plain",)).get_content())

    def test_protected_mime_and_attached_forwarded_message(self):
        message = sample(token())
        nested = EmailMessage()
        nested.set_content("Forwarded content")
        message.add_attachment(nested)
        raw = message.as_bytes(policy=policy.SMTP)
        output = transform(raw, KEY, NOW)
        parsed = BytesParser(policy=policy.SMTP).parsebytes(output)
        forwarded = next(part for part in parsed.walk() if part.get_content_type() == "message/rfc822")
        self.assertNotIn(BANNER, forwarded.as_string())
        signed = EmailMessage()
        signed["Message-ID"] = "<test@example.invalid>"
        signed["X-Clef-Result"] = token()
        signed.set_type("multipart/signed")
        signed.attach(EmailMessage())
        protected = signed.as_bytes(policy=policy.SMTP)
        self.assertEqual(transform(protected, KEY, NOW), protected)
        encrypted = EmailMessage()
        encrypted["Message-ID"] = "<test@example.invalid>"
        encrypted["X-Clef-Result"] = token()
        encrypted.set_type("application/pkcs7-mime")
        encrypted.set_payload("synthetic encrypted payload")
        protected = encrypted.as_bytes(policy=policy.SMTP)
        self.assertEqual(transform(protected, KEY, NOW), protected)

    def test_score_boundaries_and_protected_junk(self):
        for score in (0.6999, 0.7, 0.8999, 0.9, 1):
            with self.subTest(score=score):
                raw = sample(token(spam=score)).as_bytes(policy=policy.SMTP)
                output = transform(raw, KEY, NOW)
                parsed = BytesParser(policy=policy.SMTP).parsebytes(output)
                self.assertEqual(parsed.get("X-Clef-Verified-Action"), "junk" if score >= 0.9 else None)
                self.assertEqual(BANNER in parsed.get_body(preferencelist=("plain",)).get_content(), 0.7 <= score < 0.9)
                if score >= 0.9 or score < 0.7:
                    self.assertEqual(output.split(b"\r\n\r\n", 1)[1], raw.split(b"\r\n\r\n", 1)[1])
        signed = EmailMessage()
        signed["Message-ID"] = "<test@example.invalid>"
        signed["X-Clef-Result"] = token(spam=0.9)
        signed.set_type("multipart/signed")
        signed.attach(EmailMessage())
        raw = signed.as_bytes(policy=policy.SMTP)
        output = transform(raw, KEY, NOW)
        self.assertEqual(output.split(b"\r\n\r\n", 1)[1], raw.split(b"\r\n\r\n", 1)[1])
        self.assertIn(b"X-Clef-Verified-Action: junk", output)

    def test_spoofed_action_is_stripped_on_all_paths(self):
        for result in (None, "garbage", token(spam=0.8), token(spam=0.9)):
            with self.subTest(result=result):
                raw = sample(result).as_bytes(policy=policy.SMTP)
                injected = b"X-Clef-Verified-Action: junk\r\n\tcontinued\r\n" + raw
                output = transform(injected, KEY, NOW)
                self.assertEqual(output.count(b"X-Clef-Verified-Action: junk"), int(result == token(spam=0.9)))
                if result is None or result == "garbage":
                    self.assertEqual(output, raw)
        raw = b"X-Clef-Verified-Action: junk\r\nSubject: test\r\n\r\nBody\r\n"
        script = Path(__file__).with_name("warn.py")
        result = subprocess.run([sys.executable, str(script), "/nonexistent/clef-key"], input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        self.assertEqual(result.stdout, b"Subject: test\r\n\r\nBody\r\n")
        last = b"Subject: test\r\nX-Clef-Verified-Action: junk\r\n\r\nBody\r\n"
        self.assertEqual(transform(last, KEY, NOW), b"Subject: test\r\n\r\nBody\r\n")
        bare_cr = b"Subject: test\rX-Clef-Verified-Action: junk\r\rBody\r"
        self.assertEqual(transform(bare_cr, KEY, NOW), b"Subject: test\r\rBody\r")

    def test_action_removal_preserves_mixed_line_endings_folds_and_body(self):
        cases = (
            (b"x-clef-verified-action: junk\r\n\tspoof\nSubject: one\r\n\r\nBody\r\n",
             b"Subject: one\r\n\r\nBody\r\n"),
            (b"Subject: one\r\nX-Clef-Verified-Action: junk\r\n\tspoof\nX-Other: kept\r\rBody\n",
             b"Subject: one\r\nX-Other: kept\r\rBody\n"),
            (b"Subject: one\rX-Clef-Verified-Action: junk\r\rBody\r",
             b"Subject: one\r\rBody\r"),
            (b"Subject: one\nX-Clef-Verified-Action: junk",
             b"Subject: one"),
            (b"X-Clef-Verified-Action: junk", b""),
            (b"Subject: one\nX-Clef-Verified-Action: junk\nX-Clef-Verified-Action: junk\n\nBody",
             b"Subject: one\n\nBody"),
            (b"Subject: one\n\nX-Clef-Verified-Action: junk\nBody",
             b"Subject: one\n\nX-Clef-Verified-Action: junk\nBody"),
        )
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(strip_action(raw), expected)

    def test_many_spoofed_headers_use_no_repeated_prefix_enumeration(self):
        class LineEndSpy:
            def __init__(self, pattern):
                self.pattern = pattern
                self.prefix_scans = 0

            def match(self, *args):
                return self.pattern.match(*args)

            def finditer(self, *args):
                self.prefix_scans += 1
                return self.pattern.finditer(*args)

        spy = LineEndSpy(warn.LINE_END_RE)
        raw = b"Subject: synthetic\n" + b"X-Clef-Verified-Action: junk\n" * 4000 + b"\nBenign body\n"
        expected = b"Subject: synthetic\n\nBenign body\n"
        with patch.object(warn, "LINE_END_RE", spy):
            self.assertEqual(strip_action(raw), expected)
        self.assertLessEqual(spy.prefix_scans, 1)
        script = Path(__file__).with_name("warn.py")
        run = subprocess.run([sys.executable, str(script), "/nonexistent/synthetic-clef-key"],
                             input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        self.assertEqual(run.stdout, expected)
        self.assertEqual(run.stderr, b"clef_warning_failed\n")

    def test_cli_key_error_passes_exact_bytes(self):
        raw = sample(token()).as_bytes(policy=policy.SMTP)
        script = Path(__file__).with_name("warn.py")
        result = subprocess.run([sys.executable, str(script), "/nonexistent/clef-key"], input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        self.assertEqual(result.stdout, raw)
        with tempfile.TemporaryDirectory() as folder:
            key_file = Path(folder) / "key"
            key_file.write_bytes(KEY)
            result = subprocess.run([sys.executable, str(script), str(key_file)], input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            self.assertIn(BANNER.encode(), BytesParser(policy=policy.SMTP).parsebytes(result.stdout).get_body(preferencelist=("plain",)).get_content().encode())


if __name__ == "__main__":
    unittest.main()
