#!/usr/bin/env python3
"""maildrop xfilter: verify Clef results and warn or route to Junk."""

import base64
import hashlib
import hmac
import html
import json
import re
import sys
import time
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser


BANNER = "【迷惑メールの疑い】Clefが迷惑メールの可能性があると判定しました。リンク・添付・返信前に送信元を確認してください。誤判定の可能性があります。"
MAX_TOKENS = 8
TOKEN_RE = re.compile(r"v1\.([A-Za-z0-9_-]{1,2048})\.([A-Za-z0-9_-]{43})\Z")
ACTION_RE = re.compile(rb"(?:(?<=\n)|(?<=\r)|\A)X-Clef-Verified-Action:[^\r\n]*(?:(?:\r\n|\n|\r)[ \t][^\r\n]*)*", re.I)
HEADER_END_RE = re.compile(rb"\r\n\r\n|\n\n|\r\r")
LINE_END_RE = re.compile(rb"\r\n|\n|\r")
LINK_RE = re.compile(r"(?i)(?<![\w@])(?:https?://|ftp://|www\.|mailto:|javascript:|data:)[^\s<>\"']+|(?<![\w.+@-])[\w.+-]+@[\w.-]+\.[a-z]{2,}")
HIDDEN_HTML = {"script", "style", "head", "iframe", "object", "svg", "math",
               "form", "template", "video", "audio", "canvas", "applet", "frameset", "noscript"}
BREAK_HTML = {"address", "article", "blockquote", "br", "div", "h1", "h2", "h3", "h4", "h5", "h6",
              "hr", "li", "p", "pre", "section", "table", "td", "th", "tr"}


def defang_links(text):
    # shortcut: neutralize common URL and address spellings; upgrade if client-specific autolinking defeats it.
    return LINK_RE.sub(lambda match: match.group().replace(":", "[:]").replace("@", "[@]").replace(".", "[.]"), text)


class ReadableHTML(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.text = []
        self.hidden = []
        self.hidden_counts = {}

    def handle_starttag(self, tag, attrs):
        if self.hidden or tag in HIDDEN_HTML:
            self.hidden.append(tag)
            self.hidden_counts[tag] = self.hidden_counts.get(tag, 0) + 1
        elif tag in BREAK_HTML:
            self.text.append("\n")

    def handle_startendtag(self, tag, attrs):
        if not self.hidden and tag in BREAK_HTML:
            self.text.append("\n")

    def handle_endtag(self, tag):
        if self.hidden:
            if self.hidden_counts.get(tag, 0):
                while self.hidden:
                    popped = self.hidden.pop()
                    count = self.hidden_counts[popped] - 1
                    if count:
                        self.hidden_counts[popped] = count
                    else:
                        del self.hidden_counts[popped]
                    if popped == tag:
                        break
        elif tag in BREAK_HTML:
            self.text.append("\n")

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)


def readable_html(source):
    parser = ReadableHTML()
    try:
        parser.feed(source)
        parser.close()
    except Exception:
        # Keep the source as text; add_warning still defangs and escapes it.
        return source
    return "".join(parser.text).strip()


def strip_action(raw):
    """Remove untrusted routing headers without parsing or rewriting the body."""
    boundary = HEADER_END_RE.search(raw)
    split = boundary.start() if boundary else len(raw)
    head = raw[:split]
    kept = []
    cursor = 0
    missing_final_newline = False
    for match in ACTION_RE.finditer(head):
        start, end = match.span()
        kept.append(head[cursor:start])
        following = LINE_END_RE.match(head, end)
        if following:
            cursor = following.end()
        else:
            cursor = end
            missing_final_newline = True
    kept.append(head[cursor:])
    cleaned = b"".join(kept)
    if missing_final_newline:
        if cleaned.endswith(b"\r\n"):
            cleaned = cleaned[:-2]
        elif cleaned.endswith((b"\r", b"\n")):
            cleaned = cleaned[:-1]
    return cleaned + raw[split:]


def decode_url(value):
    data = base64.b64decode(value.replace("-", "+").replace("_", "/") + "=" * (-len(value) % 4), validate=True)
    if base64.urlsafe_b64encode(data).decode().rstrip("=") != value:
        raise ValueError("noncanonical base64url")
    return data


def valid_token(token, key, message_id, now):
    token = re.sub(r"[ \t\r\n]+", "", str(token))
    match = TOKEN_RE.fullmatch(token)
    if not match:
        return None
    try:
        signature = decode_url(match.group(2))
        payload_bytes = decode_url(match.group(1))
        expected = hmac.new(key, ("v1." + match.group(1)).encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(payload_bytes)
        if not isinstance(payload, dict) or set(payload) != {"version", "spam", "timestamp", "message_id"}:
            return None
        score = payload["spam"]
        stamp = payload["timestamp"]
        if (type(payload["version"]) is int and payload["version"] == 1
                and type(score) in (int, float) and 0.7 <= score <= 1
                and type(stamp) is int and now - 7 * 86400 <= stamp <= now + 300
                and type(payload["message_id"]) is str and payload["message_id"] == message_id):
            return payload
        return None
    except (ValueError, TypeError, UnicodeError, OverflowError):
        return None


def protected_mime(part):
    kind = part.get_content_type().lower()
    if kind in {"multipart/signed", "multipart/encrypted", "application/pkcs7-mime",
                "application/x-pkcs7-mime", "application/pgp-encrypted"}:
        return True
    if part.is_multipart() and kind != "message/rfc822":
        return any(protected_mime(child) for child in part.iter_parts())
    return False


def malformed_mime(part):
    if part.defects:
        return True
    return part.is_multipart() and part.get_content_type() != "message/rfc822" and any(
        malformed_mime(child) for child in part.iter_parts()
    )


def add_warning(part):
    if part.get_content_type() == "message/rfc822" or part.get_content_disposition() == "attachment":
        return 0
    if part.is_multipart():
        return sum(add_warning(child) for child in part.iter_parts())
    kind = part.get_content_type()
    if kind not in {"text/plain", "text/html"} or part.get_filename() is not None:
        return 0
    charset = part.get_content_charset() or "utf-8"
    body = part.get_payload(decode=True).decode(charset, errors="strict")
    prefix = BANNER + "\n\n" if kind == "text/plain" else (
        '<div style="border:2px solid #b45309;padding:12px;color:#7c2d12;font-weight:bold">'
        + html.escape(BANNER) + "</div>\n"
    )
    cte = part.get("Content-Transfer-Encoding", "").lower()
    if cte not in {"base64", "quoted-printable"}:
        cte = "quoted-printable"
    kept = [(name, value) for name, value in part.items()
            if name.lower().startswith("content-") and name.lower() not in {"content-type", "content-transfer-encoding"}]
    if kind == "text/html":
        warned = prefix + '<div style="white-space:pre-wrap">' + html.escape(defang_links(readable_html(body))) + "</div>"
    else:
        warned = prefix + defang_links(body)
    try:
        warned.encode(charset, errors="strict")
    except UnicodeError:
        charset = "utf-8"
    part.set_content(warned, subtype=kind.split("/")[1], charset=charset, cte=cte)
    for name, value in kept:
        if name not in part:
            part[name] = value
    return 1


def _transform(raw, key, now):
    message = BytesParser(policy=policy.SMTP).parsebytes(raw)
    if malformed_mime(message):
        print("clef_warning_skipped: malformed_mime", file=sys.stderr)
        return raw
    tokens = message.get_all("X-Clef-Result", [])
    if not tokens or len(tokens) > MAX_TOKENS:
        return raw
    ids = message.get_all("Message-ID", [])
    if len(ids) > 1:
        return raw
    message_id = ids[0] if ids else ""
    verified = [valid_token(token, key, message_id, now) for token in tokens]
    scores = [payload["spam"] for payload in verified if payload is not None]
    if not scores:
        return raw
    if max(scores) >= 0.9:
        boundary = HEADER_END_RE.search(raw)
        if not boundary:
            return raw
        newline = b"\r\n" if boundary.group().startswith(b"\r\n") else boundary.group()[:1]
        return raw[:boundary.start()] + newline + b"X-Clef-Verified-Action: junk" + raw[boundary.start():]
    if protected_mime(message):
        print("clef_warning_skipped: protected_mime", file=sys.stderr)
        return raw
    if not add_warning(message):
        return raw
    # maildrop/spamc/cc use Unix LF internally; SMTP CRLF here breaks forwarding headers.
    return message.as_bytes(policy=policy.SMTP.clone(linesep="\n"))


def transform(raw, key, now=None):
    raw = strip_action(raw)
    try:
        return _transform(raw, key, int(time.time()) if now is None else now)
    except Exception:
        print("clef_warning_failed", file=sys.stderr)
        return raw


def main():
    raw = sys.stdin.buffer.read()
    raw = strip_action(raw)
    try:
        with open(sys.argv[1], "rb") as file:
            key = file.read()
        if not key:
            raise ValueError("empty signing key")
        output = transform(raw, key)
    except Exception:
        print("clef_warning_failed", file=sys.stderr)
        output = raw
    sys.stdout.buffer.write(output)


if __name__ == "__main__":
    main()
