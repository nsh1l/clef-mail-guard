import { strict as assert } from "node:assert";
import { createHash, createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";
import { test } from "bun:test";
import * as workerModule from "../src/index.mjs";

const worker = workerModule.default;
const KEY = "test-only-shared-key";
const RECIPIENT = workerModule.RECIPIENT || "contact@example.com";
const RELAY = workerModule.RELAY || "clef-relay@mx.example.com";
const PYTHON = `
import base64,json,sys
from email import policy
from email.parser import BytesParser
import warn
value=json.load(sys.stdin)
raw=base64.b64decode(value['raw'])
output=warn.transform(raw,b'test-only-shared-key',value['now'])
message=BytesParser(policy=policy.SMTP).parsebytes(output)
plain=message.get_body(preferencelist=('plain',))
print(json.dumps({'junk':message.get('X-Clef-Verified-Action')=='junk',
                  'warning':plain is not None and warn.BANNER in plain.get_content(),
                  'unchanged':raw==output}))
`;

function fixture(body, newline = "\r\n", extra = [], contentType = "text/plain; charset=utf-8", separator = newline + newline) {
  const head = ["From: sender@example.invalid", `To: ${RECIPIENT}`, "Subject: Synthetic transport test",
    `Content-Type: ${contentType}`, ...extra].join(newline) + separator;
  const raw = Buffer.concat([Buffer.from(head), Buffer.from(body)]);
  const forwards = [];
  return {
    raw, forwards, newline,
    message: {
      to: RECIPIENT, rawSize: raw.byteLength,
      raw: new ReadableStream({ start(controller) { controller.enqueue(raw); controller.close(); } }),
      async forward(address, headers) { forwards.push({ address, headers }); },
      setReject() { throw new Error("Synthetic recipient must be accepted"); },
    },
  };
}

async function classify(value, spam = 0.95) {
  await worker.email(value.message, {
    MAIL_RECIPIENT: RECIPIENT, MAIL_RELAY: RELAY, CLEF_SIGNING_KEY: KEY,
    AI: { async run() { return { answers: { spam: { choice: "spam", probabilities: { spam, legitimate: 1 - spam } } } }; } },
  });
  assert.equal(value.forwards.length, 1);
  assert.equal(value.forwards[0].address, RELAY);
  return value.forwards[0].headers?.get("X-Clef-Result");
}

function mailbox(raw, now) {
  const run = Bun.spawnSync({ cmd: ["python3", "-B", "-c", PYTHON],
    cwd: fileURLToPath(new URL("../xserver/", import.meta.url)),
    stdin: Buffer.from(JSON.stringify({ raw: raw.toString("base64"), now })), stdout: "pipe", stderr: "pipe" });
  assert.equal(run.exitCode, 0, run.stderr.toString());
  return JSON.parse(run.stdout.toString());
}

function delivered(value, token, addedId = true) {
  return Buffer.concat([Buffer.from(`X-Clef-Result: ${token}${value.newline}` +
    (addedId ? `Message-ID: <transport-added@example.invalid>${value.newline}` : "")), value.raw]);
}

test("missing Message-ID uses domain-separated v2 HMAC and a wire-body digest", async () => {
  const body = Buffer.from("First\r\nSecond\rThird\n\x00\xff", "latin1");
  const value = fixture(body, "\r\n", [], "application/octet-stream");
  const token = await classify(value);
  const [prefix, encoded, signature] = token.split(".");
  const payload = JSON.parse(Buffer.from(encoded, "base64url"));
  assert.equal(prefix, "v2");
  assert.deepEqual(Object.keys(payload), ["version", "spam", "timestamp", "message_id", "body_sha256"]);
  assert.equal(payload.version, 2);
  assert.equal(payload.message_id, "");
  assert.equal(payload.body_sha256, createHash("sha256").update(Buffer.from("First\nSecond\nThird\n\x00\xff", "latin1")).digest("hex"));
  assert.equal(signature, createHmac("sha256", KEY).update(`v2.${encoded}`).digest("base64url"));
  assert.equal(mailbox(delivered(value, token), payload.timestamp).junk, true);
});

test("real Worker tokens survive a transport-added ID and CRLF/LF conversion at both thresholds", async () => {
  for (const spam of [0.7, 0.8999, 0.9, 1]) {
    const value = fixture("Synthetic body https://example.invalid/\r\n");
    const token = await classify(value, spam);
    const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url"));
    for (const addId of [true, false]) {
      const wire = delivered(value, token, addId);
      for (const raw of [wire, Buffer.from(wire.toString().replace(/\r\n/g, "\n"))]) {
        const result = mailbox(raw, payload.timestamp);
        assert.equal(result.junk, spam >= 0.9);
        assert.equal(result.warning, spam < 0.9);
        assert.equal(result.unchanged, false);
      }
    }
  }
});

test("v2 interop rejects another body, changed attachment bytes and a different key", async () => {
  const value = fixture("Original body\r\n");
  const token = await classify(value);
  const [prefix, encoded] = token.split(".");
  const payload = JSON.parse(Buffer.from(encoded, "base64url"));
  const altered = delivered(value, token).toString().replace("Original body", "Replaced body");
  assert.deepEqual(mailbox(Buffer.from(altered), payload.timestamp), { junk: false, warning: false, unchanged: true });
  const forged = `${prefix}.${encoded}.${createHmac("sha256", "wrong-test-key").update(`${prefix}.${encoded}`).digest("base64url")}`;
  assert.deepEqual(mailbox(delivered(value, forged), payload.timestamp), { junk: false, warning: false, unchanged: true });
  const binary = fixture(Buffer.from([0, 255, 16, 1]), "\r\n", [], "application/octet-stream");
  const binaryToken = await classify(binary);
  const binaryPayload = JSON.parse(Buffer.from(binaryToken.split(".")[1], "base64url"));
  const wire = delivered(binary, binaryToken);
  wire[wire.length - 1] ^= 1;
  assert.equal(mailbox(wire, binaryPayload.timestamp).unchanged, true);
});

test("missing-ID low-score mail remains unsigned and present-ID mail retains v1 binding", async () => {
  assert.equal(await classify(fixture("Synthetic body"), 0.6999), undefined);
  const value = fixture("Synthetic body", "\r\n", ["Message-ID: <original@example.invalid>"]);
  const token = await classify(value);
  assert.ok(token.startsWith("v1."));
  const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url"));
  const wire = delivered(value, token, false);
  assert.equal(mailbox(wire, payload.timestamp).junk, true);
  const changed = Buffer.from(wire.toString().replace("<original@example.invalid>", "<changed@example.invalid>"));
  assert.equal(mailbox(changed, payload.timestamp).unchanged, true);
});

test("v2 fallback requires an absent ID header, not empty or duplicate ID headers", async () => {
  for (const extra of [["Message-ID: "], ["Message-ID:", " folded"],
    ["Message-ID:", "Message-ID:"], ["Message-ID: not-an-id"]]) {
    const token = await classify(fixture("Synthetic body", "\r\n", extra));
    assert.ok(!token?.startsWith("v2."));
  }
});

test("v2 does not sign missing or mixed header/body separators", async () => {
  for (const separator of ["\r\n", "\n\r\n", "\r\n\n", "\r\r\n", "\n\r"]) {
    const value = fixture("not a header\n\nLater body", "\r\n", [], "text/plain", separator);
    assert.equal(await classify(value), undefined);
  }
  const mixed = fixture("Synthetic body", "\r\n", ["X-Test: one\nX-Other: two"]);
  assert.equal(await classify(mixed), undefined);
});

test("v2 canonicalization agrees across supported header separators and empty bodies", async () => {
  for (const newline of ["\r\n", "\n", "\r"]) {
    for (const body of ["", `First${newline}Second${newline}`]) {
      const value = fixture(body, newline);
      const token = await classify(value);
      const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url"));
      const canonical = body.replace(/\r\n|\r/g, "\n");
      assert.equal(payload.body_sha256, createHash("sha256").update(canonical).digest("hex"));
      assert.equal(mailbox(delivered(value, token), payload.timestamp).junk, true);
    }
  }
});
