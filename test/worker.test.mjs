import { strict as assert } from "node:assert";
import { test } from "bun:test";
import worker from "../src/index.mjs";

const KEY = "test-only-shared-key";
const RECIPIENT = "contact@example.com";
const RELAY = "clef-relay@mx.example.com";
const CONFIG = { MAIL_RECIPIENT: RECIPIENT, MAIL_RELAY: RELAY };

function makeMessage(to = RECIPIENT) {
  const raw = [
    'From: "ACME Notice" <sales@Promo.Example.>',
    `To: ${RECIPIENT}`,
    "Subject: Test inquiry",
    "Message-ID: <worker-test@example.invalid>",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Could you send details about your product range?",
  ].join("\r\n");
  const bytes = new TextEncoder().encode(raw);
  const forwards = [];
  let rejected = null;
  return {
    message: {
      to,
      rawSize: bytes.byteLength,
      raw: new ReadableStream({
        start(controller) { controller.enqueue(bytes); controller.close(); },
      }),
      async forward(address, headers) { forwards.push({ address, headers }); },
      setReject(reason) { rejected = reason; },
    },
    forwards,
    get rejected() { return rejected; },
  };
}

function answer(choice, spam) {
  return { answers: { spam: { choice, probabilities: { spam, legitimate: 1 - spam }, confidence: spam } } };
}

async function run(fixture, env) {
  await worker.email(fixture.message, { ...CONFIG, ...env });
  assert.equal(fixture.forwards.length, 1);
  assert.equal(fixture.forwards[0].address, RELAY);
  assert.equal(fixture.rejected, null);
  return fixture.forwards[0].headers;
}

test("legitimate classification includes sender features and forwards once without warning", async () => {
  const fixture = makeMessage();
  const headers = await run(fixture, { CLEF_SIGNING_KEY: KEY, AI: {
    async run(model, input) {
      assert.equal(model, "@cf/cloudflare/clef-flash");
      assert.equal(input.model, "clef-flash");
      assert.equal(input.state.sender_domain, "promo.example");
      assert.equal(input.state.sender_name, "ACME Notice");
      assert.match(input.state.body, /product range/);
      return answer("legitimate", 0.1);
    },
  } });
  assert.equal(headers, undefined);
});

test("high confidence spam carries a verifiable signed result", async () => {
  const fixture = makeMessage();
  const headers = await run(fixture, { CLEF_SIGNING_KEY: KEY, AI: { async run() { return answer("spam", 0.9); } } });
  assert.ok(headers instanceof Headers);
  assert.deepEqual([...headers.keys()], ["x-clef-result"]);
  const [version, encoded, mac] = headers.get("X-Clef-Result").split(".");
  assert.equal(version, "v1");
  const payload = JSON.parse(Buffer.from(encoded, "base64url").toString());
  assert.deepEqual(Object.keys(payload), ["version", "spam", "timestamp", "message_id"]);
  assert.equal(payload.version, 1);
  assert.equal(payload.spam, 0.9);
  assert.equal(payload.message_id, "<worker-test@example.invalid>");
  assert.ok(Math.abs(Date.now() / 1000 - payload.timestamp) < 5);
  const secret = await crypto.subtle.importKey("raw", new TextEncoder().encode(KEY), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  assert.equal(await crypto.subtle.verify("HMAC", secret, Buffer.from(mac, "base64url"), new TextEncoder().encode(`v1.${encoded}`)), true);
});

test("score boundaries use probability regardless of choice", async () => {
  for (const score of [0.6999, 0.7, 0.8999, 0.9, 1]) {
    const headers = await run(makeMessage(), { CLEF_SIGNING_KEY: KEY, AI: { async run() { return answer("legitimate", score); } } });
    assert.equal(headers?.has("X-Clef-Result") ?? false, score >= 0.7);
  }
});

test("missing key forwards without signed result", async () => {
  assert.equal(await run(makeMessage(), { AI: { async run() { return answer("spam", 0.9); } } }), undefined);
});

test("AI failure forwards once without warning", async () => {
  assert.equal(await run(makeMessage(), { CLEF_SIGNING_KEY: KEY, AI: { async run() { throw new Error("outage"); } } }), undefined);
});

test("AI timeout forwards once without warning", async () => {
  const fixture = makeMessage();
  const started = Date.now();
  assert.equal(await run(fixture, { CLEF_SIGNING_KEY: KEY, AI: { run() { return new Promise(() => {}); } } }), undefined);
  assert.ok(Date.now() - started >= 14_000);
}, 20_000);

test("recipient outside configured mailbox is rejected", async () => {
  const fixture = makeMessage("unrelated@example.invalid");
  await worker.email(fixture.message, { ...CONFIG, AI: { run() { throw new Error("must not run"); } } });
  assert.equal(fixture.rejected, "Unsupported recipient");
  assert.equal(fixture.forwards.length, 0);
});

test("recipient comparison ignores case and surrounding space", async () => {
  const fixture = makeMessage("  CONTACT@EXAMPLE.COM  ");
  await run(fixture, { AI: { async run() { return answer("legitimate", 0.1); } } });
});

test("missing and malformed mail configuration throws without forwarding or rejecting", async () => {
  const invalid = [
    {}, { ...CONFIG, MAIL_RECIPIENT: undefined }, { ...CONFIG, MAIL_RELAY: undefined },
    { ...CONFIG, MAIL_RECIPIENT: " contact@example.com" },
    { ...CONFIG, MAIL_RECIPIENT: "contact@example.com\r\nBcc: x@example.com" },
    { ...CONFIG, MAIL_RELAY: "clef-relay@@mx.example.com" },
    { ...CONFIG, MAIL_RELAY: "clef-relay@mx.example.com\n" },
    { ...CONFIG, MAIL_RELAY: "CONTACT@example.COM" },
  ];
  for (const env of invalid) {
    const fixture = makeMessage();
    await assert.rejects(worker.email(fixture.message, env), /Invalid MAIL_RECIPIENT or MAIL_RELAY/);
    assert.equal(fixture.forwards.length, 0);
    assert.equal(fixture.rejected, null);
  }
});

test("relay errors propagate", async () => {
  const fixture = makeMessage();
  fixture.message.forward = async () => { throw new Error("relay failed"); };
  await assert.rejects(worker.email(fixture.message, {
    ...CONFIG, AI: { async run() { return answer("legitimate", 0.1); } },
  }), /relay failed/);
  assert.equal(fixture.rejected, null);
});
