import { strict as assert } from "node:assert";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "bun:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const docs = ["README.md", "docs/setup.md", "docs/architecture.md", "docs/security.md", "docs/article.ja.md", "AGENTS.md", "THIRD_PARTY.md"];

test("documentation index and local Markdown links resolve", () => {
  const index = readFileSync(join(root, "llms.txt"), "utf8");
  for (const path of docs) {
    assert.ok(existsSync(join(root, path)), `${path} is required`);
    assert.ok(index.includes(`](${path})`), `${path} must be indexed`);
  }
  for (const path of ["llms.txt", ...docs]) {
    const content = readFileSync(join(root, path), "utf8");
    for (const [, target] of content.matchAll(/\]\(([^)]+)\)/g)) {
      if (/^[a-z]+:\/\//i.test(target)) continue;
      const local = target.split("#", 1)[0];
      assert.ok(local && existsSync(resolve(root, dirname(path), local)), `${path}: ${target}`);
    }
  }
});

test("exported configuration and mailbox sample remain generic", () => {
  const config = readFileSync(join(root, "wrangler.jsonc"), "utf8");
  const worker = readFileSync(join(root, "src/index.mjs"), "utf8");
  const sample = readFileSync(join(root, "xserver/contact.mailfilter.sample"), "utf8");
  assert.match(config, /"MAIL_RECIPIENT": "contact@example\.com"/);
  assert.match(config, /"MAIL_RELAY": "clef-relay@mx\.example\.com"/);
  assert.doesNotMatch(worker, /[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/);
  assert.match(sample, /\/home\/ACCOUNT\/bin\/clef-warning\.py/);
  assert.match(sample, /\/home\/ACCOUNT\/\.local\/share\/clef\/signing-key/);
  assert.doesNotMatch(sample, /\/home\/(?!ACCOUNT\/)[A-Za-z0-9_-]+\//);
});
