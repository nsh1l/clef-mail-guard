# Setup

## Requirements and example configuration

This is a manual integration, not a hosted mail service. You need Cloudflare Email Routing and Workers AI, a **verified** forwarding destination, and an Xserver mailbox using maildrop. See the [Email handler API](https://developers.cloudflare.com/email-service/api/route-emails/email-handler/) and [clef-flash model](https://developers.cloudflare.com/workers-ai/models/clef-flash/). Use Bun for JavaScript tooling and a maintained Python 3 for new mailbox installations.

Replace **both** example addresses in `wrangler.jsonc`:

- `MAIL_RECIPIENT`: the existing public address, for example `contact@example.com`.
- `MAIL_RELAY`: a separate, Cloudflare-verified destination, for example `clef-relay@mx.example.com`.
- `AI`: the Workers AI binding; keep this name.
- `CLEF_SIGNING_KEY`: a secret shared with the mailbox verifier, never a plain configuration variable.

Both addresses must be plain ASCII dot-atom mailboxes with DNS-style domains; display names, quoted local parts, whitespace and CR/LF are not supported. Equal recipient and relay values are rejected case-insensitively. There is no production default. Keep `workers_dev: false`: this Worker has no HTTP handler. Supply your account through `CLOUDFLARE_ACCOUNT_ID` in the authorized shell or CI environment, not an embedded account ID. Obtain Cloudflare authentication separately; do not paste tokens into source or examples.

## Preserve the old address without making a loop

The intended path is:

```text
sender -> public domain's Cloudflare MX -> Email Worker
       -> separate relay subdomain's Xserver MX
       -> Xserver internal delivery to the existing mailbox
       -> mailbox-scoped verifier -> Inbox or .Junk
```

Create the relay subdomain and mailbox on the existing provider, preserve their MX pointing to that provider, and verify the destination in Cloudflare Email Routing. Set up the provider's internal delivery from the relay to the final mailbox. Check that this is genuinely internal: forwarding back through the public address's Cloudflare MX would loop. Different address strings alone do not guarantee different delivery paths. Keep the old public MX unchanged while staging and testing the relay.

The public address and website hosting do not need to change. The domain's authoritative DNS must be compatible with Cloudflare Email Routing. If a nameserver migration is needed, inventory and preserve the full existing zone before a separately approved migration. Do not blindly replace MX, SPF, DKIM or DMARC records; preserve existing sending providers and maintain a single SPF record.

## Install and check locally

```sh
git clone https://github.com/nsh1l/clef-mail-guard.git
cd clef-mail-guard
bun install --frozen-lockfile
bun run test
bun run check
```

The clone URL becomes usable when the repository is published or when you have private access. The tests use synthetic mail and mocked AI; the Wrangler check is a local dry run. Neither proves live delivery or classifier accuracy. No cloud credentials are needed for these checks.

## Create a shared key without printing it

Run this on a trusted machine, outside the checkout. It fails rather than replacing an existing key. Do not add a trailing newline or put the key in command arguments.

```sh
umask 077
install -d -m 700 "$HOME/.local/share/clef"
python3 - <<'PY'
from pathlib import Path
import secrets

path = Path.home() / ".local/share/clef/signing-key"
with path.open("x") as file:
    file.write(secrets.token_hex(32))
path.chmod(0o600)
PY
```

The Worker uses the secret's UTF-8 bytes; Python reads the entire key file. Transfer **the same file bytes** securely to the mailbox server and restrict access to its owner (file mode `0600`, private parent directory). The remote example path is `/home/ACCOUNT/.local/share/clef/signing-key`; replace `ACCOUNT` with the actual server account. Do not generate a different remote key. Never commit the file, paste it into logs or public issues, or copy it into fixtures.

## Stage the Worker and mailbox filter

These commands **change Cloudflare state**. Run them only as part of an explicitly authorized deployment, after replacing example addresses and selecting the correct account. Do not enable the production Email Routing rule yet.

```sh
bunx --bun wrangler deploy
bunx --bun wrangler secret put CLEF_SIGNING_KEY < "$HOME/.local/share/clef/signing-key"
```

`wrangler deploy` uploads the Worker; it does not configure the domain's incoming mail route. Verify the deployed Worker name and both address variables in the selected account before continuing.

On the mailbox server, install `xserver/warn.py` as an account-controlled executable, for example `/home/ACCOUNT/bin/clef-warning.py`. Adapt both paths in [the sample stanza](../xserver/contact.mailfilter.sample). Back up the **existing** mailbox `.mailfilter`; merge only the `xfilter` and `if` stanza after its `../../.header` include and before `.alias` or spam includes. Do not paste the sample as a complete default filter or overwrite generated rules. The Xserver panel may regenerate it, so inspect it after panel changes. Existing server filters still apply.

Create and verify a valid `.Junk` Maildir for the target mailbox before enabling the rule. Maildir structure, ownership and permissions must match the existing mailbox. In maildrop, `to "./.Junk"` finishes processing: it prevents later rules, including external forwarding. Keep scripts and key files outside any public web directory.

## Enable routing only after a cutover review

1. Back up current authoritative DNS, Email Routing rules and mailbox filters. Plan rollback before changing them.
2. In Cloudflare Email Routing, configure an exact-address rule for `MAIL_RECIPIENT` with the action **Send to a Worker**, selecting the staged `clef-mail-guard` Worker. Verify the relay destination is approved. Do not add an unintended catch-all.
3. When ready, apply the DNS/MX records currently required by Cloudflare for the public receiving domain. Preserve the relay's separate provider MX and existing sending-provider authentication. Nameserver and MX changes need explicit deployment approval; use current dashboard requirements rather than copying someone else's DNS records.
4. Send uniquely marked synthetic mail from a real, separate account you control. Confirm Worker invocation **and** final mailbox arrival. Check for loops, duplicates and latency. A mailbox arrival alone may have used cached old MX.
5. Separately verify warning display, defanged links and text-only HTML, `.Junk` routing, attachment integrity and downstream forwarding with controlled signed-score fixtures around `0.7` and `0.9`. Mail clients may autolink unrecognized text, so check the intended client. A manually signed score tests the mail path, not AI detection accuracy. Never use a production key in committed fixtures.
6. Inspect `.Junk` regularly for false positives. No message is deleted by this project's Clef policy, but other provider filters still have their own behavior.

There is no automatic deployment workflow. [Security and rollback](security.md) explains failure behavior and restoring the old path. Disabling a Worker route while leaving Cloudflare MX in place is **not** a rollback to Xserver.
