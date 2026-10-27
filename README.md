# clef-mail-guard

An installable Cloudflare Email Worker and Xserver/maildrop filter that classify incoming mail with Workers AI. The Worker forwards the original message to a verified relay, adding a signed `X-Clef-Result` header for scores at least 0.7. The mailbox filter verifies that header, adds a Japanese warning and defangs links in editable mail for scores from 0.7 to below 0.9, and routes scores at least 0.9 to `.Junk`. Warned HTML is rebuilt from escaped readable text, so its original formatting and remote images are removed.

```
Cloudflare Email Routing -> Email Worker -> verified relay -> Xserver maildrop -> Inbox or .Junk
                              clef-flash          HMAC verification
```

Requirements: Cloudflare Email Routing, Workers AI and a verified relay destination; an Xserver mailbox using maildrop; Bun for build/tests; and Python 3 for the mailbox filter. Use a maintained Python release for new installations. The filter uses Python 3.6.8-compatible standard-library syntax for an existing runtime; this does not mean Python 3.6 remains vendor supported or security maintained.

## Quick start

1. Read [setup](docs/setup.md) before changing routing. Replace **both example addresses** in `wrangler.jsonc` with your own recipient and verified relay. Configure a separate relay that cannot route back through the public MX.
2. Configure the `AI` binding and a shared `CLEF_SIGNING_KEY` secret as described in [setup](docs/setup.md). Adapt the paths in `xserver/contact.mailfilter.sample` and merge its scoped stanza into the existing mailbox filter.
3. Run `bun install --frozen-lockfile`, `bun run test`, and `bun run check` locally. These are mocked unit tests and a dry run, not a delivery or detection validation.
4. Review and back up the live routing and mailbox state before any separately approved deployment or DNS/MX cutover. This repository does not automate either action.

See [architecture and protocol](docs/architecture.md) for the signed header and failure behavior, and [security and limitations](docs/security.md) for operational risks. [llms.txt](llms.txt) is a compact documentation index. [The Japanese article draft](docs/article.ja.md) describes the motivation and integration experience; it is not a deployment guide.

The code is [MIT licensed](LICENSE). External Cloudflare services and the clef-flash model have separate terms; the code license does not license them. Direct package licensing is noted in [THIRD_PARTY.md](THIRD_PARTY.md). Classification and delivery are not guaranteed.
