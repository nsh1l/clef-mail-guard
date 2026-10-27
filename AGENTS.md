# Repository guide

Scope: this repository is the OSS extraction. Keep fixtures synthetic and use example domains; never add secrets, real mail, raw logs, production identifiers, or DNS backups. Do not deploy, publish, change DNS/mailbox settings, or create/push a repository without explicit approval.

- `src/index.mjs`: Email Worker, configuration validation, AI call, signed result.
- `xserver/warn.py`: Python standard-library maildrop verifier and warning/Junk action.
- `xserver/contact.mailfilter.sample`: scoped sample stanza; never overwrite a live filter.
- `test/worker.test.mjs`, `xserver/test_warn.py`, `test/docs.test.mjs`: synthetic tests.
- `README.md`, `docs/setup.md`, `docs/architecture.md`, `docs/security.md`: canonical user documentation; `llms.txt` indexes it.
- `wrangler.jsonc`: example configuration; both addresses require replacement.

Run `bun install --frozen-lockfile`, `bun run test`, and `bun run check`. The check is a Wrangler dry run and does not require cloud credentials. Keep Python code compatible with the existing 3.6.8 runtime while recommending a maintained runtime for new installations.
