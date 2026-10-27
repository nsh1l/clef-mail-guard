# Security and limitations

## Trust boundaries and privacy

The envelope recipient is checked against one configured mailbox. From, Subject, Message-ID, MIME content, and any incoming `X-Clef-*` headers are untrusted. The mailbox filter trusts only a verified HMAC result for its actions and removes forged `X-Clef-Verified-Action` headers. The warning is a visual cue, not proof that other mail is safe. Scores are model outputs, not calibrated guarantees of accuracy.

Only editable bodies with a verified score from 0.7 to below 0.9 receive link defanging. Warned HTML is reduced to readable text and escaped into a fixed wrapper; original active markup, attributes, remote resources, and formatting are removed. Common visible `http`, `https`, `ftp`, `www`, `mailto`, and email address forms are broken without opening URLs or checking their reputation. A mail client may still autolink other spellings or apply its own rendering rules. This is not a replacement for safe client rendering, antivirus, phishing verdicts, or attachment scanning. Unsigned, invalid, lower-score, AI-failure, and Junk-bound messages are not sanitized by this filter.

The Worker minimizes its own logs to event, choice, probabilities, confidence, and failure names. Raw content and personal information still pass through Cloudflare Email Routing and selected mail fields go to Workers AI. Review the external service and [model terms](https://developers.cloudflare.com/workers-ai/models/clef-flash/) before use. Avoid enabling extra mail logging without a separate privacy review.

The HMAC binds score, timestamp, and Message-ID, not message body. It does not authenticate the original sender, prevent replay within the 7-day window, or provide confidentiality; there is no replay database. Up to 8 candidate result headers are checked. Keep the shared key out of the repository and rotate it with a coordinated Worker and mailbox update. Warning body edits can break DKIM signatures. Signed and encrypted MIME, attachments, and attached messages are left unedited; Junk routing can still occur at 0.9 or above. Malformed MIME and failed charset decoding pass through with a skip or failure log; unsupported content types remain untouched. HTML-only mail is not converted to text for AI classification. Oversize or unparsable mail is forwarded without a warning.

## Operations and rollback

Only configured addresses are accepted. Bad configuration throws; AI failures pass through; forwarding failures propagate. Cloudflare, relay, Xserver, and existing mailbox filters can still delay, filter, or fail delivery. The example `.Junk` destination must be an existing valid Maildir. The maildrop `to` rule stops later rules, including external forwarding.

Back up live mail rules and routing settings before an approved cutover. Merge a scoped stanza into the existing `.mailfilter` after `../../.header` and before `.alias` or spam includes. Xserver panel edits can regenerate it. To roll back the mailbox change, remove the stanza or restore the backed-up filter, then verify routing and delivery. Disabling the Worker route while Cloudflare MX remains in place does not restore the old provider; MX rollback requires its own approved plan and backups. Preserve old provider SPF/DKIM during migration.

Unit tests use synthetic mail and mocked Cloudflare calls. They do not validate live MTA delivery or detection accuracy. For security reports, use the proposed repository's GitHub private advisory mechanism **if enabled**; otherwise request a private reporting channel from the maintainer. Do not include real mail or secrets in a public issue.
