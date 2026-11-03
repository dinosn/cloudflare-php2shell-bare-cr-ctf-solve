# Cloudflare PHP CTF bare-CR multipart bypass

Private HackerOne submission package for a distinct Cloudflare PHP CTF WAF
bypass demonstrated on 2026-11-03.

The new carrier exploits a parser differential in multipart part headers. PHP
8.5.11 accepts a bare carriage return as whitespace after the
`Content-Disposition:` colon and subsequently concatenates colonless physical
lines. That reconstructs the protected upload-progress field name at PHP while
the contiguous name is absent from the wire representation. The body starts at
its native offset and uses no oversized inert prefix.

## Package contents

- `REPORT.md` — HackerOne-ready technical report.
- `VERIFICATION.md` — sanitized live verification receipt.
- `SUBMISSION-CHECKLIST.md` — final submission and privacy checks.
- `poc/` — readable, pinned controller and carrier implementation.
- `evidence-public/` — sanitized public discriminator and exact-image receipts.
- `evidence-private/` — sanitized live receipts plus locally retained private
  material. The live flag and raw responses are intentionally ignored by Git.

## Reproduction

From this directory, render and validate the request sequence without network
traffic:

```bash
python3 -B poc/bare_cr_accepted_schedule_live.py \
  --dry-run --out-dir ./dry-run --timeout 90
```

The live mode is restricted to the Cloudflare challenge target and requires an
explicit scope acknowledgement:

```bash
python3 -B poc/bare_cr_accepted_schedule_live.py \
  --authorized-live --out-dir ./live-run --timeout 90
```

Run at most one bounded live wave, stop on rate limiting or platform
unavailability, and submit the returned flag immediately because the sandbox
flag rotates on reset.

## Privacy

Do not commit or publicly share `evidence-private/flag.txt` or any
`evidence-private/*.raw` file. The report and sanitized receipts identify the
flag only by byte length and SHA-256.

