# PHP CTF: bare-CR multipart header reconstruction bypasses WAF inspection and enables verified sandbox exploitation

## Executive Summary

An unauthenticated, authorized CTF participant can send a multipart part whose `Content-Disposition` value begins with a bare carriage return and continues across colonless physical lines. The Cloudflare-protected challenge endpoint admitted this representation, while PHP 8.5.11 reconstructed it as `form-data; name="PHP_SESSION_UPLOAD_PROGRESS"`. Applying that representation to the complete challenge exploit allowed the request sequence to reach PHP, execute the intended sandbox chain, read `/flag`, and obtain an accepted verifier result.

The assessed target was `https://php-rce.cloudflare.app/php/index.php`, backed by the challenge's stock PHP 8.5.11, Apache, and `mod_php` configuration. The narrow parser failure is an interpretation difference at the WAF-to-origin boundary. The strongest demonstrated consequence is verifier-confirmed exploitation of this CTF sandbox. I do not claim a Cloudflare product version, a broader affected-version range, customer deployment prevalence, or a fixed release; Cloudflare's WAF implementation and release history were not available for source inspection.

This is not the previously reported inspection-window method that used an oversized inert multipart preamble to move protected fields beyond an inspected prefix. The bare-CR method uses zero prefix bytes and leaves the native multipart body at offset 0. Its public discriminator was at most 323 bytes. Distinctness rests on the MIME-header parsing differential, not on a sandbox reset, a new flag, different ASLR bases, or a changed PHP exploitation schedule. This report also makes no claim about the contents or priority of undisclosed reports.

I reviewed the PHP 8.5.11 multipart parser, the supplied carrier and full-chain controller, the exact-image parser and full-chain records, the six-request public discriminator, and the preserved winning and verifier responses. The live evidence records one response-local flag of 36 bytes with SHA-256 `ab2a121586e6c4578177de1abf56c012a7657c67ef415f33b7bb57a3e630bc8a`; the flag value is intentionally omitted from this report.

## Background

### Tested topology and prerequisites

The actor in this report is Mallory, an authorized participant in the public PHP CTF. Mallory needs only the ability to send `multipart/form-data` POST requests to the public challenge endpoint; no application account or stolen credential is involved.

The tested path was:

1. Cloudflare receives a multipart POST for `/php/index.php`.
2. The request is either rejected at the managed edge or forwarded to the challenge sandbox.
3. PHP 8.5.11 parses the part headers in `main/rfc1867.c` and recognizes the session upload-progress field.
4. The challenge-specific heap and code-address acquisition stages derive a strict same-run address pair.
5. The terminal stages use that pair to open `/flag`, read it, and write a per-run marker followed by the flag into the HTTP response.
6. The response's `X-Attempt-ID` and the returned flag are submitted once to `/api/verify`.

The required challenge configuration includes PHP session upload progress and the intentionally vulnerable PHP2Shell target. The report does not infer that equivalent settings are common outside the challenge.

### Expected security behavior

The edge and origin should agree on the security-relevant meaning of a multipart header. A representation that PHP reconstructs as the protected upload-progress field should receive the same WAF decision as the canonical representation. On this target, the canonical exact field was rejected with HTTP 403. A one-byte near-name control reached the origin, showing the rule distinguished the protected name rather than blocking all multipart uploads.

## Vulnerability Details

### The bare-CR carrier

In escaped notation, the decisive first physical line begins:

```text
Content-Disposition:\rform-data; name="...
```

Here `\r` denotes one bare `0x0d` byte. It is not the `\r\n` line ending. The supplied carrier places the first byte of the protected field name on that line, then places each remaining byte on its own colonless line. A shortened escaped illustration is:

```text
Content-Disposition:\rform-data; name="P\r\n
H\r\n
P\r\n
_\r\n
...\r\n
S"\r\n
```

The complete implementation is in `poc/bare_cr_carrier.py`. It rewrites the original canonical header; it does not add a prefix or relocate the native body.

### Why PHP 8.5.11 reconstructs the protected field

Two behaviors in PHP 8.5.11's [`main/rfc1867.c`](https://github.com/php/php-src/blob/php-8.5.11/main/rfc1867.c) are decisive.

First, [`next_line`](https://github.com/php/php-src/blob/php-8.5.11/main/rfc1867.c#L275-L305) searches for line feed and strips a carriage return only when that carriage return is immediately before the line feed:

```c
char* ptr = memchr(self->buf_begin, '\n', self->bytes_in_buffer);
if ((ptr - line) > 0 && *(ptr-1) == '\r') {
```

The carriage return immediately after `Content-Disposition:` therefore remains inside the returned line.

Second, [`multipart_buffer_headers`](https://github.com/php/php-src/blob/php-8.5.11/main/rfc1867.c#L348-L404) skips whitespace after the colon and appends colonless lines to the preceding value:

```c
do { value++; } while (isspace((unsigned char)*value));
/* ... */
smart_string_appends(&buf_value, line);
```

Because carriage return satisfies `isspace`, PHP skips the embedded bare CR and starts the value at `form-data`. It then concatenates the single-character continuation lines. The logical value seen by PHP is consequently the canonical form-data disposition with the exact protected field name, even though the raw header does not contain that name contiguously.

This source review establishes PHP's side of the differential. The WAF side is inferred from black-box positive and negative controls; no claim is made about Cloudflare's internal parser implementation.

### Compact public discriminator

The bounded public test sent six requests at a minimum two-second cadence and performed no cookie, OOM, pointer, command, flag, or verifier operation. All bodies used zero oversized-prefix bytes.

| Case | Semantic change | Body | SHA-256 | Live result |
|---|---|---:|---|---|
| `C3` | Canonical exact protected name | 271 bytes | `809088aca8460d2d2cdbc063f0e01350f59b8b6de21a2ebdfb9e67a1080c4e33` | Managed HTTP 403 |
| `C4` | Canonical one-byte near-name | 271 bytes | `64b8cdd275daff4392a05252076afbeb7d327435f1883b612bae9cf40f528afa` | Origin HTTP 200 with garbled-header warning |
| `CHAR` | Exact name split over colonless lines, without bare CR | 323 bytes | `4e963abf30b14d0994d41def92065acee6a423a4d308eb26fe110bc29266f8ec` | Managed HTTP 403 |
| `CR4` | Bare-CR one-byte near-name | 323 bytes | `bacc0ea9446fda5056fb1ee590d1afa1e3448878fb5a6a7eed6a51da9f70c1be` | Origin HTTP 200 with garbled-header warning |
| `CR3` | Bare-CR exact protected name | 323 bytes | `e33592009fe8c1769949f5af0619cefc97104200be8a615ab7ba4f5c8c61d36a` | Origin HTTP 200 twice with garbled-header warning |

The exact-image parser control independently showed that `CR3` produced the `PHP_SESSION_UPLOAD_PROGRESS` POST key, while `CR4`, which differs by one field-name byte, produced `PHP_SESSION_UPLOAD_PROGRESX`. `CHAR` produced the exact protected key without a bare CR, but the public WAF blocked it. Together these controls isolate the bare CR as the admission-changing byte and rule out an inspection-window explanation. The preserved records are `evidence-public/public-discriminator-receipt.json` and `evidence-public/exact-image-parser-receipt.json`.

### From parser differential to accepted exploitation

The carrier was applied in two ways:

- Heap and code-address acquisition rewrote the one upload-progress disposition. Each rewrite added 52 bytes, removed the contiguous protected name, and kept the native body at offset 0.
- The terminal `S` and `D` bodies rewrote all 47 `Content-Disposition` headers from `Content-Disposition: form-data;` to the equal-length `Content-Disposition:\rform-data;` form. The body-size delta was zero.

An initial full-chain control left `S` and `D` without the progress-header rewrite; all 25 `S` requests received managed HTTP 403 responses. Applying the all-disposition bare-CR carrier changed the same stage to 25/25 origin OOM responses and allowed all 25 `D` requests to reach the origin. That intermediate run used an experimental `zif_system` terminal layout and did not pivot. Restoring the previously accepted derived-adjacent terminal while retaining the same all-disposition carrier produced verifier acceptance. This sequence separates WAF admission from PHP exploitation geometry: the carrier changed admission, while the terminal layout determined whether the admitted request completed the exploit.

The exact-image full-chain control separately captured its lab flag. Its records are `evidence-public/exact-image-fullchain-receipt.json` and `evidence-public/exact-image-carrier-log.json`.

### Related submission and root-cause distinction

The earlier submission was closed as a duplicate of `#4155237` because both compared methods used an oversized inert multipart preamble to place exploit-critical fields beyond an inspected prefix. This report is related because it targets the same protected CTF endpoint and ultimately invokes the same PHP exploit family. It differs at the WAF-bypass root cause:

- previous method: inspection-window displacement with a large inert prefix;
- this method: bare-CR and colonless-line reconstruction at native body offset 0.

The public 323-byte control set is sufficient to demonstrate that parser distinction without running the exploit. The accepted flag and unchanged terminal schedule demonstrate impact, not distinctness.

## Exploitability Analysis

### Demonstrated primitive and impact

The narrow primitive is edge admission of a multipart field that PHP 8.5.11 interprets as the exact upload-progress field that the canonical WAF control rejects. On the assessed challenge, that primitive was sufficient to carry every stage of the known PHP2Shell chain.

The accepted run directly measured a same-run pair:

- heap base `0x7f2b4d800000`, two agreeing observations;
- `libphp` base `0x7f2b4f200000`, two agreeing observations;
- separation `0x1a00000`.

The terminal ran `A80/B25/S25/D25`. All `A`, `B`, and `S` requests passed their expected OOM gates. Of 25 `D` responses, 22 were HTTP 200 and three were HTTP 500; 18 contained the expected 81,920-byte OOM, and four contained both the per-run marker and a parsed flag. `D8` was the verifier candidate.

The derived-adjacent terminal used the measured addresses to open `/flag`, read it, and write the response-local marker and flag to the client socket. This establishes direct control-flow execution sufficient to invoke the sandbox's `open`, `read`, and `write` paths, not merely WAF traversal or an HTTP 200 response.

### Controls and alternative explanations

The evidence rules out the main benign alternatives:

- `C3` versus `C4` shows the canonical rule distinguishes the exact protected name from a near-name.
- `CHAR` versus `CR3` keeps the character ladder and exact logical name while changing the bare-CR condition; only the bare-CR form reached PHP.
- `CR3` versus `CR4` differs by one field-name byte, and the exact PHP image reconstructed the corresponding exact and near-name POST keys.
- Every discriminator body was at most 323 bytes with zero prefix, excluding raw-window displacement.
- Exact-image parser and full-chain runs establish the origin semantics independently of the public WAF responses.
- The final verifier accepted the flag associated with the winning request's `X-Attempt-ID`; crashes, OOM messages, markers, and HTTP status codes alone were not treated as success.

Reliability remains workload- and allocator-dependent. The accepted live run used 195 exploit-stage requests plus one verifier call, substantial concurrency, repeated OOM conditions, and three terminal HTTP 500 responses. The result does not establish a reliable technique against other PHP builds, Apache configurations, WAF rule sets, or customer environments.

## Proof of Concept

### Supplied artifacts

The readable controller is `poc/bare_cr_accepted_schedule_live.py`; the compact carrier is `poc/bare_cr_carrier.py`; pinned supporting builders are under `poc/src/`. The controller hard-codes the authorized CTF endpoint, checks source and body hashes, requires a fresh private output directory, caps the verifier at one call, and refuses live execution unless `--authorized-live` is supplied.

The accepted wire bodies were:

| Phase | Requests | Body bytes | SHA-256 |
|---|---:|---:|---|
| Heap arm | 15 | 1,012,641 | `158a87f3d00d51c2cb5e0f64776a8208ea0fa493204bf5d14c5f01b7ef747b41` |
| Heap disclosure | 15 | 1,236,226 | `719a69106c422aa87b44bef4f71f53d300c7f6d033af443a410af4da72896f9c` |
| Code producer | 5 | 251,721 | `e88322cc1569b936256bbd2a96b9a166d289228ccd6d57151715c67c539d789b` |
| Code consumer | 5 | 92,440 | `b3b9380a6cb8b2d56d7860bc7b57e2747f9709e15926e20d091e5c9f806e35bf` |
| Terminal `A` | 80 | 1,012,641 | `158a87f3d00d51c2cb5e0f64776a8208ea0fa493204bf5d14c5f01b7ef747b41` |
| Terminal `B` | 25 | 952,812 | `e2b1de5ec558954a68d0f8f06b8a586b34f6ffe5e25bf19b2c2aa67062e41f40` |
| Terminal `S` | 25 | 7,205,832 | `751e25c10034ea6a0366af9d2b10dd41c1b6dab24c605b3852ca10b2c83959ed` |
| Terminal `D` | 25 | 6,138,311 | `d7ea90a4da90cbf4b2942f707276c22d463859734c72e70c9be76281633b7dbf` |

The complete accepted-run metadata is in `evidence-private/run-summary.json`, `heap-receipt.json`, `code-receipt.json`, `terminal-receipt.json`, and `carrier-log.json` under `evidence-private/`.

### Offline dry run

From the report directory, choose a fresh output path and run:

```sh
python3 -B poc/bare_cr_accepted_schedule_live.py \
  --dry-run \
  --timeout 90 \
  --out-dir evidence-local/dry-run-001
```

The portable dry run was observed to pass its source pins, generate the compact bodies, match the pinned wire hashes, and complete without contacting the target. A repeated run must use a new output path because the controller intentionally refuses to overwrite evidence.

### Authorized live reproduction

This command is specific to the public CTF target hard-coded in the controller. It is high-load and intentionally triggers OOM conditions. Run it only with explicit target authorization, only once per bounded attempt, and stop rather than retrying if the service returns HTTP 429 or 503:

```sh
python3 -B poc/bare_cr_accepted_schedule_live.py \
  --authorized-live \
  --timeout 90 \
  --out-dir evidence-live/run-001
```

The sequence is fixed: heap `A15/B15`, code-pointer `A5/B5`, terminal `A80/B25/S25` with one `D` submitted for each completed `S`, and at most one verifier call. The controller gates the terminal on strict address measurements and treats success only as a response-local marker plus a parsed flag plus a canonical `X-Attempt-ID` followed by `verified: true` from the verifier.

The PoC can consume substantial CPU and memory, force worker OOMs, and cause sandbox worker failures. It does not install persistence; its terminal reads `/flag` and writes the result to the response. Preserve any generated flag file as private material and do not publish it.

### Accepted live result

The winning `D8` response is preserved as `evidence-private/winning-D-008.raw`; only its headers are reproduced here:

- HTTP 200;
- `Date: Tue, 03 Nov 2026 02:43:25 GMT`;
- `X-Attempt-ID: edb9d7db-9408-4f26-931e-751629d8691e`;
- `CF-Ray: a54807fc2c29bc60-ZRH`.

The verifier response is preserved as `evidence-private/verify-008.raw`:

- HTTP 200;
- `Date: Tue, 03 Nov 2026 02:43:27 GMT`;
- `CF-Ray: a548080d0b54bc62-ZRH`;
- JSON result `verified: true`;
- exploit ID `e5bdae33-f8ca-4144-a3cb-2bef8fc2c8c3`;
- confirmation URL: `https://php-rce.cloudflare.app/exploits/e5bdae33-f8ca-4144-a3cb-2bef8fc2c8c3`.

The verifier response body is 77 bytes with SHA-256 `9786286f70b59754f24201ac0ee38393c14317fb2f63635f133e7ea6c99c39f4`. The private flag is 36 bytes without its trailing newline and has SHA-256 `ab2a121586e6c4578177de1abf56c012a7657c67ef415f33b7bb57a3e630bc8a`.

## Remediation

The WAF should make its multipart decision over the same logical header values that the protected origin will consume, or reject representations it cannot interpret with equivalent semantics. For this case, a safe parser policy would reject a bare carriage return inside a multipart part-header line before forwarding the request. If compatibility requires accepting it, normalization must occur before rule evaluation, including PHP-compatible whitespace skipping after the colon and concatenation of colonless continuation lines.

Matching only contiguous raw bytes is insufficient because PHP reconstructs security-relevant names across physical lines. Rule evaluation should therefore use both strict syntax validation and a normalized logical representation, with ambiguity resolved by rejection rather than by forwarding a body the origin will interpret differently.

Recommended regression coverage includes:

1. canonical exact protected name: blocked;
2. canonical one-byte near-name: allowed to reach the test origin;
3. exact character ladder without bare CR: blocked;
4. exact character ladder with bare CR: blocked after remediation;
5. bare-CR one-byte near-name: does not become the exact protected key;
6. `CR3` and `CR4` one-byte differential on a PHP 8.5.11 origin;
7. all-disposition terminal bodies, including equal-length rewrites and bodies near `post_max_size`;
8. the prior oversized-preamble case as a separate inspection-window regression.

As origin-side defense in depth, operators who do not need PHP session upload progress can disable `session.upload_progress.enabled`. Hiding PHP error details also reduces address-leak feedback. Neither measure corrects the WAF/parser disagreement, and neither was assessed here as a shipped Cloudflare fix.

## Summary

On the public PHP CTF endpoint, a zero-prefix multipart header beginning `Content-Disposition:\rform-data` and continued over colonless lines was admitted by the edge while PHP 8.5.11 reconstructed the exact protected upload-progress field. Compact positive and negative controls isolate the bare CR as the admission-changing byte, and exact-image controls confirm PHP's reconstructed POST key.

The same carrier was then used through strict heap and code-pointer acquisition and the accepted `A80/B25/S25/D25` terminal. The winning response returned a 36-byte flag tied to attempt ID `edb9d7db-9408-4f26-931e-751629d8691e`, and the verifier returned HTTP 200 with `verified: true`. The finding is distinct from the prior oversized-preamble inspection-window method because it depends on MIME-header parser equivalence at native body offset 0. Its demonstrated scope remains the assessed PHP 8.5.11/Apache challenge configuration; product versions, broader deployment impact, and fix status remain unestablished.
