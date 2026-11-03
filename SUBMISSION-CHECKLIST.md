# HackerOne submission checklist

- [ ] Submit `REPORT.md` as a new report and identify the endpoint as
      `https://php-rce.cloudflare.app/php/index.php`.
- [ ] Attach the three top-level PoC files and the required `poc/src/` modules,
      or provide the private repository link.
- [ ] Attach the sanitized files from `evidence-public/` and the sanitized JSON
      receipts from `evidence-private/`.
- [ ] Provide the private flag value only in HackerOne's private report field or
      attachment when required. Do not paste it into public comments.
- [ ] Include Attempt ID `edb9d7db-9408-4f26-931e-751629d8691e` and Exploit ID
      `e5bdae33-f8ca-4144-a3cb-2bef8fc2c8c3`.
- [ ] Link the confirmation permalink from `VERIFICATION.md`.
- [ ] Disclose the related duplicate and explain the material distinction:
      #4155237 used an oversized inert preamble to displace protected content
      beyond an inspected prefix; this report starts at native offset zero and
      relies on bare-CR MIME-header reconstruction.
- [ ] State that fresh ASLR values, a new terminal schedule, or a rotated flag
      are not claimed as separate bypass methods.
- [ ] Confirm the repository is private before pushing.
- [ ] Confirm `evidence-private/flag.txt` and `evidence-private/*.raw` remain
      untracked.
- [ ] Submit before any challenge-state expiration affects the verification
      record.

