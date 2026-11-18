# Contributing to PromptHound

Thanks for your interest in improving PromptHound.

## Ground rules

- **Authorized use only.** Do not submit issues, PRs, or output involving targets
  you were not authorized to test.
- Keep the core (`docgen`, `payloads`) dependency-free; only `prober` may use
  `requests`.
- New payloads should be *detectable* (carry a canary) and non-destructive by
  default — the goal is to prove injection, not to cause harm.

## Development

```bash
git clone https://github.com/R00t3dbyFa17h/PromptHound.git
cd PromptHound
pip install ".[probe]"
python3 -m py_compile prompthound/*.py
python3 -m prompthound gen -f pdf -o /tmp/t.pdf && pdftotext /tmp/t.pdf -   # smoke test
```

## Pull requests

1. Fork and branch.
2. Verify byte-compile passes and `gen`/`payloads` still run.
3. Update `README.md` / `CHANGELOG.md` for any new flags or payloads.
4. Open the PR with a clear description.
