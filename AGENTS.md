# Project

- Root package is `main`; module is `github.com/gwillem/stena`. One CLI exposes `login` and `scan`.
- Keep real MAC addresses, voucher codes, zone IDs, and captured network details out of source/tests. Use synthetic locally administered MACs and documentation IPs.
- `.gitignore` is a reviewed-file allowlist. Session JSON, `mac`, local Python scripts, and binaries contain private or generated data. Never force-add them; review new exceptions.
- `scan` writes session JSON to its working directory and uses empty files as negative-cache markers.
- `go fix` can inline generic pointer helpers. Remove helpers left unused before linting.
- Always sign commits. Preserve the repository-local commit identity; if signing fails, resolve the key configuration rather than bypassing signing.
