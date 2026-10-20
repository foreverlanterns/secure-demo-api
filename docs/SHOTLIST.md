# Evidence — what is captured and what is still missing

All images live in `docs/screenshots/`, with the raw stdout of every command in
`docs/screenshots/raw/<same-name>.txt`. They were rendered from real command
output on this machine (Windows 11 + Docker Desktop 29.9.1), not drawn by hand.

---

## A. Application — captured

| File | Command behind it | Shows |
| --- | --- | --- |
| `01-tests.png` | `pytest -q` | 22 tests green |
| `03-api-401.png` | `curl -i /api/data` | `401` + the security headers |
| `04-api-login.png` | `POST /auth/login` | JWT issued (`cut -c1-104` for readability) |
| `05-api-data.png` | login → `GET /api/data` | two users, **no `password_hash`** |
| `06-api-xss-escaped.png` | `POST /api/posts` with `<script>` | stored payload returned as `&lt;script&gt;` |
| `07-api-sqli-blocked.png` | login with `alice' OR '1'='1` | `401`, generic message |

## B. CI/CD — still to do

| File | What to capture |
| --- | --- |
| `02-ci-green.png` | GitHub Actions: the three jobs (`test`, `sast`, `sca`) green |

This one cannot be produced locally: it requires the repository to be pushed to
GitHub so Actions actually runs. Push, open the **Actions** tab, screenshot the
run, and optionally the **Security → Code scanning** tab for the bandit SARIF.

## C. CVE-2021-41773 — captured

| File | Shows |
| --- | --- |
| `10-cve-env.png` | container up on 8080, `200`, `Server: Apache/2.4.49` |
| `11-cve-passwd.png` | traversal returns `/etc/passwd`, HTTP `200` |
| `12-cve-rce.png` | `uid=1(daemon)` through `mod_cgi` |
| `13-cve-conf.png` | `httpd.conf` read through the traversal (`Require all granted`) |
| `14-cve-fix-diff.png` | the fix: `2.4.49` → `2.4.51`, one line |
| `15-cve-fixed-400.png` | patched build returns **`400`** for both payloads |
| `16-cve-regression.png` | patched build still serves `/` with `200` |
| `17-cve-stock-403.png` | stock config (`Require all denied`) returns `403` — the second layer |

---

## If a native screen capture is required

The images above are terminal renderings of real output. If the instructor wants
screenshots of the desktop itself, re-run the same commands and capture the
window; every command is listed in `CVE-2021-41773-walkthrough.md` §1–§7 and in
the raw transcripts. Nothing needs to be re-derived — only re-photographed.
