# Linux CIS Agent

A lightweight Linux agent written in Go. It collects the installed packages on a host, runs 10 security configuration checks mapped to the CIS Ubuntu Linux 22.04 LTS Benchmark (Level 1) and sends the results as JSON over HTTPS to a backend on AWS. The backend stores the data, exposes REST APIs and serves a web dashboard.

## Architecture

```
┌──────────── Linux host ────────────┐          ┌──────────────── AWS EC2 ─────────────────┐
│ cis-agent (installed from .deb)    │          │ Caddy :443 (Let's Encrypt TLS)           │
│  • host info  (/etc/os-release)    │  HTTPS   │   │                                      │
│  • packages   (dpkg / rpm)         │ ───────▶ │   ▼                                      │
│  • 10 CIS checks + evidence        │  JSON +  │ cis-server (Go, 127.0.0.1:8080)          │
│ systemd timer: runs every hour     │  API key │   • POST /ingest  • GET REST APIs        │
└────────────────────────────────────┘          │   • serves dashboard (HTML/CSS/JS)       │
                                                │   ▼                                      │
               Browser ── HTTPS ──────────────▶ │ SQLite (/var/lib/cis-server/cis.db)      │
                                                └──────────────────────────────────────────┘
```

## Repository layout

| Path | What it contains |
|---|---|
| `agent/cmd/agent` | Agent entry point: collects data, then prints it (`-dry-run`) or sends it |
| `agent/internal/hostinfo` | Hostname, OS name/version, kernel, machine ID |
| `agent/internal/collector` | Installed packages via `dpkg-query` (Debian/Ubuntu) or `rpm` (RHEL) |
| `agent/internal/cis` | Check framework and the 10 CIS checks |
| `agent/internal/sender` | HTTPS POST with timeout and retry/backoff |
| `server/` | Go REST API and SQLite storage |
| `frontend/` | Dashboard (`index.html` + `style.css`, plain JavaScript) |
| `packaging/` | nfpm config, systemd service and timer, install scripts |

## CIS checks

References are recommendation numbers from the **CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0, Level 1 – Server**.

| ID | Check | How it is verified | CIS recommendation |
|---|---|---|---|
| CIS-01 | Password expiration and minimum length | `PASS_MAX_DAYS` 1–365 in `/etc/login.defs`; `minlen` ≥ 14 in `/etc/security/pwquality.conf` | 5.4.1.1, 5.3.3.2.2 |
| CIS-02 | SSH root login disabled | `sshd -T` → `permitrootlogin no` (effective config, including drop-in files) | 5.1.20 |
| CIS-03 | Unused filesystem modules not available | `modprobe -n -v` shows `install /bin/false` (or no module) for cramfs, freevxfs, udf, and none are loaded | 1.1.1.1, 1.1.1.2, 1.1.1.7 |
| CIS-04 | Host firewall enabled | `ufw status` is active (or `firewall-cmd --state` is running) | 4.1.3 |
| CIS-05 | A single time sync daemon in use | Exactly one of chrony, systemd-timesyncd and ntp is active | 2.3.1.1 |
| CIS-06 | auditd installed, enabled and active | `systemctl is-active` / `is-enabled auditd` | 6.3.1.1, 6.3.1.2 |
| CIS-07 | AppArmor (or SELinux) enabled | `aa-status --enabled` (or `getenforce` = Enforcing) | 1.3.1.2 |
| CIS-08 | No world-writable files | `find / -xdev -type f -perm -0002` returns nothing | 7.1.11 |
| CIS-09 | GDM automatic login disabled | `AutomaticLoginEnable` is not true in GDM's `custom.conf` (passes if GDM isn't installed) | 1.7 section* |
| CIS-10 | `/etc/shadow` permissions | Mode 0640 or stricter, owned by root | 7.1.5 |

\* GDM auto-login comes from the assignment's example list. The 22.04 benchmark has no separate recommendation for it, so it's mapped to the GDM section (1.7).

The same controls exist in the **CIS Ubuntu 24.04 Benchmark v1.0.0** (used on the test host). Only a few numbers differ there: udf 1.1.1.8, ufw 4.2.3, auditd 6.2.1.1/6.2.1.2.

squashfs (1.1.1.6) is deliberately not checked: Ubuntu snaps need it, and the benchmark notes this.

Each result is `pass`, `fail` or `error`, and it includes the raw evidence (command output or config line) used to decide.

## REST API

| Method and path | Description |
|---|---|
| `POST /ingest` | Agent upload. Requires the `x-api-key` header. |
| `GET /hosts` | All hosts with summary (package count, CIS pass/total, last seen) |
| `GET /hosts/{id}` | One host |
| `GET /hosts/{id}/apps` or `GET /apps?host_id=` | Installed packages |
| `GET /hosts/{id}/cis-results` or `GET /cis-results?host_id=` | CIS results with evidence |

Example agent payload:
```json
{
  "agent_version": "0.2.0",
  "host": { "host_id": "…", "hostname": "ip-172-31-43-42", "os_name": "Ubuntu", "os_version": "24.04", "kernel": "…" },
  "packages": [ { "name": "openssh-server", "version": "1:9.6p1-3ubuntu13", "arch": "amd64", "manager": "dpkg" } ],
  "cis_results": [ { "id": "CIS-02", "title": "SSH root login disabled", "cis_ref": "5.1.20", "status": "pass", "evidence": "permitrootlogin no" } ]
}
```

## Build and run

### Agent
```bash
cd agent
go build -o bin/cis-agent ./cmd/agent
sudo ./bin/cis-agent -dry-run          # print the JSON instead of sending it
sudo ./bin/cis-agent                   # send it (reads /etc/cis-agent/agent.json)
```
`/etc/cis-agent/agent.json`:
```json
{ "api_url": "https://<server-host>", "api_key": "<key>" }
```

### Tests
Run these on Linux (the agent's checks use Linux-only system calls):
```bash
cd agent  && go test ./...
cd server && go test ./...
```
- **Agent tests** cover:
  - config parsing and the password, GDM, `/etc/shadow` and time-sync decision logic
  - status mapping (pass/fail/error)
  - dpkg and rpm output parsing
  - `/etc/os-release` parsing
  - the sender's retry behaviour (retries 5xx, gives up after 3 attempts, never retries 4xx)
- **Server tests** run the real HTTP handlers against a temporary SQLite database:
  - API-key rejection, invalid JSON and missing host ID
  - ingest followed by every read endpoint
  - a re-scan replacing the previous data
  - 404 and 400 responses

### Package (.deb / .rpm)
```bash
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
mkdir -p dist
nfpm pkg --config packaging/nfpm.yaml --packager deb --target dist/
nfpm pkg --config packaging/nfpm.yaml --packager rpm --target dist/
sudo apt install ./dist/cis-agent_0.2.0_amd64.deb
dpkg -l cis-agent                      # registered with the package manager
systemctl list-timers | grep cis       # runs hourly
```

### Server
```bash
cd server
go build -o bin/cis-server .
AGENT_API_KEY=<key> DB_PATH=cis.db WEB_DIR=../frontend ./bin/cis-server   # listens on 127.0.0.1:8080
```
In production it runs as a systemd service (`DynamicUser=yes`, so not as root), with Caddy in front for automatic HTTPS.

## Design decisions

- **Go agent:** a single static binary with no runtime dependencies, which keeps packaging simple and the footprint small.
- **Pluggable checks:** each check is a function returning `(pass, evidence, error)`. One failing check never stops the others, and adding a check is one line in the registry.
- **Evidence-first results:** every result carries the exact output that led to the decision, so an auditor can verify it.
- **Read-only agent:** it reports problems and never changes system configuration. Remediation is the operator's decision.
- **nfpm packaging:** a single config builds both `.deb` and `.rpm`. The config file is marked `config|noreplace` so upgrades keep local settings.
- **systemd timer instead of a daemon:** nothing stays resident between scans, and systemd handles scheduling and logging.
- **Backend on EC2:** the AWS organization's service control policy blocks Lambda, API Gateway and DynamoDB in this account, so the backend uses the "simpler REST ingestion service" option from the brief.
- **Security:**
  - TLS end to end
  - API key compared in constant time
  - 10 MB request limit
  - API bound to localhost behind Caddy
  - service runs as an unprivileged dynamic user
  - config files are mode 0600
- **SQLite:** zero administration and transactional writes (each scan replaces the host's data atomically). It's enough for an MVP.
- **squashfs not checked:** Ubuntu snaps depend on it, and CIS notes this exception.

## Future improvements

- Move the backend to API Gateway, Lambda and DynamoDB (or S3) when the account allows it.
- Per-agent credentials (mTLS or signed tokens) instead of a shared API key, and authentication on the read APIs and dashboard.
- Keep scan history to show compliance trends over time.
- More CIS controls, severity levels and remediation guidance.
- CI pipeline that runs tests and publishes the `.deb` and `.rpm` on each release.
- An agent self-update mechanism and RHEL 9 test coverage.
