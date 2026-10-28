# Linux CIS Agent

A lightweight Linux agent written in Go. It collects the installed packages on a host, runs 10 security configuration checks mapped to the CIS Ubuntu Linux Benchmark (Level 1) and sends the results as JSON over HTTPS to a backend on AWS. The backend stores the data, exposes REST APIs and serves a web dashboard.

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

| ID | Check | How it is verified | CIS section |
|---|---|---|---|
| CIS-01 | Password expiration and complexity | `PASS_MAX_DAYS` ≤ 365 in `/etc/login.defs`, `minlen` ≥ 14 in `pwquality.conf` | 5.4 / 5.5 |
| CIS-02 | SSH root login disabled | `sshd -T` → `permitrootlogin no` | 5.2 |
| CIS-03 | Unused filesystems disabled | `modprobe -n -v` for cramfs, freevxfs, udf and not loaded in `lsmod` | 1.1.1 |
| CIS-04 | Firewall active | `ufw status` (or `firewall-cmd --state`) | 3.5 |
| CIS-05 | Time synchronization | chrony / systemd-timesyncd / ntp active | 2.1 |
| CIS-06 | auditd running | `systemctl is-active` and `is-enabled auditd` | 4.1.1 |
| CIS-07 | AppArmor / SELinux enabled | `aa-status --enabled` (or `getenforce` = Enforcing) | 1.6.1 |
| CIS-08 | No world-writable files | `find / -xdev -type f -perm -0002` | 6.1 |
| CIS-09 | GDM auto-login disabled | `AutomaticLoginEnable` in `/etc/gdm3/custom.conf` (N/A if no GDM) | 1.8 |
| CIS-10 | `/etc/shadow` permissions | mode 0640 or stricter, owned by root | 6.1 |

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
  "agent_version": "0.1.0",
  "host": { "host_id": "…", "hostname": "ip-172-31-43-42", "os_name": "Ubuntu", "os_version": "24.04", "kernel": "…" },
  "packages": [ { "name": "openssh-server", "version": "1:9.6p1-3ubuntu13", "arch": "amd64", "manager": "dpkg" } ],
  "cis_results": [ { "id": "CIS-02", "title": "SSH root login disabled", "cis_ref": "5.2", "status": "pass", "evidence": "permitrootlogin no" } ]
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

### Package (.deb / .rpm)
```bash
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
mkdir -p dist
nfpm pkg --config packaging/nfpm.yaml --packager deb --target dist/
nfpm pkg --config packaging/nfpm.yaml --packager rpm --target dist/
sudo apt install ./dist/cis-agent_0.1.0_amd64.deb
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
