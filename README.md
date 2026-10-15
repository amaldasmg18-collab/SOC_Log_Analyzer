# SOC Log Analyzer

A Django web application for uploading authentication logs, detecting suspicious activity, and triaging alerts in a dark SOC-style dashboard.

> **Portfolio project.** It demonstrates log analysis and detection-engineering fundamentals. It is **not** a replacement for a production SIEM.

## The problem
Authentication logs hold the earliest signs of credential attacks (brute force, password spraying, compromised accounts), but reading them by hand does not scale. This tool parses logs into structured events, applies explainable detection rules, and gives an analyst a place to investigate.

## Features
- Login/logout with Django auth; every page requires authentication; first admin via `createsuperuser`
- `.log`/`.txt` upload with extension, size, UTF-8 and binary checks; malformed lines are reported, duplicates skipped; per-upload summary (processed / imported / skipped / rejected)
- Log Explorer: search, date/type/user/IP/severity/outcome filters, sorting, pagination, CSV export of the current filter
- Detection engine with 5 configurable rules, evidence, linked events and alert de-duplication
- Alert management: filter, status workflow (Open / Investigating / Resolved / False Positive), investigation notes, status history
- Detection Rules page (staff can edit thresholds/windows and enable/disable)
- Reports with analysis period, CSV export with spreadsheet-formula-injection protection
- Dashboard KPIs and charts computed from the database; empty states when there is no data
- Demo data command with `is_demo` flag and a purge that never touches uploaded data

## Screenshots
_Placeholders: capture real screenshots after running the app and save them in `static/images/`._

| Overview | Log Explorer | Alert detail |
|---|---|---|
| _(pending)_ | _(pending)_ | _(pending)_ |

## Architecture
```
config/                  settings, root URLs
analyzer/models.py       LogImport, SecurityEvent, DetectionRule, SecurityAlert, AlertNote
analyzer/services/
    log_parser.py        parsing + import (dedupe by SHA-256 of timestamp+line)
    detection_engine.py  rule registry + run_detection()
    report_generator.py  report aggregates
    demo_data.py         fictional data (RFC 5737 / RFC 1918 IPs)
analyzer/views.py        dashboard, explorer, alerts, rules, reports, settings
templates/ static/       Bootstrap 5.3 + Chart.js 4.4 (CDN), custom CSS/JS
sample_data/             fictional logs for testing
```
**Indexed fields:** `SecurityEvent.timestamp`, `username`, `source_ip`, `is_demo`, composite `(source_ip, timestamp)` and `(event_type, timestamp)` (explorer filters, per-IP detection); `line_hash` is unique (duplicate prevention); `SecurityAlert.status`, `severity`, `last_seen`, unique `dedupe_key`.

## Tech stack
Python 3.10+ (3.13 supported), Django 5.2 LTS, SQLite, Bootstrap 5.3.3, Bootstrap Icons 1.11.3, Chart.js 4.4.1. The front-end libraries load from jsDelivr, so the browser needs internet access on first load. Python dependency: Django only.

## Installation
### Windows (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python manage.py migrate
python manage.py createsuperuser
python manage.py seed_demo_data
python manage.py runserver
```
### Kali / Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
python manage.py migrate
python manage.py createsuperuser
python manage.py seed_demo_data
python manage.py runserver
```
Open <http://127.0.0.1:8000/>. Edit `.env` to set `DJANGO_SECRET_KEY` (otherwise a random per-run key is used and sessions reset on restart). With `DJANGO_DEBUG=0`, cookies are marked Secure (HTTPS required) and `runserver` does not serve static files; use `DJANGO_DEBUG=1` locally.

Remove demo data: `python manage.py seed_demo_data --purge` (or Settings page). Seeding is refused when `DJANGO_DEBUG=0` unless `--force` is passed.

### Tests
```
python manage.py test
```

## Log format
```
2026-10-15 10:21:05 WARN LOGIN_FAILED user=admin ip=192.168.1.25
```
`<YYYY-MM-DD HH:MM:SS, UTC> <INFO|WARN|ERROR|CRITICAL> <EVENT> user=<name> ip=<IPv4/IPv6>`. Events: `LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGOUT`, `PASSWORD_CHANGE`, `ACCOUNT_LOCKED`. Blank lines and `#` comments are ignored. Samples: `sample_data/`.

## Detection rules (defaults; editable on the Rules page)
| ID | Rule | Logic | Severity |
|---|---|---|---|
| SOC-001 | Brute-force | >=5 failed logins from one IP in 5 min | High |
| SOC-002 | Multiple targeted accounts | >=3 distinct usernames failed from one IP in 10 min | High |
| SOC-003 | Success after failures | success for an account after >=3 failures from the same IP/account in 15 min | Critical |
| SOC-004 | Off-hours login | >=1 successful login by a user between 00:00-05:59 UTC (fixed time-of-day heuristic, not behavioural anomaly detection) | Low |
| SOC-005 | Repeated activity | >=20 auth events of any type from one IP in 10 min | Medium |

Alerts carry evidence and linked events. A deterministic `dedupe_key` (rule, IP, user, first event time) prevents duplicates on re-analysis. No MITRE ATT&CK mapping is implemented. "Open Alerts" on the dashboard counts Open + Investigating. Add a rule by writing a generator in `detection_engine.py` decorated with `@register(...)`.

## Example workflow
1. Upload `sample_data/attack_patterns.log` (Upload Logs). 2. Review the new alerts. 3. Open an alert, read the evidence and events, set status and add a note. 4. Pivot to the Log Explorer by IP. 5. Export CSVs from Reports.

## Security considerations and limitations
CSRF protection, login required everywhere, POST-only logout, staff-only rule edits and demo purge, ORM-only queries, template auto-escaping, whitelist-based sorting, uploads parsed in memory and never stored or served, filename sanitised, CSV formula-injection guard, secrets from environment, HttpOnly/SameSite cookies, no stack traces when debug is off.
Limitations: all authenticated users see all data (no per-user tenancy); timestamps assumed UTC; detection re-scans all events (fine for thousands of events, not millions); one log format; no rate limiting on login; SQLite only.

## Roadmap
Per-user data ownership, more log formats (syslog/auth.log), IP allow-lists, GeoIP enrichment, login rate limiting, rule-tuning UI for hours, PDF reports.

## License
MIT (add a `LICENSE` file before publishing).
