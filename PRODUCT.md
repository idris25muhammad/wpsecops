# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Flask + Jinja2 server-rendered templates, Tailwind CSS (Play CDN), Chart.js, SQLAlchemy/SQLite, Celery + Redis broker, external CLI tools (WhatWeb, WPScan, Nuclei), Gemini/Claude AI providers.

## Users

- **Primary: internal security admin/operator.** Runs the dashboard from a workstation, adds WordPress target servers, kicks off scans, and reviews results to track and remediate vulnerabilities across the organization's sites. Single-admin login (`admin` / default `admin123`, changeable).
- The interface copy is Indonesian (Bahasa); the operator works in Indonesian.

## Product Purpose

WP-SecOps is a centralized WordPress security scanner: it enumerates the technologies and components of many WordPress targets, runs a multi-tool detection pipeline, and produces a trackable history of vulnerabilities per server so the admin can see what is exposed and whether it has been fixed over time. Success is an admin who can, from one dashboard, know which WordPress sites have which vulnerabilities and monitor remediation progress.

## Positioning

A centralized, multi-scanner WordPress exposure tracker rather than a single-tool point solution: it sequences WhatWeb (technology identification) → WPScan (WordPress fingerprinting + plugin/theme/user enumeration) → Nuclei (exposure detection) → hardening review, and layers per-finding AI analysis (severity, component, provider) on top, all stored in a persistent history. The sequential 4-tool pipeline is the product's core mechanism.

## Operating Context

- Admin logs in, manages target servers (name + URL), triggers scans.
- Scans run asynchronously via Celery/Redis in the background; a real-time monitor (async-worker page) shows worker status, active tasks, queue depth, and running scans (auto-refresh).
- A 4-tool sequential pipeline per scan; each phase's logs and raw output are recorded and viewable on a workflow timeline.
- System-status page reports tool availability (WhatWeb/WPScan/Nuclei engines, Celery/Redis, AI provider keys).
- Statistics page aggregates 30-day scan trend, AI severity/component/provider distribution, and per-server performance/vuln totals (read from `ai_cache` JSON files + DB).
- Scan history is filterable by server and deletable; detail pages list core/theme/plugin vulnerabilities with references/CVEs.

## Capabilities and Constraints

- **Capabilities:** server management; async scan pipeline; per-phase workflow timeline with raw output; scan history (filter/delete); dashboard KPI; statistics with Chart.js; real-time Celery/Redis worker monitor; system dependency health; per-finding AI recommendations (Gemini or Claude).
- **Constraints:** server-rendered Flask app; Tailwind + Chart.js loaded from CDN (no local build pipeline); AI analysis gated on API keys; Nuclei needs its templates dir (`/home/idris/nuclei-templates`); WPScan runs in no-API mode; single default admin account; SQLite persistence.
- **Terminology (Indonesian):** Dashboard, Servers (Server), Scan History (Riwayat), Statistics (Statistik), System Status (Status Sistem), Async Worker, Kerentanan (vulnerability), Temuan (finding), Pemindaian (scan).

## Brand Commitments

- Product name **WP-SecOps**, two-tone brand mark: `WP` in sky and `SecOps` in emerald.
- **Daylight Mission Console** aesthetic (user-pinned, light mode): light neutral ground + white surfaces with hairline borders, ink text, semantic status color used deliberately (green/amber/red/sky as light-tinted badges, never neon), **common system fonts** (Segoe UI for UI, Consolas/Cascadia Mono for data) so text always renders clearly, shield motif. Refuses dark "hacker-glow" AI-slop: no gradients, glass, neon glow, decorative grids, or purple/indigo accents. The page-header band (dark security pattern, emerald "Security Monitoring" eyebrow, white title) is preserved as a deliberate brand element.
- UI language is Indonesian.

## Evidence on Hand

- Repo: `C:\idlabs\wpsecops` - Flask app (`app.py`, `routes/`, `templates/`, `static/style.css`, `static/images/logo.png`).
- Two existing scan records in the SQLite DB (scan ids 1, 2) and `ai_cache/scan_*.json` files feed statistics.
- Default login `admin` / `admin123` (created in `app.py` when no admin exists - note this is a known default credential).
- No real customer testimonials, case studies, or press exist; future work must not fabricate them.

## Product Principles

- **Track, don't just scan:** every detection is persisted into a per-server history so remediation progress is visible over time.
- **Evidence over opinion:** findings carry raw tool output, CVEs/references, and an attributed AI analysis rather than bare verdicts.
- **One operator, many targets:** the dashboard exists to make N WordPress sites manageable from a single surface.
- **Surfaces system health:** the operator must know whether each engine (and the AI provider) is actually available before trusting a scan result.
- **Async by default:** long multi-tool scans never block the operator; background workers and real-time monitoring carry the load.

## Accessibility & Inclusion

- No product-specific accessibility standard or user need has been established beyond general web accessibility; target at least WCAG AA for the dashboard and login.
