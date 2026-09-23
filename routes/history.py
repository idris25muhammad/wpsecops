import os
import json
from datetime import timedelta, timezone
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app, jsonify
from flask_login import login_required
from extensions import db
from models import Server, ScanHistory, ScanResult, ScanFinding
from services.vuln_analyzer import analyze_vulnerabilities, analyze_single_vulnerability, call_llm_text, build_cve_search_prompt

def extract_severity_from_vuln(v):
    cvss = v.get("cvss")
    score = None
    
    if isinstance(cvss, dict):
        score = cvss.get("score")
    elif isinstance(cvss, list) and len(cvss) > 0:
        scores = []
        for c in cvss:
            if isinstance(c, dict) and c.get("score") is not None:
                try:
                    scores.append(float(c.get("score")))
                except (ValueError, TypeError):
                    pass
        if scores:
            score = max(scores)
            
    if score is not None:
        try:
            score_val = float(score)
            if score_val >= 9.0:
                return "critical"
            elif score_val >= 7.0:
                return "high"
            elif score_val >= 4.0:
                return "medium"
            else:
                return "low"
        except (ValueError, TypeError):
            pass
            
    return None


history_bp = Blueprint("history", __name__)

def _normalize_finding_items(items):
    """WPScan timthumbs/config_backups/themes can be a dict (keyed by URL/slug)
    or a list of dicts. Normalize to a list of dicts with a 'url'/'name' key."""
    if isinstance(items, dict):
        out = []
        for url, d in items.items():
            if isinstance(d, dict):
                item = dict(d)
                item.setdefault("url", url)
                out.append(item)
            else:
                out.append({"url": url})
        return out
    if isinstance(items, list):
        return [it for it in items if isinstance(it, dict)]
    return []


def get_scan_findings_and_info(scan):
    findings = []
    api_error = None
    target_info = {
        "wordpress_version": "-",
        "main_theme": "-",
        "theme_details": {},
        "themes_detected": [],
        "plugins_detected": [],
        "plugin_details": [],
        "users_detected": [],
        "user_details": [],
        "timthumbs": [],
        "config_backups": [],
        "interesting_urls": [],
        "target_ip": None,
        "effective_url": None,
        "scan_stats": {},
        "tech_stack": [],      # from WhatWeb
        "server": None,        # from WhatWeb
        "php_version": None    # from WhatWeb
    }
    interesting_findings = []

    # Collect raw outputs
    whatweb_raw = None
    wpscan_raw = None
    nuclei_raw = None

    for r in (scan.results or []):
        if r.scanner_type == "whatweb" and r.raw_output:
            whatweb_raw = r.raw_output
        elif r.scanner_type == "wpscan" and r.raw_output:
            wpscan_raw = r.raw_output
        elif r.scanner_type == "nuclei" and r.raw_output:
            nuclei_raw = r.raw_output

    # Fallback: legacy scans stored JSON in ScanHistory.raw_output
    if not wpscan_raw and scan.raw_output:
        raw = scan.raw_output.strip()
        if raw.startswith("{"):
            wpscan_raw = raw

    idx = 1

    # ── 1. Parse WhatWeb → tech_stack + initial WP version ────────────────
    if whatweb_raw:
        try:
            data_list = []
            try:
                parsed = json.loads(whatweb_raw)
                data_list = parsed if isinstance(parsed, list) else [parsed]
            except json.JSONDecodeError:
                for line in whatweb_raw.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, list):
                            data_list.extend(obj)
                        elif isinstance(obj, dict):
                            data_list.append(obj)
                    except json.JSONDecodeError:
                        continue

            for entry in data_list:
                if not isinstance(entry, dict):
                    continue
                plugins = entry.get("plugins", {}) or {}
                for tech_name, tech_data in plugins.items():
                    if not isinstance(tech_data, dict):
                        continue
                    versions = tech_data.get("string", []) or []
                    version = versions[0] if versions else None
                    tech_str = f"{tech_name}{': ' + version if version else ''}"
                    if tech_str not in target_info["tech_stack"]:
                        target_info["tech_stack"].append(tech_str)

                    # Extract specific values
                    tech_lower = tech_name.lower()
                    if "wordpress" in tech_lower and version and target_info["wordpress_version"] == "-":
                        target_info["wordpress_version"] = version
                    elif tech_lower in ("apache", "nginx", "iis", "litespeed") and version:
                        target_info["server"] = f"{tech_name} {version}"
                    elif tech_lower == "php" and version:
                        target_info["php_version"] = version

        except Exception:
            pass

    # ── 2. Parse WPScan (no-API) → full WP info + enrich target_info ──────
    if wpscan_raw:
        try:
            raw = wpscan_raw.strip()
            # raw_output in DB = WPScan JSON + trailing log lines dari ThrottledLogWriter.
            # Ambil blok JSON murni: dari '{' pertama sampai '}' terakhir.
            json_start = raw.find("{")
            json_end = raw.rfind("}")
            if json_start == -1 or json_end == -1:
                data = {}
            else:
                try:
                    data = json.loads(raw[json_start:json_end + 1])
                except (json.JSONDecodeError, ValueError):
                    data = {}

            if not isinstance(data, dict) or "scan_aborted" in data:
                data = {}

            version_data = data.get("version", {}) or {}
            main_theme = data.get("main_theme", {}) or {}
            plugins = data.get("plugins", {}) or {}
            themes = data.get("themes", {}) or {}
            users = data.get("users", {}) or {}
            wp_interesting = data.get("interesting_findings", []) or []

            # WP version (WPScan is more authoritative than WhatWeb for this)
            if isinstance(version_data, dict) and version_data.get("number"):
                target_info["wordpress_version"] = version_data["number"]
            elif isinstance(version_data, dict) and version_data.get("found_by"):
                target_info["wordpress_version"] = "terdeteksi (belum diketahui)"

            # Target network info
            target_info["target_ip"] = data.get("target_ip")
            target_info["effective_url"] = data.get("effective_url")

            # Scan stats
            stats = {}
            for k in ("elapsed", "requests_done", "cached_requests",
                      "data_sent_humanised", "data_received_humanised",
                      "used_memory_humanised"):
                if data.get(k) is not None:
                    stats[k] = data[k]
            target_info["scan_stats"] = stats

            # Main theme (full detail)
            if main_theme.get("slug") or main_theme.get("style_name"):
                target_info["main_theme"] = main_theme.get("style_name") or main_theme.get("friendly_name") or main_theme.get("slug")
                version_obj = main_theme.get("version")
                main_theme_version = version_obj.get("number") if isinstance(version_obj, dict) else None
                target_info["theme_details"] = {
                    "slug": main_theme.get("slug"),
                    "name": main_theme.get("style_name") or main_theme.get("friendly_name"),
                    "version": main_theme_version,
                    "location": main_theme.get("location"),
                    "style_uri": main_theme.get("style_uri"),
                    "description": main_theme.get("description"),
                    "outdated": main_theme.get("outdated", False),
                    "latest_version": main_theme.get("latest_version"),
                    "last_updated": main_theme.get("last_updated"),
                    "readme_url": main_theme.get("readme_url"),
                    "directory_listing": main_theme.get("directory_listing", False),
                }

            # All themes (beyond main theme)
            for theme_item in _normalize_finding_items(themes):
                if theme_item.get("slug") and theme_item["slug"] not in [t.get("slug") for t in target_info["themes_detected"]]:
                    version_obj = theme_item.get("version")
                    theme_item["version"] = version_obj.get("number") if isinstance(version_obj, dict) else None
                    target_info["themes_detected"].append(theme_item)

            # Plugins (keep full details: version, outdated, latest, location)
            if isinstance(plugins, dict):
                plugin_details = []
                for slug, plugin_data in plugins.items():
                    if slug == "*" or not isinstance(plugin_data, dict):
                        continue
                    if slug not in target_info["plugins_detected"]:
                        target_info["plugins_detected"].append(slug)
                    version_obj = plugin_data.get("version")
                    plugin_version = version_obj.get("number") if isinstance(version_obj, dict) else None
                    plugin_details.append({
                        "slug": slug,
                        "version": plugin_version,
                        "location": plugin_data.get("location"),
                        "outdated": plugin_data.get("outdated", False),
                        "latest_version": plugin_data.get("latest_version"),
                        "last_updated": plugin_data.get("last_updated"),
                        "readme_url": plugin_data.get("readme_url"),
                    })
                if plugin_details:
                    target_info["plugin_details"] = plugin_details

            # Users (username + metode deteksi + confidence)
            if isinstance(users, dict):
                for username, u_data in users.items():
                    if username not in target_info["users_detected"]:
                        target_info["users_detected"].append(username)
                    if isinstance(u_data, dict):
                        confirmed_urls = []
                        confirmed_by = u_data.get("confirmed_by", {}) or {}
                        if isinstance(confirmed_by, dict):
                            for method, m_data in confirmed_by.items():
                                if isinstance(m_data, dict) and m_data.get("interesting_entries"):
                                    confirmed_urls.extend(m_data["interesting_entries"])
                        target_info["user_details"].append({
                            "username": username,
                            "found_by": u_data.get("found_by"),
                            "confidence": u_data.get("confidence"),
                            "confirmed_urls": confirmed_urls,
                        })

            # timthumbs & config_backups (potensi risiko)
            target_info["timthumbs"] = _normalize_finding_items(data.get("timthumbs", {}))
            target_info["config_backups"] = _normalize_finding_items(data.get("config_backups", {}))

            # Interesting findings dari WPScan (xmlrpc, readme, login, robots, headers, dll.)
            for item in wp_interesting:
                if not isinstance(item, dict):
                    continue
                url = item.get("url", "")
                to_s = item.get("to_s") or item.get("to_find") or item.get("interesting_entry") or url
                if url and url not in target_info["interesting_urls"]:
                    target_info["interesting_urls"].append(url)
                    interesting_findings.append({
                        "url": url,
                        "to_find": to_s or url,
                        "description": item.get("to_s") or item.get("description"),
                        "type": item.get("type", "wpscan"),
                        "found_by": item.get("found_by"),
                        "confidence": item.get("confidence"),
                        "references": item.get("references", {}) or {},
                        "interesting_entries": item.get("interesting_entries", [url])
                    })

        except Exception:
            pass

    # ── 3. Parse Nuclei JSONL → active exposure findings ──────────────────
    if nuclei_raw:
        try:
            for line in nuclei_raw.splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "template-id" not in item:
                    continue

                info = item.get("info", {}) or {}
                severity = (info.get("severity") or "medium").lower()
                classification = info.get("classification", {}) or {}
                cve_ids = classification.get("cve-id", []) or []
                if isinstance(cve_ids, str):
                    cve_ids = [cve_ids]

                findings.append({
                    "index": idx,
                    "component": "wordpress",
                    "component_name": item.get("template-id", "Nuclei"),
                    "title": info.get("name") or "Nuclei Finding",
                    "fixed_in": None,
                    "references": {"url": [item.get("matched-at")]} if item.get("matched-at") else {},
                    "cve_ids": cve_ids,
                    "severity": severity,
                    "severity_reason": (
                        f"Nuclei template '{item.get('template-id')}' "
                        f"mendeteksi eksposur aktif dengan severity {severity.upper()}."
                    ),
                    "recommendations": [info.get("remediation")] if info.get("remediation") else None,
                    "matched_at": item.get("matched-at", ""),
                    "is_ai": False,
                    "scanner": "nuclei"
                })
                idx += 1
        except Exception:
            pass

    return findings, api_error, target_info, interesting_findings




@history_bp.route("/history")
@login_required
def history():
    server_id = request.args.get("server_id", type=int)

    query = ScanHistory.query.order_by(ScanHistory.scanned_at.desc())
    if server_id:
        query = query.filter_by(server_id=server_id)

    histories = query.all()
    all_servers = Server.query.order_by(Server.name.asc()).all()

    return render_template(
        "history.html",
        histories=histories,
        servers=all_servers,
        selected=server_id
    )


def get_hardening_report(scan):
    """Ambil & parse laporan hardening (FASE 4) dari ScanResult 'hardening'."""
    hardening = None
    for r in (scan.results or []):
        if r.scanner_type == "hardening" and r.raw_output:
            raw = r.raw_output.strip()
            try:
                hardening = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                # raw_output mungkin JSON + trailing log lines dari ThrottledLogWriter
                start = raw.find("{")
                end = raw.rfind("}")
                if start != -1 and end != -1:
                    try:
                        hardening = json.loads(raw[start:end + 1])
                    except (json.JSONDecodeError, ValueError):
                        hardening = None
            break
    return hardening


def _severity_from_confidence(confidence):
    if confidence in ("Confirmed", "Cross-verified"):
        return "high"
    if confidence == "Likely":
        return "medium"
    return "low"


@history_bp.route("/history/<int:scan_id>")
@login_required
def history_detail(scan_id):
    scan = db.session.get(ScanHistory, scan_id)
    if not scan:
        flash("History scan tidak ditemukan.")
        return redirect(url_for("history.history"))

    _, api_error, target_info, interesting_findings = get_scan_findings_and_info(scan)

    findings = []
    if scan.findings_list:
        for idx, f in enumerate(scan.findings_list, 1):
            findings.append({
                "id": f.id,
                "index": idx,
                "component": f.component,
                "component_name": f.component_name,
                "version": f.version,
                "cve_id": f.cve_id,
                "cve_ids": [f.cve_id] if f.cve_id else [],
                "title": f.title,
                "confidence": f.confidence,
                "evidence_summary": f.evidence_summary,
                "ai_prompt_template": f.ai_prompt_template,
                "ai_response": f.ai_response,
                "manual_note": f.manual_note,
                "is_ai": bool(f.ai_response),
                "severity": _severity_from_confidence(f.confidence),
                "scanner": "pipeline"
            })
    else:
        # Fallback for legacy scans
        findings_raw, _, _, _ = get_scan_findings_and_info(scan)
        for f in findings_raw:
            f["id"] = None
            f["confidence"] = "Unconfirmed"
            f["evidence_summary"] = "Legacy scan. Detail verifikasi tidak tersedia."
            f["ai_prompt_template"] = ""
            f["ai_response"] = f.get("recommendations", [None])[0] if f.get("recommendations") else None
            f["manual_note"] = None
            f["is_ai"] = bool(f["ai_response"])
            findings.append(f)

    findings_count = len(findings)

    # Calculate overall metrics
    levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    highest_level = 0
    highest_name = None
    ai_generated_count = 0

    for f in findings:
        if f.get("is_ai"):
            ai_generated_count += 1
        sev = f.get("severity")
        if sev in levels and levels[sev] > highest_level:
            highest_level = levels[sev]
            highest_name = sev

    overall_severity = highest_name if highest_name else "medium"

    if findings_count == 0:
        overall_summary = "Tidak ada kerentanan terdeteksi."
        overall_recommendations = []
    else:
        overall_summary = f"Terdeteksi {findings_count} temuan keamanan."
        overall_recommendations = [
            "Segera lakukan patching/update pada komponen dengan tingkat risiko tinggi/terkonfirmasi.",
            "Gunakan tombol 'Minta Rekomendasi AI' pada masing-masing temuan di bawah untuk langkah mitigasi spesifik."
        ]

    merged_ai_analysis = {
        "is_fallback": False,
        "findings": findings,
        "overall_severity": overall_severity,
        "overall_summary": overall_summary,
        "overall_recommendations": overall_recommendations
    }

    return render_template(
        "history_ai.html",
        h=scan,
        ai_analysis=merged_ai_analysis,
        findings_count=findings_count,
        target_info=target_info,
        api_error=api_error,
        interesting_findings=interesting_findings,
        hardening=get_hardening_report(scan)
    )


PHASE_ORDER = ["whatweb", "wpscan", "nuclei", "hardening"]
PHASE_META = {
    "whatweb": {"label": "FASE 1 - WhatWeb", "desc": "Identifikasi Teknologi", "color": "teal"},
    "wpscan": {"label": "FASE 2 - WPScan", "desc": "WP Fingerprint + Enumerasi (No-API)", "color": "orange"},
    "nuclei": {"label": "FASE 3 - Nuclei", "desc": "Exposure Detection", "color": "purple"},
    "hardening": {"label": "FASE 4 - Hardening", "desc": "Audit Hardening Eksternal", "color": "rose"},
}
LOG_PREFIXES = ("[WHATWEB]", "[WPSCAN]", "[NUCLEI]", "[HARDENING]", "[SYSTEM]")


def _extract_log_lines(raw_output):
    out = []
    for line in (raw_output or "").splitlines():
        s = line.strip()
        if s.startswith(LOG_PREFIXES) or s.startswith("\u2501\u2501\u2501"):
            out.append(s)
    return out


def _utc_to_local_str(dt):
    if not dt:
        return "\u2014"
    try:
        return dt.replace(tzinfo=timezone.utc).astimezone().strftime("%H:%M:%S")
    except Exception:
        return dt.strftime("%H:%M:%S")


def build_pipeline_timeline(scan):
    """Susun timeline 4 fase dari hasil ScanResult.
    Pipeline berjalan sekuensial, jadi start/end tiap fase dihitung kumulatif
    dari ScanHistory.scanned_at + durasi fase sebelumnya."""
    results = {r.scanner_type: r for r in (scan.results or [])}
    cursor = scan.scanned_at
    timeline = []
    for st in PHASE_ORDER:
        res = results.get(st)
        meta = PHASE_META[st]
        if res:
            duration = res.duration or 0.0
            start = cursor
            end = start + timedelta(seconds=duration) if start else start
            cursor = end
            timeline.append({
                "scanner_type": st,
                "label": meta["label"],
                "desc": meta["desc"],
                "color": meta["color"],
                "status": res.status,
                "duration": duration,
                "start_str": _utc_to_local_str(start),
                "end_str": _utc_to_local_str(end),
                "vuln_count": res.vuln_count or 0,
                "logs": _extract_log_lines(res.raw_output),
                "raw_output": res.raw_output or "",
            })
        else:
            timeline.append({
                "scanner_type": st,
                "label": meta["label"],
                "desc": meta["desc"],
                "color": meta["color"],
                "status": "missing",
                "duration": 0,
                "start_str": _utc_to_local_str(cursor),
                "end_str": _utc_to_local_str(cursor),
                "vuln_count": 0,
                "logs": [],
                "raw_output": "",
            })
    return timeline


@history_bp.route("/history/<int:scan_id>/workflow")
@login_required
def workflow_timeline(scan_id):
    scan = db.session.get(ScanHistory, scan_id)
    if not scan:
        flash("History scan tidak ditemukan.")
        return redirect(url_for("history.history"))

    timeline = build_pipeline_timeline(scan)
    return render_template("workflow.html", h=scan, timeline=timeline)


@history_bp.route("/history/<int:scan_id>/pipeline")
@login_required
def pipeline_timeline(scan_id):
    return redirect(url_for("history.workflow_timeline", scan_id=scan_id))


@history_bp.route("/history/finding/<string:finding_id>/analyze", methods=["POST"])
@login_required
def analyze_finding(finding_id):
    finding = db.session.get(ScanFinding, finding_id)
    if not finding:
        return jsonify({"success": False, "error": "Temuan tidak ditemukan"}), 404

    req_data = request.get_json(silent=True) or {}
    provider = req_data.get("provider", "gemini").strip().lower()
    if provider not in ("gemini", "anthropic", "claude"):
        return jsonify({
            "success": False,
            "error": f"Provider Gen AI '{provider}' tidak didukung. Pilih 'gemini' atau 'claude'."
        }), 400

    if not finding.ai_prompt_template and finding.confidence != "Confirmed":
        return jsonify({
            "success": False,
            "error": "Temuan ini tidak memiliki data cukup untuk pencarian CVE. Jalankan ulang scan untuk membuat data temuan lengkap."
        }), 400

    # "Analisis & Pencarian CVE via Gen AI" → hanya NOMOR CVE, NAMA, LINK.
    # "Rekomendasi Remediasi AI (Terkonfirmasi)" → tetap pakai prompt remediasi.
    if finding.confidence == "Confirmed":
        prompt = finding.ai_prompt_template
    else:
        prompt = build_cve_search_prompt({
            "component": finding.component,
            "component_name": finding.component_name,
            "version": finding.version,
            "title": finding.title,
            "evidence_summary": finding.evidence_summary,
        })

    # Call LLM with the prompt template
    try:
        response = call_llm_text(prompt, provider)
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Terjadi kesalahan tak terduga saat memanggil Gen AI ({provider}): {e}"
        }), 500

    if not response or response.strip().lower().startswith("error"):
        return jsonify({"success": False, "error": response or "Model Gen AI tidak mengembalikan respons."}), 500

    # Save to finding
    finding.ai_response = response
    db.session.commit()

    return jsonify({
        "success": True,
        "ai_response": response
    })


@history_bp.route("/history/finding/<string:finding_id>/note", methods=["POST"])
@login_required
def save_finding_note(finding_id):
    finding = db.session.get(ScanFinding, finding_id)
    if not finding:
        return jsonify({"success": False, "error": "Temuan tidak ditemukan"}), 404

    req_data = request.get_json() or {}
    note = req_data.get("note", "")

    finding.manual_note = note
    db.session.commit()

    return jsonify({"success": True})


@history_bp.route("/history/<int:scan_id>/generate/<int:vuln_idx>", methods=["POST"])
@login_required
def generate_single_recommendation(scan_id, vuln_idx):
    scan = db.session.get(ScanHistory, scan_id)
    if not scan:
        return jsonify({"success": False, "error": "Scan history tidak ditemukan"}), 404

    req_data = request.get_json(silent=True) or {}
    provider = req_data.get("provider", "gemini").strip().lower()
    if provider not in ("gemini", "anthropic", "claude"):
        return jsonify({
            "success": False,
            "error": f"Provider Gen AI '{provider}' tidak didukung. Pilih 'gemini' atau 'claude'."
        }), 400

    findings, _, _, _ = get_scan_findings_and_info(scan)
    target_vuln = None
    for f in findings:
        if f["index"] == vuln_idx:
            target_vuln = f
            break

    if not target_vuln:
        return jsonify({"success": False, "error": f"Kerentanan dengan indeks {vuln_idx} tidak ditemukan"}), 404

    # Call AI
    try:
        res = analyze_single_vulnerability(target_vuln, scan.server.url, provider)
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Terjadi kesalahan tak terduga saat memanggil Gen AI ({provider}): {e}"
        }), 500

    if not res or "error" in res:
        err_msg = res.get("error") if res else "Terjadi kesalahan yang tidak diketahui saat memanggil API Gen AI"
        return jsonify({"success": False, "error": err_msg}), 500

    # Save to Cache
    cache_dir = current_app.config.get("CACHE_DIR", "ai_cache")
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)
    json_file_path = os.path.join(cache_dir, f"scan_{scan_id}.json")

    cache_data = {}
    if os.path.exists(json_file_path):
        try:
            with open(json_file_path, "r", encoding="utf-8") as f:
                cache_data = json.load(f)
        except Exception:
            pass

    # Ensure findings is a dict
    if "findings" not in cache_data or not isinstance(cache_data["findings"], dict):
        old_findings = cache_data.get("findings", [])
        cache_data["findings"] = {}
        if isinstance(old_findings, list):
            for item in old_findings:
                if "index" in item:
                    cache_data["findings"][str(item["index"])] = item

    # Save recommendations
    ai_item = {
        "index": vuln_idx,
        "component": target_vuln["component"],
        "component_name": target_vuln["component_name"],
        "title": target_vuln["title"],
        "cve_ids": target_vuln["cve_ids"],
        "severity": res.get("severity"),
        "severity_reason": res.get("severity_reason"),
        "recommendations": res.get("recommendations"),
        "provider": provider
    }

    cache_data["findings"][str(vuln_idx)] = ai_item

    # Update overall summary/severity
    levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    highest_level = 0
    highest_name = "medium"
    for k, v in cache_data["findings"].items():
        sev = v.get("severity")
        if sev in levels and levels[sev] > highest_level:
            highest_level = levels[sev]
            highest_name = sev
    cache_data["overall_severity"] = highest_name
    cache_data["overall_summary"] = f"Dianalisis menggunakan sistem rekomendasi interaktif."

    try:
        with open(json_file_path, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, indent=4, ensure_ascii=False)
    except Exception as e:
        return jsonify({"success": False, "error": f"Gagal menulis cache file: {str(e)}"}), 500

    return jsonify({
        "success": True,
        "severity": ai_item["severity"],
        "severity_reason": ai_item["severity_reason"],
        "recommendations": ai_item["recommendations"],
        "provider": provider
    })



@history_bp.route("/history/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete_history(scan_id):
    scan = db.session.get(ScanHistory, scan_id)
    if not scan:
        flash("History scan tidak ditemukan.", "error")
        return redirect(url_for("history.history"))

    # Delete AI cache file if exists
    cache_dir = current_app.config.get("CACHE_DIR", "ai_cache")
    json_file_path = os.path.join(cache_dir, f"scan_{scan_id}.json")
    if os.path.exists(json_file_path):
        try:
            os.remove(json_file_path)
        except Exception:
            pass

    # Delete scan history from DB
    db.session.delete(scan)
    db.session.commit()

    flash("Riwayat scan berhasil dihapus.")
    return redirect(url_for("history.history"))


