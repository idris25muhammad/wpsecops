import re
from flask import Blueprint, render_template, request
from flask_login import login_required
from models import ScanFinding, ScanHistory, Server
from services.parsers import parse_hardening, parse_nuclei, parse_whatweb, parse_wpscan

riset_bp = Blueprint("riset", __name__)


def _classify_wp_group(wp_version):
    """Classify WordPress version into Grup A (Legacy), B (Mid-Era), C (Modern), or Lainnya."""
    if not wp_version or wp_version in ("-", "terdeteksi (belum diketahui)"):
        return "Lainnya"
    m = re.match(r"(\d+)\.(\d+)", str(wp_version).strip())
    if not m:
        return "Lainnya"
    major, minor = int(m.group(1)), int(m.group(2))
    ver = (major, minor)
    if ver < (5, 4):
        return "Grup A (Legacy < 5.4)"
    if ver < (6, 4):
        return "Grup B (Mid-Era 5.4–6.3)"
    return "Grup C (Modern ≥ 6.4)"


def _get_parsed(res, parser_fn):
    if not res:
        return {}
    if isinstance(res.parsed, dict) and res.parsed:
        return res.parsed
    if res.raw_output:
        return parser_fn(res.raw_output)
    return {}


def _extract_scan_metrics(scan):
    """Extract normalized per-scanner metrics from a ScanHistory."""
    results_map = {r.scanner_type: r for r in (scan.results or [])}

    ww_parsed = _get_parsed(results_map.get("whatweb"), parse_whatweb)
    wp_parsed = _get_parsed(results_map.get("wpscan"), parse_wpscan)
    nuc_parsed = _get_parsed(results_map.get("nuclei"), parse_nuclei)
    hd_parsed = _get_parsed(results_map.get("hardening"), parse_hardening)

    wp_ti = wp_parsed.get("target_info", {}) or {}
    ww_ti = ww_parsed.get("target_info", {}) or {}

    wp_version = wp_ti.get("wordpress_version") or ww_ti.get("wordpress_version") or "-"
    php_version = ww_ti.get("php_version") or "-"

    tech_count = len(ww_parsed.get("tech_stack") or ww_ti.get("technologies") or [])
    wp_comp_count = len(wp_parsed.get("components") or []) + len(wp_ti.get("config_backups") or []) + len(wp_ti.get("timthumbs") or [])
    nuclei_count = len(nuc_parsed.get("findings") or [])

    hd_summary = hd_parsed.get("summary") or {}
    hd_pass = hd_summary.get("PASS", 0)
    hd_fail = hd_summary.get("FAIL", 0)
    hd_warn = hd_summary.get("WARN", 0)
    hd_total = sum(hd_summary.values()) or 13
    hd_score = round((hd_pass / hd_total) * 100, 1) if hd_summary else 0.0

    params = scan.params or {}
    exec_mode = params.get("execution_mode", "parallel")
    plugins_det = params.get("plugins_detection", "passive")

    phase_durations = {
        st: round(results_map[st].duration or 0.0, 2) if st in results_map else 0.0
        for st in ("whatweb", "wpscan", "nuclei", "hardening")
    }

    return {
        "scan": scan,
        "exec_mode": exec_mode,
        "plugins_detection": plugins_det,
        "wp_version": wp_version,
        "php_version": php_version,
        "wp_group": _classify_wp_group(wp_version),
        "tech_count": tech_count,
        "wp_comp_count": wp_comp_count,
        "nuclei_count": nuclei_count,
        "hd_pass": hd_pass,
        "hd_fail": hd_fail,
        "hd_warn": hd_warn,
        "hd_score": hd_score,
        "phase_durations": phase_durations,
    }


@riset_bp.route("/riset")
@login_required
def riset():
    selected_server_id = request.args.get("server_id", type=int)
    all_servers = Server.query.order_by(Server.name.asc()).all()

    query = ScanHistory.query.filter_by(status="scanned").order_by(ScanHistory.scanned_at.desc())
    if selected_server_id:
        query = query.filter_by(server_id=selected_server_id)
    scans = query.all()

    metrics_list = [_extract_scan_metrics(s) for s in scans]

    # Latest scan per server
    latest_by_server = {}
    # Latest per (server_id, exec_mode) for Table 1
    by_server_mode = {}
    for m in metrics_list:
        sid = m["scan"].server_id
        if sid not in latest_by_server:
            latest_by_server[sid] = m
        key = (sid, m["exec_mode"])
        if key not in by_server_mode:
            by_server_mode[key] = m

    # ── TABEL 1: Sequential vs Async IO Parallel ─────────────────────────────
    t1_rows = []
    server_ids_seen = list(dict.fromkeys(m["scan"].server_id for m in metrics_list))
    for sid in server_ids_seen:
        seq_m = by_server_mode.get((sid, "sequential"))
        par_m = by_server_mode.get((sid, "parallel"))
        ref_m = par_m or seq_m
        srv = ref_m["scan"].server
        pd = ref_m["phase_durations"]

        seq_dur = round(seq_m["scan"].duration or 0.0, 2) if seq_m else None
        par_dur = round(par_m["scan"].duration or 0.0, 2) if par_m else None

        # Fallback estimate for sequential if only parallel was run
        est_seq = round(sum(pd.values()), 2) if sum(pd.values()) > 0 else None
        effective_seq = seq_dur if seq_dur is not None else est_seq

        speedup = round(effective_seq / par_dur, 2) if (effective_seq and par_dur and par_dur > 0) else None
        eff_pct = round(((effective_seq - par_dur) / effective_seq) * 100, 1) if (effective_seq and par_dur and effective_seq > 0) else None

        t1_rows.append({
            "server_name": srv.name if srv else f"Server #{sid}",
            "wp_group": ref_m["wp_group"],
            "t_whatweb": pd["whatweb"],
            "t_wpscan": pd["wpscan"],
            "t_nuclei": pd["nuclei"],
            "t_hardening": pd["hardening"],
            "t_seq": seq_dur,
            "t_seq_est": est_seq if seq_dur is None else None,
            "t_par": par_dur,
            "speedup": speedup,
            "eff_pct": eff_pct,
        })

    valid_speedups = [r["speedup"] for r in t1_rows if r["speedup"] is not None]
    valid_effs = [r["eff_pct"] for r in t1_rows if r["eff_pct"] is not None]
    t1_avg = {
        "speedup": round(sum(valid_speedups) / len(valid_speedups), 2) if valid_speedups else None,
        "eff_pct": round(sum(valid_effs) / len(valid_effs), 1) if valid_effs else None,
    }

    # ── TABEL 2: Cakupan Deteksi Antar-Scanner ───────────────────────────────
    t2_rows = []
    for sid, m in latest_by_server.items():
        scan = m["scan"]
        total = scan.vuln_count or 0
        nuc_pct = round((m["nuclei_count"] / total) * 100, 1) if total > 0 else 0.0
        hd_pct = round((m["hd_fail"] / total) * 100, 1) if total > 0 else 0.0
        t2_rows.append({
            "server_name": scan.server.name if scan.server else f"Server #{sid}",
            "wp_version": m["wp_version"],
            "whatweb_count": m["tech_count"],
            "wpscan_count": m["wp_comp_count"],
            "nuclei_count": m["nuclei_count"],
            "hd_fail": m["hd_fail"],
            "hd_warn": m["hd_warn"],
            "total_findings": total,
            "nuclei_pct": nuc_pct,
            "hd_pct": hd_pct,
        })

    # ── TABEL 3: Akurasi & Korelasi Confidence ───────────────────────────────
    t3_rows = []
    for sid, m in latest_by_server.items():
        scan = m["scan"]
        findings = scan.findings_list or []
        conf_counts = {"Cross-verified": 0, "Confirmed": 0, "Likely": 0, "Unconfirmed": 0}
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            if f.confidence in conf_counts:
                conf_counts[f.confidence] += 1
            sev = (f.severity or "low").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1
        total_f = len(findings)
        verified = conf_counts["Cross-verified"] + conf_counts["Confirmed"]
        verified_ratio = round((verified / total_f) * 100, 1) if total_f > 0 else 0.0

        t3_rows.append({
            "server_name": scan.server.name if scan.server else f"Server #{sid}",
            "wp_group": m["wp_group"],
            "cross_verified": conf_counts["Cross-verified"],
            "confirmed": conf_counts["Confirmed"],
            "likely": conf_counts["Likely"],
            "unconfirmed": conf_counts["Unconfirmed"],
            "sev": sev_counts,
            "total": total_f,
            "verified_ratio": verified_ratio,
        })

    # ── TABEL 4: Postur Keamanan Lintas Generasi WordPress ───────────────────
    groups_map = {}
    for sid, m in latest_by_server.items():
        g = m["wp_group"]
        groups_map.setdefault(g, []).append(m)

    t4_rows = []
    for group_name in sorted(groups_map.keys()):
        items = groups_map[group_name]
        n = len(items)
        avg_dur = round(sum((i["scan"].duration or 0.0) for i in items) / n, 2)
        avg_vulns = round(sum((i["scan"].vuln_count or 0) for i in items) / n, 1)
        avg_hd = round(sum(i["hd_score"] for i in items) / n, 1)
        colors = [i["scan"].risk_color or "blue" for i in items]
        dom_color = max(set(colors), key=colors.count)
        t4_rows.append({
            "group": group_name,
            "targets": ", ".join(i["scan"].server.name for i in items if i["scan"].server),
            "wp_versions": ", ".join(sorted({i["wp_version"] for i in items})),
            "php_versions": ", ".join(sorted({i["php_version"] for i in items})),
            "count": n,
            "avg_duration": avg_dur,
            "avg_vulns": avg_vulns,
            "avg_hd_score": avg_hd,
            "dominant_risk": dom_color,
        })

    # ── TABEL 5: Mode Deteksi (passive vs mixed vs aggressive) ───────────────
    mode_map = {"passive": [], "mixed": [], "aggressive": []}
    for m in metrics_list:
        mode = m["plugins_detection"]
        if mode in mode_map:
            mode_map[mode].append(m)

    t5_rows = []
    for mode in ("passive", "mixed", "aggressive"):
        items = mode_map[mode]
        if not items:
            t5_rows.append({
                "mode": mode, "count": 0, "avg_wpscan_dur": None,
                "avg_total_dur": None, "avg_comp": None, "avg_vulns": None, "findings_per_sec": None,
            })
            continue
        n = len(items)
        avg_wp_dur = round(sum(i["phase_durations"]["wpscan"] for i in items) / n, 2)
        avg_tot_dur = round(sum((i["scan"].duration or 0.0) for i in items) / n, 2)
        avg_comp = round(sum(i["wp_comp_count"] for i in items) / n, 1)
        avg_v = round(sum((i["scan"].vuln_count or 0) for i in items) / n, 1)
        fps = round(avg_v / avg_tot_dur, 3) if avg_tot_dur > 0 else 0.0
        t5_rows.append({
            "mode": mode,
            "count": n,
            "avg_wpscan_dur": avg_wp_dur,
            "avg_total_dur": avg_tot_dur,
            "avg_comp": avg_comp,
            "avg_vulns": avg_v,
            "findings_per_sec": fps,
        })

    return render_template(
        "riset.html",
        servers=all_servers,
        selected_server_id=selected_server_id,
        total_scanned=len(scans),
        t1_rows=t1_rows,
        t1_avg=t1_avg,
        t2_rows=t2_rows,
        t3_rows=t3_rows,
        t4_rows=t4_rows,
        t5_rows=t5_rows,
    )
