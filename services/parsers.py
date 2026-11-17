import json
import re


def extract_json_block(raw_output):
    """Extract the outermost JSON object or array from mixed text + JSON output."""
    if not raw_output:
        return None
    text = raw_output.strip()
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    obj_start, obj_end = text.find("{"), text.rfind("}")
    arr_start, arr_end = text.find("["), text.rfind("]")

    candidates = []
    if obj_start != -1 and obj_end > obj_start:
        candidates.append((obj_start, text[obj_start:obj_end + 1]))
    if arr_start != -1 and arr_end > arr_start:
        candidates.append((arr_start, text[arr_start:arr_end + 1]))

    for _, snippet in sorted(candidates, key=lambda x: x[0]):
        try:
            return json.loads(snippet)
        except (json.JSONDecodeError, ValueError):
            continue
    return None


def _normalize_finding_items(items):
    """Normalize WPScan dict/list finding collections into a list of dicts."""
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


def parse_whatweb(raw_output):
    """Parse WhatWeb output (JSON, JSONL, or ANSI text) into tech_stack + target_info."""
    tech_stack = {}
    target_info = {
        "wordpress_version": None,
        "server": None,
        "php_version": None,
        "ip_address": None,
        "technologies": [],
    }
    if not raw_output:
        return {"tech_stack": tech_stack, "target_info": target_info}

    text = re.sub(r"\x1b\[[0-9;]*m", "", raw_output).strip()
    data_list = []

    parsed = extract_json_block(text)
    if isinstance(parsed, list):
        data_list = parsed
    elif isinstance(parsed, dict):
        data_list = [parsed]
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line or not (line.startswith("{") or line.startswith("[")):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, list):
                    data_list.extend(obj)
                elif isinstance(obj, dict):
                    data_list.append(obj)
            except (json.JSONDecodeError, ValueError):
                continue

    if not data_list:
        for name, value in re.findall(r"([A-Za-z][A-Za-z0-9_]*)\[([^\]]*)\]", text):
            if name.lower().startswith("http"):
                continue
            tech_stack.setdefault(name, None)
            if value and tech_stack[name] is None:
                tech_stack[name] = value
            entry_str = f"{name}{': ' + value if value else ''}"
            if entry_str not in target_info["technologies"]:
                target_info["technologies"].append(entry_str)

            tech_lower = name.lower()
            if "wordpress" in tech_lower or (value and "WordPress" in value):
                m = re.search(r"WordPress\s+([\d.]+)", value)
                if m and not target_info["wordpress_version"]:
                    target_info["wordpress_version"] = m.group(1)
            elif tech_lower in ("apache", "nginx", "iis", "litespeed") and value:
                if not target_info["server"]:
                    target_info["server"] = f"{name} {value}"
            elif tech_lower == "php" and value:
                if not target_info["php_version"]:
                    target_info["php_version"] = value
            elif tech_lower == "ip" and value:
                if not target_info["ip_address"]:
                    target_info["ip_address"] = value
        return {"tech_stack": tech_stack, "target_info": target_info}

    for entry in data_list:
        if not isinstance(entry, dict):
            continue
        plugins = entry.get("plugins", {}) or {}
        for tech_name, tech_data in plugins.items():
            if not isinstance(tech_data, dict):
                continue
            versions = tech_data.get("string", []) or []
            version = versions[0] if versions else None
            tech_stack[tech_name] = version
            entry_str = f"{tech_name}{': ' + version if version else ''}"
            if entry_str not in target_info["technologies"]:
                target_info["technologies"].append(entry_str)

            tech_lower = tech_name.lower()
            if "wordpress" in tech_lower and version:
                target_info["wordpress_version"] = version
            elif tech_lower in ("apache", "nginx", "iis", "litespeed") and version:
                target_info["server"] = f"{tech_name} {version}"
            elif tech_lower == "php" and version:
                target_info["php_version"] = version

        ip = plugins.get("IP", {})
        if isinstance(ip, dict):
            ips = ip.get("string", [])
            if ips:
                target_info["ip_address"] = ips[0]

    return {"tech_stack": tech_stack, "target_info": target_info}


def parse_wpscan(raw_output):
    """Parse WPScan JSON (No-API mode) into components, target_info, and findings."""
    components = []
    target_info = {
        "wordpress_version": None,
        "main_theme": None,
        "theme_details": {},
        "themes_detected": [],
        "plugins_detected": [],
        "plugin_details": [],
        "users_detected": [],
        "user_details": [],
        "timthumbs": [],
        "config_backups": [],
        "interesting_urls": [],
        "interesting_findings": [],
        "target_ip": None,
        "effective_url": None,
        "scan_stats": {},
    }

    data = extract_json_block(raw_output)
    if not isinstance(data, dict) or "scan_aborted" in data:
        return {"components": components, "target_info": target_info, "raw_data": {}}

    version_data = data.get("version", {}) or {}
    main_theme = data.get("main_theme", {}) or {}
    plugins = data.get("plugins", {}) or {}
    themes = data.get("themes", {}) or {}
    users = data.get("users", {}) or {}
    wp_interesting = data.get("interesting_findings", []) or []

    if isinstance(version_data, dict) and version_data.get("number"):
        target_info["wordpress_version"] = version_data["number"]
    elif isinstance(version_data, dict) and version_data.get("found_by"):
        target_info["wordpress_version"] = "terdeteksi (belum diketahui)"

    target_info["target_ip"] = data.get("target_ip")
    target_info["effective_url"] = data.get("effective_url")

    stats = {}
    for k in (
        "elapsed", "requests_done", "cached_requests",
        "data_sent_humanised", "data_received_humanised", "used_memory_humanised",
    ):
        if data.get(k) is not None:
            stats[k] = data[k]
    target_info["scan_stats"] = stats

    if main_theme.get("slug") or main_theme.get("style_name"):
        target_info["main_theme"] = (
            main_theme.get("style_name") or main_theme.get("friendly_name") or main_theme.get("slug")
        )
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
        if main_theme.get("slug"):
            components.append({
                "component_type": "theme",
                "component_name": main_theme.get("slug"),
                "version": main_theme_version,
                "source": "wpscan",
                "outdated": bool(main_theme.get("outdated", False)),
                "latest_version": main_theme.get("latest_version"),
            })

    for theme_item in _normalize_finding_items(themes):
        slug = theme_item.get("slug")
        if slug and slug not in [t.get("slug") for t in target_info["themes_detected"]]:
            version_obj = theme_item.get("version")
            theme_item["version"] = version_obj.get("number") if isinstance(version_obj, dict) else None
            target_info["themes_detected"].append(theme_item)

    if isinstance(plugins, dict):
        for slug, plugin_data in plugins.items():
            if not isinstance(plugin_data, dict) or slug == "*":
                continue
            version_obj = plugin_data.get("version")
            plugin_version = version_obj.get("number") if isinstance(version_obj, dict) else None
            target_info["plugins_detected"].append(slug)
            target_info["plugin_details"].append({
                "slug": slug,
                "version": plugin_version,
                "location": plugin_data.get("location"),
                "outdated": plugin_data.get("outdated", False),
                "latest_version": plugin_data.get("latest_version"),
                "last_updated": plugin_data.get("last_updated"),
                "readme_url": plugin_data.get("readme_url"),
            })
            components.append({
                "component_type": "plugin",
                "component_name": slug,
                "version": plugin_version,
                "source": "wpscan",
                "outdated": bool(plugin_data.get("outdated", False)),
                "latest_version": plugin_data.get("latest_version"),
            })

    if isinstance(users, dict):
        for username, u_data in users.items():
            if username not in target_info["users_detected"]:
                target_info["users_detected"].append(username)
            if isinstance(u_data, dict):
                confirmed_urls = []
                confirmed_by = u_data.get("confirmed_by", {}) or {}
                if isinstance(confirmed_by, dict):
                    for _, m_data in confirmed_by.items():
                        if isinstance(m_data, dict) and m_data.get("interesting_entries"):
                            confirmed_urls.extend(m_data["interesting_entries"])
                target_info["user_details"].append({
                    "username": username,
                    "found_by": u_data.get("found_by"),
                    "confidence": u_data.get("confidence"),
                    "confirmed_urls": confirmed_urls,
                })

    target_info["timthumbs"] = _normalize_finding_items(data.get("timthumbs", {}))
    target_info["config_backups"] = _normalize_finding_items(data.get("config_backups", {}))

    for item in wp_interesting:
        if not isinstance(item, dict):
            continue
        url = item.get("url", "")
        to_s = item.get("to_s") or item.get("to_find") or item.get("interesting_entry") or url
        if url and url not in target_info["interesting_urls"]:
            target_info["interesting_urls"].append(url)
            target_info["interesting_findings"].append({
                "url": url,
                "to_find": to_s or url,
                "description": item.get("to_s") or item.get("description"),
                "type": item.get("type", "wpscan"),
                "found_by": item.get("found_by"),
                "confidence": item.get("confidence"),
                "references": item.get("references", {}) or {},
                "interesting_entries": item.get("interesting_entries", [url]),
            })

    return {"components": components, "target_info": target_info, "raw_data": data}


def parse_nuclei(raw_output):
    """Parse Nuclei JSONL output into a normalized list of finding dicts."""
    findings = []
    for line in (raw_output or "").splitlines():
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
        classification = info.get("classification", {}) or {}
        cve_ids = classification.get("cve-id", []) or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        findings.append({
            "template_id": item.get("template-id", ""),
            "name": info.get("name") or "Nuclei Finding",
            "severity": (info.get("severity") or "medium").lower(),
            "description": info.get("description", ""),
            "remediation": info.get("remediation", ""),
            "tags": info.get("tags", []) or [],
            "cve_ids": cve_ids,
            "matched_at": item.get("matched-at", ""),
            "matcher_name": item.get("matcher-name", ""),
            "extracted_results": item.get("extracted-results", []) or [],
        })
    return {"findings": findings}


def parse_hardening(raw_output):
    """Parse hardening JSON report."""
    data = extract_json_block(raw_output)
    return data if isinstance(data, dict) else {}
