import re
from packaging.version import InvalidVersion, Version


def _token_match(slug, text):
    """Match component slug on token boundaries to avoid substring false positives."""
    if not slug or not text or len(slug) < 3:
        return False
    pattern = rf"(^|[^a-z0-9]){re.escape(slug.lower())}($|[^a-z0-9])"
    return bool(re.search(pattern, text.lower()))


def _extract_version_from_finding(nuclei_finding):
    """Best-effort version extraction from Nuclei extracted_results or description."""
    for item in nuclei_finding.get("extracted_results") or []:
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", str(item))
        if m:
            return m.group(1)
    return None


def assign_confidence(nuclei_finding, wpscan_components):
    """
    Cross-match a Nuclei finding against WPScan component list.
    Returns (confidence, matched_component_dict | None):
    - 'Cross-verified' when slug AND version both match
    - 'Confirmed' when slug matches on token boundary
    - 'Likely' when no WPScan component matches
    """
    template_id = nuclei_finding.get("template_id") or ""
    name = nuclei_finding.get("name") or ""
    extracted_ver = _extract_version_from_finding(nuclei_finding)

    for comp in wpscan_components or []:
        comp_name = comp.get("component_name") or ""
        if _token_match(comp_name, template_id) or _token_match(comp_name, name):
            comp_ver = comp.get("version")
            if extracted_ver and comp_ver:
                try:
                    if Version(str(extracted_ver)) == Version(str(comp_ver)):
                        return "Cross-verified", comp
                except InvalidVersion:
                    if str(extracted_ver) == str(comp_ver):
                        return "Cross-verified", comp
            return "Confirmed", comp

    return "Likely", None
