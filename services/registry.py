from dataclasses import dataclass
from typing import Callable, Dict
from services.whatweb_runner import run_whatweb
from services.wpscan_runner import run_wpscan
from services.nuclei_runner import run_nuclei
from services.hardening_runner import run_hardening
from services.parsers import parse_whatweb, parse_wpscan, parse_nuclei, parse_hardening


@dataclass(frozen=True)
class ScannerSpec:
    name: str
    phase: int
    label: str
    desc: str
    color: str
    runner: Callable
    parser: Callable
    is_async: bool
    vuln_counter: Callable[[dict, dict], int]


SCANNERS: Dict[str, ScannerSpec] = {
    "whatweb": ScannerSpec(
        name="whatweb",
        phase=1,
        label="FASE 1 - WhatWeb",
        desc="Identifikasi Teknologi",
        color="teal",
        runner=run_whatweb,
        parser=parse_whatweb,
        is_async=True,
        vuln_counter=lambda res, parsed: 0,
    ),
    "wpscan": ScannerSpec(
        name="wpscan",
        phase=2,
        label="FASE 2 - WPScan",
        desc="WP Fingerprint + Enumerasi (No-API)",
        color="orange",
        runner=run_wpscan,
        parser=parse_wpscan,
        is_async=True,
        vuln_counter=lambda res, parsed: 0,
    ),
    "nuclei": ScannerSpec(
        name="nuclei",
        phase=3,
        label="FASE 3 - Nuclei",
        desc="Exposure Detection",
        color="purple",
        runner=run_nuclei,
        parser=parse_nuclei,
        is_async=True,
        vuln_counter=lambda res, parsed: len((parsed or {}).get("findings", [])),
    ),
    "hardening": ScannerSpec(
        name="hardening",
        phase=4,
        label="FASE 4 - Hardening",
        desc="Audit Hardening Eksternal",
        color="rose",
        runner=run_hardening,
        parser=parse_hardening,
        is_async=False,
        vuln_counter=lambda res, parsed: (parsed or res or {}).get("summary", {}).get("FAIL", 0),
    ),
}

PHASE_ORDER = list(SCANNERS.keys())
