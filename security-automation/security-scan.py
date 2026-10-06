#!/usr/bin/env python3
"""Cloud Security Scanner

Runs Checkov, tfsec, TFLint, Semgrep, Trivy and Gitleaks, aggregates findings,
and produces a production-style Old Mutual themed HTML report plus optional JSON.

Usage:
    ./security-scan.py <repository-name>

Examples:
    ./security-scan.py mytestcompany
    ./security-scan.py mytestcompany --format all
    ./security-scan.py mytestcompany --path ../mytestcompany

Exit codes:
  0 = security gate passed
  1 = findings detected or a scanner failed
  2 = configuration/tooling error
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


TOOLS = [
    "Checkov",
    "tfsec",
    "TFLint",
    "Semgrep",
    "Trivy",
    "Gitleaks",
]

SEVERITIES = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
]

SEV_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "UNKNOWN": 0,
}


OML_DISCLOSURE = (
    "Old Mutual Limited (OML) is a licensed Controlling Company of the "
    "Designated Old Mutual Limited Insurance Group. Registration number "
    "2017/235138/06. Entities in the Group are Licensed Financial Services "
    "Providers and Insurers that offer a broad spectrum of financial "
    "solutions to retail and corporate customers across key markets in "
    "12 countries."
)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str = "UNKNOWN"
    title: str = "Security finding"
    rule_id: str = ""
    file: str = ""
    line: str = ""
    resource: str = ""
    module: str = ""
    message: str = ""
    impact: str = ""
    resolution: str = ""
    references: list[str] = field(default_factory=list)
    code: str = ""
    scanner: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResult:
    name: str
    status: str = "PASS"
    exit_code: int = 0
    duration_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    raw_output: str = ""
    raw_error: str = ""
    version: str = "unknown"
    error: str = ""
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def severity_counts(self) -> dict[str, int]:
        c = Counter(f.severity for f in self.findings)

        return {
            s: c.get(s, 0)
            for s in SEVERITIES
        }


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def run_command(
    command: list[str],
    cwd: Path | None = None,
) -> tuple[int, str, str, float]:

    start = time.perf_counter()

    try:
        p = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
        )

        return (
            p.returncode,
            p.stdout or "",
            p.stderr or "",
            time.perf_counter() - start,
        )

    except FileNotFoundError as exc:
        return (
            127,
            "",
            str(exc),
            time.perf_counter() - start,
        )

    except Exception as exc:
        return (
            126,
            "",
            str(exc),
            time.perf_counter() - start,
        )


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def tool_version(command: str) -> str:

    if not command_exists(command):
        return "not installed"

    rc, out, err, _ = run_command(
        [command, "--version"]
    )

    text = (
        out or err
    ).strip().splitlines()

    return text[0] if text else "unknown"


def read_json(text: str) -> Any:

    text = text.strip()

    if not text:
        return {}

    try:
        return json.loads(text)

    except json.JSONDecodeError:

        # Some tools can prefix JSON with banners/warnings.
        # Try to find the first JSON object or array.
        for marker in ("{", "["):

            pos = text.find(marker)

            if pos >= 0:

                try:
                    return json.loads(
                        text[pos:]
                    )

                except json.JSONDecodeError:
                    pass

    return {}


def severity(
    value: Any,
    default: str = "UNKNOWN",
) -> str:

    if value is None:
        return default

    s = str(value).upper().strip()

    aliases = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "WARN": "MEDIUM",
        "NOTICE": "LOW",
        "CRIT": "CRITICAL",
        "MED": "MEDIUM",
        "INFORMATIONAL": "INFO",
    }

    return aliases.get(
        s,
        s if s in SEV_RANK else default,
    )


def esc(value: Any) -> str:
    return html.escape(
        "" if value is None else str(value)
    )


def rel_file(
    path: str,
    target: Path,
) -> str:

    if not path:
        return ""

    p = Path(path)

    try:
        return str(
            p.resolve().relative_to(
                target.resolve()
            )
        )

    except Exception:
        return str(p)


def code_excerpt(
    target: Path,
    file_name: str,
    line: str,
) -> str:

    if not file_name:
        return ""

    try:

        p = Path(file_name)

        if not p.is_absolute():
            p = target / p

        if (
            not p.exists()
            or not p.is_file()
            or p.stat().st_size > 1_000_000
        ):
            return ""

        lines = p.read_text(
            errors="replace"
        ).splitlines()

        nums = [
            int(x)
            for x in re.findall(
                r"\d+",
                line or "",
            )
        ]

        center = nums[0] if nums else 1

        start = max(
            1,
            center - 2,
        )

        end = min(
            len(lines),
            center + 2,
        )

        return "\n".join(
            f"{i:>5}: {lines[i - 1]}"
            for i in range(
                start,
                end + 1,
            )
        )

    except Exception:
        return ""


def html_badge(status: str) -> str:

    cls = (
        "pass"
        if status == "PASS"
        else "fail"
    )

    if status == "ERROR":
        cls = "error"

    return (
        f'<span class="status {cls}">'
        f'{esc(status)}'
        f'</span>'
    )


def sev_badge(sev: str) -> str:

    s = severity(sev)

    cls = (
        s.lower()
        if s.lower()
        in {
            "critical",
            "high",
            "medium",
            "low",
            "info",
        }
        else "unknown"
    )

    return (
        f'<span class="sev {cls}">'
        f'{esc(s)}'
        f'</span>'
    )


# ---------------------------------------------------------------------------
# Scanner Adapters
# ---------------------------------------------------------------------------

def finish_tool(
    name: str,
    target: Path,
    command: list[str],
    json_command: list[str],
    parser: Callable[
        [Any, Path],
        list[Finding],
    ],
) -> ToolResult:

    result = ToolResult(
        name=name,
        version=tool_version(
            command[0]
        ),
    )

    if not command_exists(command[0]):

        result.status = "ERROR"

        result.error = (
            f"{command[0]} is not installed "
            "or not on PATH."
        )

        return result

    rc, out, err, duration = run_command(
        command
    )

    result.exit_code = rc
    result.raw_output = out
    result.raw_error = err
    result.duration_seconds = duration

    # Run machine-readable companion scan.
    jrc, jout, jerr, _ = run_command(
        json_command
    )

    data = read_json(jout)

    if (
        not data
        and jout.strip() == ""
        and jerr.strip()
    ):
        data = read_json(jerr)

    try:

        result.findings = parser(
            data,
            target,
        )

    except Exception as exc:

        result.error = (
            f"Could not parse structured output: "
            f"{exc}"
        )

    for f in result.findings:

        f.scanner = name

        if not f.code:

            f.code = code_excerpt(
                target,
                f.file,
                f.line,
            )

    # Exit 126/127 indicate execution/tooling errors.
    if rc in (126, 127):

        result.status = "ERROR"

        result.error = (
            result.raw_error.strip()
            or f"{name} failed to execute."
        )

    else:

        result.status = (
            "FAIL"
            if result.findings
            else "PASS"
        )

    return result


def parse_checkov(
    data: Any,
    target: Path,
) -> list[Finding]:

    failed = []

    if isinstance(data, dict):

        results = data.get(
            "results",
            {},
        )

        if isinstance(results, dict):
            failed = results.get(
                "failed_checks",
                [],
            )

    elif isinstance(data, list):
        failed = data

    findings = []

    for x in failed or []:

        findings.append(
            Finding(
                severity=severity(
                    x.get("severity")
                    or x.get("check_severity")
                    or "HIGH"
                ),
                title=(
                    x.get("check_name")
                    or x.get("name")
                    or x.get("check_id")
                    or "Checkov finding"
                ),
                rule_id=(
                    x.get("check_id")
                    or x.get("id")
                    or ""
                ),
                file=rel_file(
                    x.get("file_path")
                    or x.get("file")
                    or "",
                    target,
                ),
                line=str(
                    x.get("file_line_range")
                    or x.get("file_line")
                    or ""
                ),
                resource=x.get(
                    "resource"
                ) or "",
                module=x.get(
                    "bc_check_id"
                ) or "",
                message=(
                    x.get("check_name")
                    or x.get("name")
                    or ""
                ),
                impact=x.get(
                    "guideline"
                ) or "",
                resolution=x.get(
                    "guideline"
                ) or "",
                references=[
                    x.get("guideline_url")
                ]
                if x.get("guideline_url")
                else [],
                extra={
                    k: v
                    for k, v in x.items()
                    if k not in {
                        "check_name",
                        "check_id",
                        "file_path",
                        "file_line_range",
                        "resource",
                        "guideline",
                        "guideline_url",
                    }
                },
            )
        )

    return findings


def parse_tfsec(
    data: Any,
    target: Path,
) -> list[Finding]:

    findings = []

    items = (
        data.get("results", [])
        if isinstance(data, dict)
        else data
        if isinstance(data, list)
        else []
    )

    for x in items or []:

        loc = (
            x.get("location")
            or {}
        )

        start = (
            loc.get("start_line")
            or loc.get("startLine")
            or ""
        )

        end = (
            loc.get("end_line")
            or loc.get("endLine")
            or start
        )

        line = (
            f"{start}"
            if start == end or not end
            else f"{start}-{end}"
        )

        refs = (
            x.get("links")
            or x.get("references")
            or []
        )

        if isinstance(refs, str):
            refs = [refs]

        findings.append(
            Finding(
                severity=severity(
                    x.get("severity")
                ),
                title=(
                    x.get("description")
                    or x.get("title")
                    or x.get("long_id")
                    or "tfsec finding"
                ),
                rule_id=(
                    x.get("rule_id")
                    or x.get("long_id")
                    or x.get("id")
                    or ""
                ),
                file=rel_file(
                    loc.get("filename")
                    or x.get(
                        "location",
                        {},
                    ).get(
                        "filename"
                    )
                    or "",
                    target,
                ),
                line=line,
                resource=x.get(
                    "resource"
                ) or "",
                module=x.get(
                    "module"
                ) or "",
                message=x.get(
                    "description"
                ) or "",
                impact=x.get(
                    "impact"
                ) or "",
                resolution=x.get(
                    "resolution"
                ) or "",
                references=refs,
                extra={
                    k: v
                    for k, v in x.items()
                    if k not in {
                        "description",
                        "title",
                        "rule_id",
                        "long_id",
                        "location",
                        "resource",
                        "module",
                        "impact",
                        "resolution",
                        "links",
                        "references",
                    }
                },
            )
        )

    return findings


def parse_tflint(
    data: Any,
    target: Path,
) -> list[Finding]:

    diagnostics = (
        data.get("issues", [])
        if isinstance(data, dict)
        else []
    )

    findings = []

    for x in diagnostics:

        rng = (
            x.get("range")
            or {}
        )

        filename = (
            rng.get("filename")
            or x.get("filename")
            or ""
        )

        start = (
            (rng.get("start") or {}).get(
                "line"
            )
            or x.get("line")
            or ""
        )

        end = (
            (rng.get("end") or {}).get(
                "line"
            )
            or start
        )

        line = (
            str(start)
            if start == end or not end
            else f"{start}-{end}"
        )

        findings.append(
            Finding(
                severity=severity(
                    x.get("severity"),
                    "MEDIUM",
                ),
                title=(
                    x.get("message")
                    or x.get("rule")
                    or "TFLint issue"
                ),
                rule_id=x.get(
                    "rule"
                ) or "",
                file=rel_file(
                    filename,
                    target,
                ),
                line=line,
                message=x.get(
                    "message"
                ) or "",
                resolution=x.get(
                    "link"
                ) or "",
                references=[
                    x.get("link")
                ]
                if x.get("link")
                else [],
            )
        )

    return findings


def parse_semgrep(
    data: Any,
    target: Path,
) -> list[Finding]:

    findings = []

    for x in (
        data.get(
            "results",
            [],
        )
        if isinstance(data, dict)
        else []
    ):

        extra = (
            x.get("extra")
            or {}
        )

        start = (
            (x.get("start") or {}).get(
                "line"
            )
            or ""
        )

        end = (
            (x.get("end") or {}).get(
                "line"
            )
            or start
        )

        line = (
            str(start)
            if start == end or not end
            else f"{start}-{end}"
        )

        metadata = (
            extra.get("metadata")
            or {}
        )

        refs = (
            metadata.get(
                "references"
            )
            or []
        )

        if isinstance(refs, str):
            refs = [refs]

        findings.append(
            Finding(
                severity=severity(
                    extra.get("severity")
                    or metadata.get(
                        "severity"
                    ),
                    "MEDIUM",
                ),
                title=(
                    extra.get("message")
                    or x.get("check_id")
                    or "Semgrep finding"
                ),
                rule_id=x.get(
                    "check_id"
                ) or "",
                file=rel_file(
                    x.get("path")
                    or "",
                    target,
                ),
                line=line,
                resource=metadata.get(
                    "technology"
                ) or "",
                message=extra.get(
                    "message"
                ) or "",
                impact=metadata.get(
                    "impact"
                ) or "",
                resolution=(
                    metadata.get("fix")
                    or metadata.get(
                        "fix_regex"
                    )
                    or ""
                ),
                references=refs,
                code=extra.get(
                    "lines"
                ) or "",
                extra={
                    "metadata": metadata
                },
            )
        )

    return findings


def parse_trivy(
    data: Any,
    target: Path,
) -> list[Finding]:

    findings = []

    if not isinstance(data, dict):
        return findings

    for result in (
        data.get("Results", [])
        or []
    ):

        target_name = (
            result.get("Target")
            or ""
        )

        # IaC misconfigurations
        for x in (
            result.get(
                "Misconfigurations",
                [],
            )
            or []
        ):

            findings.append(
                Finding(
                    severity=severity(
                        x.get("Severity")
                    ),
                    title=(
                        x.get("Title")
                        or x.get("ID")
                        or "Trivy misconfiguration"
                    ),
                    rule_id=x.get(
                        "ID"
                    ) or "",
                    file=rel_file(
                        target_name,
                        target,
                    ),
                    line="",
                    resource=(
                        x.get(
                            "IacMetadata",
                            {},
                        ).get(
                            "Resource"
                        )
                        or ""
                    ),
                    message=x.get(
                        "Message"
                    ) or "",
                    impact=x.get(
                        "Description"
                    ) or "",
                    resolution=x.get(
                        "Resolution"
                    ) or "",
                    references=(
                        [x.get("PrimaryURL")]
                        if x.get("PrimaryURL")
                        else []
                    ),
                    code=(
                        x.get(
                            "Code",
                            {},
                        ).get(
                            "Lines",
                            [{}],
                        )[0].get(
                            "Content",
                            "",
                        )
                        if isinstance(
                            x.get("Code"),
                            dict,
                        )
                        else ""
                    ),
                )
            )

        # Vulnerabilities
        for x in (
            result.get(
                "Vulnerabilities",
                [],
            )
            or []
        ):

            findings.append(
                Finding(
                    severity=severity(
                        x.get("Severity")
                    ),
                    title=(
                        x.get("Title")
                        or x.get(
                            "VulnerabilityID"
                        )
                        or "Trivy vulnerability"
                    ),
                    rule_id=x.get(
                        "VulnerabilityID"
                    ) or "",
                    file=rel_file(
                        target_name,
                        target,
                    ),
                    message=x.get(
                        "Description"
                    ) or "",
                    resolution=(
                        f"Upgrade to "
                        f"{x.get('FixedVersion')}"
                        if x.get(
                            "FixedVersion"
                        )
                        else
                        "Review and remediate "
                        "the vulnerable dependency."
                    ),
                    references=[
                        x.get(
                            "PrimaryURL"
                        )
                    ]
                    if x.get("PrimaryURL")
                    else [],
                    extra={
                        "package": x.get(
                            "PkgName"
                        ),
                        "installed": x.get(
                            "InstalledVersion"
                        ),
                        "fixed": x.get(
                            "FixedVersion"
                        ),
                    },
                )
            )

        # Secrets
        for x in (
            result.get(
                "Secrets",
                [],
            )
            or []
        ):

            findings.append(
                Finding(
                    severity=severity(
                        x.get(
                            "Severity"
                        ),
                        "HIGH",
                    ),
                    title=(
                        x.get("Title")
                        or "Secret detected"
                    ),
                    rule_id=x.get(
                        "RuleID"
                    ) or "",
                    file=rel_file(
                        target_name,
                        target,
                    ),
                    line=str(
                        x.get(
                            "StartLine"
                        )
                        or ""
                    ),
                    message=(
                        "Potential secret detected. "
                        "Secret value is intentionally "
                        "not included in this report."
                    ),
                    resolution=(
                        "Remove the secret from source "
                        "control and rotate the credential "
                        "if it is valid."
                    ),
                )
            )

    return findings


def parse_gitleaks(
    data: Any,
    target: Path,
) -> list[Finding]:

    findings = []

    items = (
        data
        if isinstance(data, list)
        else data.get(
            "findings",
            [],
        )
        if isinstance(data, dict)
        else []
    )

    for x in items or []:

        findings.append(
            Finding(
                severity=severity(
                    x.get("Severity"),
                    "HIGH",
                ),
                title=(
                    x.get("Description")
                    or x.get("RuleID")
                    or "Secret detected"
                ),
                rule_id=x.get(
                    "RuleID"
                ) or "",
                file=rel_file(
                    x.get("File")
                    or "",
                    target,
                ),
                line=(
                    f"{x.get('StartLine', '')}"
                    f"-{x.get('EndLine', '')}"
                ).strip("-")
                if x.get("StartLine")
                else "",
                message=(
                    "Potential secret detected. "
                    "Secret value is intentionally "
                    "redacted."
                ),
                resolution=(
                    "Remove the secret from source control "
                    "and rotate/revoke the credential."
                ),
                extra={
                    "commit": x.get(
                        "Commit"
                    ),
                    "author": x.get(
                        "AuthorEmail"
                    ),
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Scanner Commands
# ---------------------------------------------------------------------------

def scan_checkov(
    target: Path,
) -> ToolResult:

    return finish_tool(
        "Checkov",
        target,
        [
            "checkov",
            "-d",
            str(target),
            "--quiet",
        ],
        [
            "checkov",
            "-d",
            str(target),
            "-o",
            "json",
            "--quiet",
        ],
        parse_checkov,
    )


def scan_tfsec(
    target: Path,
) -> ToolResult:

    return finish_tool(
        "tfsec",
        target,
        [
            "tfsec",
            str(target),
        ],
        [
            "tfsec",
            str(target),
            "--format",
            "json",
        ],
        parse_tfsec,
    )


def scan_tflint(
    target: Path,
) -> ToolResult:

    # Init is intentionally best-effort.
    if command_exists("tflint"):
        run_command(
            [
                "tflint",
                "--init",
            ],
            cwd=target,
        )

    return finish_tool(
        "TFLint",
        target,
        [
            "tflint",
            "--recursive",
        ],
        [
            "tflint",
            "--recursive",
            "--format",
            "json",
        ],
        parse_tflint,
    )


def scan_semgrep(
    target: Path,
) -> ToolResult:

    return finish_tool(
        "Semgrep",
        target,
        [
            "semgrep",
            "scan",
            "--config",
            "auto",
            str(target),
        ],
        [
            "semgrep",
            "scan",
            "--config",
            "auto",
            "--json",
            str(target),
        ],
        parse_semgrep,
    )


def scan_trivy(
    target: Path,
) -> ToolResult:

    return finish_tool(
        "Trivy",
        target,
        [
            "trivy",
            "fs",
            "--scanners",
            "misconfig,secret,vuln",
            str(target),
        ],
        [
            "trivy",
            "fs",
            "--scanners",
            "misconfig,secret,vuln",
            "--format",
            "json",
            str(target),
        ],
        parse_trivy,
    )


def scan_gitleaks(
    target: Path,
) -> ToolResult:

    return finish_tool(
        "Gitleaks",
        target,
        [
            "gitleaks",
            "detect",
            "--source",
            str(target),
            "--no-banner",
        ],
        [
            "gitleaks",
            "detect",
            "--source",
            str(target),
            "--no-banner",
            "--report-format",
            "json",
        ],
        parse_gitleaks,
    )


# ---------------------------------------------------------------------------
# Report Styling
# ---------------------------------------------------------------------------

CSS = r"""
:root{--green:#00866a;--green-dark:#006b55;--green-light:#e9f6f1;--green-pale:#f5fbf8;--text:#17332b;--muted:#61746e;--border:#d8e5df;--critical:#a51d2d;--high:#c45a00;--medium:#9b7600;--low:#47759a;--info:#667085;--white:#fff;--shadow:0 4px 18px rgba(17,53,43,.08)}
*{box-sizing:border-box}
body{margin:0;background:#f4f7f5;color:var(--text);font-family:Arial,Helvetica,sans-serif;line-height:1.5}
.page{max-width:1280px;margin:0 auto;background:#fff;min-height:100vh;box-shadow:0 0 30px rgba(0,0,0,.05)}
.header{background:linear-gradient(135deg,#006b55,#00866a 58%,#22a878);color:#fff;padding:34px 44px 38px}
.brand{display:flex;align-items:center;gap:18px}
.logo{width:235px;max-height:95px;object-fit:contain;object-position:left center;background:#fff;padding:7px 10px;border-radius:5px}
.brand-title{font-size:16px;font-weight:700;letter-spacing:.8px;text-transform:uppercase}
.brand-sub{font-size:13px;opacity:.85}
.header-rule{height:1px;background:rgba(255,255,255,.35);margin:26px 0}
.header h1{margin:0;font-size:32px;line-height:1.15}
.meta{display:flex;gap:25px;flex-wrap:wrap;margin-top:15px;font-size:13px;opacity:.95}
.gate{display:inline-block;margin-top:24px;padding:9px 16px;border-radius:5px;background:#fff;color:var(--green-dark);font-weight:800;letter-spacing:.4px}
.gate.fail{color:var(--critical)}
.content{padding:34px 44px}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:30px}
.card{border:1px solid var(--border);border-radius:8px;padding:20px;background:#fff;box-shadow:var(--shadow)}
.label{font-size:11px;color:var(--muted);font-weight:800;letter-spacing:1px}
.metric{font-size:30px;font-weight:800;margin-top:4px}
.metric.critical{color:var(--critical)}
.section{margin-top:30px}
.section-title{font-size:19px;font-weight:800;color:var(--green-dark);border-bottom:2px solid var(--green);padding-bottom:9px;margin-bottom:15px}
.section-note{color:var(--muted);font-size:13px;margin:-5px 0 15px}
.table-wrap{overflow:auto;border:1px solid var(--border);border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:var(--green-pale);color:var(--green-dark);text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.6px}
th,td{padding:11px 13px;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:0}
.status{display:inline-block;padding:3px 9px;border-radius:12px;font-size:11px;font-weight:800}
.status.pass{background:#e6f5ee;color:#08704f}
.status.fail{background:#fdeaea;color:#a51d2d}
.status.error{background:#fff1e5;color:#a24d00}
.scanner{border:1px solid var(--border);border-radius:9px;margin:18px 0;overflow:hidden;box-shadow:var(--shadow)}
.scanner-head{display:flex;justify-content:space-between;align-items:center;gap:15px;background:var(--green-pale);padding:15px 18px;border-bottom:1px solid var(--border)}
.scanner-head h3{margin:0;color:var(--green-dark)}
.scanner-body{padding:18px}
.finding{border:1px solid var(--border);border-left:5px solid #b9cbc3;border-radius:6px;padding:15px;margin:12px 0;background:#fff}
.finding h4{margin:0 0 12px;font-size:15px}
.finding-meta{display:grid;grid-template-columns:125px 1fr;gap:6px;font-size:13px}
.finding-meta b{color:var(--muted)}
.sev{display:inline-block;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:900;letter-spacing:.4px;vertical-align:2px}
.sev.critical{background:#f8dadd;color:#8e1826}
.sev.high{background:#fde5d1;color:#a34b00}
.sev.medium{background:#fff2bf;color:#7d6000}
.sev.low{background:#deedf7;color:#315e7b}
.sev.info,.sev.unknown{background:#e9edf0;color:#56636c}
.critical{color:var(--critical)}
.high{color:var(--high)}
.medium{color:var(--medium)}
.low{color:var(--low)}
.references a{color:var(--green-dark);word-break:break-all}
.code,pre{background:#17231f;color:#eaf4ef;border-radius:6px;padding:14px;overflow:auto;font:12px/1.55 "SFMono-Regular",Consolas,monospace}
.code{margin-top:12px}
.details{margin-top:14px}
details{border-top:1px solid var(--border);padding-top:10px}
summary{cursor:pointer;color:var(--green-dark);font-weight:800}
.error-box{background:#fff3f2;border-left:4px solid var(--critical);padding:13px;margin-bottom:12px}
.gate-box{border:1px solid var(--border);border-radius:8px;padding:22px;background:var(--green-pale)}
.gate-box.failed{background:#fff5f5;border-color:#f0cccc}
.footer{margin-top:40px;background:#f2f5f3;border-top:1px solid var(--border);padding:22px 44px;color:var(--muted);font-size:11px}
.footer strong{color:var(--green-dark)}
@media(max-width:900px){
.header,.content,.footer{padding-left:20px;padding-right:20px}
.cards{grid-template-columns:repeat(2,1fr)}
.brand{align-items:flex-start;flex-direction:column}
.logo{width:220px}
.finding-meta{grid-template-columns:1fr}
}
"""


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

def load_logo_data(
    logo: Path | None,
) -> str:

    if not logo or not logo.exists():
        return ""

    suffix = logo.suffix.lower()

    if suffix == ".png":
        mime = "image/png"
    elif suffix in {".jpg", ".jpeg"}:
        mime = "image/jpeg"
    else:
        return ""

    return (
        f"data:{mime};base64,"
        + base64.b64encode(
            logo.read_bytes()
        ).decode("ascii")
    )


def render_finding(
    f: Finding,
) -> str:

    meta = []

    for label, value in [
        (
            "Rule / Check ID",
            f.rule_id,
        ),
        (
            "Location",
            f.file
            + (
                ":"
                + f.line
                if f.line
                else ""
            ),
        ),
        (
            "Resource",
            f.resource,
        ),
        (
            "Module",
            f.module,
        ),
        (
            "Message",
            f.message,
        ),
        (
            "Impact",
            f.impact,
        ),
        (
            "Resolution",
            f.resolution,
        ),
    ]:

        if value:

            meta.append(
                f"<b>{esc(label)}</b>"
                f"<span>{esc(value)}</span>"
            )

    refs = ""

    valid_refs = [
        r
        for r in f.references
        if r
    ]

    if valid_refs:

        links = " ".join(
            f'<a href="{esc(r)}" '
            f'target="_blank" '
            f'rel="noopener noreferrer">'
            f'{esc(r)}</a>'
            for r in valid_refs
        )

        meta.append(
            '<b>References</b>'
            f'<span class="references">'
            f'{links}'
            f'</span>'
        )

    code = ""

    if f.code:

        code = (
            '<div class="code">'
            '<strong>Source / code</strong>'
            f'<pre>{esc(f.code)}</pre>'
            '</div>'
        )

    return (
        '<div class="finding">'
        f'<h4>{sev_badge(f.severity)}'
        f' &nbsp; {esc(f.title)}</h4>'
        f'<div class="finding-meta">'
        f'{"".join(meta)}'
        f'</div>'
        f'{code}'
        '</div>'
    )


def build_html(
    target: Path,
    results: list[ToolResult],
    generated: datetime,
    logo_data: str,
    report_name: str,
    repo_name: str,
) -> str:

    total = sum(
        r.finding_count
        for r in results
    )

    sev = Counter(
        f.severity
        for r in results
        for f in r.findings
    )

    passed = sum(
        r.status == "PASS"
        for r in results
    )

    failed = sum(
        r.status == "FAIL"
        for r in results
    )

    errors = sum(
        r.status == "ERROR"
        for r in results
    )

    gate_failed = (
        failed > 0
        or errors > 0
    )

    gate_text = (
        "FAILED"
        if gate_failed
        else "PASSED"
    )

    gate_class = (
        "fail"
        if gate_failed
        else ""
    )

    if logo_data:

        logo = (
            '<img class="logo" '
            'src="'
            + logo_data
            + '" alt="Old Mutual" />'
        )

    else:

        logo = (
            '<div class="brand-title">'
            'OLD MUTUAL'
            '</div>'
        )

    # ---------------------------------------------------------
    # Scanner overview
    # ---------------------------------------------------------

    overview_rows = []

    for r in results:

        sc = r.severity_counts

        overview_rows.append(
            "<tr>"
            f"<td><strong>{esc(r.name)}</strong>"
            f"<br><small>{esc(r.version)}</small></td>"
            f"<td>{html_badge(r.status)}</td>"
            f"<td>{r.finding_count}</td>"
            f"<td>{sc['CRITICAL']}</td>"
            f"<td>{sc['HIGH']}</td>"
            f"<td>{sc['MEDIUM']}</td>"
            f"<td>{sc['LOW']}</td>"
            f"<td>{r.duration_seconds:.2f}s</td>"
            "</tr>"
        )

    # ---------------------------------------------------------
    # Detailed scanner results
    # ---------------------------------------------------------

    scanner_sections = []

    for r in results:

        body = ""

        if r.error:

            body += (
                '<div class="error-box">'
                '<strong>Scanner error:</strong> '
                f'{esc(r.error)}'
                '</div>'
            )

        if r.findings:

            body += "".join(
                render_finding(f)
                for f in r.findings
            )

        else:

            body += (
                "<p>"
                "No findings reported by this scanner."
                "</p>"
            )

        raw = r.raw_output.strip()

        if r.raw_error.strip():

            raw += (
                "\n\n--- STDERR ---\n"
                + r.raw_error.strip()
            )

        body += (
            '<div class="details">'
            '<details>'
            f'<summary>▶ View raw '
            f'{esc(r.name)} output</summary>'
            '<pre>'
            f'{esc(raw) if raw else "No raw output captured."}'
            '</pre>'
            '</details>'
            '</div>'
        )

        scanner_sections.append(
            '<div class="scanner">'
            '<div class="scanner-head">'
            f'<h3>{esc(r.name)}</h3>'
            f'<span>{html_badge(r.status)}'
            f' &nbsp; {r.finding_count} findings'
            '</span>'
            '</div>'
            '<div class="scanner-body">'
            f'<div class="section-note">'
            f'Version: {esc(r.version)} · '
            f'Exit code: {r.exit_code} · '
            f'Duration: '
            f'{r.duration_seconds:.2f}s'
            f'</div>'
            f'{body}'
            '</div>'
            '</div>'
        )

    # ---------------------------------------------------------
    # Severity summary
    # ---------------------------------------------------------

    summary_rows = []

    for s in SEVERITIES[:4]:

        n = sev.get(
            s,
            0,
        )

        pct = (
            n / total * 100
            if total
            else 0
        )

        summary_rows.append(
            f'<tr>'
            f'<td class="{s.lower()}">'
            f'{s.title()}'
            f'</td>'
            f'<td>{n}</td>'
            f'<td>{pct:.0f}%</td>'
            f'</tr>'
        )

    # ---------------------------------------------------------
    # Gate reason
    # ---------------------------------------------------------

    gate_reasons = []

    if failed:

        gate_reasons.append(
            f"{failed} scanner(s) "
            "reported findings"
        )

    if errors:

        gate_reasons.append(
            f"{errors} scanner(s) "
            "encountered execution/"
            "configuration errors"
        )

    reason = (
        "; ".join(gate_reasons)
        if gate_reasons
        else
        "No findings were reported by "
        "the configured scanners."
    )

    # ---------------------------------------------------------
    # HTML
    # ---------------------------------------------------------

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">
<title>{esc(report_name)}</title>
<style>{CSS}</style>
</head>

<body>

<div class="page">

<header class="header">

<div class="brand">

{logo}

<div>

<div class="brand-title">
Cloud Security Assurance
</div>

<div class="brand-sub">
Security Automation Assessment
</div>

</div>

</div>

<div class="header-rule"></div>

<h1>
Cloud Security Scan Report
</h1>

<div class="meta">

<span>
<strong>Repository:</strong>
{esc(repo_name)}
</span>

<span>
<strong>Target:</strong>
{esc(target)}
</span>

<span>
<strong>Generated:</strong>
{generated.strftime('%d %B %Y %H:%M:%S UTC')}
</span>

<span>
<strong>Scanner:</strong>
security-scan.py
</span>

</div>

<div class="gate {gate_class}">
{('❌' if gate_failed else '✓')}
OVERALL SECURITY GATE:
{gate_text}
</div>

</header>

<main class="content">

<div class="cards">

<div class="card">
<div class="label">SCANNERS</div>
<div class="metric">{len(results)}</div>
</div>

<div class="card">
<div class="label">PASSED</div>
<div class="metric">{passed}</div>
</div>

<div class="card">
<div class="label">FAILED</div>
<div class="metric">
{failed + errors}
</div>
</div>

<div class="card">
<div class="label">TOTAL FINDINGS</div>
<div class="metric">{total}</div>
</div>

<div class="card">
<div class="label">CRITICAL</div>
<div class="metric critical">
{sev.get('CRITICAL', 0)}
</div>
</div>

</div>


<section class="section">

<div class="section-title">
Scan Overview
</div>

<div class="table-wrap">

<table>

<thead>

<tr>
<th>Tool</th>
<th>Status</th>
<th>Findings</th>
<th>Critical</th>
<th>High</th>
<th>Medium</th>
<th>Low</th>
<th>Duration</th>
</tr>

</thead>

<tbody>
{''.join(overview_rows)}
</tbody>

</table>

</div>

</section>


<section class="section">

<div class="section-title">
Detailed Scanner Results
</div>

<p class="section-note">
Each scanner retains its native CLI output while
structured findings are normalized for cross-tool
reporting. Secret values are never rendered.
</p>

{''.join(scanner_sections)}

</section>


<section class="section">

<div class="section-title">
Findings Summary
</div>

<div class="table-wrap">

<table>

<thead>

<tr>
<th>Severity</th>
<th>Count</th>
<th>Percentage</th>
</tr>

</thead>

<tbody>
{''.join(summary_rows)}
</tbody>

</table>

</div>

</section>


<section class="section">

<div class="section-title">
Final Security Gate
</div>

<div class="gate-box {'failed' if gate_failed else ''}">

<h2 class="{'critical' if gate_failed else ''}">
{
    '❌ SECURITY GATE: FAILED'
    if gate_failed
    else
    '✓ SECURITY GATE: PASSED'
}
</h2>

<p>
{esc(reason)}.
</p>

<p>

<strong>Critical:</strong>
{sev.get('CRITICAL', 0)}

&nbsp;

<strong>High:</strong>
{sev.get('HIGH', 0)}

&nbsp;

<strong>Medium:</strong>
{sev.get('MEDIUM', 0)}

&nbsp;

<strong>Low:</strong>
{sev.get('LOW', 0)}

</p>

</div>

</section>

</main>


<footer class="footer">

<strong>
Cloud Security Assurance
</strong>

· Generated by security-scan.py
· Internal Use

<br>
<br>

{esc(OML_DISCLOSURE)}

</footer>

</div>

</body>
</html>
"""


# ---------------------------------------------------------------------------
# JSON Aggregation
# ---------------------------------------------------------------------------

def aggregate_json(
    target: Path,
    results: list[ToolResult],
    generated: datetime,
    repo_name: str,
) -> dict[str, Any]:

    total = sum(
        r.finding_count
        for r in results
    )

    severity_counts = Counter(
        f.severity
        for r in results
        for f in r.findings
    )

    gate_failed = any(
        r.status != "PASS"
        for r in results
    )

    return {

        "report": {
            "generated_at": generated.isoformat(),
            "repository": repo_name,
            "target": str(target),
            "scanner": "security-scan.py",
            "security_gate": (
                "FAIL"
                if gate_failed
                else "PASS"
            ),
        },

        "summary": {

            "scanners": len(results),

            "passed": sum(
                r.status == "PASS"
                for r in results
            ),

            "failed": sum(
                r.status != "PASS"
                for r in results
            ),

            "findings": total,

            "severity": {
                s: severity_counts.get(
                    s,
                    0,
                )
                for s in SEVERITIES
            },
        },

        "scanners": [
            {
                **asdict(r),
                "severity_counts":
                    r.severity_counts,
            }
            for r in results
        ],
    }


# ---------------------------------------------------------------------------
# Command Line Arguments
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:

    p = argparse.ArgumentParser(
        description=(
            "Run cloud/IaC security scanners "
            "and generate HTML/JSON reports."
        )
    )

    p.add_argument(
        "repo",
        nargs="?",
        help=(
            "Repository name to scan. If --path "
            "is not supplied, the repository is "
            "expected to be located beside the "
            "security-automation directory."
        ),
    )

    p.add_argument(
        "--path",
        default=None,
        help=(
            "Explicit directory to scan. If omitted, "
            "the repository name is resolved relative "
            "to the security-automation directory."
        ),
    )

    p.add_argument(
        "--format",
        choices=[
            "html",
            "json",
            "both",
            "all",
        ],
        default="both",
        help=(
            "Output format. "
            "'all' is an alias for 'both'."
        ),
    )

    p.add_argument(
        "--output",
        default=None,
        help=(
            "Optional HTML output path. "
            "Defaults to "
            "results/<repo>-security-scan-report.html"
        ),
    )

    p.add_argument(
        "--json-output",
        default=None,
        help=(
            "Optional JSON output path. "
            "Defaults to "
            "results/<repo>-security-scan-results.json"
        ),
    )

    p.add_argument(
        "--logo",
        default=None,
        help=(
            "Optional path to Old Mutual logo PNG/JPG. "
            "Defaults to assets/old-mutual-logo.png"
        ),
    )

    p.add_argument(
        "--name",
        default=None,
        help=(
            "Optional report title."
        ),
    )

    p.add_argument(
        "--no-tflint-init",
        action="store_true",
        help=(
            "Skip TFLint plugin initialization."
        ),
    )

    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:

    args = parse_args()

    script_dir = (
        Path(__file__)
        .resolve()
        .parent
    )

    results_dir = (
        script_dir / "results"
    )

    assets_dir = (
        script_dir / "assets"
    )

    # ---------------------------------------------------------
    # Determine repository name
    # ---------------------------------------------------------

    if args.repo:

        repo_name = Path(
            args.repo
        ).name

    elif args.path:

        repo_name = Path(
            args.path
        ).resolve().name

    else:

        print(
            "ERROR: repository name or "
            "--path must be supplied.",
            file=sys.stderr,
        )

        print(
            "Example: "
            "./security-scan.py mytestcompany",
            file=sys.stderr,
        )

        return 2

    # ---------------------------------------------------------
    # Determine target repository
    # ---------------------------------------------------------

    if args.path:

        target = (
            Path(args.path)
            .expanduser()
            .resolve()
        )

    else:

        # Expected layout:
        #
        # Assessment-Mbali/
        # ├── security-automation/
        # │   └── security-scan.py
        # └── mytestcompany/
        #
        target = (
            script_dir.parent
            / repo_name
        )

    if (
        not target.exists()
        or not target.is_dir()
    ):

        print(
            "ERROR: repository does not exist "
            "or is not a directory: "
            f"{target}",
            file=sys.stderr,
        )

        return 2

    # ---------------------------------------------------------
    # Output format
    # ---------------------------------------------------------

    output_format = (
        "both"
        if args.format == "all"
        else args.format
    )

    # ---------------------------------------------------------
    # Results directory
    # ---------------------------------------------------------

    results_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    # ---------------------------------------------------------
    # Output filenames
    # ---------------------------------------------------------

    html_output = (

        Path(args.output)
        .expanduser()
        .resolve()

        if args.output

        else
        results_dir
        / f"{repo_name}-security-scan-report.html"
    )

    json_output = (

        Path(args.json_output)
        .expanduser()
        .resolve()

        if args.json_output

        else
        results_dir
        / f"{repo_name}-security-scan-results.json"
    )

    # ---------------------------------------------------------
    # Report title
    # ---------------------------------------------------------

    report_name = (

        args.name

        if args.name

        else
        f"Cloud Security Scan Report - {repo_name}"
    )

    # ---------------------------------------------------------
    # Logo
    # ---------------------------------------------------------

    if args.logo:

        logo_path = (
            Path(args.logo)
            .expanduser()
            .resolve()
        )

    else:

        logo_path = (
            assets_dir
            / "old-mutual-logo.png"
        )

    logo_data = load_logo_data(
        logo_path
    )

    # ---------------------------------------------------------
    # Console header
    # ---------------------------------------------------------

    print("=" * 64)
    print(" Cloud Security Scanner")
    print("=" * 64)
    print(
        f"Repository: {repo_name}"
    )
    print(
        f"Target:     {target}"
    )
    print(
        f"Results:    {results_dir}"
    )
    print()

    # ---------------------------------------------------------
    # Scanner list
    # ---------------------------------------------------------

    scanners = [
        scan_checkov,
        scan_tfsec,
    ]

    if args.no_tflint_init:

        scanners.append(
            lambda p:
                finish_tool(
                    "TFLint",
                    p,
                    [
                        "tflint",
                        "--recursive",
                    ],
                    [
                        "tflint",
                        "--recursive",
                        "--format",
                        "json",
                    ],
                    parse_tflint,
                )
        )

    else:

        scanners.append(
            scan_tflint
        )

    scanners += [
        scan_semgrep,
        scan_trivy,
        scan_gitleaks,
    ]

    # ---------------------------------------------------------
    # Execute scanners
    # ---------------------------------------------------------

    results: list[ToolResult] = []

    for scanner in scanners:

        name = (
            scanner.__name__
            .replace(
                "scan_",
                "",
            )
            .upper()
        )

        print(
            f"[SCAN] {name}..."
        )

        r = scanner(target)

        results.append(r)

        print(
            f"       {r.status}: "
            f"{r.finding_count} findings "
            f"({r.duration_seconds:.2f}s)"
        )

        if r.error:

            print(
                f"       {r.error}"
            )

    # ---------------------------------------------------------
    # Generate reports
    # ---------------------------------------------------------

    generated = datetime.now(
        timezone.utc
    )

    if output_format in (
        "html",
        "both",
    ):

        html_output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        html_output.write_text(
            build_html(
                target,
                results,
                generated,
                logo_data,
                report_name,
                repo_name,
            ),
            encoding="utf-8",
        )

        print(
            f"\n[OK] HTML report: "
            f"{html_output}"
        )

    if output_format in (
        "json",
        "both",
    ):

        json_output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        json_output.write_text(
            json.dumps(
                aggregate_json(
                    target,
                    results,
                    generated,
                    repo_name,
                ),
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )

        print(
            f"[OK] JSON results: "
            f"{json_output}"
        )

    # ---------------------------------------------------------
    # Security gate
    # ---------------------------------------------------------

    gate_failed = any(
        r.status != "PASS"
        for r in results
    )

    print()

    print(
        "SECURITY GATE: "
        f"{'FAIL' if gate_failed else 'PASS'}"
    )

    return (
        1
        if gate_failed
        else 0
    )


if __name__ == "__main__":
    raise SystemExit(
        main()
    )