"""Render a ScanReport to Markdown (for humans) and JSON (for CI/diffing)."""
from __future__ import annotations

from ..models import ScanReport, Severity

_EMOJI = {
    Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵", Severity.INFO: "⚪",
}


def render_json(report: ScanReport) -> str:
    return report.model_dump_json(indent=2)


def render_markdown(report: ScanReport) -> str:
    counts = report.counts()
    lines: list[str] = []
    lines.append("# personal_hacker — Security Report")
    lines.append("")
    lines.append(f"- **Repo:** `{report.target_repo or '—'}`")
    lines.append(f"- **Targets:** {', '.join(report.target_urls) or '—'}")
    lines.append(f"- **Safe mode:** {'on' if report.safe_mode else 'OFF'}")
    lines.append(f"- **Started:** {report.started_at.isoformat()}")
    lines.append("")
    summary = "  ".join(
        f"{_EMOJI[s]} {s.value.title()}: {counts[s.value]}"
        for s in reversed(list(Severity)) if counts[s.value]
    )
    lines.append(f"**Summary:** {summary or 'No findings 🎉'}")
    lines.append("")

    ranked = report.ranked()
    if not ranked:
        lines.append("No findings. (Verify scope actually reached the target.)")
        return "\n".join(lines)

    for i, f in enumerate(ranked, 1):
        badge = _EMOJI[f.severity]
        xv = " ✅ cross-validated" if f.cross_validated else ""
        lines.append(f"## {i}. {badge} {f.severity.value.upper()} — {f.title}{xv}")
        lines.append("")
        lines.append(f"- **Threat class:** {f.threat_class.value}")
        lines.append(f"- **Method:** {f.method.value}")
        if f.location:
            lines.append(f"- **Location:** `{f.location}`")
        if f.evidence:
            lines.append(f"- **Evidence:** `{f.evidence}`")
        lines.append("")
        lines.append(f.detail)
        if f.remediation:
            lines.append("")
            lines.append(f"**Fix:** {f.remediation}")
        lines.append("")
    return "\n".join(lines)
