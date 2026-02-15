"""
Report Generator Module

Generates structured scan reports in JSON and HTML formats from
port scan, network mapping, and vulnerability assessment results.

The HTML report uses inline CSS for a clean, professional appearance
without external dependencies. Reports include executive summaries,
detailed findings, and visual severity indicators.

Usage:
    generator = ReportGenerator()
    generator.add_port_scan(scan_result)
    generator.add_vuln_report(vuln_report)
    generator.generate_json("report.json")
    generator.generate_html("report.html")
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from netsec_toolkit.port_scanner import ScanResult
from netsec_toolkit.network_mapper import NetworkMap
from netsec_toolkit.vuln_checker import VulnReport


@dataclass
class ReportData:
    """Container for all scan data to be included in a report."""
    port_scans: list[ScanResult] = field(default_factory=list)
    network_maps: list[NetworkMap] = field(default_factory=list)
    vuln_reports: list[VulnReport] = field(default_factory=list)


# Inline CSS for the HTML report. Self-contained with no external deps.
HTML_STYLES = """
:root {
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-tertiary: #21262d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --border: #30363d;
    --accent-blue: #58a6ff;
    --accent-green: #3fb950;
    --accent-red: #f85149;
    --accent-orange: #d29922;
    --accent-purple: #bc8cff;
    --accent-yellow: #e3b341;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
}
.header {
    text-align: center;
    padding: 2rem 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 2rem;
}
.header h1 {
    font-size: 2rem;
    color: var(--accent-blue);
    margin-bottom: 0.5rem;
}
.header .subtitle {
    color: var(--text-secondary);
    font-size: 0.9rem;
}
.meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
}
.meta-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem;
}
.meta-card .label {
    color: var(--text-secondary);
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
.meta-card .value {
    font-size: 1.4rem;
    font-weight: 600;
    margin-top: 0.25rem;
}
section {
    margin-bottom: 2rem;
}
section h2 {
    font-size: 1.4rem;
    color: var(--accent-blue);
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
}
section h3 {
    font-size: 1.1rem;
    color: var(--text-primary);
    margin: 1rem 0 0.5rem;
}
table {
    width: 100%;
    border-collapse: collapse;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
    margin-bottom: 1rem;
}
th {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 0.75rem 1rem;
    text-align: left;
}
td {
    padding: 0.65rem 1rem;
    border-top: 1px solid var(--border);
    font-size: 0.9rem;
}
tr:hover { background: var(--bg-tertiary); }
.badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}
.badge-open { background: rgba(63, 185, 80, 0.15); color: var(--accent-green); }
.badge-closed { background: rgba(139, 148, 158, 0.15); color: var(--text-secondary); }
.badge-filtered { background: rgba(210, 153, 34, 0.15); color: var(--accent-orange); }
.badge-critical { background: rgba(248, 81, 73, 0.3); color: #ff7b72; }
.badge-high { background: rgba(248, 81, 73, 0.15); color: var(--accent-red); }
.badge-medium { background: rgba(210, 153, 34, 0.15); color: var(--accent-orange); }
.badge-low { background: rgba(227, 179, 65, 0.15); color: var(--accent-yellow); }
.badge-info { background: rgba(88, 166, 255, 0.15); color: var(--accent-blue); }
.finding-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem 1.25rem;
    margin-bottom: 0.75rem;
}
.finding-card .finding-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}
.finding-card .finding-title {
    font-weight: 600;
    font-size: 1rem;
}
.finding-card .finding-desc {
    color: var(--text-secondary);
    font-size: 0.9rem;
    margin-bottom: 0.5rem;
}
.finding-card .finding-remediation {
    background: var(--bg-tertiary);
    border-left: 3px solid var(--accent-blue);
    padding: 0.5rem 0.75rem;
    font-size: 0.85rem;
    color: var(--text-secondary);
    border-radius: 0 4px 4px 0;
}
.host-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem;
    margin-bottom: 0.5rem;
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 0.5rem;
}
.host-card .host-ip { font-weight: 600; color: var(--accent-green); }
.host-card .host-detail { color: var(--text-secondary); font-size: 0.85rem; }
.footer {
    text-align: center;
    padding: 2rem 0;
    border-top: 1px solid var(--border);
    color: var(--text-secondary);
    font-size: 0.8rem;
}
.disclaimer {
    background: rgba(248, 81, 73, 0.1);
    border: 1px solid rgba(248, 81, 73, 0.3);
    border-radius: 6px;
    padding: 1rem;
    margin-bottom: 2rem;
    font-size: 0.85rem;
    color: #ff7b72;
}
"""


def _escape_html(text: str) -> str:
    """Escape HTML special characters to prevent XSS in report output."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


class ReportGenerator:
    """
    Multi-format security scan report generator.

    Aggregates results from port scans, network mapping, and vulnerability
    assessments into professional JSON and HTML reports.

    Args:
        title: Report title (default: "Network Security Assessment").
        author: Report author name.
    """

    def __init__(
        self,
        title: str = "Network Security Assessment",
        author: str = "",
    ) -> None:
        self.title = title
        self.author = author
        self.data = ReportData()
        self.generated_at = ""

    def add_port_scan(self, result: ScanResult) -> None:
        """Add a port scan result to the report."""
        self.data.port_scans.append(result)

    def add_network_map(self, network_map: NetworkMap) -> None:
        """Add a network map result to the report."""
        self.data.network_maps.append(network_map)

    def add_vuln_report(self, report: VulnReport) -> None:
        """Add a vulnerability assessment report."""
        self.data.vuln_reports.append(report)

    def _build_report_dict(self) -> dict[str, Any]:
        """Build the complete report data as a nested dictionary."""
        self.generated_at = datetime.now(timezone.utc).isoformat()

        report: dict[str, Any] = {
            "report_metadata": {
                "title": self.title,
                "generated_at": self.generated_at,
                "generator": "netsec-toolkit v1.0.0",
            },
        }

        if self.author:
            report["report_metadata"]["author"] = self.author

        if self.data.port_scans:
            report["port_scans"] = [
                scan.to_dict() for scan in self.data.port_scans
            ]

        if self.data.network_maps:
            report["network_maps"] = [
                nm.to_dict() for nm in self.data.network_maps
            ]

        if self.data.vuln_reports:
            report["vulnerability_assessments"] = [
                vr.to_dict() for vr in self.data.vuln_reports
            ]

        return report

    def generate_json(self, output_path: str) -> str:
        """
        Generate a JSON report file.

        Args:
            output_path: File path for the JSON output.

        Returns:
            Absolute path to the generated report file.
        """
        report = self._build_report_dict()
        path = Path(output_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        return str(path)

    def generate_html(self, output_path: str) -> str:
        """
        Generate a self-contained HTML report with inline CSS.

        The report includes:
        - Executive summary with key metrics
        - Port scan results tables
        - Network map host listing
        - Vulnerability findings with severity badges
        - Remediation recommendations

        Args:
            output_path: File path for the HTML output.

        Returns:
            Absolute path to the generated report file.
        """
        self.generated_at = datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )

        html_parts: list[str] = []

        # Document head
        html_parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{_escape_html(self.title)}</title>
    <style>{HTML_STYLES}</style>
</head>
<body>""")

        # Header
        html_parts.append(f"""
<div class="header">
    <h1>{_escape_html(self.title)}</h1>
    <div class="subtitle">
        Generated: {self.generated_at}
        {f' | Author: {_escape_html(self.author)}' if self.author else ''}
        | netsec-toolkit v1.0.0
    </div>
</div>""")

        # Disclaimer
        html_parts.append("""
<div class="disclaimer">
    <strong>DISCLAIMER:</strong> This report is generated for authorized
    security testing purposes only. Unauthorized use of this information
    to access or attack systems you do not own or have permission to test
    is illegal. The authors assume no liability for misuse.
</div>""")

        # Executive summary cards
        html_parts.append(self._build_summary_cards())

        # Port scan section
        if self.data.port_scans:
            html_parts.append(self._build_port_scan_section())

        # Network map section
        if self.data.network_maps:
            html_parts.append(self._build_network_map_section())

        # Vulnerability section
        if self.data.vuln_reports:
            html_parts.append(self._build_vuln_section())

        # Footer
        html_parts.append("""
<div class="footer">
    <p>Generated by netsec-toolkit v1.0.0</p>
    <p>For authorized security testing only.</p>
</div>
</body>
</html>""")

        # Write the file
        path = Path(output_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(html_parts))

        return str(path)

    def _build_summary_cards(self) -> str:
        """Build HTML for the executive summary metric cards."""
        total_open_ports = sum(
            len(scan.open_ports) for scan in self.data.port_scans
        )
        total_hosts = sum(
            len(nm.alive_hosts) for nm in self.data.network_maps
        )
        total_vulns = sum(
            len(vr.findings) for vr in self.data.vuln_reports
        )
        critical_vulns = sum(
            vr.critical_count + vr.high_count for vr in self.data.vuln_reports
        )

        return f"""
<div class="meta-grid">
    <div class="meta-card">
        <div class="label">Open Ports Found</div>
        <div class="value" style="color: var(--accent-green)">{total_open_ports}</div>
    </div>
    <div class="meta-card">
        <div class="label">Live Hosts</div>
        <div class="value" style="color: var(--accent-blue)">{total_hosts}</div>
    </div>
    <div class="meta-card">
        <div class="label">Total Findings</div>
        <div class="value" style="color: var(--accent-orange)">{total_vulns}</div>
    </div>
    <div class="meta-card">
        <div class="label">Critical / High</div>
        <div class="value" style="color: var(--accent-red)">{critical_vulns}</div>
    </div>
</div>"""

    def _build_port_scan_section(self) -> str:
        """Build HTML for the port scan results section."""
        parts: list[str] = ['<section>', '<h2>Port Scan Results</h2>']

        for scan in self.data.port_scans:
            parts.append(
                f"<h3>Target: {_escape_html(scan.target)} "
                f"({_escape_html(scan.resolved_ip)}) "
                f"- {scan.duration_seconds}s</h3>"
            )

            # Only show open ports in the table (closed are omitted for clarity)
            open_ports = scan.open_ports
            if open_ports:
                parts.append("""<table>
<thead><tr>
    <th>Port</th><th>State</th><th>Service</th>
    <th>Banner</th><th>Response Time</th>
</tr></thead><tbody>""")

                for port_result in open_ports:
                    badge = f'<span class="badge badge-{port_result.state.value}">{port_result.state.value}</span>'
                    banner = _escape_html(port_result.banner[:80]) if port_result.banner else "-"
                    parts.append(
                        f"<tr>"
                        f"<td><strong>{port_result.port}</strong></td>"
                        f"<td>{badge}</td>"
                        f"<td>{_escape_html(port_result.service)}</td>"
                        f"<td><code>{banner}</code></td>"
                        f"<td>{port_result.response_time_ms:.1f}ms</td>"
                        f"</tr>"
                    )

                parts.append("</tbody></table>")

                # SSL info sub-table if any ports have it
                ssl_ports = [p for p in open_ports if p.ssl_info]
                if ssl_ports:
                    parts.append("<h3>SSL/TLS Information</h3>")
                    parts.append("""<table>
<thead><tr><th>Port</th><th>Protocol</th><th>Cipher</th><th>Bits</th></tr></thead><tbody>""")
                    for p in ssl_ports:
                        parts.append(
                            f"<tr>"
                            f"<td>{p.port}</td>"
                            f"<td>{_escape_html(p.ssl_info.get('protocol', 'N/A'))}</td>"
                            f"<td>{_escape_html(p.ssl_info.get('cipher_suite', 'N/A'))}</td>"
                            f"<td>{_escape_html(p.ssl_info.get('cipher_bits', 'N/A'))}</td>"
                            f"</tr>"
                        )
                    parts.append("</tbody></table>")
            else:
                parts.append(
                    '<p style="color: var(--text-secondary)">'
                    'No open ports found.</p>'
                )

        parts.append("</section>")
        return "\n".join(parts)

    def _build_network_map_section(self) -> str:
        """Build HTML for the network map section."""
        parts: list[str] = ['<section>', '<h2>Network Map</h2>']

        for nm in self.data.network_maps:
            parts.append(
                f"<h3>Subnet: {_escape_html(nm.subnet)} "
                f"- {len(nm.alive_hosts)} hosts alive "
                f"({nm.duration_seconds}s)</h3>"
            )

            if nm.alive_hosts:
                parts.append("""<table>
<thead><tr>
    <th>IP Address</th><th>Hostname</th><th>OS Hint</th>
    <th>MAC Address</th><th>Open Ports</th><th>Response</th>
</tr></thead><tbody>""")

                for host in nm.alive_hosts:
                    open_ports_str = ", ".join(str(p) for p in host.open_ports) or "-"
                    parts.append(
                        f"<tr>"
                        f"<td><strong>{_escape_html(host.ip)}</strong></td>"
                        f"<td>{_escape_html(host.hostname) or '-'}</td>"
                        f"<td>{_escape_html(host.os_hint) or '-'}</td>"
                        f"<td><code>{_escape_html(host.mac_address) or '-'}</code></td>"
                        f"<td>{open_ports_str}</td>"
                        f"<td>{host.response_time_ms:.1f}ms</td>"
                        f"</tr>"
                    )

                parts.append("</tbody></table>")
            else:
                parts.append(
                    '<p style="color: var(--text-secondary)">'
                    'No alive hosts discovered.</p>'
                )

        parts.append("</section>")
        return "\n".join(parts)

    def _build_vuln_section(self) -> str:
        """Build HTML for the vulnerability findings section."""
        parts: list[str] = ['<section>', '<h2>Vulnerability Findings</h2>']

        for vr in self.data.vuln_reports:
            parts.append(
                f"<h3>Target: {_escape_html(vr.target)} "
                f"- {len(vr.findings)} findings ({vr.duration_seconds}s)</h3>"
            )

            if vr.findings:
                for finding in vr.findings:
                    sev = finding.severity.value
                    port_str = f" (Port {finding.port})" if finding.port else ""
                    parts.append(f"""
<div class="finding-card">
    <div class="finding-header">
        <span class="finding-title">{_escape_html(finding.title)}{port_str}</span>
        <span class="badge badge-{sev}">{sev}</span>
    </div>
    <div class="finding-desc">{_escape_html(finding.description)}</div>""")

                    if finding.remediation:
                        parts.append(
                            f'    <div class="finding-remediation">'
                            f"<strong>Remediation:</strong> "
                            f"{_escape_html(finding.remediation)}</div>"
                        )

                    parts.append("</div>")
            else:
                parts.append(
                    '<p style="color: var(--accent-green)">'
                    'No vulnerabilities found.</p>'
                )

        parts.append("</section>")
        return "\n".join(parts)
