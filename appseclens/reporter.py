import html
import json
from pathlib import Path

from .models import ScanResult


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def build_summary(
    results: list[ScanResult]
) -> dict[str, int]:
    """Build a severity summary."""

    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for result in results:

        for finding in result.findings:

            severity = finding.severity.upper()

            if severity in summary:
                summary[severity] += 1

    return summary


def save_json(
    results: list[ScanResult],
    output_dir: str
) -> Path:
    """Save scan results as JSON."""

    output_path = Path(output_dir)

    output_path.mkdir(
        parents=True,
        exist_ok=True
    )

    file_path = output_path / "report.json"

    data = {
        "summary": build_summary(results),
        "results": [
            result.to_dict()
            for result in results
        ],
    }

    file_path.write_text(
        json.dumps(
            data,
            indent=2
        ),
        encoding="utf-8"
    )

    return file_path


def save_html(
    results: list[ScanResult],
    output_dir: str
) -> Path:
    """Save scan results as an HTML report."""

    output_path = Path(output_dir)

    output_path.mkdir(
        parents=True,
        exist_ok=True
    )

    file_path = output_path / "report.html"

    summary = build_summary(results)

    rows = []

    for result in results:

        for finding in result.findings:

            rows.append(
                f"""
                <tr>
                    <td>{html.escape(result.url)}</td>
                    <td>{html.escape(finding.check)}</td>
                    <td>{html.escape(finding.title)}</td>
                    <td>{html.escape(finding.severity)}</td>
                    <td>{html.escape(finding.evidence)}</td>
                    <td>{html.escape(finding.remediation)}</td>
                </tr>
                """
            )

    if not rows:

        rows.append(
            """
            <tr>
                <td colspan="6">
                    No findings detected.
                </td>
            </tr>
            """
        )

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>AppSecLens Security Report</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background: #f5f5f5;
            color: #222;
        }}

        h1 {{
            margin-bottom: 5px;
        }}

        .summary {{
            display: flex;
            gap: 15px;
            margin: 25px 0;
            flex-wrap: wrap;
        }}

        .card {{
            background: white;
            padding: 18px;
            border-radius: 8px;
            min-width: 100px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
        }}

        th, td {{
            padding: 12px;
            border: 1px solid #ddd;
            text-align: left;
            vertical-align: top;
        }}

        th {{
            background: #222;
            color: white;
        }}

        tr:nth-child(even) {{
            background: #fafafa;
        }}

        .note {{
            color: #666;
        }}
    </style>
</head>

<body>

<h1>AppSecLens Security Report</h1>

<p class="note">
    Passive web application security posture assessment.
</p>

<div class="summary">

    <div class="card">
        <strong>Critical</strong>
        <br>
        {summary["CRITICAL"]}
    </div>

    <div class="card">
        <strong>High</strong>
        <br>
        {summary["HIGH"]}
    </div>

    <div class="card">
        <strong>Medium</strong>
        <br>
        {summary["MEDIUM"]}
    </div>

    <div class="card">
        <strong>Low</strong>
        <br>
        {summary["LOW"]}
    </div>

    <div class="card">
        <strong>Info</strong>
        <br>
        {summary["INFO"]}
    </div>

</div>

<table>

<thead>
<tr>
    <th>Target</th>
    <th>Check</th>
    <th>Finding</th>
    <th>Severity</th>
    <th>Evidence</th>
    <th>Remediation</th>
</tr>
</thead>

<tbody>
{"".join(rows)}
</tbody>

</table>

</body>
</html>
"""

    file_path.write_text(
        html_content,
        encoding="utf-8"
    )

    return file_path
