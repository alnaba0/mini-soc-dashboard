from __future__ import annotations

import csv
import io
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from flask import Flask, Response, render_template, request

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
app = Flask(__name__)

RISKY_SERVICES = {
    "ftp": "high",
    "telnet": "high",
    "mysql": "high",
    "mssql": "high",
    "rdp": "high",
    "vnc": "high",
    "ssh": "medium",
    "smtp": "medium",
    "dns": "medium",
    "snmp": "medium",
}


def load_json(filename: str) -> list[dict[str, Any]]:
    with (DATA_DIR / filename).open("r", encoding="utf-8") as file:
        return json.load(file)


def load_text(filename: str) -> str:
    return (DATA_DIR / filename).read_text(encoding="utf-8")


def load_csv(filename: str) -> list[dict[str, Any]]:
    with (DATA_DIR / filename).open("r", encoding="utf-8-sig") as file:
        return list(csv.DictReader(file))


def parse_open_ports(nmap_text: str) -> list[dict[str, str]]:
    ports: list[dict[str, str]] = []
    for line in nmap_text.splitlines():
        line = line.strip()
        if "/tcp" not in line:
            continue
        parts = line.split()
        if len(parts) >= 3:
            service = parts[2].lower()
            ports.append(
                {
                    "port": parts[0],
                    "state": parts[1],
                    "service": parts[2],
                    "risk": RISKY_SERVICES.get(service, "low"),
                }
            )
    return ports


def generate_alerts(logs: list[dict[str, Any]], ids_rows: list[dict[str, Any]], nmap_text: str) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    failed = defaultdict(int)

    for log in logs:
        event = str(log.get("event", "")).lower()
        source = str(log.get("source_ip", "Unknown"))
        severity = str(log.get("severity", "low")).lower()

        if "failed login" in event:
            failed[source] += 1

        if "port scan" in event:
            alerts.append(
                {
                    "severity": "high",
                    "type": "Port Scan",
                    "source": source,
                    "details": log.get("event", "Port scan found"),
                    "reason": "The log text contains a port-scan event, so it is marked as suspicious.",
                }
            )
        elif severity == "high":
            alerts.append(
                {
                    "severity": "high",
                    "type": "High Severity Event",
                    "source": source,
                    "details": log.get("event", "High severity event"),
                    "reason": "The source log already carries a high severity value.",
                }
            )

    for source, count in failed.items():
        if count >= 3:
            alerts.append(
                {
                    "severity": "medium",
                    "type": "Repeated Failed Logins",
                    "source": source,
                    "details": f"{count} failed login attempts from the same IP",
                    "reason": "Three or more failed logins from the same IP can indicate brute-force activity.",
                }
            )

    for row in ids_rows:
        label = str(row.get("Label", "BENIGN"))
        if label.upper() != "BENIGN":
            alerts.append(
                {
                    "severity": "high",
                    "type": "Attack Label",
                    "source": row.get("Source IP", "IDS Sample"),
                    "details": f"Detected attack label: {label}",
                    "reason": "The IDS sample row is labeled as an attack instead of benign traffic.",
                }
            )

    open_ports = parse_open_ports(nmap_text)
    if len(open_ports) >= 4:
        risky_count = sum(1 for port in open_ports if port["risk"] in {"medium", "high"})
        alerts.append(
            {
                "severity": "medium",
                "type": "Multiple Open Ports",
                "source": "Nmap",
                "details": f"{len(open_ports)} open ports were found",
                "reason": f"The scan exposed {len(open_ports)} open ports, including {risky_count} medium/high-risk services.",
            }
        )
    return alerts


def build_data(logs: list[dict[str, Any]] | None = None, ids_rows: list[dict[str, Any]] | None = None, nmap_text: str | None = None) -> dict[str, Any]:
    logs = logs if logs is not None else load_json("sample_logs.json")
    ids_rows = ids_rows if ids_rows is not None else load_csv("ids_sample.csv")
    nmap_text = nmap_text if nmap_text is not None else load_text("nmap_results.txt")

    alerts = generate_alerts(logs, ids_rows, nmap_text)
    open_ports = parse_open_ports(nmap_text)

    event_counts = Counter(str(log.get("event", "Unknown")) for log in logs)
    source_counts = Counter(str(log.get("source_ip", "Unknown")) for log in logs)
    suspicious_logs = [log for log in logs if str(log.get("severity", "low")).lower() in {"medium", "high"}]
    attack_rows = [row for row in ids_rows if str(row.get("Label", "BENIGN")).upper() != "BENIGN"]

    top_events = event_counts.most_common(4)
    top_sources = source_counts.most_common(4)
    top_event_name = top_events[0][0] if top_events else "None"
    top_source_name = top_sources[0][0] if top_sources else "None"

    stats = {
        "total_logs": len(logs),
        "total_alerts": len(alerts),
        "high_alerts": sum(1 for alert in alerts if alert["severity"] == "high"),
        "open_ports": len(open_ports),
        "suspicious_logs": len(suspicious_logs),
        "top_event": top_event_name,
        "top_source": top_source_name,
        "attack_rows": len(attack_rows),
    }

    return {
        "logs": logs,
        "ids_rows": ids_rows,
        "nmap_text": nmap_text,
        "alerts": alerts,
        "open_ports": open_ports,
        "stats": stats,
        "top_events": top_events,
        "top_sources": top_sources,
        "upload_message": None,
        "upload_error": None,
    }


def filter_logs(logs: list[dict[str, Any]], severity: str, query: str) -> list[dict[str, Any]]:
    filtered = logs
    if severity:
        filtered = [log for log in filtered if str(log.get("severity", "")).lower() == severity]
    if query:
        q = query.lower()
        filtered = [
            log
            for log in filtered
            if q in str(log.get("source_ip", "")).lower()
            or q in str(log.get("destination_ip", "")).lower()
            or q in str(log.get("event", "")).lower()
            or q in str(log.get("status", "")).lower()
        ]
    return filtered


def csv_response(filename: str, rows: list[dict[str, Any]], fieldnames: list[str]) -> Response:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: row.get(key, "") for key in fieldnames})
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def parse_uploaded_file(file_storage) -> tuple[str | None, dict[str, Any] | None, str | None]:
    if not file_storage or not file_storage.filename:
        return None, None, "Please choose a file first."

    filename = file_storage.filename.lower()
    try:
        content = file_storage.read().decode("utf-8-sig")
    except UnicodeDecodeError:
        return None, None, "The file could not be read as text."

    if filename.endswith(".json"):
        parsed = json.loads(content)
        if not isinstance(parsed, list):
            return None, None, "The JSON file must contain a list of log records."
        data = build_data(logs=parsed)
        data["upload_message"] = f"Loaded JSON logs from {file_storage.filename}."
        return "logs.html", data, None

    if filename.endswith(".csv"):
        reader = csv.DictReader(io.StringIO(content))
        rows = list(reader)
        data = build_data(ids_rows=rows)
        data["upload_message"] = f"Loaded IDS CSV data from {file_storage.filename}."
        return "scans.html", data, None

    if filename.endswith(".txt"):
        data = build_data(nmap_text=content)
        data["upload_message"] = f"Loaded scan text from {file_storage.filename}."
        return "scans.html", data, None

    return None, None, "Use a .json log file, .csv IDS file, or .txt scan output file."


@app.route("/")
def index():
    return render_template("index.html", **build_data())


@app.route("/logs")
def logs_page():
    data = build_data()
    selected = request.args.get("severity", "").lower().strip()
    query = request.args.get("q", "").strip()
    data["logs"] = filter_logs(data["logs"], selected, query)
    return render_template("logs.html", selected_severity=selected, query=query, **data)


@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html", **build_data())


@app.route("/scans")
def scans_page():
    return render_template("scans.html", **build_data())


@app.route("/upload", methods=["POST"])
def upload_file():
    template_name, data, error = parse_uploaded_file(request.files.get("sample_file"))
    if error:
        data = build_data()
        data["upload_error"] = error
        return render_template("scans.html", **data)
    return render_template(template_name, selected_severity="", query="", **data)


@app.route("/export/logs")
def export_logs():
    data = build_data()
    selected = request.args.get("severity", "").lower().strip()
    query = request.args.get("q", "").strip()
    rows = filter_logs(data["logs"], selected, query)
    return csv_response(
        "mini_soc_logs.csv",
        rows,
        ["time", "source_ip", "destination_ip", "event", "severity", "status"],
    )


@app.route("/export/alerts")
def export_alerts():
    data = build_data()
    return csv_response(
        "mini_soc_alerts.csv",
        data["alerts"],
        ["severity", "type", "source", "details", "reason"],
    )


if __name__ == "__main__":
    app.run(debug=False)
