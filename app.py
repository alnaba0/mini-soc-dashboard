from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from flask import Flask, render_template, request

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
app = Flask(__name__)


def load_json(filename: str) -> list[dict[str, Any]]:
    with (DATA_DIR / filename).open("r", encoding="utf-8") as file:
        return json.load(file)


def load_text(filename: str) -> str:
    return (DATA_DIR / filename).read_text(encoding="utf-8")


def load_csv(filename: str) -> list[dict[str, Any]]:
    with (DATA_DIR / filename).open("r", encoding="utf-8-sig") as file:
        return list(csv.DictReader(file))


def parse_open_ports(nmap_text: str) -> list[dict[str, str]]:
    ports = []
    for line in nmap_text.splitlines():
        line = line.strip()
        if "/tcp" not in line:
            continue
        parts = line.split()
        if len(parts) >= 3:
            ports.append({"port": parts[0], "state": parts[1], "service": parts[2]})
    return ports


def generate_alerts(logs: list[dict[str, Any]], ids_rows: list[dict[str, Any]], nmap_text: str) -> list[dict[str, Any]]:
    alerts = []
    failed = defaultdict(int)
    for log in logs:
        event = str(log.get("event", "")).lower()
        source = str(log.get("source_ip", "Unknown"))
        severity = str(log.get("severity", "low")).lower()
        if "failed login" in event:
            failed[source] += 1
        if "port scan" in event:
            alerts.append({"severity": "high", "type": "Port Scan", "source": source, "details": log.get("event", "Port scan found")})
        elif severity == "high":
            alerts.append({"severity": "high", "type": "High Severity Event", "source": source, "details": log.get("event", "High severity event")})
    for source, count in failed.items():
        if count >= 3:
            alerts.append({"severity": "medium", "type": "Repeated Failed Logins", "source": source, "details": f"{count} failed login attempts from the same IP"})
    for row in ids_rows:
        label = str(row.get("Label", "BENIGN"))
        if label.upper() != "BENIGN":
            alerts.append({"severity": "high", "type": "Attack Label", "source": "IDS Sample", "details": f"Detected attack label: {label}"})
    open_ports = parse_open_ports(nmap_text)
    if len(open_ports) >= 4:
        alerts.append({"severity": "medium", "type": "Multiple Open Ports", "source": "Nmap", "details": f"{len(open_ports)} open ports were found"})
    return alerts


def build_data() -> dict[str, Any]:
    logs = load_json("sample_logs.json")
    ids_rows = load_csv("ids_sample.csv")
    nmap_text = load_text("nmap_results.txt")
    alerts = generate_alerts(logs, ids_rows, nmap_text)
    open_ports = parse_open_ports(nmap_text)
    stats = {
        "total_logs": len(logs),
        "total_alerts": len(alerts),
        "high_alerts": sum(1 for a in alerts if a["severity"] == "high"),
        "open_ports": len(open_ports),
    }
    return {"logs": logs, "ids_rows": ids_rows, "nmap_text": nmap_text, "alerts": alerts, "open_ports": open_ports, "stats": stats}


@app.route('/')
def index():
    return render_template('index.html', **build_data())


@app.route('/logs')
def logs_page():
    data = build_data()
    selected = request.args.get('severity', '').lower().strip()
    if selected:
        data['logs'] = [log for log in data['logs'] if str(log.get('severity', '')).lower() == selected]
    return render_template('logs.html', selected_severity=selected, **data)


@app.route('/alerts')
def alerts_page():
    return render_template('alerts.html', **build_data())


@app.route('/scans')
def scans_page():
    return render_template('scans.html', **build_data())


if __name__ == '__main__':
    app.run(debug=False)
