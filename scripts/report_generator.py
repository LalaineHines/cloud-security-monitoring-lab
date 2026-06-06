"""
report_generator.py

Generate a security incident report
from detected alerts
"""

import json
from pathlib import Path
from datetime import datetime
from collections import Counter

ALERT_FILE = Path("alerts/alerts.json")
REPORT_FILE = Path("reports/incident_report.md")

def load_alerts():
    
    if not ALERT_FILE.exists():
        return []
    
    with open(ALERT_FILE, "r") as file:
        return json.load(file)
    
    
def calculate_statistics(alerts):
    
    severity_counts = Counter()
    finding_counts = Counter()
    
    for alert in alerts:
        
        severity_counts[alert["severity"]] += 1
        finding_counts[alert["finding"]] += 1
        
    return severity_counts, finding_counts


def generate_report():
    
    alerts = load_alerts()
    
    severity_counts, finding_counts = calculate_statistics(alerts)
    
    report = []
    
    report.append("# Security Incident Report\n")
    report.append(
        f"Generate: {datetime.utcenow().isoformat()}\n"
    )
    
    report.append("## Executive Summary\n")
    
    report.append(
        f"A total of {len(alerts)} security alerts "
        f"were identified during analysis.\n"
    )
    
    report.append("## Severity Breakdown\n")
    
    for severity, count in severity_counts.items():
        report.append(f"- {severity}: {count}")
        
    report.append("\n## Findings Summary\n")
    
    for finding, count in finding_counts.items():
        report.append(f"- {finding}: {count}")
        
    report.append("\n## Alert Details\n")
    
    for alert in alerts:
        
        report.append(
            f"### Alert #{alert['id']}"
        )
        
        report.append(
            f"- Finding: {alert['finding']}"
        )
        
        report.append(
            f"- Severity: {alert['severity']}"
        )
        
        report.append(
            f"- User: {alert['user']}"
        )
        
        report.append(
            f"- Source IP:{alert['source_ip']}"
        )
        
        report.append(
            f"- Mitre ATT&CK: {alert['mitre_technique']}"
        )
        
        report.append(
            f"- Description: {alert['description']}"
        )
        
        report.append(
            f"- Status: {alert['status']}\n"
        )
        
    REPORT_FILE.parent.mkdir(exist_ok=True)
    
    with open(REPORT_FILE, "w") as file:
        file.write("\n".join(report))
        
    print(
        f"Report saved to {REPORT_FILE}"
    )
    

if __name__ == "__main__":
    generate_report()