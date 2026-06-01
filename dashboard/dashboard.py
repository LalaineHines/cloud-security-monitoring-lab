import json
import os
from collections import Counter
from datetime import datetime

ALERTS_FILE = "alerts/alerts.json"


def load_alerts():
    """
    Load alerts from alerts.json.
    Return a list of alert dictionaries
    """
    
    if not os.path.exists(ALERT_FILE):
        return []
    
    try:
        with open(ALERTS_FILE, "r") as f:
            data = json.loads(f)
            
            if isinstance(data, list):
                return data
            
            return []
        
    except Exception:
        return []
    
    
def calculate_statistics(alerts):
    """
    Generate Dashboard Statistics
    """
    
    severity_counts = Counter()
    finding_counts = Counter()
    
    for alert in alerts:
        severity = alert.get("severity", "UNKNOWN")
        finding = alert.get("finding", "Unknown Finding")
        
        severity_counts[severity] += 1
        finding_counts[finding] += 1
        
    return severity_counts, finding_counts


def print_header():
    print("=" * 60)
    print(" CLOUD SECURITY MONITORING DASHBAORD ".center(60))
    print("=" * 60)
    print(f"Generated: {datetime.now()}")
    print()
    
    
def print_summary(alerts, severity_counts):
    print("SUMMARY")
    print("-" * 60)
    
    print(f"Total Alerts : {len(alerts)}")
    print(f"Critical:    : {severity_counts.get('CRITICAL', 0)}")
    print(f"High         : {severity_counts.get('HIGH', 0)}")
    print(f"Medium       : {severity_counts.get('MEDIUM', 0)}")
    print(f"Low          : {severity_counts.get('LOW', 0)}")
    
    print()
    
    
def print_top_findings(finding_counts):
    print("TOP SECURITY FINDINGS")
    print("-" * 60)
    
    if not finding_counts:
        print("No findings detected.\n")
        return
    
    for finding, count in finding_counts.most_common(10):
        print(f"{finding:<40} {count}")
        
    print()
    
    
def print_recent_alerts(alerts):
    print("RECENT ALERTS")
    print("-" * 60)
    
    if not alerts:
        print("No alerts available.\n")
        return
    
    recent = alerts[-10:]
    
    for alert in recent:
        
        timestamp = alert.get("timestamp", "Unknown")
        severity = alert.get("severity", "UNKNOWN")
        finding = alert.get("finding", "Unknown Finding")
        status = alert.get("status", "OPEN")
        
        print(
            f"[{severity:^8}] "
            f"{finding:<30} "
            f"Status: {status:<8} "
            f"{timestamp}"
        )
        
    print()
    
    
def print_recommendations(severity_counts):
    
    print("RECOMMENDED ACTIONS")
    print("-" * 60)
    
    if severity_counts.get("CRITICAL", 0) > 0:
        print("- Investigate CRITICAL alerts immediately")
        
    if severity_counts.get("HIGH", 0) > 0:
        print("- Review HIGH severity findings")
        
    if severity_counts.get("MEDIUM", 0) > 0:
        print("- Validate suspicious user activity")
        
    if sum(severity_counts.values()) == 0:
        print("- No action required")
        
    
    print()
    
    
def main():
    
    alerts = load_alerts()
    
    severity_counts, finding_counts = calculate_statistics(alerts)
    
    print_header()
    
    print_summary(alerts, severity_counts)
    
    print_top_findings(finding_counts)
    
    print_recent_alerts(alerts)
    
    print_recommendations(severity_counts)
    
    print("=" * 60)
    
    
if __name__ == "__main__":
    main()