"""
detection_engine.py

Read cloud audit logs and generates
security findings based on detection rules
"""

import json
from pathlib import Path

from alert_manager import create_alert

LOG_FILE = Path("logs/cloudtrail.json")


def load_logs():
    """
    Load all log entries
    """
    
    if not LOG_FILE.exists():
        print("No log file found.")
        return []
    
    logs = []
    
    with open(LOG_FILE, "r") as file:
        
        for line in file:
            
            line = line.strip()
            
            if not line:
                continue
            try:
                logs.append(json.loads(line))
                
            except json.JSONDecodeError:
                continue
            
    return logs


def detect_public_bucket(event):
    """
    Detect public S3 bucket exposure
    """
    
    if (
        event.get("eventName") == "PutBucketAcl"
        and event.get("acl") == "public-read"
    ):
        
        create_alert(
            finding="Public Bucket Exposure",
            severity="HIGH",
            source_ip=event.get("sourceIPAddress", "Unknown"),
            user=event.get("user", "Unknown"),
            mitre_technique="T1530",
            description="Nucket ACL charges to public-read."
        )
        
        
def detect_privilege_escalation(event):
    """
    Detect IAM privilege escalation.
    """
    
    if (
        event.get("eventName") == "AttachUserPolicy"
        and event.get("policy") == "AdministratorAccess"
    ):
        
        create_alert(
            finding="Privilege Escalation",
            severity="HIGH",
            source_ip=event.get("sourceIPAddress", "Unknown"),
            user=event.get("user", "Unknown"),
            mitre_technique="T1098",
            description="AdministratorAccess policy attached."
        )
        

def detect_reconnaissance(logs):
    """
    Detect excessive ListUser activity
    """
    
    count = 0
    
    for event in logs:
        
        if event.get("eventName") == "ListUsers":
            count += 1
            
    if count >= 5:
        
        create_alert(
            finding="Cloud Reconnaissance",
            severity="MEDIUM",
            source_ip="Multiple",
            user="Unknown",
            mitre_technique="T1580"
            descritption=f"{count} ListUsers requests detected."
        )
        
        
def detect_bruteforce(logs):
    """
    Detect repeated failed logins.
    """
    
    failed_logins = {}
    
    for event in logs:
        
        if (
            event.get("eventName") == "ConsoleLogin"
            and event.get("errorMessage") == "Failed authentication"
        ):
            
            ip = event.get("sourceIPAddress", "Unknown")
            
            failed_logins[ip] = (
                failed_logins.get(ip, 0) + 1
            )
            
    for ip, count in failed_logins.items():
        
        if count >= 5:
            
            create_alert(
                finding="Brute Force Attempt",
                severity="HIGH",
                source_ip=ip,
                user="Unknown",
                mitre_technique="T1110",
                description=f"{count} failed login attempts."
            )
            
            
def run_detections(logs):
    """
    Run all detections
    """
    
    print(f"Processing {len(logs)} events...")
    
    for event in logs:
        
        detect_public_bucket(event)
        detect_privilege_escalation(event)
        
    detect_reconnaissance(logs)
    detect_bruteforce(logs)
    
    
def main():
    
    logs = load_logs()
    
    if not logs:
        print("No event to process.")
        return
    
    run_detections(logs)
    
    print("Detection run complete.")
    
    
if __name__ == "__main__":
    main()