"""
attack_simulator.py

Generate simulated cloud attacks and 
writes events to logs/cloudtrail.json
"""


import json
import random
from pathlib import Path
from datetime import datetime

LOG_FILE = Path("logs/cloudtrail.json")


def write_event(event):
    
    LOG_FILE.parent.mkdir(exist_ok=True)
    
    with open(LOG_FILE, "a") as file:
        file.write(json.dumps(event) + "\n")
        
        
def create_base_event():
    
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "sourceIPAddress": f"192.168.1.{random.randint(1, 254)}"
    }
    
    
def simulate_failed_login():
    
    event = create_base_event()
    
    event.update({
        "eventName": "ConsoleLogin",
        "errorMessage": "Failed authentication",
        "user": "admin"
    })
    
    write_event(event)
    
    
def simulate_privilege_escalation():
    
    event = create_base_event()
    
    event.update({
        "eventName": "AttachUserPolicy",
        "user": "developer",
        "policy": "AdministratorAccess"
    })
    
    write_event(event)
    
    
def simulate_public_bucket():
    
    event = create_base_event()
    
    event.update({
        "eventName": "PutBucketAcl",
        "bucket": "finance-data",
        "acl": "public-read",
        "user": "storage-admin"
    })
    
    write_event(event)
    
    
def simulate_reconnaissance():
    
    event = create_base_event()
    
    event.update({
        "eventName": "ListUsers",
        "user": "unknown"
    })
    
    write_event(event)
    
    
def simulate_normal_activity():
    
    event = create_base_event()
    
    event.update({
        "eventName": "GetObject",
        "bucket": "company-files",
        "user": "employee"
    })
    
    write_event(event)
    
    
def run_simulation():
    
    print("Generating simulated cloud activity...")
    
    # Normal Events
    for _ in range(20):
        simulate_normal_activity()
        
    # Failed logins
    for _ in range(8):
        simulate_failed_login()
        
    # Recon activity
    for _ in range(6):
        simulate_reconnaissance()
        
    # Privilege escalation
    simulate_privilege_escalation()
    
    # Public bucket exposure
    simulate_public_bucket()
    
    print("Simulation complete")
    print("Events written to logs/cloudtrail.json")
    
    
if __name__ == "__main__":
    run_simulation()