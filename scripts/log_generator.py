"""
log_generator.py

Generates realistics cloud audit logs
representing normal user activity.
"""


import json
import random
from pathlib import Path
from datetime import datetime

LOG_FILE = Path("logs/cloudtrail.json")

USERS = [
    "alice",
    "bob",
    "charlie",
    "developer",
    "analyst",
    "manager"
]

EVENTS = [
    "GetObject",
    "PutObject",
    "ListBuckets",
    "DescribeInstances",
    "StartInstances",
    "StopInstances",
    "ConsoleLogin"
]

BUCKETS = [
    "finance-data",
    "employee-records",
    "project-files",
    "company-backups"
]


def write_event(event):
    
    LOG_FILE.parent.mkdir(exist_ok=True)
    
    with open(LOG_FILE, "a") as file:
        file.write(json.dumps(event) + "\n")
        
        
def random_ip():
    
    return (
        f"10.{random.randint(0, 255)}."
        f"{random.randint(0, 255)}."
        f"{random.randint(1, 254)}"
    )
    
    
def generate_event():
    
    event_name = random.choice(EVENTS)
    
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "eventName": event_name,
        "sourceIPAddress": random_ip(),
        "user": random.choice(USERS),
        "bucket": random.choice(BUCKETS)
    }
    
    
def generate_logs(count=100):
    
    print(f"Generating {count} normal events...")
    
    for _ in range(count):
        write_event(generate_event())
        
    print("Log generation complete.")
    
    
if __name__ == "__main__":
    generate_logs()