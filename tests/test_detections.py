"""
test_detections.py

Tests for detection_engine.py
"""

from scripts.detection_engine import (
    detect_public_bucket,
    detect_privilege_escalation,
)


def test_public_bucket_detection(monkeypatch):
    
    alerts_created = []
    
    def mock_create_alert(**kwargs):
        alerts_created.append(kwargs)
        
    monkeypatch.setattr(
        "scripts.detection_engine.create_alert",
        mock_create_alert
    )
    
    event = {
        "eventName": "PutBucketAcl",
        "acl": "public-read",
        "sourceIPAddress": "192.168.1.100",
        "user": "storage-admin"
    }

    detect_public_bucket(event)
        
    assert len(alerts_created) == 1
    assert alerts_created[0]["finding"] == (
        "Public Bucket Exposure"
    )
        
        
def test_privilege_escalation_detection(monkeypatch):
    
    alerts_created = []
    
    def mock_create_alert(**kwargs):
        alerts_created.append(kwargs)
            
    monkeypatch.setattr(
        "scripts.detection_engine.create_alert",
        mock_create_alert
    )
    
    event = {
        "eventName": "AttachuserPolicy",
        "policy": "AdministratorAccess",
        "sourceIPAddress": "10.0.0.5",
        "user": "developer"
    }
    
    detect_privilege_escalation(event)
    
    assert len(alerts_created) == 1
    assert alerts_created[0]["finding"] == (
        "Privilege Escalation"
    )
    
    
def test_bruteforce_detection(monkeypatch):
    
    alerts_created = []
    
    def mock_create_alert(**kwargs):
        alerts_created.append(kwargs)
        
    monkeypatch.setattr(
        "scripts.detection_engine.create_alert",
        mock_create_alert
    )
    
    logs = []
    
    for _ in range(6):
        
        logs.append({
            "eventName": "ConsoleLogin",
            "errorMessage": "Failed authentication",
            "sourceIPAddress": "8.8.8.8"
        })
        
    from scripts.detection_engine import (
        detect_bruteforce
    )
    
    detect_bruteforce(logs)
    
    assert len(alerts_created) == 1
    assert alerts_created[0]["finding"] == (
        "Brute Force Attempt"
    )
    
    
def test_reconnaissance_detection(monkeypatch):
    
    alerts_created = []
    
    def mock_create_alert(**kwargs):
        alerts_created.append(kwargs)
        
    monkeypatch.setattr(
        "scripts.detection_engine.create_alert",
        mock_create_alert
    )
    
    logs = []
    
    for _ in range(6):
        
        logs.append({
            "eventName": "ListUsers"
        })
        
    from scripts.detection_engine import (
        detect_reconnaissance
    )
    
    detect_reconnaissance(logs)
    
    assert len(alerts_created) == 1
    assert alerts_created[0]["finding"] == (
        "Cloud Reconnaissance"
    )
    
    
def test_normal_activity_generates_no_alerts(
    monkeypatch
):
    
    alerts_created = []
    
    def mock_create_alert(**kwargs):
        alerts_created.append(kwargs)
        
    monkeypatch.setattr(
        "scripts.detection_engine.create_alert",
        mock_create_alert
    )
    
    event = {
        "eventName": "GetObject",
        "user": "alice"
    }
    
    detect_public_bucket(event)
    
    assert len(alerts_created) == 0