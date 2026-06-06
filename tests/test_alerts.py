"""
test_alerts.py

Tests for alert_manager.py
"""

import json
import tempfile
from pathlib import Path

import pytest

import scripts.alert_manager as alert_manager

@pytest.fixture
def temp_alert_file():
    
    with tempfile.TemporaryDirectory() as tmpdir:
        
        alert_manager.ALERT_FILE = (
            Path(tmpdir) / "alerts.json"
        )
        
        yield
        
        
def test_create_alert(temp_alert_file):
    
    alert = alert_manager.create_alert(
        finding="Privilege Escalation",
        severity="High",
        source_ip="192.168.1.10",
        user="developer",
        mitre_technique="T1098",
        description="Admin policy attached."
    )
    
    assert alert["finding"] == "Privilege Escalation"
    assert alert["severity"] == "HIGH"
    assert alert["status"] == "OPEN"
    
    
def test_alert_saved_to_file(temp_alert_file):
    
    alert_manager.create_alert(
        finding="Cloud Reconnaissance",
        severity="Medium",
        source_ip="10.0.0.5",
        user="unknown",
        mitre_technique="T1580",
        description="Enumeration activity."
    )
    
    with open(alert_manager.ALERT_FILE, "r") as file:
        
        alerts = json.load(file)
        
    assert len(alerts) == 1
    assert alerts[0]["finding"] == "Cloud Reconnaissance"
    
    
def test_close_alert(temp_alert_file):
    
    alert = alert_manager.create_alert(
        finding="Brute Force Attempt",
        severity="HIGH",
        source_ip="8.8.8.8",
        user="admin",
        mitre_technique="T1110",
        description="Repeated failed logins."
    )
    
    alert_manager.close_alert(alert["id"])
    
    alerts = alert_manager.load_alerts()
    
    assert alerts[0]["status"] == "CLOSED"
    
    
def test_get_open_alerts(temp_alert_file):
    
    alert_manager.create_alert(
        finding="Public Bucket Exposure",
        severity="HIGH",
        source_ip="1.1.1.1",
        user="storage-admin",
        mitre_technique="T1530",
        description="Bucket made public."
    )
    
    open_alerts = alert_manager.get_open_alerts()
    
    assert len(open_alerts) == 1
    assert open_alerts[0]["status"] == "OPEN"