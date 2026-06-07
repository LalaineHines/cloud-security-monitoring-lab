"""
test_detections.py

Tests for detection_engine.py
"""

from scripts.detection_engine import (
    detect_public_bucket,
    detect_privilege_escalation,
)

from unittest import patch


def test_public_bucket_detection():
    
    event = {
        "eventName": "PutBucketAcl",
        "acl": "public-read",
        "sourceIPAddress": "192.168.1.50",
        "user": "storage-admin"
    }
    
    with patch(
        "scripts.detection_engine.create_alert"
    ) as mock_alert:
        
        detect_public_bucket(event)
        
        mock_alert.assert_called_once()
        
        
def test_privilege_escalation_detection():
    
    event = {
        "eventName": "AttachuserPolicy",
        "policy": "AdministratorAccess",
        "sourceIPAddress": "192.168.1.100",
        "user": "developer"
    }
    
    with patch(
        "scripts.detection_engine.create_alert"
    ) as mock_alert:
        
        detect_privilege_escalation(event)
        
        mock_alert.assert_called_once()