![Pipeline Status](https://github.com/USERNAME/cloud-security-monitoring-lab/actions/workflows/security_pipeline.yml/badge.svg)
# Cloud Security Monitoring & Threat Detection Platform

## Overview

The Cloud Security Monitoring & Threat Detection Platform is a Python-based security engineering project that simulates cloud audit logging, threat detection, security alerting, and incident reporting.

The platform generates realistic cloud activity, simulates attack scenarios, analyzes audit logs, identifies suspicious behavior, generates alerts, and produces incident reports. The project was designed to demonstrate security monitoring, detection engineering, incident response, and automation skills without requiring paid cloud infrastructure.

---

## Objectives

* Simulate cloud security monitoring workflows
* Detect common cloud attack techniques
* Generate security alerts automatically
* Produce incident reports and executive summaries
* Map findings to MITRE ATT&CK techniques
* Demonstrate security engineering best practices

---

## Features

### Log Generation

Creates realistic cloud audit logs that simulate normal user activity.

Examples:

* User logins
* Storage access
* Instance management
* Resource enumeration

### Attack Simulation

Generates simulated attacker activity including:

* Brute force authentication attempts
* Privilege escalation
* Public bucket exposure
* Cloud reconnaissance

### Threat Detection

Detects suspicious activity using custom detection rules.

Supported detections:

* Brute Force Attempt
* Privilege Escalation
* Public Bucket Exposure
* Cloud Reconnaissance

### Alert Management

Creates structured security alerts including:

* Severity
* Description
* MITRE ATT&CK Mapping
* Source Information
* Alert Status

### Security Dashboard

Displays:

* Alert counts
* Severity breakdown
* Top findings
* Open incidents
* Recommended actions

### Incident Reporting

Automatically generates:

* Incident Reports
* Executive Summaries
* Risk Assessments

---

## Project Architecture

```text
Log Generator
      │
      ▼
Attack Simulator
      │
      ▼
cloudtrail.json
      │
      ▼
Detection Engine
      │
      ▼
Alert Manager
      │
      ▼
alerts.json
      │
      ├── Dashboard
      │
      └── Report Generator
               │
               ▼
      incident_report.md
```

---

## Repository Structure

```text
cloud-security-monitoring-lab/
│
├── alerts/
├── dashboard/
├── detections/
├── docs/
├── incident_response/
├── logs/
├── reports/
├── scripts/
├── tests/
│
└── README.md
```

---

## Detection Coverage

| Attack Scenario        | Severity | MITRE ATT&CK |
| ---------------------- | -------- | ------------ |
| Brute Force Attempt    | HIGH     | T1110        |
| Privilege Escalation   | HIGH     | T1098        |
| Public Bucket Exposure | HIGH     | T1530        |
| Cloud Reconnaissance   | MEDIUM   | T1580        |

---

## Installation

### Clone Repository

```bash
git clone https://github.com/yourusername/cloud-security-monitoring-lab.git

cd cloud-security-monitoring-lab
```

### Install Requirements

```bash
pip install pytest
```

---

## Usage

### Generate Normal Activity

```bash
python scripts/log_generator.py
```

### Simulate Attacks

```bash
python scripts/attack_simulator.py
```

### Run Detections

```bash
python scripts/detection_engine.py
```

### View Dashboard

```bash
python dashboard/dashboard.py
```

### Generate Incident Report

```bash
python scripts/report_generator.py
```

---

## Example Dashboard Output

```text
============================================================
 CLOUD SECURITY MONITORING DASHBOARD
============================================================

Total Alerts : 4

HIGH         : 3
MEDIUM       : 1

Top Findings

Privilege Escalation
Public Bucket Exposure
Cloud Reconnaissance
Brute Force Attempt
```

---

## Testing

Run all tests:

```bash
pytest tests/
```

Expected result:

```text
========================
6 passed
========================
```

---

## Documentation

Additional documentation is available in the docs directory:

* architecture.md
* threat_model.md
* deployment_guide.md
* security_assessment.md

Incident response documentation is available in:

* playbook_bruteforce.md
* playbook_iam_abuse.md
* playbook_public_bucket.md

---

## Skills Demonstrated

### Security Engineering

* Security Monitoring
* Detection Engineering
* Threat Detection
* Incident Response
* Security Reporting

### Software Engineering

* Python Development
* Automated Testing
* JSON Data Processing
* Modular Design
* Git Version Control

### Security Operations

* Alert Triage
* Risk Assessment
* MITRE ATT&CK Mapping
* Threat Analysis

---

## Future Improvements

* Web-Based Dashboard
* Real-Time Log Streaming
* Threat Intelligence Integration
* User Behavior Analytics
* Alert Deduplication
* Automated Response Actions

---

## Author

Lalaine Hines

Security Engineering Portfolio Project
