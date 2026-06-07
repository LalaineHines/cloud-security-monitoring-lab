# System Architecture

## Components

### Log Generator

Creates realistic cloud audit logs.

### Attack Simulator

Generates malicious cloud activity.

### Detection Engine

Processes logs and identifies suspicious behavior.

### Alert Manager

Stores and manages security findings.

### Dashboard

Displays security metrics and alerts.

### Report Generator

Creates incident reports for analysts.

## Data Flow

Log Generator
↓
Attack Simulator
↓
cloudtrail.json
↓
Detection Engine
↓
alerts.json
↓
Dashboard
↓
Incident Report