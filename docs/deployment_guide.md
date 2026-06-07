# Deployment Guide

## Requirements

- Python 3.11+
- pytest

## Installation

git clone <repository>

cd cloud-security-monitoring-lab

pip install pytest

## Running the Platform

Generate normal activity:

python scripts/log_generator.py

Generate attacks:

python scripts/attack_simulator.py

Run detections:

python scripts/detection_engine.py

View dashboard:

python dashboard/dashboard.py

Generate report:

python scripts/report_generator.py