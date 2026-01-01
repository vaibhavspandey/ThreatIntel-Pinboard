# TIPinBoard: Automated Workbench for Threat Intelligence

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white)](https://www.docker.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=flat&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=flat&logo=streamlit&logoColor=white)](https://streamlit.io/)

**TIPinBoard** is an open-source, longitudinal tracking workbench for Cyber Threat Intelligence (CTI) analysts. It shifts the paradigm from passive, point-in-time data collection to **active, state-change monitoring**.

By automating the lifecycle management of Indicators of Compromise (IOCs), TIPinBoard solves the "stale intelligence" problem, alerting analysts only when a monitored asset evolves (e.g., a hash detection spike or a domain resolving to a new C2 IP).

---

## 🚀 Why TIPinBoard?

### The Problem: Stale Intelligence
Adversaries rotate infrastructure rapidly. A C2 domain might be active for only 24 hours, or a malware hash might be "Clean" today but "Malicious" tomorrow. Traditional workflows involve analysts manually re-checking VirusTotal or spreadsheets. This is slow, unscalable, and leads to **alert fatigue**.

### The Solution: The Delta Engine
TIPinBoard introduces the concept of **"Deltas"**—algorithmic detections of state variance over time.
1.  **Pin:** You track an IOC (Hash, Domain, IP).
2.  **Snapshot:** The system creates a baseline (Time 0).
3.  **Monitor:** It polls high-fidelity APIs (VirusTotal, MalwareBazaar) on a schedule.
4.  **Alert:** If $State_{current} \neq State_{baseline}$, a Delta Alert is generated.

---

## ✨ Key Features

* **Longitudinal Tracking:** Maintains a history of JSON snapshots for every IOC, creating a timeline of adversarial evolution.
* **Infrastructure Pivoting:** Automatically detects when a monitored malware sample communicates with a *new*, previously unknown IP or Domain, exposing new parts of the attacker's infrastructure.
* **Cognitive Load Reduction:** Filters out static noise. You are only notified when a metric (Detection Ratio, WHOIS info, DNS resolution) actually changes.
* **Decoupled Architecture:** Built with microservices (FastAPI backend, Streamlit frontend, Postgres DB) to handle API rate limits asynchronously.
* **Containerized:** Fully Dockerized for one-command deployment.

---

## 🛠️ Tech Stack

* **Frontend:** Streamlit (Python)
* **Backend:** FastAPI (Python)
* **Database:** PostgreSQL
* **Task Scheduling:** APScheduler (Async)
* **Containerization:** Docker & Docker Compose
* **Integrations:** VirusTotal API v3, MalwareBazaar, URLScan.io

---

## 🏗️ Architecture

The system follows a standard Producer-Consumer model to handle external API rate limits gracefully.

```mermaid
graph TD
    User((Analyst)) -->|Pin IOC| UI[Streamlit Frontend]
    UI -->|POST /pin| API[FastAPI Backend]
    API -->|Write| DB[(PostgreSQL)]
    
    Scheduler[Monitor Service] -->|Fetch Active Pins| DB
    Scheduler -->|Poll| Ext[External APIs (VT/MalwareBazaar)]
    Ext -->|JSON Report| Scheduler
    
    Scheduler -->|Compare vs Baseline| DeltaEngine{Delta Engine}
    DeltaEngine -- No Change --> DB
    DeltaEngine -- CHANGE DETECTED --> Alert[Create Alert Record]
    Alert --> DB
