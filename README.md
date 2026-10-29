# AI Guardrail & Prompt Injection Sandbox Dashboard

> A production-grade MLSecOps security gateway and real-time monitoring dashboard designed to detect, filter, and log prompt injections, jailbreaks, and adversarial payloads before they reach downstream LLMs.

---

## 🏗️ Architecture & Tech Stack

This project implements a multi-service microservice security architecture:
* **Backend & Guardrail Engine:** Python, FastAPI, Regex/Heuristic Rules, Pytest
* **Database & Log Store:** MongoDB (for asynchronous threat telemetry and structured payload logging)
* **Frontend & SOC Dashboard:** React (Real-time alert feeds, threat-score metrics, and security logs)
* **Orchestration & Deployment:** Docker, Docker Compose, GitHub Actions (CI/CD)

---

## 🛡️ Core Features (OWASP Top 10 for LLMs)

* **Inline Prompt Inspection:** Analyzes incoming text payloads in real-time before LLM execution.
* **Deterministic Heuristic Filters:** Instantly flags high-risk signatures (e.g., direct instruction overrides, roleplay jailbreaks, base64-encoded strings).
* **Fail-Secure Architecture:** Automatically blocks malicious inputs, preventing unsafe code execution or model manipulation.
* **SOC Real-Time Dashboard:** Visualizes blocked requests, threat severity scores, and latency telemetry.

---

## 📁 Project Structure

```text
ai-guardrail-sandbox/
├── .github/workflows/       # Automated CI/CD pipelines (GitHub Actions)
├── backend/                 # FastAPI security engine & unit tests
├── frontend/                # React Security Operations Center (SOC) dashboard
├── docker-compose.yml       # Multi-container orchestration config
└── README.md
```

---

## 🚀 Getting Started Locally

1. Prerequisites

* Docker & Docker Compose installed on your machine.
* Python 3.10+ (for local backend development/testing).

2. Running with Docker Compose

To spin up the entire stack (FastAPI backend, MongoDB, and React frontend) with a single command:
docker compose up --build

3. Running Backend Unit Tests

To run the security rule test suite using pytest:
cd backend
PYTHONPATH=. pytest

---

## 👩‍💻 Author

Sunsuvan Bakshi
Computer Science & Engineering | MLSecOps & AI Security Engineering
