# 🛡️ SentinelX AI

**AI-Assisted Cybersecurity Incident Detection & Investigation Platform**

> Built for hackathons. Powered by Google Gemma 4 on DigitalOcean.

---

## Overview

**SentinelX AI** is an intelligent, human-in-the-loop cybersecurity incident detection and triage platform designed to augment Security Operations Center (SOC) teams. Modern security analysts face a deluge of security telemetry across thousands of endpoints and firewalls, causing severe alert fatigue, missed signals, and protracted response times. SentinelX AI bridges the gap between raw data collection and rapid, verifiable incident containment.

The platform pairs high-speed deterministic threat correlation engines with advanced generative AI reasoning powered by Google Gemma 4 (`gemma-4-31B-it`) hosted on DigitalOcean's Serverless Inference infrastructure. SentinelX AI automatically parses raw authentication and network connection logs, links disparate events into cohesive incident clusters, and presents analysts with concrete evidence chains. Every AI inference is grounded directly in verified log records to prevent hallucinations and support defensible triage.

With built-in features including an interactive Investigation Copilot, quantitative detection evaluation metrics (Precision, Recall, F1 score), and safe, review-gated response checklists, SentinelX AI empowers tier-1 analysts to perform senior-level security triage with confidence and speed.

---

## Features

- ✅ **Security Log Ingestion**: High-throughput parsing for both CSV and JSON log formats with automatic schema validation and normalization.
- ✅ **Deterministic Rule-Based Threat Detection**: Accurate correlation rules identifying brute force credential attacks, horizontal/vertical port scans, and suspicious authentication bursts.
- ✅ **Evidence-Linked Incident Triage**: Direct bidirectional mapping between high-level security alerts and underlying raw event records, providing complete provenance.
- ✅ **AI-Powered Deep Incident Analysis**: Automated root cause analysis, MITRE ATT&CK technique mapping, and risk severity scoring via Google Gemma 4.
- ✅ **Interactive Investigation Copilot**: Conversational AI assistant allowing analysts to probe suspicious anomalies, draft custom hunting queries, and contextualize threat actors.
- ✅ **Detection Performance Evaluation**: Built-in benchmark suite computing precision, recall, and F1 score against labelled ground-truth security datasets.
- ✅ **Safe Response Planning**: Defensible, human-gated remediation playbooks with structured pre-flight checklists to prevent accidental operational outages.
- ✅ **Cybersecurity SOC Dashboard**: Professional, dark-mode responsive user interface built for high-density information display and low cognitive friction.

---

## Quick Start

### Prerequisites
- Python 3.10+
- (Optional) DigitalOcean API key for AI features

### Local Setup

```bash
# Clone the repository
git clone <your-repo-url>
cd sentinelx-ai

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r backend/requirements.txt

# Configure environment (optional - for AI features)
cp .env.example .env
# Edit .env and add your DIGITALOCEAN_INFERENCE_KEY

# Run the application
python backend/main.py
```

Open [http://localhost:8000](http://localhost:8000) in your browser.

### Using Docker

```bash
docker build -t sentinelx-ai .
docker run -p 8000:8000 -e DIGITALOCEAN_INFERENCE_KEY=your_key sentinelx-ai
```

---

## Demo Walkthrough

Follow this step-by-step walkthrough to experience the end-to-end capabilities of SentinelX AI during a demo or evaluation:

1. **Open the Dashboard**: Navigate to `http://localhost:8000` to access the SentinelX AI Security Operations Center dashboard.
2. **Navigate to Log Explorer**: Select **Log Explorer** from the navigation sidebar.
3. **Load Demo Data**: Click **'Load Demo Data'** to ingest the pre-packaged 200+ record synthetic security dataset (`data/demo_logs.csv`), containing realistic business traffic, an active SSH brute-force attack, and a rapid multi-port scan.
4. **Inspect Telemetry**: Browse, search, and filter the parsed events table by status (`success`/`failure`), event type, or IP address.
5. **Inspect Threat Incidents**: Navigate to **Incidents**. Notice the rule detection engine has automatically correlated suspicious clusters into distinct incidents.
6. **Examine Incident Details**: Select a brute force incident (e.g., source IP `203.0.113.42` targeting port 22).
7. **Review Evidence Timeline**: Inspect the timestamped evidence timeline displaying the sequence of failed authentication attempts, targeted accounts, and rapid repetition intervals.
8. **Generate AI Analysis**: Click **'Generate AI Analysis'** to invoke Google Gemma 4 on DigitalOcean. Review the structured summary, severity justification, MITRE ATT&CK technique IDs (e.g., T1110.001), and immediate containment advice.
9. **Engage Investigation Copilot**: In the incident's Copilot chat window, ask follow-up questions such as *"Did this IP attempt to access any other internal hosts?"* or *"Draft an iptables rule to block this source subnet."*
10. **Review Safe Response Checklist**: Inspect the generated remediation plan. Verify safety items (e.g., validating source IP ownership, reviewing whitelists) before executing containment actions.
11. **Evaluate Detection Accuracy**: Navigate to **Evaluation** and click **'Run Evaluation'** against `data/labelled_test_logs.csv` to view precision, recall, confusion matrix, and F1 performance metrics.

---

## Architecture

SentinelX AI is built on a clean, decoupled architecture optimized for low-latency triage and reliable AI integration:

```
+-------------------------------------------------------------------------+
|                         SentinelX AI Frontend                           |
|       (HTML5, CSS3 Custom SOC Theme, Vanilla ES6+ JavaScript)          |
|  - Dashboard Overview   - Log Explorer       - Incident Detail Modal    |
|  - Threat Timeline      - Copilot Chat Box   - Evaluation Benchmark     |
+------------------------------------+------------------------------------+
                                     | HTTP / REST API (Port 8000)
                                     v
+-------------------------------------------------------------------------+
|                        FastAPI Backend Engine                           |
|                                                                         |
|  +--------------------+   +---------------------+   +----------------+  |
|  | Log Ingestion &    |   | Deterministic Rule  |   | Evidence       |  |
|  | Normalization      |-->| Correlation Engine  |-->| Graph Linker   |  |
|  +--------------------+   +---------------------+   +----------------+  |
|                                                               |         |
|  +--------------------+   +---------------------+             v         |
|  | Evaluation Bench   |   | Safe Response       |   +----------------+  |
|  | (Precision/Recall) |   | Playbook Generator  |   | Incidents Repo |  |
|  +--------------------+   +---------------------+   +----------------+  |
|                                     |                         |         |
|                                     v                         v         |
|                 +---------------------------------------+               |
|                 |    AI Orchestration & Prompt Engine   |               |
|                 +-------------------+-------------------+               |
+-------------------------------------|-----------------------------------+
                                      | OpenAI-Compatible API
                                      v
+-------------------------------------------------------------------------+
|                     DigitalOcean Inference Cloud                        |
|                                                                         |
|                 Model: Google Gemma 4 (gemma-4-31B-it)                  |
|          - Structured Threat Analysis   - Copilot Dialogue              |
+-------------------------------------------------------------------------+
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check verifying server and inference readiness |
| `POST` | `/api/logs/upload` | Upload and parse custom CSV or JSON security log files |
| `GET` | `/api/logs/demo` | Ingest and initialize the bundled synthetic demo dataset |
| `GET` | `/api/logs` | Query stored logs with filtering by IP, event type, status, and paging |
| `POST` | `/api/detection/run` | Execute detection correlation rules over current logs |
| `GET` | `/api/incidents` | List all identified security incidents and summary metrics |
| `GET` | `/api/incidents/{incident_id}` | Retrieve comprehensive incident dossier with linked evidence |
| `POST` | `/api/incidents/{incident_id}/analyze` | Invoke Google Gemma 4 AI reasoning for threat summarization |
| `POST` | `/api/incidents/{incident_id}/chat` | Ask interactive follow-up questions to the Investigation Copilot |
| `POST` | `/api/evaluation/run` | Run benchmark detection against ground-truth labelled test logs |

---

## DigitalOcean Deployment

### Using App Platform

1. Fork or push this repository to your GitHub or GitLab account.
2. In the [DigitalOcean Cloud Console](https://cloud.digitalocean.com/), navigate to **App Platform** and click **Create App**.
3. Select your repository and designated branch (`main`).
4. Configure the service as a **Web Service**:
   - **Environment**: Python
   - **Build Command**: `pip install -r backend/requirements.txt`
   - **Run Command**: `python backend/main.py`
   - **HTTP Port**: `8000`
5. In the **Environment Variables** section, configure:
   - `DIGITALOCEAN_INFERENCE_KEY`: Your DigitalOcean Inference API access token
   - `PORT`: `8000`
6. Click **Deploy** to launch the live SentinelX AI instance.

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DIGITALOCEAN_INFERENCE_KEY` | For AI features | DigitalOcean Inference API token for Gemma 4 access |
| `PORT` | No | Server listening port (default: `8000`) |

### Health Check

The service exposes an automated health probe at:
```http
GET /api/health
```
Returning HTTP 200:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "ai_configured": true
}
```

---

## Technology Stack

- **Frontend**: HTML5, Modern CSS3 with CSS Variables, Vanilla ES6+ JavaScript (Zero external JS build dependencies for instant deployment).
- **Backend**: Python 3.11, FastAPI, Uvicorn, Pydantic v2.
- **AI Model**: Google Gemma 4 (`gemma-4-31B-it`).
- **AI Inference Infrastructure**: DigitalOcean Serverless Inference API.
- **Containerization & Deployment**: Docker (OCI-compliant), DigitalOcean App Platform.

---

## Limitations

- **Demo Telemetry Scope**: Uses synthetic log data crafted to illustrate realistic attack trajectories rather than live network tap feeds.
- **Rule Threshold Heuristics**: Detection thresholds are optimized for demo datasets; production deployment requires environment-specific baselining.
- **Evaluation Dataset Size**: The evaluation dataset contains 100 annotated records designed for hackathon verification rather than exhaustive enterprise benchmarks.
- **Inference Availability**: Advanced AI synthesis requires connectivity to DigitalOcean Inference API endpoints.
- **In-Memory Volatility**: Telemetry and incident states are retained in memory during runtime and reset upon application restart.
- **Authentication**: Authentication and role-based access control (RBAC) are excluded to streamline hackathon demonstration.

---

## Security Considerations

- **Server-Side API Key Protection**: The `DIGITALOCEAN_INFERENCE_KEY` is maintained exclusively on the server backend and never exposed to the client browser.
- **Untrusted File Ingestion**: Ingested log files are strictly sanitized, type-validated, and schema-checked; executable payloads or malicious markup are discarded.
- **Human-in-the-Loop Safeguards**: Remediation recommendations (such as firewall blocks or credential revoking) are strictly advisory and require human confirmation before action.
- **Payload Limits**: Strict file size constraints are enforced on log upload endpoints to mitigate Denial of Service (DoS) risks.
- **No Remote Code Execution**: Log processing is restricted to declarative parsing and matching without evaluating user-supplied code or queries.

---

## License

This project is licensed under the [MIT License](LICENSE).
