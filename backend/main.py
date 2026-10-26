"""
SentinelX AI - FastAPI Application
Main backend API server providing endpoints for log ingestion, attack detection,
AI-powered incident explanation, analyst chat, and empirical detector evaluation.
"""

from datetime import datetime, timezone
import math
import os
import sys
from typing import Any, Dict, List, Optional

# Ensure backend directory is in Python path for imports
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import uvicorn

from ai_explainer import AIExplainer
from detector import DetectionEngine, Incident
from evaluation import evaluate_detector, load_labelled_data
import log_parser

# Load environment variables
load_dotenv()

# App initialization
app = FastAPI(
    title="SentinelX AI",
    description="Autonomous Cybersecurity Detection & AI Explainer Engine",
    version="1.0.0"
)

# CORS configuration for development and frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for parsed events and engine instances
parsed_events: List[Dict[str, Any]] = []
detection_engine = DetectionEngine()
ai_explainer = AIExplainer()

# Directories
PROJECT_ROOT = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(FRONTEND_DIR, exist_ok=True)

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB


# Pydantic models for request bodies
class QuestionRequest(BaseModel):
    question: str = Field(..., min_length=1, description="Question for the AI security analyst")


def _ensure_sample_datasets() -> None:
    """Ensures that demo and labelled test files exist on disk."""
    demo_path = os.path.join(DATA_DIR, "demo_logs.csv")
    labelled_path = os.path.join(DATA_DIR, "labelled_test_logs.csv")

    if not os.path.exists(demo_path) or not os.path.exists(labelled_path):
        import csv

        rows = []
        base_time = 1730000000  # Unix timestamp

        # 1. Normal benign activity (50 events)
        users = ["alice", "bob", "carol", "david", "emma"]
        benign_ips = ["10.0.0.15", "10.0.0.22", "10.0.0.30", "192.168.1.105"]
        ports = [80, 443, 22, 53]

        for i in range(50):
            ts = datetime.fromtimestamp(base_time + (i * 20), tz=timezone.utc).isoformat()
            rows.append({
                "event_id": f"EVT-{i+1:04d}",
                "timestamp": ts,
                "src_ip": benign_ips[i % len(benign_ips)],
                "dst_ip": "10.0.0.1",
                "dst_port": ports[i % len(ports)],
                "event_type": "login_success" if i % 4 == 0 else "connection",
                "username": users[i % len(users)],
                "status": "success",
                "label": "normal"
            })

        # 2. Brute Force attack from 198.51.100.42 (35 events in 70s)
        bf_ip = "198.51.100.42"
        for i in range(35):
            ts = datetime.fromtimestamp(base_time + 1200 + (i * 2), tz=timezone.utc).isoformat()
            rows.append({
                "event_id": f"EVT-{len(rows)+1:04d}",
                "timestamp": ts,
                "src_ip": bf_ip,
                "dst_ip": "10.0.0.5",
                "dst_port": 22,
                "event_type": "login_failed",
                "username": "root",
                "status": "failed",
                "label": "brute_force"
            })

        # 3. Port Scan attack from 203.0.113.88 (20 distinct ports in 40s)
        scan_ip = "203.0.113.88"
        scan_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 9200]
        for i, port in enumerate(scan_ports):
            ts = datetime.fromtimestamp(base_time + 2400 + (i * 2), tz=timezone.utc).isoformat()
            rows.append({
                "event_id": f"EVT-{len(rows)+1:04d}",
                "timestamp": ts,
                "src_ip": scan_ip,
                "dst_ip": "10.0.0.10",
                "dst_port": port,
                "event_type": "connection",
                "username": "",
                "status": "closed",
                "label": "port_scan"
            })

        # 4. Login Burst (Credential Stuffing) from 192.0.2.15 (8 different usernames in 60s)
        burst_ip = "192.0.2.15"
        burst_users = ["admin", "administrator", "guest", "test", "sales", "operator", "backup", "support"]
        for i, user in enumerate(burst_users):
            ts = datetime.fromtimestamp(base_time + 3600 + (i * 6), tz=timezone.utc).isoformat()
            rows.append({
                "event_id": f"EVT-{len(rows)+1:04d}",
                "timestamp": ts,
                "src_ip": burst_ip,
                "dst_ip": "10.0.0.20",
                "dst_port": 443,
                "event_type": "login_failed",
                "username": user,
                "status": "failed",
                "label": "login_burst"
            })

        fieldnames = ["event_id", "timestamp", "src_ip", "dst_ip", "dst_port", "event_type", "username", "status", "label"]

        if not os.path.exists(labelled_path):
            with open(labelled_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

        if not os.path.exists(demo_path):
            with open(demo_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=[col for col in fieldnames if col != "label"])
                writer.writeheader()
                for r in rows:
                    demo_r = {k: v for k, v in r.items() if k != "label"}
                    writer.writerow(demo_r)


# Initialize sample datasets on module startup
_ensure_sample_datasets()


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/api/health")
def health_check() -> Dict[str, Any]:
    """Health check endpoint indicating server and AI status."""
    return {
        "status": "ok",
        "service": "SentinelX AI",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ai_available": ai_explainer.is_available(),
        "ai_model": ai_explainer.model,
        "events_loaded": len(parsed_events),
        "incidents_count": len(detection_engine.get_all_incidents()),
    }


@app.get("/api/demo-logs")
def load_demo_logs() -> Dict[str, Any]:
    """Loads demo security logs from disk and initializes parsed events."""
    global parsed_events
    demo_path = os.path.join(DATA_DIR, "demo_logs.csv")
    if not os.path.exists(demo_path):
        _ensure_sample_datasets()

    try:
        result = log_parser.load_demo_logs(demo_path)
        parsed_events = result.get("events", [])
        return {
            "status": "success",
            "message": f"Successfully loaded {len(parsed_events)} demo log events.",
            "total": result.get("total", len(parsed_events)),
            "errors": result.get("errors", 0),
            "error_details": result.get("error_details", []),
            "events_sample": parsed_events[:25],
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load demo logs: {str(e)}"
        )


@app.post("/api/logs/upload")
async def upload_logs(file: UploadFile = File(...)) -> Dict[str, Any]:
    """
    Accepts CSV or JSON file upload (up to 10MB), validates and normalizes events,
    and saves them to in-memory storage.
    """
    global parsed_events

    filename = file.filename or "unknown"
    ext = os.path.splitext(filename)[1].lower()

    if ext not in (".csv", ".json", ".jsonl", ".ndjson"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file extension '{ext}'. Only .csv and .json files are accepted."
        )

    # Read content with size enforcement
    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum size of 10MB ({len(contents)} bytes uploaded)."
        )

    try:
        decoded_text = contents.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to decode file text: {str(e)}"
        )

    if ext in (".json", ".jsonl", ".ndjson"):
        parse_result = log_parser.parse_json(decoded_text)
    else:
        parse_result = log_parser.parse_csv(decoded_text)

    events = parse_result.get("events", [])
    if not events and parse_result.get("errors", 0) > 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": "Failed to parse any valid records from uploaded file.",
                "errors": parse_result.get("error_details", [])[:10]
            }
        )

    parsed_events = events

    return {
        "status": "success",
        "filename": filename,
        "total_events": len(parsed_events),
        "parse_errors": parse_result.get("errors", 0),
        "error_details": parse_result.get("error_details", [])[:20],
        "events_sample": parsed_events[:50],
    }


@app.get("/api/logs")
def get_logs(
    search: Optional[str] = Query(None, description="Free text search filter"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    src_ip: Optional[str] = Query(None, description="Filter by source IP"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(100, ge=1, le=1000, description="Page size"),
) -> Dict[str, Any]:
    """Retrieves loaded events with optional search, filtering, and pagination."""
    filtered = parsed_events

    if search:
        s = search.lower().strip()
        filtered = [
            e for e in filtered
            if s in str(e.get("event_id", "")).lower()
            or s in str(e.get("src_ip", "")).lower()
            or s in str(e.get("dst_ip", "")).lower()
            or s in str(e.get("username", "")).lower()
            or s in str(e.get("event_type", "")).lower()
            or s in str(e.get("status", "")).lower()
        ]

    if event_type:
        et = event_type.lower().strip()
        filtered = [e for e in filtered if et in str(e.get("event_type", "")).lower()]

    if src_ip:
        sip = src_ip.strip()
        filtered = [e for e in filtered if sip == str(e.get("src_ip", ""))]

    total_matching = len(filtered)
    total_pages = math.ceil(total_matching / limit) if limit > 0 else 1
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    page_events = filtered[start_idx:end_idx]

    return {
        "events": page_events,
        "total": total_matching,
        "page": page,
        "limit": limit,
        "total_pages": total_pages,
        "total_loaded_in_memory": len(parsed_events),
    }


@app.post("/api/detect")
def run_detection() -> Dict[str, Any]:
    """Runs all correlation rules on current in-memory events and creates incidents."""
    global parsed_events

    if not parsed_events:
        # If no events uploaded, auto-load demo data so user gets immediate results
        demo_path = os.path.join(DATA_DIR, "demo_logs.csv")
        if os.path.exists(demo_path):
            res = log_parser.load_demo_logs(demo_path)
            parsed_events = res.get("events", [])

    if not parsed_events:
        return {
            "status": "warning",
            "message": "No log events loaded. Upload a file or load demo logs first.",
            "incidents": [],
            "total_incidents": 0,
            "events_analyzed": 0,
        }

    detection_engine.clear()
    incidents = detection_engine.run_all_rules(parsed_events)

    return {
        "status": "success",
        "incidents": [inc.to_dict() for inc in incidents],
        "total_incidents": len(incidents),
        "events_analyzed": len(parsed_events),
    }


@app.get("/api/incidents")
def list_incidents() -> Dict[str, Any]:
    """Returns all incidents detected by the detection engine."""
    incidents = detection_engine.get_all_incidents()
    return {
        "incidents": [inc.to_dict() for inc in incidents],
        "total": len(incidents),
    }


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str) -> Dict[str, Any]:
    """Retrieves full details of a specific incident along with its supporting evidence."""
    incident = detection_engine.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found."
        )

    evidence = detection_engine.get_evidence(incident_id, parsed_events)
    return {
        "incident": incident.to_dict(),
        "evidence": evidence,
        "evidence_count": len(evidence),
    }


@app.post("/api/incidents/{incident_id}/explain")
def explain_incident(incident_id: str) -> Dict[str, Any]:
    """
    Invokes the AI Explainer (Gemma 4 31B) to analyze the incident and its evidence.
    Falls back gracefully if the API key is not configured.
    """
    incident = detection_engine.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found."
        )

    evidence = detection_engine.get_evidence(incident_id, parsed_events)
    result = ai_explainer.explain_incident(incident.to_dict(), evidence)
    return result


@app.post("/api/incidents/{incident_id}/ask")
def ask_incident_question(incident_id: str, payload: QuestionRequest) -> Dict[str, Any]:
    """Answers analyst questions grounded strictly in the incident's evidence logs."""
    incident = detection_engine.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found."
        )

    evidence = detection_engine.get_evidence(incident_id, parsed_events)
    result = ai_explainer.ask_question(incident.to_dict(), evidence, payload.question)
    return result


@app.get("/api/evaluation")
def run_evaluation() -> Dict[str, Any]:
    """
    Evaluates detector performance against labelled ground-truth security datasets.
    Computes precision, recall, F1, and confusion matrix.
    """
    labelled_path = os.path.join(DATA_DIR, "labelled_test_logs.csv")
    if not os.path.exists(labelled_path):
        _ensure_sample_datasets()

    try:
        labelled_events = load_labelled_data(labelled_path)
        eval_detector = DetectionEngine()
        metrics = evaluate_detector(eval_detector, labelled_events)
        return {
            "status": "success",
            "metrics": metrics,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Evaluation failed: {str(e)}"
        )


# ============================================================================
# Frontend Static Files & SPA Routing
# ============================================================================

index_html_path = os.path.join(FRONTEND_DIR, "index.html")

if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static-assets")


@app.get("/", response_class=HTMLResponse)
def serve_index():
    """Serves index.html from frontend directory, or a default status page if frontend is building."""
    if os.path.exists(index_html_path):
        return FileResponse(index_html_path)

    return HTMLResponse(content="""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelX AI - Cybersecurity Intelligence Platform</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 32px; max-width: 600px; text-align: center; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
        h1 { color: #38bdf8; margin-top: 0; }
        p { color: #94a3b8; line-height: 1.6; }
        .badge { display: inline-block; padding: 6px 12px; border-radius: 9999px; background: #0369a1; color: #e0f2fe; font-size: 13px; font-weight: 600; margin-bottom: 16px; }
        a { color: #38bdf8; text-decoration: none; font-weight: 600; }
        a:hover { text-decoration: underline; }
        .endpoints { text-align: left; background: #0f172a; padding: 16px; border-radius: 8px; margin-top: 20px; font-family: monospace; font-size: 13px; color: #cbd5e1; }
    </style>
</head>
<body>
    <div class="card">
        <span class="badge">Backend Active</span>
        <h1>🛡️ SentinelX AI Engine</h1>
        <p>The backend API is running and ready. Detection rules, log parser, AI explainer (Gemma 4 31B), and evaluation modules are fully loaded.</p>
        <div class="endpoints">
            <div>• <a href="/docs" target="_blank">Interactive API Docs (/docs)</a></div>
            <div>• <a href="/api/health" target="_blank">Health Status (/api/health)</a></div>
            <div>• <a href="/api/demo-logs" target="_blank">Demo Logs (/api/demo-logs)</a></div>
            <div>• <a href="/api/evaluation" target="_blank">Evaluation Metrics (/api/evaluation)</a></div>
        </div>
    </div>
</body>
</html>
""")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
