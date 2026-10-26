"""
SentinelX AI - Log Parser Module
Parses, normalizes, and validates security logs from CSV and JSON files.
Treats all log data as untrusted input.
"""

from datetime import datetime, timezone
import io
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

MAX_RECORDS_LIMIT = 50000

# Canonical mappings from possible input column/field names to canonical fields
FIELD_MAPPINGS = {
    "event_id": [
        "event_id", "eventid", "evt_id", "id", "log_id", "record_id",
        "event_identifier", "uuid"
    ],
    "timestamp": [
        "timestamp", "time", "datetime", "date", "ts", "@timestamp",
        "event_time", "log_time", "time_stamp", "created_at"
    ],
    "src_ip": [
        "src_ip", "source_ip", "source", "src", "client_ip", "ip_address",
        "ip", "caller_ip", "origin_ip", "source_address", "src_host"
    ],
    "dst_ip": [
        "dst_ip", "dest_ip", "destination_ip", "destination", "dst",
        "target_ip", "server_ip", "host_ip", "destination_address", "dst_host"
    ],
    "dst_port": [
        "dst_port", "dest_port", "destination_port", "port", "dport",
        "target_port", "server_port", "service_port"
    ],
    "event_type": [
        "event_type", "action", "event", "type", "activity", "operation",
        "event_name", "name", "category", "log_type"
    ],
    "username": [
        "username", "user", "user_name", "account", "principal", "login_user",
        "user_id", "target_user", "identity"
    ],
    "status": [
        "status", "result", "outcome", "state", "response", "login_status",
        "auth_status", "disposition"
    ]
}


def _clean_string(value: Any) -> Optional[str]:
    """Safely converts untrusted value to trimmed string, or None if empty."""
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


def _parse_port(value: Any) -> Optional[int]:
    """Safely parses port to integer (1-65535) or None."""
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            p = int(value)
        else:
            s = str(value).strip()
            if not s:
                return None
            p = int(s)
        if 1 <= p <= 65535:
            return p
        return None
    except (ValueError, TypeError):
        return None


def _parse_timestamp(value: Any) -> str:
    """
    Safely parses timestamp string or unix timestamp into an ISO-8601 string.
    If parsing fails, returns cleaned string or current UTC timestamp.
    """
    if value is None or str(value).strip() == "":
        return datetime.now(timezone.utc).isoformat()

    val_str = str(value).strip()

    # Check if numeric unix timestamp (seconds or milliseconds)
    try:
        numeric_val = float(val_str)
        # If timestamp is likely in milliseconds (greater than 1e11)
        if numeric_val > 1e11:
            numeric_val /= 1000.0
        dt = datetime.fromtimestamp(numeric_val, tz=timezone.utc)
        return dt.isoformat()
    except (ValueError, OverflowError):
        pass

    # Common datetime string formats
    formats = [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%b %d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(val_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except (ValueError, TypeError):
            continue

    # Fallback to trimmed original string representation
    return val_str


def _normalize_dict_keys(record: Dict[str, Any]) -> Dict[str, Any]:
    """Finds best matching canonical field names from raw dictionary keys."""
    # Pre-build lookup from lower-case key to original key
    key_lookup = {str(k).lower().strip(): k for k in record.keys()}

    normalized: Dict[str, Any] = {}
    matched_raw_keys = set()

    for canonical_field, aliases in FIELD_MAPPINGS.items():
        val = None
        for alias in aliases:
            if alias in key_lookup:
                raw_k = key_lookup[alias]
                val = record[raw_k]
                matched_raw_keys.add(raw_k)
                break
        normalized[canonical_field] = val

    # Preserve any additional unmapped keys in raw
    return normalized


def normalize_record(raw_record: Any, index: int = 1) -> Dict[str, Any]:
    """
    Normalizes a single log record dictionary into canonical format.
    
    Returns:
        dict with keys: event_id, timestamp, src_ip, dst_ip, dst_port,
                        event_type, username, status, raw
    """
    if not isinstance(raw_record, dict):
        raise ValueError(f"Record at index {index} is not a dictionary/object: {type(raw_record).__name__}")

    norm = _normalize_dict_keys(raw_record)

    # Event ID normalization
    event_id = _clean_string(norm.get("event_id"))
    if not event_id:
        # Generate stable EVT-XXXX format
        event_id = f"EVT-{index:04d}"

    # Timestamp normalization
    ts = _parse_timestamp(norm.get("timestamp"))

    # IPs normalization
    src_ip = _clean_string(norm.get("src_ip"))
    dst_ip = _clean_string(norm.get("dst_ip"))

    # Port normalization
    dst_port = _parse_port(norm.get("dst_port"))

    # Event type normalization
    raw_event_type = norm.get("event_type")
    event_type = _clean_string(raw_event_type).lower() if raw_event_type is not None else "unknown"

    # Username normalization
    username = _clean_string(norm.get("username"))

    # Status normalization
    raw_status = norm.get("status")
    status = _clean_string(raw_status).lower() if raw_status is not None else None

    # Derive status/event_type if one hints at the other
    if status is None:
        if "failed" in event_type or "failure" in event_type or "denied" in event_type:
            status = "failed"
        elif "success" in event_type or "allowed" in event_type or "accepted" in event_type:
            status = "success"

    # Validation: at least one of event_type, src_ip, timestamp, or username must exist
    if event_type == "unknown" and not src_ip and not username:
        raise ValueError(f"Record at index {index} has no identifiable event_type, src_ip, or username")

    return {
        "event_id": event_id,
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "event_type": event_type,
        "username": username,
        "status": status,
        "raw": raw_record,
    }


def parse_csv(file_content: str) -> Dict[str, Any]:
    """
    Parses CSV security log content into normalized event dictionaries.
    
    Args:
        file_content: Raw CSV string
        
    Returns:
        Dict with "events", "total", "errors", "error_details"
    """
    import csv

    if not file_content or not file_content.strip():
        return {
            "events": [],
            "total": 0,
            "errors": 0,
            "error_details": []
        }

    events: List[Dict[str, Any]] = []
    error_details: List[Dict[str, Any]] = []
    errors_count = 0

    try:
        # Use StringIO to parse CSV without filesystem writes
        reader = csv.DictReader(io.StringIO(file_content))
        
        # Check if CSV headers exist
        if not reader.fieldnames:
            return {
                "events": [],
                "total": 0,
                "errors": 1,
                "error_details": [{"row_index": 0, "error": "CSV contains no header row"}]
            }

        for idx, row in enumerate(reader, start=1):
            if idx > MAX_RECORDS_LIMIT:
                error_details.append({
                    "row_index": idx,
                    "error": f"Maximum record limit of {MAX_RECORDS_LIMIT} reached; remaining records truncated."
                })
                break

            # Skip empty rows
            if not row or not any(str(v).strip() for v in row.values() if v is not None):
                continue

            try:
                normalized = normalize_record(row, index=idx)
                events.append(normalized)
            except Exception as e:
                errors_count += 1
                error_details.append({
                    "row_index": idx,
                    "error": str(e),
                    "data": {k: str(v)[:60] for k, v in row.items() if v is not None}
                })

    except Exception as e:
        errors_count += 1
        error_details.append({
            "row_index": 0,
            "error": f"Failed to parse CSV: {str(e)}"
        })

    return {
        "events": events,
        "total": len(events),
        "errors": errors_count,
        "error_details": error_details
    }


def parse_json(file_content: str) -> Dict[str, Any]:
    """
    Parses JSON (or NDJSON) security log content into normalized event dictionaries.
    
    Args:
        file_content: Raw JSON or newline-delimited JSON string
        
    Returns:
        Dict with "events", "total", "errors", "error_details"
    """
    if not file_content or not file_content.strip():
        return {
            "events": [],
            "total": 0,
            "errors": 0,
            "error_details": []
        }

    events: List[Dict[str, Any]] = []
    error_details: List[Dict[str, Any]] = []
    errors_count = 0
    records_to_process: List[Any] = []

    cleaned = file_content.strip()

    # Try standard JSON parse first
    try:
        parsed_data = json.loads(cleaned)
        if isinstance(parsed_data, list):
            records_to_process = parsed_data
        elif isinstance(parsed_data, dict):
            # Check for common wrapper keys like "events", "logs", "records", "data"
            for key in ["events", "logs", "records", "data", "items"]:
                if key in parsed_data and isinstance(parsed_data[key], list):
                    records_to_process = parsed_data[key]
                    break
            if not records_to_process:
                # Single record dict
                records_to_process = [parsed_data]
        else:
            errors_count += 1
            error_details.append({
                "row_index": 0,
                "error": f"Expected JSON array or object, got {type(parsed_data).__name__}"
            })
            return {
                "events": [],
                "total": 0,
                "errors": errors_count,
                "error_details": error_details
            }
    except json.JSONDecodeError:
        # Try Newline-Delimited JSON (NDJSON / JSON Lines)
        lines = cleaned.splitlines()
        for line_idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                obj = json.loads(line_str)
                records_to_process.append(obj)
            except json.JSONDecodeError as jde:
                errors_count += 1
                error_details.append({
                    "row_index": line_idx,
                    "error": f"Invalid JSON line: {str(jde)}"
                })

    # Process all identified records
    for idx, item in enumerate(records_to_process, start=1):
        if idx > MAX_RECORDS_LIMIT:
            error_details.append({
                "row_index": idx,
                "error": f"Maximum record limit of {MAX_RECORDS_LIMIT} reached; remaining records truncated."
            })
            break

        try:
            normalized = normalize_record(item, index=idx)
            events.append(normalized)
        except Exception as e:
            errors_count += 1
            error_details.append({
                "row_index": idx,
                "error": str(e),
                "data": str(item)[:100]
            })

    return {
        "events": events,
        "total": len(events),
        "errors": errors_count,
        "error_details": error_details
    }


def load_demo_logs(path: str) -> Dict[str, Any]:
    """
    Loads demo logs from a file path (CSV or JSON) and returns normalized parsed results.
    
    Args:
        path: Filesystem path to the log file.
        
    Returns:
        Dict with "events", "total", "errors", "error_details"
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Demo log file not found at path: {path}")

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    lower_path = path.lower()
    if lower_path.endswith(".json") or lower_path.endswith(".jsonl") or lower_path.endswith(".ndjson"):
        return parse_json(content)
    elif lower_path.endswith(".csv"):
        return parse_csv(content)
    else:
        # Try JSON first; if it fails, fallback to CSV
        trimmed = content.strip()
        if trimmed.startswith("{") or trimmed.startswith("["):
            res = parse_json(content)
            if res["total"] > 0 or res["errors"] == 0:
                return res
        return parse_csv(content)
