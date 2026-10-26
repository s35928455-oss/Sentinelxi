"""
SentinelX AI - Detection Engine
Rule-based detection for cybersecurity incidents:
- Brute Force Detection
- Port Scan Detection
- Login Burst (Credential Stuffing) Detection
"""

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid


@dataclass
class Incident:
    incident_id: str
    incident_type: str
    severity: str  # high, medium, low
    title: str
    description: str
    src_ip: Optional[str]
    first_seen: str
    last_seen: str
    event_count: int
    evidence_event_ids: List[str]
    rule_name: str
    rule_explanation: str
    recommendations: List[str]
    confidence: str  # high, medium, low

    def to_dict(self) -> Dict[str, Any]:
        """Convert Incident dataclass to standard Python dictionary."""
        return asdict(self)


# Default detection rule configurations
DEFAULT_CONFIG = {
    # Rule 1: Brute Force
    "brute_force_window_seconds": 120,   # 2 minutes
    "brute_force_threshold": 20,         # 20 failed attempts
    "brute_force_high_threshold": 50,
    "brute_force_medium_threshold": 20,
    "brute_force_low_threshold": 10,
    
    # Rule 2: Port Scan
    "port_scan_window_seconds": 60,      # 1 minute
    "port_scan_threshold": 15,           # 15 distinct ports
    "port_scan_high_threshold": 50,
    "port_scan_medium_threshold": 25,
    "port_scan_low_threshold": 15,
    
    # Rule 3: Login Burst
    "login_burst_window_seconds": 300,   # 5 minutes
    "login_burst_threshold": 5,          # 5 different usernames
    "login_burst_high_threshold": 15,
}

# Matching sets for event types
FAILED_LOGIN_EVENT_TYPES = {
    "login_failed",
    "auth_failure",
    "failed_login",
    "authentication_failure",
    "login_failure",
    "user_login_failed",
    "ssh_failed",
    "auth_failed",
}

PORT_SCAN_EVENT_TYPES = {
    "connection",
    "port_scan",
    "syn",
    "connect",
    "connection_attempt",
    "tcp_syn",
    "probe",
    "port_sweep",
}


def _parse_timestamp_to_dt(ts_str: Optional[str]) -> datetime:
    """Parses ISO timestamp string or unix timestamp to timezone-aware UTC datetime."""
    if not ts_str:
        return datetime.fromtimestamp(0, tz=timezone.utc)

    cleaned = str(ts_str).strip()
    # Try numeric timestamp first
    try:
        numeric_val = float(cleaned)
        if numeric_val > 1e11:
            numeric_val /= 1000.0
        return datetime.fromtimestamp(numeric_val, tz=timezone.utc)
    except (ValueError, OverflowError):
        pass

    # Try ISO parsing
    try:
        # Normalize trailing Z to +00:00
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        pass

    # Common formats
    for fmt in (
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S.%f",
    ):
        try:
            dt = datetime.strptime(cleaned, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            continue

    return datetime.fromtimestamp(0, tz=timezone.utc)


def _is_failed_login(event: Dict[str, Any]) -> bool:
    """Checks whether an event indicates a failed login attempt."""
    event_type = (event.get("event_type") or "").lower().strip()
    status = (event.get("status") or "").lower().strip()

    if event_type in FAILED_LOGIN_EVENT_TYPES:
        return True
    
    if status in ("failed", "failure", "denied", "rejected"):
        if any(term in event_type for term in ("login", "auth", "signin", "logon", "session")):
            return True
        # If event_type is generic or unknown but status is failed and username is present
        if event.get("username") and status in ("failed", "failure"):
            return True

    return False


def _is_port_scan_event(event: Dict[str, Any]) -> bool:
    """Checks whether an event matches port scanning / connection attempts."""
    event_type = (event.get("event_type") or "").lower().strip()
    dst_port = event.get("dst_port")

    if dst_port is None:
        return False

    if event_type in PORT_SCAN_EVENT_TYPES:
        return True

    # Any network connection or probe event with a destination port
    if any(term in event_type for term in ("syn", "scan", "conn", "probe", "traffic", "network")):
        return True

    return False


class DetectionEngine:
    """
    Stateful detection engine that evaluates normalized security log events
    against correlation rules, generates incidents, and stores evidence.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initializes the detection engine with optional config overrides."""
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self._incidents: Dict[str, Incident] = {}

    def _generate_incident_id(self) -> str:
        """Generates a unique INC-XXXX identifier."""
        return f"INC-{uuid.uuid4().hex[:6].upper()}"

    def _group_by_src_ip(self, events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Groups events by source IP address and sorts each group chronologically."""
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for event in events:
            src_ip = event.get("src_ip")
            if not src_ip:
                continue
            grouped.setdefault(src_ip, []).append(event)

        for ip in grouped:
            grouped[ip].sort(key=lambda ev: _parse_timestamp_to_dt(ev.get("timestamp")))

        return grouped

    def detect_brute_force(self, events: List[Dict[str, Any]]) -> List[Incident]:
        """
        Rule 1: Brute Force Detection
        Repeated failed logins from same src_ip within configurable time window.
        """
        window_seconds = self.config["brute_force_window_seconds"]
        threshold = self.config["brute_force_threshold"]
        high_thresh = self.config["brute_force_high_threshold"]
        med_thresh = self.config["brute_force_medium_threshold"]
        low_thresh = self.config["brute_force_low_threshold"]

        failed_events = [e for e in events if _is_failed_login(e)]
        grouped = self._group_by_src_ip(failed_events)
        incidents: List[Incident] = []

        for src_ip, ip_events in grouped.items():
            if len(ip_events) < low_thresh:
                continue

            n = len(ip_events)
            i = 0
            while i < n:
                start_dt = _parse_timestamp_to_dt(ip_events[i].get("timestamp"))
                j = i
                # Slide window forward while within window_seconds from start_dt
                while j < n and (_parse_timestamp_to_dt(ip_events[j].get("timestamp")) - start_dt).total_seconds() <= window_seconds:
                    j += 1

                window_events = ip_events[i:j]
                count = len(window_events)

                if count >= threshold:
                    # Extend window if consecutive events form a continuous burst
                    last_event_dt = _parse_timestamp_to_dt(window_events[-1].get("timestamp"))
                    while j < n and (_parse_timestamp_to_dt(ip_events[j].get("timestamp")) - last_event_dt).total_seconds() <= (window_seconds / 2):
                        last_event_dt = _parse_timestamp_to_dt(ip_events[j].get("timestamp"))
                        window_events.append(ip_events[j])
                        j += 1

                    count = len(window_events)
                    first_seen = str(window_events[0].get("timestamp", ""))
                    last_seen = str(window_events[-1].get("timestamp", ""))
                    evidence_ids = [str(e.get("event_id")) for e in window_events if e.get("event_id")]

                    # Determine severity and confidence
                    if count >= high_thresh:
                        severity = "high"
                        confidence = "high"
                    elif count >= med_thresh:
                        severity = "medium"
                        confidence = "medium"
                    else:
                        severity = "low"
                        confidence = "low"

                    incident = Incident(
                        incident_id=self._generate_incident_id(),
                        incident_type="brute_force",
                        severity=severity,
                        title="Possible Brute Force Login Attempt",
                        description=(
                            f"Detected {count} repeated failed login attempts originating from source IP "
                            f"{src_ip} between {first_seen} and {last_seen}. "
                            "This activity pattern suggests potential automated password guessing or dictionary attacks."
                        ),
                        src_ip=src_ip,
                        first_seen=first_seen,
                        last_seen=last_seen,
                        event_count=count,
                        evidence_event_ids=evidence_ids,
                        rule_name="Brute Force Detection",
                        rule_explanation=(
                            f"Triggers when a single source IP generates at least {threshold} failed login attempts "
                            f"within a {window_seconds}-second sliding window."
                        ),
                        recommendations=[
                            "Verify whether the source IP belongs to an authorized user, VPN, or internal service.",
                            "Check target accounts for signs of successful compromise following the failed attempts.",
                            "Temporarily rate-limit or block suspicious authentication requests from this IP at the perimeter.",
                            "Enforce multi-factor authentication (MFA) and initiate password resets for targeted accounts."
                        ],
                        confidence=confidence,
                    )
                    incidents.append(incident)
                    i = j  # Move past this burst to avoid duplicate incidents
                else:
                    i += 1

        return incidents

    def detect_port_scan(self, events: List[Dict[str, Any]]) -> List[Incident]:
        """
        Rule 2: Port Scan Detection
        Single src_ip contacting many distinct dst_ports within time window.
        """
        window_seconds = self.config["port_scan_window_seconds"]
        threshold = self.config["port_scan_threshold"]
        high_thresh = self.config["port_scan_high_threshold"]
        med_thresh = self.config["port_scan_medium_threshold"]
        low_thresh = self.config["port_scan_low_threshold"]

        conn_events = [e for e in events if _is_port_scan_event(e)]
        grouped = self._group_by_src_ip(conn_events)
        incidents: List[Incident] = []

        for src_ip, ip_events in grouped.items():
            if len(ip_events) < low_thresh:
                continue

            n = len(ip_events)
            i = 0
            while i < n:
                start_dt = _parse_timestamp_to_dt(ip_events[i].get("timestamp"))
                j = i
                distinct_ports: Set[int] = set()

                while j < n and (_parse_timestamp_to_dt(ip_events[j].get("timestamp")) - start_dt).total_seconds() <= window_seconds:
                    p = ip_events[j].get("dst_port")
                    if p is not None:
                        distinct_ports.add(p)
                    j += 1

                if len(distinct_ports) >= threshold:
                    window_events = ip_events[i:j]
                    # Extend if scan is actively continuing
                    last_event_dt = _parse_timestamp_to_dt(window_events[-1].get("timestamp"))
                    while j < n and (_parse_timestamp_to_dt(ip_events[j].get("timestamp")) - last_event_dt).total_seconds() <= (window_seconds / 2):
                        last_event_dt = _parse_timestamp_to_dt(ip_events[j].get("timestamp"))
                        p = ip_events[j].get("dst_port")
                        if p is not None:
                            distinct_ports.add(p)
                        window_events.append(ip_events[j])
                        j += 1

                    port_count = len(distinct_ports)
                    first_seen = str(window_events[0].get("timestamp", ""))
                    last_seen = str(window_events[-1].get("timestamp", ""))
                    evidence_ids = [str(e.get("event_id")) for e in window_events if e.get("event_id")]

                    if port_count >= high_thresh:
                        severity = "high"
                        confidence = "high"
                    elif port_count >= med_thresh:
                        severity = "medium"
                        confidence = "medium"
                    else:
                        severity = "low"
                        confidence = "low"

                    incident = Incident(
                        incident_id=self._generate_incident_id(),
                        incident_type="port_scan",
                        severity=severity,
                        title="Potential Port Scan Activity",
                        description=(
                            f"Detected probe connections across {port_count} distinct destination ports from source IP "
                            f"{src_ip} ({len(window_events)} total connection events) between {first_seen} and {last_seen}. "
                            "This pattern suggests automated network reconnaissance or vulnerability discovery."
                        ),
                        src_ip=src_ip,
                        first_seen=first_seen,
                        last_seen=last_seen,
                        event_count=len(window_events),
                        evidence_event_ids=evidence_ids,
                        rule_name="Port Scan Detection",
                        rule_explanation=(
                            f"Triggers when a single source IP contacts at least {threshold} distinct destination "
                            f"ports within a {window_seconds}-second sliding window."
                        ),
                        recommendations=[
                            "Investigate source IP reputation and ownership in threat intelligence databases.",
                            "Review firewall and honeypot logs to evaluate if scanned ports returned open or closed statuses.",
                            "Ensure strict network segmentation prevents unauthorized lateral probing from this source.",
                            "Deploy rate-limiting or perimeter filtering rules for the scanning source IP pending investigation."
                        ],
                        confidence=confidence,
                    )
                    incidents.append(incident)
                    i = j
                else:
                    i += 1

        return incidents

    def detect_login_burst(self, events: List[Dict[str, Any]]) -> List[Incident]:
        """
        Rule 3: Login Burst Detection (Credential Stuffing)
        Multiple failed logins across different usernames from same IP within time window.
        """
        window_seconds = self.config["login_burst_window_seconds"]
        threshold = self.config["login_burst_threshold"]
        high_thresh = self.config["login_burst_high_threshold"]

        # Only failed logins with an identifiable username
        failed_events = [e for e in events if _is_failed_login(e) and e.get("username")]
        grouped = self._group_by_src_ip(failed_events)
        incidents: List[Incident] = []

        for src_ip, ip_events in grouped.items():
            if len(ip_events) < threshold:
                continue

            n = len(ip_events)
            i = 0
            while i < n:
                start_dt = _parse_timestamp_to_dt(ip_events[i].get("timestamp"))
                j = i
                distinct_users: Set[str] = set()

                while j < n and (_parse_timestamp_to_dt(ip_events[j].get("timestamp")) - start_dt).total_seconds() <= window_seconds:
                    u = ip_events[j].get("username")
                    if u:
                        distinct_users.add(u)
                    j += 1

                if len(distinct_users) >= threshold:
                    window_events = ip_events[i:j]
                    # Extend continuous burst
                    last_event_dt = _parse_timestamp_to_dt(window_events[-1].get("timestamp"))
                    while j < n and (_parse_timestamp_to_dt(ip_events[j].get("timestamp")) - last_event_dt).total_seconds() <= (window_seconds / 2):
                        last_event_dt = _parse_timestamp_to_dt(ip_events[j].get("timestamp"))
                        u = ip_events[j].get("username")
                        if u:
                            distinct_users.add(u)
                        window_events.append(ip_events[j])
                        j += 1

                    user_count = len(distinct_users)
                    first_seen = str(window_events[0].get("timestamp", ""))
                    last_seen = str(window_events[-1].get("timestamp", ""))
                    evidence_ids = [str(e.get("event_id")) for e in window_events if e.get("event_id")]

                    severity = "high" if user_count >= high_thresh else "medium"
                    confidence = "high" if user_count >= high_thresh else "medium"

                    sampled_users = ", ".join(sorted(list(distinct_users))[:4])
                    if user_count > 4:
                        sampled_users += f" (+{user_count - 4} more)"

                    incident = Incident(
                        incident_id=self._generate_incident_id(),
                        incident_type="login_burst",
                        severity=severity,
                        title="Suspicious Login Burst - Multiple Usernames",
                        description=(
                            f"Detected failed login attempts targeting {user_count} distinct usernames "
                            f"({sampled_users}) from source IP {src_ip} between {first_seen} and {last_seen}. "
                            "This behavior suggests potential credential stuffing or account enumeration."
                        ),
                        src_ip=src_ip,
                        first_seen=first_seen,
                        last_seen=last_seen,
                        event_count=len(window_events),
                        evidence_event_ids=evidence_ids,
                        rule_name="Login Burst Detection",
                        rule_explanation=(
                            f"Triggers when a single source IP generates failed logins across at least {threshold} "
                            f"distinct usernames within a {window_seconds}-second sliding window."
                        ),
                        recommendations=[
                            "Investigate potential credential stuffing or automated dictionary spray against corporate accounts.",
                            "Verify whether any targeted username experienced a subsequent successful login from this IP.",
                            "Apply CAPTCHA or progressive exponential backoff delays on repeated authentication failures.",
                            "Notify targeted account owners and prompt review of recent sign-in activity."
                        ],
                        confidence=confidence,
                    )
                    incidents.append(incident)
                    i = j
                else:
                    i += 1

        return incidents

    def run_all_rules(self, events: List[Dict[str, Any]]) -> List[Incident]:
        """
        Runs all correlation rules on the provided events, stores incidents internally,
        and returns the list of detected incidents.
        """
        incidents: List[Incident] = []

        # Run all three rules
        incidents.extend(self.detect_brute_force(events))
        incidents.extend(self.detect_port_scan(events))
        incidents.extend(self.detect_login_burst(events))

        # Store incidents internally indexed by incident_id
        for inc in incidents:
            self._incidents[inc.incident_id] = inc

        return incidents

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Retrieves a stored incident by ID."""
        return self._incidents.get(incident_id)

    def get_evidence(self, incident_id: str, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Returns matching raw/normalized event records corresponding to an incident's
        evidence_event_ids.
        """
        incident = self.get_incident(incident_id)
        if not incident:
            return []

        evidence_set = set(incident.evidence_event_ids)
        return [ev for ev in events if str(ev.get("event_id")) in evidence_set]

    def get_all_incidents(self) -> List[Incident]:
        """Returns all internally stored incidents."""
        return list(self._incidents.values())

    def clear(self) -> None:
        """Clears all stored incidents."""
        self._incidents.clear()
