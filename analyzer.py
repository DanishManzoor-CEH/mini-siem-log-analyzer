import csv
import io
import re
from datetime import datetime
from collections import Counter, defaultdict


COLUMN_ALIASES = {
    "timestamp": ["timestamp", "time", "date", "datetime", "@timestamp"],
    "host": ["host", "hostname", "computer", "computername", "device", "server"],
    "source_ip": ["source_ip", "src_ip", "src", "ip", "client_ip", "remote_ip", "ip_address"],
    "username": ["username", "user", "account", "account_name", "user_name"],
    "event_type": ["event_type", "event", "category", "action"],
    "event_id": ["event_id", "eventid", "windows_event_id", "win_event_id"],
    "status": ["status", "result", "outcome", "login_status", "authentication_result"],
    "message": ["message", "details", "description", "log", "raw", "event_message"],
}

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def _clean(value):
    if value is None:
        return ""
    return str(value).strip()

def _normalize_header(header):
    return re.sub(r"[^a-z0-9_]", "", str(header).strip().lower().replace(" ", "_"))

def _canonicalize_row(row):
    normalized = {_normalize_header(k): _clean(v) for k, v in row.items() if k is not None}
    result = {key: "" for key in COLUMN_ALIASES}
    for canonical, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            alias_norm = _normalize_header(alias)
            if alias_norm in normalized and normalized[alias_norm]:
                result[canonical] = normalized[alias_norm]
                break

    msg = result.get("message", "")
    if not result.get("source_ip"):
        match = IP_RE.search(" ".join(normalized.values()))
        if match:
            result["source_ip"] = match.group(0)
    if not result.get("message"):
        result["message"] = " | ".join(f"{k}: {v}" for k, v in normalized.items() if v)
    if not result.get("event_type"):
        result["event_type"] = _infer_event_type(" ".join([msg, *normalized.values()]))
    if not result.get("status"):
        result["status"] = _infer_status(" ".join([msg, *normalized.values()]))
    # Windows Security auditing event IDs have explicit authentication meaning.
    event_id = result.get("event_id", "").strip()
    if event_id == "4625":
        result["status"] = "failed"
        result["event_type"] = "login"
    elif event_id == "4624":
        result["status"] = "success"
        result["event_type"] = "login"
    return result

def _infer_status(text):
    t = text.lower()
    if any(s in t for s in ["failed password", "login failed", "authentication failure", "logon failure", "failed login", "status=failed"]):
        return "failed"
    if any(s in t for s in ["accepted password", "login successful", "successful login", "logon success", "status=success", "logged in successfully"]):
        return "success"
    return ""

def _infer_event_type(text):
    t = text.lower()
    if any(s in t for s in ["login", "logon", "password", "authentication", "sshd"]):
        return "login"
    if any(s in t for s in ["sudo", "privilege", "administrator", "elevation", "root access"]):
        return "privilege"
    if any(s in t for s in ["powershell", "encodedcommand", "cmd.exe", "wscript", "cscript"]):
        return "process"
    if any(s in t for s in ["malware", "ransomware", "trojan", "quarantine", "defender detected"]):
        return "malware"
    return "other"

def _parse_text_line(line):
    line = line.strip()
    if not line:
        return None

    # Our demo format: timestamp,host,source_ip,username,event_type,status,message
    parts = line.split(",", 6)
    if len(parts) >= 7:
        return _canonicalize_row({
            "timestamp": parts[0], "host": parts[1], "source_ip": parts[2],
            "username": parts[3], "event_type": parts[4], "status": parts[5],
            "message": parts[6],
        })

    ip_match = IP_RE.search(line)
    status = _infer_status(line)
    event_type = _infer_event_type(line)
    user_match = re.search(r"(?:for|user|account)\s+([A-Za-z0-9_.$-]+)", line, re.IGNORECASE)
    timestamp_match = re.match(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)

    return {
        "timestamp": timestamp_match.group(1) if timestamp_match else "",
        "host": "",
        "source_ip": ip_match.group(0) if ip_match else "",
        "username": user_match.group(1) if user_match else "",
        "event_type": event_type,
        "status": status,
        "message": line,
    }

def load_logs(raw_text):
    """Load CSV content or newline-separated plain text logs into normalized events."""
    raw_text = _clean(raw_text)
    if not raw_text:
        return []

    first_line = raw_text.splitlines()[0].lower()
    events = []

    # If the first line looks like a CSV header, parse it as CSV.
    looks_like_csv = "," in first_line and any(
        token in first_line for token in ["timestamp", "source_ip", "username", "message", "event_type", "status", "host"]
    )

    if looks_like_csv:
        try:
            reader = csv.DictReader(io.StringIO(raw_text))
            for row in reader:
                event = _canonicalize_row(row)
                if any(event.values()):
                    events.append(event)
            if events:
                return events
        except Exception:
            pass

    for line in raw_text.splitlines():
        event = _parse_text_line(line)
        if event:
            events.append(event)

    return events

def _parse_timestamp(value):
    """Parse common ISO and syslog timestamps; return None when unavailable."""
    value = _clean(value)
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized).replace(tzinfo=None)
    except ValueError:
        pass
    for fmt in ("%b %d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(value, fmt)
            if "%Y" not in fmt:
                parsed = parsed.replace(year=datetime.now().year)
            return parsed
        except ValueError:
            continue
    return None


def analyze_logs(events, failed_login_threshold=5, time_window_minutes=5, sequence_threshold=3):
    """Run explainable, time-aware rules against normalized log events.

    Events without parseable timestamps are still considered for per-event rules,
    but are excluded from time-window correlation to avoid misleading alerts.
    """
    alerts = []
    failures_by_ip = defaultdict(list)
    successes_by_ip = defaultdict(list)

    for index, event in enumerate(events):
        ip = event.get("source_ip", "")
        status = (event.get("status") or "").lower()
        message = (event.get("message") or "").lower()
        event_type = (event.get("event_type") or "").lower()
        event_id = _clean(event.get("event_id"))
        timestamp = _parse_timestamp(event.get("timestamp"))

        # Support event IDs embedded in message text as well as structured CSV fields.
        if event_id == "4625" or re.search(r"\bevent\s*id\s*[:=]?\s*4625\b", message):
            status, event_type = "failed", "login"
        elif event_id == "4624" or re.search(r"\bevent\s*id\s*[:=]?\s*4624\b", message):
            status, event_type = "success", "login"

        if ip and status in {"failed", "failure", "denied", "invalid"}:
            failures_by_ip[ip].append((index, timestamp, event))
        if ip and status in {"success", "successful", "accepted", "ok"}:
            successes_by_ip[ip].append((index, timestamp, event))

        if any(term in message for term in ["powershell -enc", "encodedcommand", "encoded command", "downloadstring", "invoke-expression", "invoke-webrequest"]):
            alerts.append({"id": f"PROC-{index+1}", "severity": "High", "title": "Potentially suspicious command execution", "description": "The log message contains a command pattern commonly worth reviewing during endpoint investigations.", "evidence": event.get("message", "")[:500], "source_ip": ip, "event_count": 1, "rule": "Suspicious process/command keywords"})

        if any(term in message for term in ["privilege escalation", "privilege elevated", "added to administrators", "added to sudoers", "sudo command", "administrator privileges granted", "new local admin"]):
            alerts.append({"id": f"PRIV-{index+1}", "severity": "High", "title": "Privileged activity detected", "description": "A log message indicates privileged command or account activity. Confirm whether it was authorized.", "evidence": event.get("message", "")[:500], "source_ip": ip, "event_count": 1, "rule": "Privileged activity keywords"})

        if any(term in message for term in ["ransomware", "trojan detected", "malware detected", "quarantined threat", "defender detected"]):
            alerts.append({"id": f"MAL-{index+1}", "severity": "Critical", "title": "Malware-related log indicator", "description": "The log contains a malware or quarantine-related indicator that should be validated in the source security product.", "evidence": event.get("message", "")[:500], "source_ip": ip, "event_count": 1, "rule": "Malware keyword detection"})

    window_seconds = max(1, int(time_window_minutes)) * 60
    for ip, failures in failures_by_ip.items():
        # Only timestamped events can be correlated into a reliable time window.
        timed_failures = sorted([(ts, event) for _, ts, event in failures if ts is not None], key=lambda x: x[0])
        peak_window = []
        left = 0
        for right, (right_ts, _) in enumerate(timed_failures):
            while (right_ts - timed_failures[left][0]).total_seconds() > window_seconds:
                left += 1
            candidate = timed_failures[left:right + 1]
            if len(candidate) > len(peak_window):
                peak_window = candidate

        count_for_rule = len(peak_window)
        if count_for_rule >= failed_login_threshold:
            users = sorted({e.get("username") for _, e in peak_window if e.get("username")})
            alerts.append({
                "id": f"AUTH-{ip}",
                "severity": "High" if count_for_rule >= max(failed_login_threshold * 2, 10) else "Medium",
                "title": "Repeated failed logins / possible brute-force activity",
                "description": f"{count_for_rule} failed authentication events from the same source IP occurred within {time_window_minutes} minutes.",
                "evidence": f"Peak window: {count_for_rule} failures; affected account(s): {', '.join(users) if users else 'not identified'}.",
                "source_ip": ip,
                "event_count": count_for_rule,
                "rule": f"Failed logins ≥ {failed_login_threshold} within {time_window_minutes} minutes",
            })

        # Correlate failed attempts followed by success using timestamps where possible.
        timed_successes = [(ts, event) for _, ts, event in successes_by_ip.get(ip, []) if ts is not None]
        sequence_detected = False
        if timed_failures and timed_successes:
            for success_ts, _ in sorted(timed_successes, key=lambda x: x[0]):
                preceding = [(ts, event) for ts, event in timed_failures if 0 <= (success_ts - ts).total_seconds() <= window_seconds]
                if len(preceding) >= sequence_threshold:
                    alerts.append({
                        "id": f"AUTH-SUCCESS-{ip}-{len(alerts)+1}", "severity": "High",
                        "title": "Successful login after repeated failures",
                        "description": f"A successful authentication followed at least {sequence_threshold} failures from the same source IP within {time_window_minutes} minutes.",
                        "evidence": f"{len(preceding)} timestamped failures preceded a successful login from {ip}.",
                        "source_ip": ip, "event_count": len(preceding) + 1,
                        "rule": "Failed-then-success authentication sequence",
                    })
                    sequence_detected = True
                    break
        # Conservative fallback for untimestamped logs: retain sequence analysis by input order.
        if not sequence_detected and not timed_failures:
            success_indices = [i for i, _, _ in successes_by_ip.get(ip, [])]
            failure_indices = [i for i, _, _ in failures]
            if success_indices:
                first_success = min(success_indices)
                preceding = [(i, e) for i, _, e in failures if i < first_success]
                if len(preceding) >= sequence_threshold:
                    alerts.append({"id": f"AUTH-SUCCESS-{ip}", "severity": "High", "title": "Successful login after repeated failures", "description": "A successful authentication appears after multiple failures in input order. Timestamps were unavailable, so verify event chronology.", "evidence": f"{len(preceding)} failures appeared before a successful login from {ip}.", "source_ip": ip, "event_count": len(preceding) + 1, "rule": "Failed-then-success sequence (input-order fallback)"})

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    alerts.sort(key=lambda a: (severity_order.get(a["severity"], 4), -a.get("event_count", 1)))
    return {"alerts": alerts, "event_count": len(events)}

def summarize_events(events):
    counts = Counter()
    for event in events:
        kind = (event.get("event_type") or "other").strip().lower() or "other"
        counts[kind] += 1
    return dict(counts)
