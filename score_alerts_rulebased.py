#!/usr/bin/env python3
import json
import csv
from collections import deque
from pathlib import Path
from ipaddress import ip_address, ip_network
from datetime import datetime, timezone

# ===== Paths =====
ALERTS_PATH = Path("/var/ossec/logs/alerts/alerts.json")
OUTPUT_CSV = Path("/home/ubuntuuser/opt/security/scored_alerts.csv")

# ===== Your lab networks =====
LAN_NETS = [
    ip_network("192.168.30.0/24"),  # LAN
]

DMZ_NETS = [
    ip_network("192.168.20.0/24"),  # DMZ
]

# Frequency window settings
FREQ_WINDOW_SECONDS = 60
TAIL_LINES = 10000  # read last N alerts from alerts.json
MAX_EXPORT_ROWS = 5000  # write only last N scored rows to CSV (keeps dashboard snappy)

# ===== Helpers: parsing & zones =====

def safe_ip(ip: str):
    if not ip:
        return None
    try:
        return ip_address(ip)
    except ValueError:
        return None

def get_zone(ip: str) -> str:
    """
    Returns: "lan" | "dmz" | "external" | "unknown"
    """
    ip_obj = safe_ip(ip)
    if ip_obj is None:
        return "unknown"

    for net in LAN_NETS:
        if ip_obj in net:
            return "lan"

    for net in DMZ_NETS:
        if ip_obj in net:
            return "dmz"

    # Treat anything not in LAN/DMZ as "external" (public or other networks)
    return "external"

def parse_ts_to_epoch_seconds(ts: str):
    """
    Tries to parse Wazuh timestamps like:
      - 2025-12-11T03:24:28.123456Z
      - 2025-12-11T03:24:28+00:00
      - 2025-12-11T03:24:28
    Returns int epoch seconds or None.
    """
    if not ts:
        return None

    try:
        # Handle "Z"
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        return None

def tail_json_lines(path: Path, max_lines: int):
    dq = deque(maxlen=max_lines)
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                dq.append(line)
    return list(dq)

# ===== Scoring logic =====

def base_score_from_rule_level(rule_level: int) -> int:
    """
    Wazuh rule level -> base score
    """
    if rule_level <= 3:
        return 10
    if rule_level <= 6:
        return 25
    if rule_level <= 9:
        return 45
    return 70  # 10+

def frequency_score(count_in_window: int) -> int:
    """
    Burst detection score (same srcip + rule_id within last FREQ_WINDOW_SECONDS)
    """
    if count_in_window <= 2:
        return 0
    if count_in_window <= 5:
        return 10
    if count_in_window <= 10:
        return 25
    return 40  # 11+

def group_score(groups_lower: list[str], desc_lower: str) -> int:
    """
    Rule group / description cues.
    Keep this practical: tune it based on what YOU see in your Wazuh alerts.
    """
    score = 0

    joined = ",".join(groups_lower)

    # SSH / auth failures / brute force
    if "ssh" in joined or "ssh" in desc_lower:
        score += 12
    if "authentication_failed" in joined or "auth" in desc_lower or "failed" in desc_lower:
        score += 12
    if "bruteforce" in joined or "brute" in desc_lower:
        score += 18

    # Web / app attacks
    if "web" in joined or "http" in desc_lower:
        score += 18

    # Suricata detection
    if "suricata" in joined or "suricata" in desc_lower:
        score += 10

    # Malware-ish hints (depends on your ruleset)
    malware_keywords = ["malware", "trojan", "virus", "ransom", "backdoor", "c2", "command and control"]
    if any(k in desc_lower for k in malware_keywords) or "malware" in joined:
        score += 25

    # Noise-ish groups (reduce a bit)
    noise_groups = ["syslog", "audit", "policy"]
    if any(g in groups_lower for g in noise_groups):
        score -= 5

    return max(score, 0)

def owasp_web_score(desc_lower: str, groups_lower: list[str]) -> int:
    """
    Lightweight OWASP-ish scoring (not perfect mapping, but good enough for SOC logic + academic justification).
    Only applies if it's web-ish.
    """
    joined = ",".join(groups_lower)
    is_webish = ("web" in joined) or ("http" in desc_lower) or ("url" in desc_lower)

    if not is_webish:
        return 0

    score = 0

    # A03: Injection (SQLi)
    if any(k in desc_lower for k in ["sqli", "sql injection", "union select", "or 1=1", "information_schema"]):
        score += 30

    # A07: XSS
    if any(k in desc_lower for k in ["xss", "<script", "javascript:"]):
        score += 25

    # A05: Security Misconfiguration / traversal / webshell-ish
    if any(k in desc_lower for k in ["../", "path traversal", "directory traversal", "webshell", "cmd=", "shell"]):
        score += 25

    # Generic CVE mention
    if "cve-" in desc_lower:
        score += 15

    return score

def source_context_score(src_zone: str, dst_zone: str) -> int:
    """
    This is where your question fits:
    "DMZ talking with internal" should be treated like an attacker.

    - external -> +15
    - dmz -> lan -> +15 (treat like external attacker)
    - dmz -> anything else -> +8
    - lan -> dmz -> +5 (often lateral / misconfig)
    - lan -> lan -> +0
    - unknown -> +5 (don’t ignore it)
    """
    if src_zone == "external":
        return 15
    if src_zone == "dmz" and dst_zone == "lan":
        return 15
    if src_zone == "dmz":
        return 8
    if src_zone == "lan" and dst_zone == "dmz":
        return 5
    if src_zone == "unknown":
        return 5
    return 0

def correlation_bonus(src_zone: str, dst_zone: str, groups_lower: list[str], desc_lower: str, freq_count: int) -> int:
    """
    Adds a small boost when multiple signals align (SOC correlation feel).
    """
    joined = ",".join(groups_lower)
    bonus = 0

    # Burst + auth/ssh = likely brute force
    if freq_count >= 6 and ("ssh" in joined or "authentication_failed" in joined or "brute" in desc_lower):
        bonus += 10

    # Web + suricata + OWASP cues = stronger confidence
    if "suricata" in joined and ("web" in joined or "http" in desc_lower):
        bonus += 5

    # DMZ -> LAN with any security group
    if src_zone == "dmz" and dst_zone == "lan" and (joined or desc_lower):
        bonus += 5

    return bonus

def clamp_0_100(x: int) -> int:
    return max(0, min(100, x))

# ===== Main scoring loop =====

def main():
    if not ALERTS_PATH.exists():
        print(f"[!] Alerts file not found: {ALERTS_PATH}")
        return

    lines = tail_json_lines(ALERTS_PATH, max_lines=TAIL_LINES)

    # Frequency tracker: key -> deque[timestamps]
    # Keyed by (srcip, rule_id) so we detect bursts per attacker per rule.
    freq_map: dict[tuple[str, str], deque[int]] = {}

    rows = []

    for line in lines:
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        rule = alert.get("rule", {}) or {}
        data = alert.get("data", {}) or {}
        agent = alert.get("agent", {}) or {}

        ts = alert.get("timestamp", "") or alert.get("@timestamp", "") or ""
        epoch = parse_ts_to_epoch_seconds(ts)

        rule_id = str(rule.get("id", "") or "")
        try:
            rule_level = int(rule.get("level", 0) or 0)
        except (TypeError, ValueError):
            rule_level = 0

        desc = str(rule.get("description", "") or "")
        desc_lower = desc.lower()

        groups = rule.get("groups", []) or []
        groups_lower = [str(g).lower() for g in groups]

        # Pull src/dst/port robustly (different rulesets use different keys)
        srcip = (
            data.get("srcip")
            or data.get("src_ip")
            or data.get("source_ip")
            or ""
        )
        dstip = (
            data.get("dstip")
            or data.get("dst_ip")
            or data.get("destination_ip")
            or ""
        )
        dstport = (
            data.get("dstport")
            or data.get("dst_port")
            or data.get("destination_port")
            or 0
        )
        try:
            dstport_int = int(dstport)
        except (TypeError, ValueError):
            dstport_int = 0

        src_zone = get_zone(str(srcip))
        dst_zone = get_zone(str(dstip))

        # Update frequency counts
        freq_key = (str(srcip), rule_id)
        if epoch is not None:
            dq = freq_map.get(freq_key)
            if dq is None:
                dq = deque()
                freq_map[freq_key] = dq

            dq.append(epoch)
            cutoff = epoch - FREQ_WINDOW_SECONDS
            while dq and dq[0] < cutoff:
                dq.popleft()

            freq_count = len(dq)
        else:
            freq_count = 1  # if timestamp missing, don't “burst” it

        # Compute score components
        base = base_score_from_rule_level(rule_level)
        freq = frequency_score(freq_count)
        grp = group_score(groups_lower, desc_lower)
        owasp = owasp_web_score(desc_lower, groups_lower)
        srcctx = source_context_score(src_zone, dst_zone)
        bonus = correlation_bonus(src_zone, dst_zone, groups_lower, desc_lower, freq_count)

        total = clamp_0_100(base + freq + grp + owasp + srcctx + bonus)

        # Optional tier (helps dashboard later if you want)
        if total >= 80:
            tier = "high"
        elif total >= 50:
            tier = "medium"
        else:
            tier = "low"

        rows.append({
            "timestamp": ts,
            "rule_id": rule_id,
            "rule_level": rule_level,
            "rule_description": desc,
            "rule_groups": ",".join(groups),
            "agent_name": str(agent.get("name", "") or ""),
            "srcip": str(srcip),
            "dstip": str(dstip),
            "dstport": str(dstport),
            "location": str(alert.get("location", "") or ""),
            "risk_score": total,
            "risk_tier": tier,

            # Debug/explainability columns (super useful for your report/demo)
            "score_base": base,
            "score_freq": freq,
            "score_groups": grp,
            "score_owasp": owasp,
            "score_srcctx": srcctx,
            "score_bonus": bonus,
            "src_zone": src_zone,
            "dst_zone": dst_zone,
            "freq_count_60s": freq_count,
        })

    if not rows:
        print("[!] No alerts found to score.")
        return

    # Keep only last N rows so CSV doesn’t grow forever
    if len(rows) > MAX_EXPORT_ROWS:
        rows = rows[-MAX_EXPORT_ROWS:]

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Scored {len(rows)} alerts and wrote to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()