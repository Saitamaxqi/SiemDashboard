#!/usr/bin/env python3
from pathlib import Path
import pickle
import numpy as np
from ipaddress import ip_address, ip_network

MODEL_PATH = Path("./model.pkl")

# Your lab networks
INTERNAL_LAN = ip_network("192.168.30.0/24")  # LAN
INTERNAL_DMZ = ip_network("192.168.20.0/24")  # DMZ

def get_zone(ip: str) -> str:
    """
    Classify IP into a simple zone:
      - 'lan'  -> 192.168.30.0/24
      - 'dmz'  -> 192.168.20.0/24
      - 'outside' -> anything else (public or other RFC1918 ranges)
    """
    if not ip:
        return "unknown"
    try:
        ip_obj = ip_address(ip)
    except ValueError:
        return "unknown"

    if ip_obj in INTERNAL_LAN:
        return "lan"
    if ip_obj in INTERNAL_DMZ:
        return "dmz"
    return "outside"


def compute_is_external_ip_feature(srcip: str, dstip: str = "") -> int:
    """
    This is *roughly* aligned with how we think at runtime:

    - traffic staying entirely inside a single zone (LAN->LAN, DMZ->DMZ)
      -> is_external_ip = 0

    - DMZ <-> LAN traffic
      -> treat as 'cross-zone' and more risky: is_external_ip = 1

    - anything with source outside (internet) hitting LAN/DMZ
      -> is_external_ip = 1
    """
    zone_src = get_zone(srcip)
    zone_dst = get_zone(dstip)

    # If source is clearly outside, treat as external
    if zone_src == "outside":
        return 1

    # Cross-zone between LAN and DMZ is considered "external-style"
    if {zone_src, zone_dst} == {"lan", "dmz"}:
        return 1

    # Otherwise, same-zone or unknown -> internal-style
    return 0


def extract_features(alert: dict) -> dict:
    """
    Must conceptually align with the features used during training
    (train_model.py), and with score_alerts_ml.py.
    """
    rule = alert.get("rule", {}) or {}
    data = alert.get("data", {}) or {}

    groups = [g.lower() for g in rule.get("groups", []) or []]
    desc = (rule.get("description") or "").lower()

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
        dstport = int(dstport)
    except (TypeError, ValueError):
        dstport = 0

    try:
        rule_level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        rule_level = 0

    # Flags (loosely aligned with training logic)
    group_str = ",".join(groups)

    is_suricata = 1 if ("suricata" in group_str or "suricata" in desc) else 0
    is_web_attack = 1 if (
        "web" in group_str or any(
            kw in desc
            for kw in ["http", "sql", "xss", "webshell", "cve-2020", "cve"]
        )
    ) else 0
    is_ssh = 1 if ("ssh" in group_str or "ssh" in desc) else 0
    is_bruteforce = 1 if (
        "authentication_failed" in group_str or any(
            kw in desc for kw in ["brute", "password cracking", "authentication failure"]
        )
    ) else 0

    is_external_ip = compute_is_external_ip_feature(srcip, dstip)

    return {
        "rule_level": rule_level,
        "is_external_ip": int(is_external_ip),
        "is_ssh": int(is_ssh),
        "is_bruteforce": int(is_bruteforce),
        "is_web_attack": int(is_web_attack),
        "is_suricata": int(is_suricata),
        "dstport": dstport,
    }


def model_score(alert: dict, model) -> int:
    """
    1) Get base risk from the ML model (0,1,2 classes -> 20/60/90)
    2) Apply a small layer of expert rules to make behaviour
       sane for your lab (SSH brute > low noise).
    """
    feats = extract_features(alert)

    vec = np.array([
        feats["rule_level"],
        feats["is_external_ip"],
        feats["is_ssh"],
        feats["is_bruteforce"],
        feats["is_web_attack"],
        feats["is_suricata"],
        feats["dstport"],
    ], dtype=float).reshape(1, -1)

    pred_class = int(model.predict(vec)[0])
    mapping = {0: 20, 1: 60, 2: 90}
    base_score = mapping.get(pred_class, 50)

    # --- Heuristic corrections for your environment ---

    # Strong SSH brute force → must be high risk
    if feats["is_ssh"] and feats["is_bruteforce"]:
        if feats["rule_level"] >= 8:
            base_score = max(base_score, 90)
        else:
            base_score = max(base_score, 80)

    # Very low-level, purely internal noise with no attack flags → keep low
    if (
        feats["rule_level"] <= 2
        and feats["is_external_ip"] == 0
        and feats["is_ssh"] == 0
        and feats["is_bruteforce"] == 0
        and feats["is_web_attack"] == 0
        and feats["is_suricata"] == 0
    ):
        base_score = min(base_score, 20)

    return int(base_score)


def main():
    if not MODEL_PATH.exists():
        print("[!] Model file not found, train it first.")
        return

    with MODEL_PATH.open("rb") as f:
        model = pickle.load(f)

    # 1) High severity SSH brute force (DMZ host attacking something)
    ssh_bruteforce = {
        "rule": {"level": 10, "groups": ["ssh", "authentication_failed"]},
        "data": {"srcip": "192.168.20.10", "dstport": "22"},
    }

    # 2) Low level internal syslog-ish noise
    low_log = {
        "rule": {"level": 2, "groups": ["syslog"]},
        "data": {"srcip": "192.168.30.10", "dstport": "80"},
    }

    # 3) Suricata style web alert from LAN
    suricata_web = {
        "rule": {"level": 7, "groups": ["suricata", "web"]},
        "data": {"srcip": "192.168.30.10", "dstport": "80"},
    }

    s1 = model_score(ssh_bruteforce, model)
    s2 = model_score(low_log, model)
    s3 = model_score(suricata_web, model)

    print(f"SSH brute force score: {s1}")
    print(f"Low noise log score:   {s2}")
    print(f"Suricata web score:    {s3}")


if __name__ == "__main__":
    main()