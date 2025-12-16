#!/usr/bin/env python3
import json
from pathlib import Path
from ipaddress import ip_address

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle

# ===== Paths =====
DATA_DIR = Path("./Dataset")
LABELS_CSV = DATA_DIR / "labels.csv"
MODEL_PATH = Path("./model.pkl")
TRAIN_CSV = Path("./training_data_ait.csv")

# Scenarios we will use
SCENARIOS = [
    "fox",
    "harrison",
    "russellmitchell",
    "santos",
    "shaw",
    "wardbeck",
    "wheeler",
    "wilson",
]

# Limit per scenario so it doesn't explode
MAX_ATTACK_PER_SCENARIO = 8000
MAX_NORMAL_PER_SCENARIO = 8000

# ===== Zoning + feature extraction (must align with runtime) =====

def get_zone(ip_str: str) -> str:
    """
    Map an IP into a simple zone for this external dataset:

      - 'INTERNAL' -> RFC1918 (private) ranges
      - 'EXTERNAL' -> public IPs or anything non-private / invalid

    This keeps semantics close to your lab logic, but generic for AIT-ADS.
    """
    if not ip_str:
        return "INTERNAL"
    try:
        ip_obj = ip_address(ip_str)
    except ValueError:
        # Broken IPs: treat as internal/benign
        return "INTERNAL"

    if ip_obj.is_private:
        return "INTERNAL"
    return "EXTERNAL"


def compute_is_external_ip_feature(zone_src: str, zone_dst: str) -> int:
    """
    Return 1 if the traffic clearly crosses a trust boundary:

      - If either side is EXTERNAL -> 1
      - INTERNAL <-> INTERNAL -> 0
    """
    if zone_src == "EXTERNAL" or zone_dst == "EXTERNAL":
        return 1
    return 0


def extract_features_from_alert(alert: dict) -> dict:
    """
    Extract features with exactly the same names your runtime model expects:

      rule_level,is_external_ip,is_ssh,is_bruteforce,is_web_attack,is_suricata,dstport
    """

    rule = alert.get("rule", {}) or {}
    data = alert.get("data", {}) or {}

    groups = [g.lower() for g in (rule.get("groups") or [])]
    desc = (rule.get("description") or "").lower()
    groups_str = ",".join(groups)

    # src/dst IPs can be in various fields (Wazuh + Suricata)
    srcip = (
        data.get("srcip")
        or data.get("src_ip")
        or data.get("source_ip")
        or alert.get("srcip")
        or ""
    )

    dstip = (
        data.get("dstip")
        or data.get("dest_ip")
        or data.get("destination_ip")
        or alert.get("dstip")
        or ""
    )

    # dstport can also appear with different keys
    dstport = (
        data.get("dstport")
        or data.get("dst_port")
        or data.get("dest_port")        
        or data.get("destination_port")
        or 0
    )
    try:
        dstport = int(dstport)
    except (TypeError, ValueError):
        dstport = 0

    # rule level
    try:
        rule_level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        rule_level = 0

    # Zones and external feature
    zone_src = get_zone(srcip)
    zone_dst = get_zone(dstip)
    is_external_ip = compute_is_external_ip_feature(zone_src, zone_dst)

    # Flags aligned with runtime logic
    is_suricata = 1 if ("suricata" in groups_str or "suricata" in desc) else 0

    is_web_attack = 1 if any(
        kw in desc
        for kw in ["http", "sql", "xss", "webshell", "cve-2020", "cve"]
    ) else 0

    is_ssh = 1 if ("ssh" in desc or "ssh" in groups_str) else 0

    is_bruteforce = 1 if any(
        kw in desc
        for kw in ["brute", "password cracking", "authentication failure"]
    ) else 0

    return {
        "rule_level": rule_level,
        "is_external_ip": int(is_external_ip),
        "is_ssh": int(is_ssh),
        "is_bruteforce": int(is_bruteforce),
        "is_web_attack": int(is_web_attack),
        "is_suricata": int(is_suricata),
        "dstport": dstport,
    }

# ===== Labels: using your labels.csv (epoch seconds) =====

def load_attack_windows():
    """
    labels.csv columns: scenario, attack, start, end
    start/end are Unix timestamps (seconds).
    Returns: scenario -> list of (start_epoch, end_epoch, attack_name)
    """
    if not LABELS_CSV.exists():
        raise FileNotFoundError(f"labels.csv not found at {LABELS_CSV}")

    df = pd.read_csv(LABELS_CSV, sep=",|\t", engine="python")

    # Normalize column names
    cols = {c.lower(): c for c in df.columns}
    scenario_col = cols.get("scenario", "scenario")
    attack_col = cols.get("attack", "attack")
    start_col = cols.get("start", "start")
    end_col = cols.get("end", "end")

    windows = {}

    for _, row in df.iterrows():
        scenario = str(row[scenario_col]).strip()
        if scenario not in SCENARIOS:
            continue

        try:
            start_epoch = int(row[start_col])
            end_epoch = int(row[end_col])
        except (TypeError, ValueError):
            continue

        attack_name = str(row[attack_col])

        windows.setdefault(scenario, []).append(
            (start_epoch, end_epoch, attack_name)
        )

    return windows


def ts_to_epoch_seconds(ts_str: str):
    """
    Convert various timestamp formats in the alerts to epoch seconds.
    Handles:
      - 2022-01-15T03:45:39.681006Z
      - 2022-01-15T03:45:39.681006+0000
      - 2022-01-15T03:45:40.410426+0000
    """
    if not ts_str:
        return None
    ts = pd.to_datetime(ts_str, errors="coerce")
    if pd.isna(ts):
        return None
    return int(ts.value // 10**9)  # ns -> seconds


def is_in_attack_window(epoch_ts, scenario_windows):
    """
    Compare alert timestamp (epoch seconds) to attack windows.
    """
    if epoch_ts is None:
        return False

    for (start_epoch, end_epoch, _attack_name) in scenario_windows:
        if start_epoch <= epoch_ts <= end_epoch:
            return True
    return False


def label_for_alert(rule_level, in_attack_window):
    """
    3-class label:
      0 = low risk (normal / benign)
      1 = medium risk (attack window, lower severity)
      2 = high risk (attack window, high severity)
    """
    if in_attack_window:
        if rule_level >= 8:
            return 2  # high
        else:
            return 1  # medium
    else:
        return 0  # outside attack window -> benign

# ===== Main training logic =====

def collect_samples():
    windows_by_scenario = load_attack_windows()
    all_rows = []

    for scenario in SCENARIOS:
        scenario_file = DATA_DIR / f"{scenario}_wazuh.json"
        if not scenario_file.exists():
            print(f"[!] Missing file for scenario {scenario}: {scenario_file}")
            continue

        scenario_windows = windows_by_scenario.get(scenario, [])
        if not scenario_windows:
            print(f"[!] No attack windows for scenario {scenario} in labels.csv")
            continue

        print(f"[+] Processing scenario: {scenario}")

        attack_count = 0
        normal_count = 0

        with scenario_file.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue

                ts_str = (
                    alert.get("@timestamp")
                    or alert.get("timestamp")
                    or alert.get("data", {}).get("timestamp")
                    or alert.get("predecoder", {}).get("timestamp")
                )
                epoch_ts = ts_to_epoch_seconds(ts_str)

                feats = extract_features_from_alert(alert)
                rule_level = feats["rule_level"]

                in_attack = is_in_attack_window(epoch_ts, scenario_windows)
                label = label_for_alert(rule_level, in_attack)

                # Balance per scenario
                if label in (1, 2):  # attack-related
                    if attack_count >= MAX_ATTACK_PER_SCENARIO:
                        continue
                    attack_count += 1
                else:
                    if normal_count >= MAX_NORMAL_PER_SCENARIO:
                        continue
                    normal_count += 1

                row = {**feats, "label": label}
                all_rows.append(row)

        print(
            f"    Collected {attack_count} attack samples and "
            f"{normal_count} normal samples for {scenario}"
        )

    return all_rows


def train_and_save_model(rows):
    if not rows:
        raise RuntimeError(
            "No training samples collected; check dataset paths and labels.csv"
        )

    df = pd.DataFrame(rows)
    TRAIN_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(TRAIN_CSV, index=False)
    print(f"[+] Saved training dataset to {TRAIN_CSV} (rows={len(df)})")

    feature_cols = [
        "rule_level",
        "is_external_ip",
        "is_ssh",
        "is_bruteforce",
        "is_web_attack",
        "is_suricata",
        "dstport",
    ]
    X = df[feature_cols].values
    y = df["label"].values

    idx = np.arange(len(X))
    np.random.shuffle(idx)
    X = X[idx]
    y = y[idx]

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        n_jobs=-1,
        random_state=42,
    )
    clf.fit(X, y)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with MODEL_PATH.open("wb") as f:
        pickle.dump(clf, f)

    print(f"[+] Trained RandomForest model and saved to {MODEL_PATH}")


def main():
    print("[*] Collecting samples from AIT-ADS Wazuh dataset...")
    rows = collect_samples()
    print(f"[*] Total collected samples: {len(rows)}")
    train_and_save_model(rows)
    print("[*] Done. Your scoring script can now use the updated model.pkl")


if __name__ == "__main__":
    main()