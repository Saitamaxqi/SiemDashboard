import json
import csv
from pathlib import Path
from ipaddress import ip_address, ip_network
from sklearn.ensemble import RandomForestClassifier
import pickle

ALERTS_PATH = Path("/var/ossec/logs/alerts/alerts.json")
MODEL_PATH = Path("./model.pkl")
DATASET_CSV = Path("./training_data.csv")

INTERNAL_NETS = [
    ip_network("192.168.30.0/24"),
    ip_network("192.168.20.0/24"),
]

def is_internal(ip):
    try:
        ip_obj = ip_address(ip)
        return any(ip_obj in net for net in INTERNAL_NETS)
    except:
        return True

def extract_features(alert):
    rule = alert.get("rule", {})
    groups = [g.lower() for g in rule.get("groups", [])]
    data = alert.get("data", {}) or {}
    srcip = data.get("srcip", "")

    features = {
        "rule_level": int(rule.get("level", 0)),
        "is_external_ip": 0 if is_internal(srcip) else 1,
        "is_ssh": 1 if "ssh" in groups else 0,
        "is_bruteforce": 1 if "authentication_failed" in groups else 0,
        "is_web_attack": 1 if "web" in groups else 0,
        "is_suricata": 1 if "suricata" in groups else 0,
        "dstport": int(data.get("dstport", 0)),
    }

    # label creation (pseudo ground truth)
    # High severity if rule level >= 8 or external + brute force
    if features["rule_level"] >= 8 or (features["is_external_ip"] == 1 and features["is_bruteforce"] == 1):
        label = 2  # high
    elif features["rule_level"] >= 4:
        label = 1  # medium
    else:
        label = 0  # low

    return features, label

def main():
    rows = []

    with ALERTS_PATH.open() as f:
        for line in f:
            try:
                alert = json.loads(line)
            except:
                continue

            feats, label = extract_features(alert)
            feats["label"] = label
            rows.append(feats)

    with DATASET_CSV.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    X = [[r["rule_level"], r["is_external_ip"], r["is_ssh"], r["is_bruteforce"],
          r["is_web_attack"], r["is_suricata"], r["dstport"]] for r in rows]
    y = [r["label"] for r in rows]

    model = RandomForestClassifier(n_estimators=50)
    model.fit(X, y)

    with MODEL_PATH.open("wb") as f:
        pickle.dump(model, f)

    print("[+] Training completed. Model saved to model.pkl")

if __name__ == "__main__":
    main()