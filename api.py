#!/usr/bin/env python3
from pathlib import Path
import os
import secrets
from functools import wraps

from flask import Flask, jsonify, request
from flask_cors import CORS
import pandas as pd
import csv
# Paths
SCORED_CSV = Path("./scored_alerts.csv")

# ---- Auth config ----
# Set these to match your Wazuh username/password (or export as env vars).
USERNAME = os.environ.get("DASH_USER", "wazuh")
PASSWORD = os.environ.get("DASH_PASS", "wazuh123!")

# In-memory token store (good enough for your lab / demo)
SESSION_TOKENS = set()

app = Flask(__name__)
# Allow frontend (Next.js) to call /api/*
CORS(app, resources={r"/api/*": {"origins": "*"}})


# ========= Auth helpers =========

def create_token() -> str:
    """Generate a random session token and store it."""
    token = secrets.token_hex(32)
    SESSION_TOKENS.add(token)
    return token


def require_auth(fn):
    """Decorator to protect routes with Bearer token auth."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401

        token = auth_header.split(" ", 1)[1].strip()
        if token not in SESSION_TOKENS:
            return jsonify({"error": "Unauthorized"}), 401

        return fn(*args, **kwargs)

    return wrapper


# ========= Core helpers =========

def load_scored_alerts():
    """
    Load scored_alerts.csv into a DataFrame.
    Handle missing/empty file gracefully.
    """
    if not SCORED_CSV.exists():
        return pd.DataFrame()

    try:
        df = pd.read_csv(SCORED_CSV)
    except Exception as e:
        print(f"[!] Error reading {SCORED_CSV}: {e}")
        return pd.DataFrame()

    # Parse timestamp if present
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    return df


# ========= Routes =========

@app.post("/api/login")
def login():
    """
    POST /api/login
    Body: { "username": "...", "password": "..." }

    If credentials match, return a session token:
      { "token": "..." }

    You should set USERNAME/PASSWORD to match your Wazuh creds.
    """
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))

    if username == USERNAME and password == PASSWORD:
        token = create_token()
        return jsonify({"token": token}), 200

    return jsonify({"error": "Invalid credentials"}), 401


SCORED_CSV = Path("./scored_alerts.csv")

@app.get("/api/alerts")
@require_auth
def get_alerts():
    """
    Return scored_alerts.csv as proper JSON so the Next.js dashboard
    can call res.json() safely.

    Shape matches your AlertRow interface:
    {
      "timestamp": str,
      "rule_id": str,
      "rule_level": int,
      "rule_description": str,
      "rule_groups": str,
      "agent_name": str,
      "srcip": str,
      "dstip": str,
      "dstport": str,
      "location": str,
      "risk_score": int
    }
    """
    if not SCORED_CSV.exists():
        # No alerts yet -> empty array
        return jsonify([])

    rows = []
    with SCORED_CSV.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Convert numeric-ish fields safely
            def to_int(value, default=0):
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return default

            rows.append({
                "timestamp": row.get("timestamp", ""),
                "rule_id": row.get("rule_id", ""),
                "rule_level": to_int(row.get("rule_level")),
                "rule_description": row.get("rule_description", ""),
                "rule_groups": row.get("rule_groups", ""),
                "agent_name": row.get("agent_name", ""),
                "srcip": row.get("srcip", ""),
                "dstip": row.get("dstip", ""),
                "dstport": row.get("dstport", ""),
                "location": row.get("location", ""),
                "risk_score": to_int(row.get("risk_score")),
            })

    # Optional: only send the latest N alerts (e.g. 500) to keep it light
    MAX_ALERTS = 500
    if len(rows) > MAX_ALERTS:
        rows = rows[-MAX_ALERTS:]

    return jsonify(rows)


@app.get("/api/alerts/summary")
@require_auth
def get_alerts_summary():
    """
    GET /api/alerts/summary

    Returns:
      {
        total_alerts,
        low,
        medium,
        high,
        top_rules: [
          { rule_id, rule_description, risk_score },
          ...
        ]
      }
    """
    df = load_scored_alerts()
    if df.empty or "risk_score" not in df.columns:
        return jsonify({
            "total_alerts": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "top_rules": [],
        }), 200

    total = int(len(df))
    low = int((df["risk_score"] < 40).sum())
    medium = int(((df["risk_score"] >= 40) & (df["risk_score"] < 80)).sum())
    high = int((df["risk_score"] >= 80).sum())

    if "rule_id" in df.columns:
        top_rules_df = (
            df.groupby(["rule_id", "rule_description"], dropna=False)["risk_score"]
            .mean()
            .reset_index()
            .sort_values("risk_score", ascending=False)
            .head(5)
        )
        top_rules = top_rules_df.to_dict(orient="records")
    else:
        top_rules = []

    summary = {
        "total_alerts": total,
        "low": low,
        "medium": medium,
        "high": high,
        "top_rules": top_rules,
    }
    return jsonify(summary), 200


if __name__ == "__main__":
    # You already run it with sudo python3 api.py
    app.run(host="0.0.0.0", port=5000, debug=True)
