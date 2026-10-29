import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

REQUIRED = {"timestamp", "event_type", "source_ip", "username", "status"}

def _make_training_data():
    # Demonstration-only synthetic examples. Replace with a documented real dataset
    # before making research or performance claims.
    rows = []
    for failed, success, unique_users, off_hours, rare_event, label in [
        (0, 1, 1, 0, 0, 0), (1, 1, 1, 0, 0, 0), (2, 0, 1, 0, 0, 0),
        (3, 0, 2, 0, 0, 0), (5, 0, 1, 0, 0, 1), (8, 0, 3, 1, 0, 1),
        (10, 1, 4, 1, 1, 1), (12, 0, 5, 1, 1, 1), (1, 1, 1, 1, 0, 0),
        (7, 1, 2, 1, 1, 1), (4, 0, 1, 0, 1, 0), (9, 0, 4, 0, 1, 1)
    ]:
        rows.append([failed, success, unique_users, off_hours, rare_event, label])
    # Add small deterministic variations for a usable classroom demo model.
    base = pd.DataFrame(rows, columns=["failed_logins", "success_logins", "unique_users", "off_hours", "rare_event", "label"])
    expanded = []
    for _, row in base.iterrows():
        for shift in range(3):
            item = row.copy()
            item["failed_logins"] = max(0, int(item["failed_logins"]) + shift)
            expanded.append(item)
    return pd.DataFrame(expanded)

def _train_demo_model():
    data = _make_training_data()
    features = ["failed_logins", "success_logins", "unique_users", "off_hours", "rare_event"]
    model = Pipeline([
        ("scale", StandardScaler()),
        ("classifier", RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced"))
    ])
    model.fit(data[features], data["label"])
    return model

MODEL = _train_demo_model()

def analyze_logs(df):
    missing = REQUIRED - set(df.columns)
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(sorted(missing)))
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["event_type"] = df["event_type"].astype(str).str.upper().str.strip()
    df["status"] = df["status"].astype(str).str.upper().str.strip()
    df["source_ip"] = df["source_ip"].astype(str)
    df["username"] = df["username"].astype(str)

    # Group events by source IP and calculate simple activity features.
    summary = df.groupby("source_ip", dropna=False).agg(
        failed_logins=("status", lambda s: int((s == "FAILED").sum())),
        success_logins=("status", lambda s: int((s == "SUCCESS").sum())),
        unique_users=("username", "nunique"),
        event_count=("event_type", "size"),
        latest_event=("timestamp", "max")
    ).reset_index()

    if df["timestamp"].notna().any():
        hours = df["timestamp"].dt.hour
        off_hour_ips = set(df.loc[(hours < 6) | (hours >= 22), "source_ip"])
    else:
        off_hour_ips = set()

    known_events = {"LOGIN", "AUTHENTICATION", "FAILED_LOGIN", "SUCCESS_LOGIN"}
    rare_event_ips = set(df.loc[~df["event_type"].isin(known_events), "source_ip"])
    summary["off_hours"] = summary["source_ip"].isin(off_hour_ips).astype(int)
    summary["rare_event"] = summary["source_ip"].isin(rare_event_ips).astype(int)

    features = ["failed_logins", "success_logins", "unique_users", "off_hours", "rare_event"]
    summary["ml_prediction"] = MODEL.predict(summary[features])
    summary["ml_prediction"] = summary["ml_prediction"].map({0: "Lower risk", 1: "Potential threat"})
    summary["rule_alert"] = summary.apply(
        lambda r: "Review: repeated failed logins" if r["failed_logins"] >= 5
        else ("Review: multiple usernames" if r["unique_users"] >= 4 else "No rule alert"),
        axis=1
    )
    summary["risk_score"] = (
        summary["failed_logins"].clip(upper=10) * 8
        + (summary["unique_users"] >= 4).astype(int) * 20
        + summary["off_hours"] * 10
        + summary["rare_event"] * 10
    ).clip(upper=100)
    summary = summary.sort_values(["risk_score", "failed_logins"], ascending=False)
    return {
        "total_events": int(len(df)),
        "unique_ips": int(df["source_ip"].nunique()),
        "alerts": int(((summary["rule_alert"] != "No rule alert") | (summary["ml_prediction"] == "Potential threat")).sum()),
        "rows": summary.fillna("").to_dict(orient="records")
    }
