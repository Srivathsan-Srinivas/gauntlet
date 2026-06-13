#!/usr/bin/env python3
"""Generate synthetic Salesforce-style audit logs for UEBA experiments.

The training split contains normal/benign behavior for five personas.
The testing split contains mostly benign behavior plus targeted anomalous behavior.
"""
from __future__ import annotations

import argparse
import ipaddress
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd


SEED = 42
random.seed(SEED)
np.random.seed(SEED)

EVENT_NAMES = [
    "Login",
    "Logout",
    "ReportExport",
    "SOQLQuery",
    "DashboardView",
    "UserPermissionChange",
    "BulkDataExport",
    "ConnectedAppOAuth",
]

EVENT_TYPES = {
    "Login": "auth",
    "Logout": "auth",
    "ReportExport": "data_access",
    "SOQLQuery": "query",
    "DashboardView": "data_access",
    "UserPermissionChange": "admin",
    "BulkDataExport": "data_export",
    "ConnectedAppOAuth": "auth",
}

DOMAINS = ["login.salesforce.com", "mycompany.my.salesforce.com"]


@dataclass(frozen=True)
class Persona:
    user_id: str
    persona: str
    city_country: List[Tuple[str, str]]
    os_choices: List[str]
    device_types: List[str]
    login_types: List[str]
    normal_hours: Tuple[int, int]
    query_complexity_mu: float
    records_accessed_mu: float
    admin_rate: float
    export_rate: float
    query_rate: float
    ip_prefixes: List[str]


PERSONAS: List[Persona] = [
    Persona(
        user_id="u_normal_sql_001",
        persona="normal_sql_user",
        city_country=[("Chicago", "US")],
        os_choices=["Windows", "macOS"],
        device_types=["desktop", "laptop"],
        login_types=["Password", "SSO"],
        normal_hours=(8, 18),
        query_complexity_mu=3.0,
        records_accessed_mu=180,
        admin_rate=0.0,
        export_rate=0.03,
        query_rate=0.45,
        ip_prefixes=["10.12.8.0/24", "10.12.9.0/24"],
    ),
    Persona(
        user_id="u_sales_traveler_002",
        persona="traveling_sales_rep",
        city_country=[("New York", "US"), ("Boston", "US"), ("San Francisco", "US"), ("Austin", "US")],
        os_choices=["iOS", "macOS"],
        device_types=["mobile", "laptop"],
        login_types=["SSO", "OAuth"],
        normal_hours=(6, 22),
        query_complexity_mu=1.5,
        records_accessed_mu=80,
        admin_rate=0.0,
        export_rate=0.02,
        query_rate=0.18,
        ip_prefixes=["10.20.0.0/24", "10.20.1.0/24", "172.16.4.0/24"],
    ),
    Persona(
        user_id="u_nightowl_noah_003",
        persona="nightowl_engineer",
        city_country=[("Seattle", "US")],
        os_choices=["Linux", "macOS"],
        device_types=["laptop", "desktop"],
        login_types=["SSO", "Password"],
        normal_hours=(19, 4),
        query_complexity_mu=6.0,
        records_accessed_mu=350,
        admin_rate=0.0,
        export_rate=0.04,
        query_rate=0.62,
        ip_prefixes=["10.44.5.0/24"],
    ),
    Persona(
        user_id="u_complex_query_004",
        persona="complex_query_engineer",
        city_country=[("Denver", "US")],
        os_choices=["Linux"],
        device_types=["desktop", "laptop"],
        login_types=["SSO"],
        normal_hours=(9, 21),
        query_complexity_mu=9.0,
        records_accessed_mu=1500,
        admin_rate=0.0,
        export_rate=0.08,
        query_rate=0.78,
        ip_prefixes=["10.51.2.0/24"],
    ),
    Persona(
        user_id="u_admin_005",
        persona="salesforce_admin",
        city_country=[("Atlanta", "US")],
        os_choices=["Windows", "macOS"],
        device_types=["laptop"],
        login_types=["SSO", "MFA"],
        normal_hours=(7, 19),
        query_complexity_mu=4.0,
        records_accessed_mu=260,
        admin_rate=0.18,
        export_rate=0.04,
        query_rate=0.32,
        ip_prefixes=["10.70.1.0/24"],
    ),
]

ANOMALY_SCENARIOS: Dict[str, List[str]] = {
    "normal_sql_user": ["foreign_country_login", "mass_export", "suspicious_oauth"],
    "traveling_sales_rep": ["impossible_travel", "unusual_os", "large_data_export"],
    "nightowl_engineer": ["daytime_admin_action", "foreign_country_login", "suspicious_oauth"],
    "complex_query_engineer": ["simple_user_mass_export", "new_country_query_burst", "unusual_device"],
    "salesforce_admin": ["after_hours_permission_change", "disable_mfa", "bulk_export_after_admin_change"],
}


def random_ip(prefix: str) -> str:
    network = ipaddress.ip_network(prefix)
    host = random.randint(5, min(network.num_addresses - 2, 240))
    return str(network.network_address + host)


def public_ip() -> str:
    return random.choice(["45.83.12.44", "185.199.108.77", "203.0.113.42", "198.51.100.19", "91.207.174.9"])


def hour_for_persona(persona: Persona) -> int:
    start, end = persona.normal_hours
    if start <= end:
        return random.randint(start, end)
    # overnight window, e.g. 19 -> 4
    return random.choice(list(range(start, 24)) + list(range(0, end + 1)))


def timestamp_for(persona: Persona, base: datetime, day_offset: int) -> datetime:
    hour = hour_for_persona(persona)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return base + timedelta(days=day_offset, hours=hour, minutes=minute, seconds=second)


def choose_event(persona: Persona) -> str:
    r = random.random()
    if r < persona.admin_rate:
        return "UserPermissionChange"
    if r < persona.admin_rate + persona.export_rate:
        return random.choice(["ReportExport", "BulkDataExport"])
    if r < persona.admin_rate + persona.export_rate + persona.query_rate:
        return "SOQLQuery"
    return random.choice(["Login", "Logout", "DashboardView", "ConnectedAppOAuth"])


def user_agent_for(os_name: str, device_type: str) -> str:
    if os_name == "Windows":
        return "Mozilla/5.0 Windows Chrome"
    if os_name == "macOS":
        return "Mozilla/5.0 macOS Safari"
    if os_name == "Linux":
        return "Mozilla/5.0 Linux Firefox"
    if os_name == "iOS":
        return "SalesforceMobileSDK iOS"
    if os_name == "Android":
        return "SalesforceMobileSDK Android"
    return f"GenericUA {device_type}"


def benign_row(persona: Persona, event_id: int, base: datetime, day_offset: int, split: str) -> dict:
    event_name = choose_event(persona)
    city, country = random.choice(persona.city_country)
    os_name = random.choice(persona.os_choices)
    device_type = random.choice(persona.device_types)
    query_complexity = max(0, int(np.random.normal(persona.query_complexity_mu, 1.2)))
    records_accessed = max(1, int(np.random.lognormal(np.log(max(persona.records_accessed_mu, 5)), 0.45)))
    if event_name not in ["SOQLQuery", "ReportExport", "BulkDataExport"]:
        query_complexity = 0
        records_accessed = random.randint(1, 40)
    return {
        "event_id": f"evt_{split}_{event_id:05d}",
        "event_name": event_name,
        "event_type": EVENT_TYPES[event_name],
        "timestamp": timestamp_for(persona, base, day_offset).isoformat(),
        "user_id": persona.user_id,
        "persona": persona.persona,
        "src_ip": random_ip(random.choice(persona.ip_prefixes)),
        "domain_name": random.choice(DOMAINS),
        "city": city,
        "country": country,
        "os": os_name,
        "user_agent": user_agent_for(os_name, device_type),
        "device_type": device_type,
        "login_type": random.choice(persona.login_types),
        "tls_version": random.choices(["TLS1.2", "TLS1.3"], weights=[0.25, 0.75])[0],
        "records_accessed": records_accessed,
        "query_complexity": query_complexity,
        "is_admin_action": event_name == "UserPermissionChange",
        "label": 0,
        "scenario": "benign",
    }


def apply_anomaly(row: dict, persona: Persona, scenario: str) -> dict:
    row = dict(row)
    row["label"] = 1
    row["scenario"] = scenario

    if scenario == "foreign_country_login":
        row.update({"event_name": "Login", "event_type": "auth", "src_ip": public_ip(), "city": "Moscow", "country": "RU", "os": "Linux", "device_type": "desktop", "login_type": "Password", "tls_version": "TLS1.0"})
        row["user_agent"] = user_agent_for(row["os"], row["device_type"])
    elif scenario == "mass_export":
        row.update({"event_name": "BulkDataExport", "event_type": "data_export", "src_ip": public_ip(), "records_accessed": int(persona.records_accessed_mu * 35), "query_complexity": 2})
    elif scenario == "suspicious_oauth":
        row.update({"event_name": "ConnectedAppOAuth", "event_type": "auth", "login_type": "OAuth", "domain_name": "evil-connected-app.example", "src_ip": public_ip(), "city": "Unknown", "country": "Unknown"})
    elif scenario == "impossible_travel":
        row.update({"event_name": "Login", "event_type": "auth", "src_ip": public_ip(), "city": "Singapore", "country": "SG", "device_type": "desktop", "os": "Windows"})
        row["user_agent"] = user_agent_for(row["os"], row["device_type"])
    elif scenario == "unusual_os":
        row.update({"event_name": "Login", "event_type": "auth", "os": "Linux", "device_type": "desktop", "user_agent": user_agent_for("Linux", "desktop")})
    elif scenario == "large_data_export":
        row.update({"event_name": "ReportExport", "event_type": "data_access", "records_accessed": 9500, "query_complexity": 1})
    elif scenario == "daytime_admin_action":
        row.update({"event_name": "UserPermissionChange", "event_type": "admin", "is_admin_action": True, "records_accessed": 20, "query_complexity": 0})
        ts = datetime.fromisoformat(row["timestamp"]).replace(hour=11, minute=5)
        row["timestamp"] = ts.isoformat()
    elif scenario == "simple_user_mass_export":
        row.update({"event_name": "BulkDataExport", "event_type": "data_export", "records_accessed": 65000, "query_complexity": 1, "src_ip": public_ip()})
    elif scenario == "new_country_query_burst":
        row.update({"event_name": "SOQLQuery", "event_type": "query", "country": "BR", "city": "Sao Paulo", "src_ip": public_ip(), "query_complexity": 14, "records_accessed": 18000})
    elif scenario == "unusual_device":
        row.update({"event_name": "Login", "event_type": "auth", "device_type": "mobile", "os": "Android", "user_agent": user_agent_for("Android", "mobile")})
    elif scenario == "after_hours_permission_change":
        row.update({"event_name": "UserPermissionChange", "event_type": "admin", "is_admin_action": True, "src_ip": public_ip(), "records_accessed": 75, "query_complexity": 0})
        ts = datetime.fromisoformat(row["timestamp"]).replace(hour=2, minute=17)
        row["timestamp"] = ts.isoformat()
    elif scenario == "disable_mfa":
        row.update({"event_name": "UserPermissionChange", "event_type": "admin", "domain_name": "setup.salesforce.com", "src_ip": public_ip(), "records_accessed": 12, "query_complexity": 0, "tls_version": "TLS1.0"})
    elif scenario == "bulk_export_after_admin_change":
        row.update({"event_name": "BulkDataExport", "event_type": "data_export", "src_ip": public_ip(), "records_accessed": 120000, "query_complexity": 4})

    return row


def generate(train_per_user: int, test_benign_per_user: int, anomalies_per_user: int) -> Tuple[pd.DataFrame, pd.DataFrame]:
    base_train = datetime(2026, 1, 1, tzinfo=timezone.utc)
    base_test = datetime(2026, 3, 15, tzinfo=timezone.utc)
    train_rows: List[dict] = []
    test_rows: List[dict] = []
    eid = 1

    for persona in PERSONAS:
        for i in range(train_per_user):
            train_rows.append(benign_row(persona, eid, base_train, i % 45, "train"))
            eid += 1
        for i in range(test_benign_per_user):
            test_rows.append(benign_row(persona, eid, base_test, i % 14, "test"))
            eid += 1
        scenarios = ANOMALY_SCENARIOS[persona.persona]
        for i in range(anomalies_per_user):
            scenario = scenarios[i % len(scenarios)]
            row = benign_row(persona, eid, base_test, 15 + i, "test")
            test_rows.append(apply_anomaly(row, persona, scenario))
            eid += 1

    return pd.DataFrame(train_rows), pd.DataFrame(test_rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default="data")
    parser.add_argument("--train-per-user", type=int, default=220)
    parser.add_argument("--test-benign-per-user", type=int, default=55)
    parser.add_argument("--anomalies-per-user", type=int, default=8)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    train_df, test_df = generate(args.train_per_user, args.test_benign_per_user, args.anomalies_per_user)
    train_df.to_csv(out_dir / "salesforce_ueba_train.csv", index=False)
    test_df.to_csv(out_dir / "salesforce_ueba_test.csv", index=False)
    print(f"Wrote {len(train_df)} train rows and {len(test_df)} test rows to {out_dir}")


if __name__ == "__main__":
    main()
