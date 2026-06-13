#!/usr/bin/env python3
"""Train/infer a compact PyTorch autoencoder for synthetic Salesforce UEBA logs.

Input: train and test CSV files.
Output: scored CSV with interestingness_score and reasons JSON.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import pickle
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)

CATEGORICAL_COLS = [
    "event_name",
    "event_type",
    "user_id",
    "persona",
    "domain_name",
    "city",
    "country",
    "os",
    "user_agent",
    "device_type",
    "login_type",
    "tls_version",
]

NUMERIC_COLS = [
    "hour",
    "is_weekend",
    "records_accessed",
    "query_complexity",
    "is_admin_action",
    "is_private_ip",
]

RAW_COLS_FOR_REASONING = [
    "event_id",
    "timestamp",
    "src_ip",
    "records_accessed",
    "query_complexity",
    "is_admin_action",
    "country",
    "city",
    "os",
    "device_type",
    "login_type",
    "tls_version",
    "domain_name",
    "event_name",
]


class AutoEncoder(nn.Module):
    def __init__(self, input_dim: int, latent_dim: int = 12) -> None:
        super().__init__()
        hidden = max(16, min(128, input_dim // 2))
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden),
            nn.ReLU(),
            nn.Linear(hidden, latent_dim),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden),
            nn.ReLU(),
            nn.Linear(hidden, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


@dataclass
class Preprocessor:
    columns: List[str]
    means: Dict[str, float]
    stds: Dict[str, float]
    profile: Dict[str, dict]

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        features = make_features(df)
        features = pd.get_dummies(features, columns=CATEGORICAL_COLS, dummy_na=True)
        for col in self.columns:
            if col not in features.columns:
                features[col] = 0
        features = features[self.columns]
        for col in NUMERIC_COLS:
            if col in features.columns:
                features[col] = (features[col].astype(float) - self.means[col]) / self.stds[col]
        return features.astype(np.float32).values


def is_private_ip(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip).is_private)
    except Exception:
        return 0


def make_features(df: pd.DataFrame) -> pd.DataFrame:
    x = df.copy()
    dt = pd.to_datetime(x["timestamp"], utc=True, errors="coerce")
    x["hour"] = dt.dt.hour.fillna(-1).astype(int)
    x["is_weekend"] = dt.dt.dayofweek.isin([5, 6]).astype(int)
    x["is_admin_action"] = x["is_admin_action"].astype(str).str.lower().isin(["true", "1", "yes"]).astype(int)
    x["is_private_ip"] = x["src_ip"].apply(is_private_ip)
    for col in ["records_accessed", "query_complexity"]:
        x[col] = pd.to_numeric(x[col], errors="coerce").fillna(0)
    keep = CATEGORICAL_COLS + NUMERIC_COLS
    return x[keep]


def build_profile(train_df: pd.DataFrame) -> Dict[str, dict]:
    prof: Dict[str, dict] = {}
    train = train_df.copy()
    train["hour"] = pd.to_datetime(train["timestamp"], utc=True).dt.hour
    train["is_admin_action"] = train["is_admin_action"].astype(str).str.lower().isin(["true", "1", "yes"]).astype(int)
    train["is_private_ip"] = train["src_ip"].apply(is_private_ip)
    for user_id, g in train.groupby("user_id"):
        p = {}
        for col in ["country", "city", "os", "device_type", "login_type", "tls_version", "domain_name", "event_name"]:
            p[f"allowed_{col}"] = sorted(g[col].dropna().astype(str).unique().tolist())
            p[f"mode_{col}"] = str(g[col].mode().iloc[0]) if not g[col].mode().empty else None
        for col in ["hour", "records_accessed", "query_complexity", "is_admin_action", "is_private_ip"]:
            vals = pd.to_numeric(g[col], errors="coerce").fillna(0)
            p[f"{col}_mean"] = float(vals.mean())
            p[f"{col}_std"] = float(max(vals.std(ddof=0), 1.0))
            p[f"{col}_p95"] = float(vals.quantile(0.95))
        prof[user_id] = p
    return prof


def fit_preprocessor(train_df: pd.DataFrame) -> Preprocessor:
    features = make_features(train_df)
    means: Dict[str, float] = {}
    stds: Dict[str, float] = {}
    for col in NUMERIC_COLS:
        means[col] = float(features[col].astype(float).mean())
        stds[col] = float(max(features[col].astype(float).std(ddof=0), 1.0))
        features[col] = (features[col].astype(float) - means[col]) / stds[col]
    features = pd.get_dummies(features, columns=CATEGORICAL_COLS, dummy_na=True)
    return Preprocessor(columns=list(features.columns), means=means, stds=stds, profile=build_profile(train_df))


def train_model(x_train: np.ndarray, epochs: int, batch_size: int, lr: float) -> AutoEncoder:
    model = AutoEncoder(input_dim=x_train.shape[1])
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.MSELoss()
    ds = TensorDataset(torch.tensor(x_train, dtype=torch.float32))
    loader = DataLoader(ds, batch_size=batch_size, shuffle=True)
    model.train()
    for epoch in range(epochs):
        losses = []
        for (batch,) in loader:
            opt.zero_grad()
            recon = model(batch)
            loss = loss_fn(recon, batch)
            loss.backward()
            opt.step()
            losses.append(loss.item())
        #if epoch in {0, epochs - 1}:
        print(f"epoch={epoch + 1} loss={np.mean(losses):.6f}")

            # Format: Epoch | Train Loss | Val Loss | Val Acc | Time
            # print(f"Epoch [{epoch+1}/{epochs}] "
            #     f"Loss: {train_loss:.4f} | "
            #     f"Val Loss: {val_loss:.4f} | "
            #     f"Val Acc: {val_accuracy:.2%}")

    return model


def reconstruction_error(model: AutoEncoder, x: np.ndarray) -> np.ndarray:
    model.eval()
    with torch.no_grad():
        inp = torch.tensor(x, dtype=torch.float32)
        recon = model(inp)
        err = torch.mean((recon - inp) ** 2, dim=1).numpy()
    return err


def zscore(value: float, mean: float, std: float) -> float:
    return float((value - mean) / max(std, 1e-6))


def hour_distance(hour: int, mean_hour: float) -> float:
    # Circular distance on a 24-hour clock.
    diff = abs(hour - mean_hour)
    return float(min(diff, 24 - diff))


def reasons_for_row(row: pd.Series, profile: Dict[str, dict], global_threshold: float, recon_err: float) -> Dict[str, dict]:
    user_id = row["user_id"]
    p = profile.get(user_id, {})
    reasons: Dict[str, dict] = {}
    if not p:
        reasons["unknown_user"] = {"value": user_id, "severity": "high"}
        return reasons

    dt = pd.to_datetime(row["timestamp"], utc=True, errors="coerce")
    hour = int(dt.hour) if not pd.isna(dt) else -1
    if hour >= 0:
        dist = hour_distance(hour, p.get("hour_mean", hour))
        if dist >= 6:
            reasons["login_hour_deviation"] = {
                "value": hour,
                "normal_mean_hour": round(p.get("hour_mean", hour), 2),
                "circular_hour_distance": round(dist, 2),
            }

    for col in ["country", "city", "os", "device_type", "login_type", "tls_version", "domain_name", "event_name"]:
        val = str(row.get(col, ""))
        allowed = set(p.get(f"allowed_{col}", []))
        if val not in allowed:
            reasons[f"unusual_{col}"] = {
                "value": val,
                "normal_values": sorted(list(allowed))[:8],
            }

    for col in ["records_accessed", "query_complexity"]:
        val = float(row.get(col, 0) or 0)
        mean = p.get(f"{col}_mean", 0.0)
        std = p.get(f"{col}_std", 1.0)
        z = zscore(val, mean, std)
        if z >= 3 or val > p.get(f"{col}_p95", math.inf) * 2:
            reasons[f"high_{col}"] = {
                "value": round(val, 2),
                "normal_mean": round(mean, 2),
                "normal_std": round(std, 2),
                "z_score": round(z, 2),
                "normal_p95": round(p.get(f"{col}_p95", 0), 2),
            }

    is_admin = str(row.get("is_admin_action", "false")).lower() in ["true", "1", "yes"]
    if is_admin and p.get("is_admin_action_mean", 0.0) < 0.05:
        reasons["unexpected_admin_action"] = {
            "value": True,
            "normal_admin_action_rate": round(p.get("is_admin_action_mean", 0.0), 3),
        }

    private_ip = is_private_ip(str(row.get("src_ip", "")))
    if private_ip == 0 and p.get("is_private_ip_mean", 1.0) > 0.8:
        reasons["public_or_unfamiliar_ip"] = {
            "src_ip": row.get("src_ip", ""),
            "normal_private_ip_rate": round(p.get("is_private_ip_mean", 0.0), 3),
        }

    if recon_err > global_threshold:
        reasons["model_reconstruction_error"] = {
            "value": round(float(recon_err), 6),
            "threshold": round(float(global_threshold), 6),
            "ratio": round(float(recon_err / max(global_threshold, 1e-9)), 2),
        }
    return reasons



def rule_score_from_reasons(reasons: Dict[str, dict]) -> float:
    score = 0.0
    for key in reasons:
        if key.startswith("high_records_accessed"):
            score += 55
        elif key.startswith("high_query_complexity"):
            score += 35
        elif key in {"public_or_unfamiliar_ip", "unexpected_admin_action"}:
            score += 30
        elif key == "login_hour_deviation":
            score += 25
        elif key.startswith("unusual_country") or key.startswith("unusual_domain_name"):
            score += 35
        elif key.startswith("unusual_"):
            score += 18
        elif key == "model_reconstruction_error":
            score += 15
        else:
            score += 10
    return float(min(100.0, score))

def score_to_0_100(errors: np.ndarray, threshold: float) -> np.ndarray:
    # Smoothly map reconstruction error to 0-100. Threshold maps near 60.
    ratios = errors / max(threshold, 1e-9)
    return np.clip(100 * (1 - np.exp(-ratios / 1.25)), 0, 100)


def cmd_train(args: argparse.Namespace) -> None:
    train_df = pd.read_csv(args.train_csv)
    pre = fit_preprocessor(train_df)
    x_train = pre.transform(train_df)
    model = train_model(x_train, epochs=args.epochs, batch_size=args.batch_size, lr=args.lr)
    train_err = reconstruction_error(model, x_train)
    threshold = float(np.quantile(train_err, args.quantile))
    Path(args.model_dir).mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), Path(args.model_dir) / "ueba_autoencoder.pt")
    with open(Path(args.model_dir) / "preprocessor.pkl", "wb") as f:
        pickle.dump(pre, f)
    with open(Path(args.model_dir) / "threshold.json", "w") as f:
        json.dump({"threshold": threshold, "train_error_p95": float(np.quantile(train_err, 0.95)), "input_dim": x_train.shape[1]}, f, indent=2)
    print(f"Saved model artifacts to {args.model_dir}; threshold={threshold:.6f}")


def cmd_score(args: argparse.Namespace) -> None:
    with open(Path(args.model_dir) / "preprocessor.pkl", "rb") as f:
        pre: Preprocessor = pickle.load(f)
    with open(Path(args.model_dir) / "threshold.json") as f:
        meta = json.load(f)
    model = AutoEncoder(input_dim=meta["input_dim"])
    model.load_state_dict(torch.load(Path(args.model_dir) / "ueba_autoencoder.pt", map_location="cpu"))
    df = pd.read_csv(args.input_csv)
    x = pre.transform(df)
    err = reconstruction_error(model, x)
    threshold = float(meta["threshold"])
    model_scores = score_to_0_100(err, threshold)
    out = df.copy()
    out["reconstruction_error"] = err
    reasons_json = []
    final_scores = []
    for i, row in out.iterrows():
        r = reasons_for_row(row, pre.profile, threshold, float(err[i]))
        rule_score = rule_score_from_reasons(r)
        final_scores.append(max(float(model_scores[i]), rule_score))
        reasons_json.append(json.dumps(r, sort_keys=True))
    out["interestingness_score"] = np.round(final_scores, 2)
    out["reasons"] = reasons_json
    out["is_interesting"] = out["interestingness_score"] >= args.score_threshold
    Path(args.output_csv).parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(args.output_csv, index=False)
    print(f"Wrote scored output to {args.output_csv}")
    if "label" in out.columns:
        tp = int(((out["label"] == 1) & out["is_interesting"]).sum())
        fp = int(((out["label"] == 0) & out["is_interesting"]).sum())
        fn = int(((out["label"] == 1) & (~out["is_interesting"])).sum())
        print(f"quick_eval tp={tp} fp={fp} fn={fn} anomalies={int((out['label']==1).sum())}")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    p_train = sub.add_parser("train")
    p_train.add_argument("--train-csv", required=True)
    p_train.add_argument("--model-dir", default="models")
    p_train.add_argument("--epochs", type=int, default=4)
    p_train.add_argument("--batch-size", type=int, default=64)
    p_train.add_argument("--lr", type=float, default=1e-3)
    p_train.add_argument("--quantile", type=float, default=0.97)
    p_train.set_defaults(func=cmd_train)

    p_score = sub.add_parser("score")
    p_score.add_argument("--input-csv", required=True)
    p_score.add_argument("--model-dir", default="models")
    p_score.add_argument("--output-csv", required=True)
    p_score.add_argument("--score-threshold", type=float, default=65.0)
    p_score.set_defaults(func=cmd_score)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
