"""
Exports admin-labeled requests (POST /admin/requests/label) from the
gateway's database into a CSV that train_model.py --data can consume,
so you can retrain on real observed traffic instead of only synthetic
archetypes.

Usage:
    python3 -m train.export_labeled_data --out real_traffic_export.csv
    python3 -m train.train_model --data real_traffic_export.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import db  # noqa: E402
from app.flow_tracker import FEATURE_NAMES  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path("real_traffic_export.csv"))
    args = parser.parse_args()

    rows = db.list_labeled_requests()
    if not rows:
        print("No labeled requests found yet. Label some via POST /admin/requests/label first.")
        return

    with open(args.out, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(FEATURE_NAMES + ["label", "ip", "path", "labeled_by"])
        n = 0
        for row in rows:
            if not row["features_json"]:
                continue
            feats = json.loads(row["features_json"])
            writer.writerow(
                [feats.get(name, 0.0) for name in FEATURE_NAMES]
                + [row["label"], row["ip"], row["path"], row["labeled_by"]]
            )
            n += 1

    print(f"Wrote {n} labeled rows to {args.out}")


if __name__ == "__main__":
    main()
