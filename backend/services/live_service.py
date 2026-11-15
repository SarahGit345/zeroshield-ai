"""Live monitor: replays recorded, labelled dataset flows one at a time through the unchanged pipeline.

The demo file (built by build_live_demo.py, gitignored) holds real CIC-IoT-2023 rows in the scaled feature space
plus their dataset label. The label is returned to the dashboard only after the pipeline has produced its decision
and is never passed to the detector, the retrieval, the report or the policy context. Simulated analyst feedback,
when switched on, uses the label exactly like the offline simulator does (after the action is chosen).
"""
from __future__ import annotations

import threading
from collections import Counter
from pathlib import Path

DEMO_FILE = Path(__file__).resolve().parents[1] / "data" / "live_demo_flows.csv"
LABEL_COLUMNS = ("label", "family")


class LiveReplay:
    def __init__(self, path: Path = DEMO_FILE, features: list[str] | None = None):
        self.path = Path(path)
        self.features = list(features or [])
        self.rows: list[dict] = []
        self.cursor = 0
        self.lock = threading.Lock()
        self.error = None
        if self.path.exists():
            self._load()
        else:
            self.error = f"Demo traffic file not found: {self.path.name}. Run: python build_live_demo.py"

    def _load(self):
        import pandas as pd
        frame = pd.read_csv(self.path)
        missing = [f for f in self.features if f not in frame.columns] + [c for c in LABEL_COLUMNS if c not in frame.columns]
        if missing:
            self.error = f"Demo traffic file is missing columns: {missing[:5]}"
            return
        cols = self.features or [c for c in frame.columns if c not in LABEL_COLUMNS]
        for record in frame.to_dict(orient="records"):
            self.rows.append({"features": {f: float(record[f]) for f in cols},
                              "truth": {"label": str(record["label"]), "family": str(record["family"])}})

    @property
    def available(self) -> bool:
        return bool(self.rows) and self.error is None

    def status(self) -> dict:
        return {"available": self.available, "error": self.error, "file": self.path.name, "total": len(self.rows),
                "cursor": self.cursor,
                "composition": dict(Counter(r["truth"]["family"] for r in self.rows)),
                "source": "Recorded CIC-IoT-2023 flows (scaled feature space), replayed in a fixed shuffled order; "
                          "per-family flagged share matches the full-data flag rate; the family mix is stratified."}

    def next(self) -> tuple[int, dict, dict]:
        """(index, features, truth). Wraps around at the end of the file."""
        if not self.available:
            raise RuntimeError(self.error or "No demo traffic loaded.")
        with self.lock:
            index = self.cursor
            self.cursor = (self.cursor + 1) % len(self.rows)
        row = self.rows[index]
        return index, dict(row["features"]), dict(row["truth"])

    def reset(self):
        with self.lock:
            self.cursor = 0
