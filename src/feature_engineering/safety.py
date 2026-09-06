import math
from datetime import datetime, timezone
from typing import Any, Iterable, List, Optional


def safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        out = float(value)
        if not math.isfinite(out):
            return default
        return out
    except Exception:
        return default


def safe_div(numer: float, denom: float, default: float = 0.0) -> float:
    try:
        numer_f = float(numer)
        denom_f = float(denom)
        if denom_f == 0.0 or not math.isfinite(numer_f) or not math.isfinite(denom_f):
            return default
        out = numer_f / denom_f
        if not math.isfinite(out):
            return default
        return out
    except Exception:
        return default


def parse_timestamp(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        out = float(value)
        return out if math.isfinite(out) else None
    if isinstance(value, str):
        v = value.strip()
        if not v:
            return None
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(v)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            try:
                out = float(value)
                return out if math.isfinite(out) else None
            except Exception:
                return None
    return None


def nan_to_num(value: Any, default: float = 0.0) -> float:
    try:
        out = float(value)
        if not math.isfinite(out):
            return float(default)
        return out
    except Exception:
        return float(default)


def shannon_entropy(values: Iterable[Any]) -> float:
    vals = [v for v in values if v is not None]
    if not vals:
        return 0.0
    counts = {}
    for v in vals:
        counts[v] = counts.get(v, 0) + 1
    total = float(len(vals))
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log(p, 2)
    return ent if math.isfinite(ent) else 0.0


def mean(values: List[float]) -> float:
    vals = [float(v) for v in values if v is not None and math.isfinite(float(v))]
    if not vals:
        return 0.0
    return sum(vals) / float(len(vals))


def std(values: List[float]) -> float:
    vals = [float(v) for v in values if v is not None and math.isfinite(float(v))]
    if len(vals) < 2:
        return 0.0
    m = mean(vals)
    var = sum((v - m) ** 2 for v in vals) / float(len(vals) - 1)
    out = math.sqrt(var)
    return out if math.isfinite(out) else 0.0


def variance(values: List[float]) -> float:
    vals = [float(v) for v in values if v is not None and math.isfinite(float(v))]
    if len(vals) < 2:
        return 0.0
    m = mean(vals)
    var = sum((v - m) ** 2 for v in vals) / float(len(vals) - 1)
    return var if math.isfinite(var) else 0.0

