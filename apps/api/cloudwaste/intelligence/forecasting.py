"""Spend forecasting from observed daily cost.

A pure function of the daily series handed to it. The method is deliberately
simple and explainable, because a forecast nobody can interrogate is one
nobody should budget against:

  1. **Data sufficiency first.** Fewer than 14 complete days: no forecast, and
     the result says why. 14-29 days: a forecast marked LIMITED with a wider
     band. 30+ days: AVAILABLE.
  2. **Damp outliers, do not delete them.** Days beyond 3.5 robust standard
     deviations (median absolute deviation) are clipped to that bound before
     fitting. A one-off anomaly should not bend the trend line, but it is real
     spend, so it is counted and reported rather than hidden.
  3. **Weekly seasonality** (28+ days): a multiplicative factor per weekday,
     so weekday-heavy workloads do not read as noise.
  4. **Linear trend** on the de-seasonalized series, projected forward and
     re-seasonalized.
  5. **An 80% interval** from the residual spread plus the uncertainty in the
     slope, which is what widens the 90-day band relative to the 7-day one.

The result separates OBSERVED history from FORECAST projection on every point.
No point is ever filled in: a day with no data is absent from the history, not
a zero.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import date, timedelta
from statistics import median

MIN_DAYS = 14
FULL_DAYS = 30
Z_80 = 1.2816


@dataclass(slots=True)
class DailyCost:
    day: date
    amount: float


def _fit(xs: list[float], ys: list[float]) -> tuple[float, float, float, float]:
    """Least squares. Returns slope, intercept, residual std, slope std error."""
    n = len(xs)
    mx = sum(xs) / n
    my = sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx if sxx else 0.0
    intercept = my - slope * mx
    residuals = [y - (intercept + slope * x) for x, y in zip(xs, ys)]
    dof = max(n - 2, 1)
    sigma = math.sqrt(sum(r * r for r in residuals) / dof)
    slope_se = sigma / math.sqrt(sxx) if sxx else 0.0
    return slope, intercept, sigma, slope_se


def forecast(
    history: list[DailyCost],
    *,
    horizons: tuple[int, ...] = (7, 30, 90),
    max_history_days: int = 90,
) -> dict:
    points = sorted(history, key=lambda p: p.day)[-max_history_days:]
    n = len(points)
    observed_series = [
        {"date": p.day.isoformat(), "amount": round(p.amount, 2), "basis": "OBSERVED"}
        for p in points
    ]
    observed = {
        "days": n,
        "first_day": points[0].day.isoformat() if points else None,
        "last_day": points[-1].day.isoformat() if points else None,
        "average_daily": round(sum(p.amount for p in points) / n, 2) if n else None,
        "last_7_days": round(sum(p.amount for p in points[-7:]), 2) if n >= 7 else None,
        "last_30_days": round(sum(p.amount for p in points[-30:]), 2) if n >= 30 else None,
        "basis": "OBSERVED",
    }

    if n < MIN_DAYS:
        return {
            "status": "INSUFFICIENT_DATA",
            "method": None,
            "observed": observed,
            "horizons": [
                {"days": h, "forecast": None, "lower": None, "upper": None, "confidence": None}
                for h in horizons
            ],
            "trend": None,
            "damped_outliers": 0,
            "series": observed_series,
            "notes": [
                f"Only {n} complete day(s) of billing history; at least {MIN_DAYS} are "
                f"needed for a forecast. No figure is shown rather than a guess."
            ],
        }

    amounts = [p.amount for p in points]
    med = median(amounts)
    mad = median(abs(a - med) for a in amounts) * 1.4826
    bound = 3.5 * mad if mad > 0 else None
    cleaned: list[float] = []
    damped = 0
    for amount in amounts:
        if bound is not None and abs(amount - med) > bound:
            damped += 1
            cleaned.append(med + math.copysign(bound, amount - med))
        else:
            cleaned.append(amount)

    notes: list[str] = []
    seasonal = n >= 28
    level = sum(cleaned) / n
    factors = {d: 1.0 for d in range(7)}
    if seasonal and level > 0:
        by_dow: dict[int, list[float]] = {}
        for p, value in zip(points, cleaned):
            by_dow.setdefault(p.day.weekday(), []).append(value)
        for dow, values in by_dow.items():
            factors[dow] = (sum(values) / len(values)) / level
    deseasonalized = [v / (factors[p.day.weekday()] or 1.0) for p, v in zip(points, cleaned)]

    origin = points[0].day
    xs = [float((p.day - origin).days) for p in points]
    slope, intercept, sigma, slope_se = _fit(xs, deseasonalized)
    x_mean = sum(xs) / n
    last_x = xs[-1]
    last_day = points[-1].day

    status = "AVAILABLE" if n >= FULL_DAYS else "LIMITED"
    if status == "LIMITED":
        notes.append(
            f"{n} days of history: the forecast is usable but the band is wide and "
            f"weekly patterns may not be captured."
        )
    if damped:
        notes.append(
            f"{damped} unusual day(s) were damped before fitting so a one-off spike "
            f"does not bend the trend. They remain in the observed history."
        )
    if not seasonal:
        notes.append("Fewer than 28 days: no weekday seasonality applied.")

    max_h = max(horizons)
    projected: list[dict] = []
    horizon_results = []
    for h in horizons:
        total = 0.0
        slope_term = 0.0
        for k in range(1, h + 1):
            x = last_x + k
            day = last_day + timedelta(days=k)
            value = max(0.0, (intercept + slope * x) * factors[day.weekday()])
            total += value
            slope_term += x - x_mean
            if h == max_h:
                projected.append(
                    {"date": day.isoformat(), "amount": round(value, 2), "basis": "FORECAST"}
                )
        spread = Z_80 * math.sqrt(h * sigma**2 + (slope_se * slope_term) ** 2)
        if h > 2 * n:
            confidence = "low"
        elif status == "LIMITED":
            confidence = "low"
        elif h > n:
            confidence = "medium"
        else:
            confidence = "high" if n >= 60 else "medium"
        horizon_results.append(
            {
                "days": h,
                "forecast": round(total, 2),
                "lower": round(max(0.0, total - spread), 2),
                "upper": round(total + spread, 2),
                "confidence": confidence,
                "extrapolates_beyond_history": h > n,
            }
        )
        if h > n:
            notes.append(
                f"The {h}-day forecast projects further ahead than the {n} days of "
                f"history it is fitted on; treat it as indicative."
            )

    mean_level = sum(deseasonalized) / n
    pct_per_30 = (slope * 30 / mean_level * 100) if mean_level > 0 else 0.0
    direction = "rising" if pct_per_30 > 2 else "falling" if pct_per_30 < -2 else "flat"

    return {
        "status": status,
        "method": "robust_linear_trend"
        + ("_weekly_seasonality" if seasonal else "")
        + "_80pct_interval",
        "observed": observed,
        "horizons": horizon_results,
        "trend": {
            "direction": direction,
            "percent_per_30_days": round(pct_per_30, 2),
            "daily_slope": round(slope, 4),
        },
        "damped_outliers": damped,
        "series": observed_series + projected,
        "notes": notes,
    }
