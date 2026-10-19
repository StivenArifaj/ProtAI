"""Server-side resolution of relative date scopes (blueprint §8.3).

Relative dates are resolved exactly once, using only a trusted IANA timezone carried by
the verified principal (or, later, a trusted tenant profile). The prompt text, IP
address, browser headers, and model output are never timezone sources. The resulting
manifest stores exact UTC instants, including across daylight-saving transitions.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ai_security.intent.models import RelativeTimeScope, TimeWindow


def resolve_relative_window(
    *,
    scope: RelativeTimeScope,
    reference: datetime,
    timezone_name: str,
) -> TimeWindow:
    """Resolve ``TODAY``/``THIS_WEEK`` in ``timezone_name`` to UTC instants."""
    if reference.utcoffset() is None:
        raise ValueError("reference time must be timezone-aware")
    try:
        zone = ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"{timezone_name!r} is not a known IANA timezone") from exc

    local_date: date = reference.astimezone(zone).date()
    if scope is RelativeTimeScope.today:
        start_date = local_date
    else:
        start_date = local_date - timedelta(days=local_date.weekday())

    end_date = start_date + timedelta(days=1 if scope is RelativeTimeScope.today else 7)
    start = datetime.combine(start_date, time.min, tzinfo=zone)
    end = datetime.combine(end_date, time.min, tzinfo=zone)
    return TimeWindow(start=start.astimezone(UTC), end=end.astimezone(UTC))


__all__ = ["resolve_relative_window"]
