from datetime import datetime, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def datetime_to_timestamp_us(value: datetime | None) -> int | None:
    if value is None:
        return None

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return int(value.timestamp() * 1_000_000)


def timestamp_us_to_datetime(value: int | None) -> datetime | None:
    if value is None:
        return None

    return datetime.fromtimestamp(value / 1_000_000, tz=timezone.utc)
