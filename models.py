from datetime import datetime, timezone
from sqlmodel import SQLModel, Field


class ScanRecord(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    domain: str = Field(index=True)
    malicious_status: int
    inference_time_ms: float
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class UserWhitelist(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    domain: str = Field(index=True, unique=True)
    note: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserBlacklist(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    domain: str = Field(index=True, unique=True)
    note: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
