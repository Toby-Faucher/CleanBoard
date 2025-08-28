from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import Dict, Any, Optional, Literal, Annotated
from datetime import datetime, UTC
from enum import Enum

def _utc_now() -> datetime:
    return datetime.now(UTC)

class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    ERROR = "error"

class CheckResult(BaseModel):
    status: HealthStatus
    response_time: Annotated[Optional[float], Field(ge=0.0)] = None
    critical: bool
    error: Annotated[Optional[str], Field(min_length=1)] = None
    details: Optional[Dict[str, Any]] = None

    @field_validator('response_time')
    @classmethod
    def validate_response_time(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and v < 0:
            raise ValueError('response_time must be non-negative')
        return v

    @field_validator('error')
    @classmethod
    def validate_error(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not v.strip():
            raise ValueError('error message cannot be empty or whitespace only')
        return v

class OverallHealth(str, Enum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"


class BaseHealthModel(BaseModel):
    model_config = ConfigDict(
        json_encoders={
            datetime: lambda v: v.isoformat()
        }
    )

class HealthCheckResponse(BaseHealthModel):
    status: OverallHealth
    timestamp: datetime = Field(default_factory=_utc_now)
    checks: Annotated[Dict[str, CheckResult], Field(min_length=1)]

    @field_validator('checks')
    @classmethod
    def validate_checks(cls, v: Dict[str, CheckResult]) -> Dict[str, CheckResult]:
        if not v:
            raise ValueError('at least one health check must be provided')
        for check_name, check_result in v.items():
            if not check_name.strip():
                raise ValueError('check names cannot be empty or whitespace only')
        return v

class ReadinessResponse(BaseHealthModel):
    status: Literal["ready", "not ready"]
    timestamp: datetime = Field(default_factory=_utc_now)
    checks: Annotated[Dict[str, CheckResult], Field(min_length=1)]

    @field_validator('checks')
    @classmethod
    def validate_checks(cls, v: Dict[str, CheckResult]) -> Dict[str, CheckResult]:
        if not v:
            raise ValueError('at least one readiness check must be provided')
        for check_name, check_result in v.items():
            if not check_name.strip():
                raise ValueError('check names cannot be empty or whitespace only')
        return v
