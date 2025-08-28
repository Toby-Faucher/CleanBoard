from pydantic import BaseModel, Field, ConfigDict
from typing import Dict, Any, Optional, Literal
from datetime import datetime, UTC
from enum import Enum

class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    ERROR = "error"

class CheckResult(BaseModel):
    status: HealthStatus
    response_time: Optional[float] = None
    critical: bool
    error: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

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
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    checks: Dict[str, CheckResult]

class ReadinessResponse(BaseHealthModel):
    status: Literal["ready", "not ready"]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    checks: Dict[str, CheckResult]
