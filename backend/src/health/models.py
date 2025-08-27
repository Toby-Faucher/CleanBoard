from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, Literal
from datetime import datetime
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

class HealthCheckResponse(BaseModel):
    status: OverallHealth
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    checks: Dict[str, CheckResult]

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()         
        }

class ReadinessResponse(BaseModel):
    status: Literal["ready", "not ready"]
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    checks: Dict[str, CheckResult]

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()         
        }
