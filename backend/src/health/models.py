"""Health check models for the application.

This module defines Pydantic models for health check responses,
including status enumerations and validation logic.
"""

from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import Dict, Any, Optional, Literal, Annotated
from datetime import datetime, UTC
from enum import Enum

def _utc_now() -> datetime:
    """Get the current UTC timestamp.
    
    Returns:
        datetime: Current UTC datetime.
    """
    return datetime.now(UTC)

class HealthStatus(str, Enum):
    """Enumeration for individual health check status values.
    
    Attributes:
        HEALTHY: Service is functioning normally
        UNHEALTHY: Service is not functioning properly but not in error state
        ERROR: Service encountered an error during health check
    """
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    ERROR = "error"

class CheckResult(BaseModel):
    """Model representing the result of an individual health check.
    
    Attributes:
        status: The health status of the check
        response_time: Optional response time in seconds (must be non-negative)
        critical: Whether this check is critical to overall system health
        error: Optional error message if the check failed
        details: Optional dictionary containing additional check details
    """
    status: HealthStatus
    response_time: Annotated[Optional[float], Field(ge=0.0)] = None
    critical: bool
    error: Annotated[Optional[str], Field(min_length=1)] = None
    details: Optional[Dict[str, Any]] = None

    @field_validator('details')
    @classmethod
    def validate_details(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Validate that details dictionary is not empty when provided.
        
        Args:
            v: The details dictionary to validate
            
        Returns:
            Optional[Dict[str, Any]]: The validated details dictionary
            
        Raises:
            ValueError: If details dictionary is empty
        """
        if v is not None and not v:
            raise ValueError('details dictionary cannot be empty')
        return v

    @field_validator('error')
    @classmethod
    def validate_error(cls, v: Optional[str]) -> Optional[str]:
        """Validate that error message is not empty or whitespace-only.
        
        Args:
            v: The error message to validate
            
        Returns:
            Optional[str]: The validated error message
            
        Raises:
            ValueError: If error message is empty or whitespace-only
        """
        if v is not None and not v.strip():
            raise ValueError('error message cannot be empty or whitespace only')
        return v

def _validate_checks_dict(v: Dict[str, CheckResult]) -> Dict[str, CheckResult]:
    """Validate that checks dictionary is not empty and has valid names.
    
    Args:
        v: Dictionary of health check results to validate
        
    Returns:
        Dict[str, CheckResult]: The validated checks dictionary
        
    Raises:
        ValueError: If no checks provided or check names are invalid
    """
    if not v:
        raise ValueError('at least one health check must be provided')
    for check_name, check_result in v.items():
        if not check_name.strip():
            raise ValueError('check names cannot be empty or whitespace only')
    return v

class SystemHealth(str, Enum):
    """Enumeration for overall system health status.
    
    Unlike individual check statuses, system health is binary - either all critical
    checks are passing (healthy) or one or more are failing (unhealthy).
    
    Attributes:
        HEALTHY: All critical checks are passing
        UNHEALTHY: One or more critical checks are failing
    """
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"


class BaseHealthModel(BaseModel):
    """Base model for health check responses with common configuration.
    
    Provides JSON encoding configuration for datetime objects to ISO format.
    """
    model_config = ConfigDict(
        json_encoders={
            datetime: lambda v: v.isoformat()
        }
    )

class HealthCheckResponse(BaseHealthModel):
    """Response model for health check endpoints.
    
    Attributes:
        status: Overall health status of the system
        timestamp: UTC timestamp when the health check was performed
        checks: Dictionary of individual health check results
    """
    status: SystemHealth
    timestamp: datetime = Field(default_factory=_utc_now)
    checks: Annotated[Dict[str, CheckResult], Field(min_length=1)]

    @field_validator('checks')
    @classmethod
    def validate_checks(cls, v: Dict[str, CheckResult]) -> Dict[str, CheckResult]:
        """Validate that checks dictionary is not empty and has valid names."""
        return _validate_checks_dict(v)

class ReadinessResponse(BaseHealthModel):
    """Response model for readiness check endpoints.
    
    Used to determine if the service is ready to accept traffic.
    
    Attributes:
        status: Readiness status - either "ready" or "not ready"
        timestamp: UTC timestamp when the readiness check was performed
        checks: Dictionary of individual readiness check results
    """
    status: Literal["ready", "not ready"]
    timestamp: datetime = Field(default_factory=_utc_now)
    checks: Annotated[Dict[str, CheckResult], Field(min_length=1)]

    @field_validator('checks')
    @classmethod
    def validate_checks(cls, v: Dict[str, CheckResult]) -> Dict[str, CheckResult]:
        """Validate that checks dictionary is not empty and has valid names."""
        return _validate_checks_dict(v)
