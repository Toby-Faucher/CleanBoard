from fastapi import APIRouter, HTTPException, status
from .checker import HealthChecker
from .checks import external_api_check, memory_check
from .models import (
    HealthCheckResponse,
    LivenessResponse,
    ReadinessResponse,
    SystemHealth,
)

router = APIRouter()
health_checker = HealthChecker()

health_checker.add_check("external_api", external_api_check, critical=False)
health_checker.add_check("memory", memory_check, critical=True)


@router.get("/health", response_model=HealthCheckResponse)
async def health_check():
    """Complete health check with all dependencies"""
    health_response = await health_checker.run_checks()

    if health_response.status == SystemHealth.UNHEALTHY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=health_response.model_dump(mode="json"),
        )

    return health_response


@router.get("/health/live", response_model=LivenessResponse)
async def liveness_check():
    """Simple liveness check - indicates the service is running"""
    return LivenessResponse()


@router.get("/health/ready", response_model=ReadinessResponse)
async def readiness_check():
    """Check if service is ready to handle requests (critical checks only)"""
    health_response = await health_checker.run_critical_checks()

    if health_response.status == SystemHealth.UNHEALTHY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=ReadinessResponse(
                status="not ready", checks=health_response.checks
            ).model_dump(mode="json"),
        )

    return ReadinessResponse(status="ready", checks=health_response.checks)
