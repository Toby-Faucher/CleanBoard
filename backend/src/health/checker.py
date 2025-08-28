from dataclasses import dataclass
from typing import Callable, Awaitable, List
import asyncio
from datetime import datetime

from .models import HealthCheckResponse, HealthStatus, CheckResult, SystemHealth

@dataclass
class HealthCheck:
    name: str
    check_func: Callable[[], Awaitable[bool]] 
    critical: bool = True

class HealthChecker:
    def __init__(self):
        self.checks: List[HealthCheck] = []


    def add_check(self, name: str, check_func: Callable, critical: bool = True):
        self.checks.append(HealthCheck(name, check_func, critical))

    async def _execute_checks(self, checks_to_run: List[HealthCheck]) -> HealthCheckResponse:
        results = {}
        critical_failed = False

        for check in checks_to_run:
            try:
                start_time = datetime.now()
                is_healthy = await check.check_func()
                end_time = datetime.now()
                response_time = (end_time - start_time).total_seconds() * 1000

                status = HealthStatus.HEALTHY if is_healthy else HealthStatus.UNHEALTHY 

                results[check.name] = CheckResult(
                    status=status,
                    response_time_ms=round(response_time, 2),
                    critical=check.critical
                )

                if not is_healthy and check.critical:
                    critical_failed = True

            except Exception as e:
                results[check.name] = CheckResult(
                    status=HealthStatus.ERROR,
                    error=str(e),
                    critical=check.critical
                )

                if check.critical:
                    critical_failed = True
                
        system_status = SystemHealth.UNHEALTHY if critical_failed else SystemHealth.HEALTHY

        return HealthCheckResponse(
                status=system_status,
                checks=results
        )

    async def run_checks(self) -> HealthCheckResponse:
        return await self._execute_checks(self.checks)

    async def run_critical_checks(self) -> HealthCheckResponse:
        critical_checks = [check for check in self.checks if check.critical]
        return await self._execute_checks(critical_checks)
