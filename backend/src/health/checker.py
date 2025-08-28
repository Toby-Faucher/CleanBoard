from dataclasses import dataclass
from typing import Callable, Awaitable, List, Optional
import asyncio
import inspect
from datetime import datetime

from .models import HealthCheckResponse, HealthStatus, CheckResult, SystemHealth

@dataclass
class HealthCheck:
    name: str
    check_func: Callable[[], Awaitable[bool]] 
    critical: bool = True
    timeout: Optional[float]

class HealthChecker:
    def __init__(self):
        self.checks: List[HealthCheck] = []


    def add_check(self, name: str, check_func: Callable, critical: bool = True, timeout: Optional[float] = 30.0):
        self._validate_check_function(check_func, name)
        self.checks.append(HealthCheck(name, check_func, critical, timeout))

    def _validate_check_function(self, check_func: Callable, name: str):
        if not callable(check_func):
            raise ValueError(f"Check function '{name}' must be callable")
        
        if not inspect.iscoroutinefunction(check_func):
            raise ValueError(f"Check function '{name}' must be an async function")
        
        sig = inspect.signature(check_func)
        if len(sig.parameters) > 0:
            raise ValueError(f"Check function '{name}' must not accept any parameters")

    async def _execute_checks(self, checks_to_run: List[HealthCheck]) -> HealthCheckResponse:
        async def execute_single_check(check: HealthCheck) -> tuple[str, CheckResult]:
            try:
                start_time = datetime.now()
                try:
                    result = await asyncio.wait_for(
                            check.check_func(),
                            check.timeout
                    )
                    
                    if not isinstance(result, bool):
                        raise ValueError(f"Check function must return a boolean, got {type(result).__name__}")
                    
                    is_healthy = result
                except asyncio.TimeoutError:
                    return check.name, CheckResult(
                            status=HealthStatus.TIMEDOUT,
                            error="Timed Out!",
                            critical=check.critical,
                            response_time=check.timeout
                    )
                except TypeError as e:
                    return check.name, CheckResult(
                        status=HealthStatus.ERROR,
                        response_time=0.0,
                        error=f"Function call error: {str(e)}",
                        critical=check.critical
                    )

                end_time = datetime.now()
                response_time = (end_time - start_time).total_seconds() * 1000

                status = HealthStatus.HEALTHY if is_healthy else HealthStatus.UNHEALTHY 

                return check.name, CheckResult(
                    status=status,
                    response_time=round(response_time, 2),
                    critical=check.critical
                )

            except Exception as e:
                return check.name, CheckResult(
                    status=HealthStatus.ERROR,
                    response_time=0.0,
                    error=str(e),
                    critical=check.critical
                )

        check_results = await asyncio.gather(
            *[execute_single_check(check) for check in checks_to_run],
            return_exceptions=False
        )

        results = dict(check_results)
        critical_failed = any(
            not result.status == HealthStatus.HEALTHY and result.critical 
            for result in results.values()
        )
        
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
