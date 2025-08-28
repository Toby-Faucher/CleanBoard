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

    async def _execute_checks(self, checks_to_run: List[HealthCheck], fail_fast: bool = False) -> HealthCheckResponse:
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

        if fail_fast:
            # Early termination mode - stop on first critical failure
            tasks = {asyncio.create_task(execute_single_check(check)): check for check in checks_to_run}
            results = {}
            critical_failed = False
            
            try:
                for completed_task in asyncio.as_completed(tasks.keys()):
                    check_name, result = await completed_task
                    results[check_name] = result
                    
                    # Check if this is a critical failure
                    if result.critical and result.status != HealthStatus.HEALTHY:
                        critical_failed = True
                        # Cancel remaining tasks
                        for task in tasks.keys():
                            if not task.done():
                                task.cancel()
                        break
                
                # Wait for cancelled tasks to complete and mark them as cancelled
                if critical_failed:
                    for task, check in tasks.items():
                        if task.cancelled():
                            results[check.name] = CheckResult(
                                status=HealthStatus.CANCELLED,
                                response_time=0.0,
                                critical=check.critical,
                                error="Check cancelled due to critical failure in fail-fast mode"
                            )
                        elif not task.done():
                            try:
                                await task
                            except asyncio.CancelledError:
                                results[check.name] = CheckResult(
                                    status=HealthStatus.CANCELLED,
                                    response_time=0.0,
                                    critical=check.critical,
                                    error="Check cancelled due to critical failure in fail-fast mode"
                                )
            except asyncio.CancelledError:
                # Handle case where the entire operation is cancelled
                for check in checks_to_run:
                    if check.name not in results:
                        results[check.name] = CheckResult(
                            status=HealthStatus.CANCELLED,
                            response_time=0.0,
                            critical=check.critical,
                            error="Check cancelled"
                        )
                critical_failed = True
        else:
            # Original behavior - run all checks to completion
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

    async def run_checks_with_fail_fast(self) -> HealthCheckResponse:
        return await self._execute_checks(self.checks, fail_fast=True)

    async def run_critical_checks_with_fail_fast(self) -> HealthCheckResponse:
        critical_checks = [check for check in self.checks if check.critical]
        return await self._execute_checks(critical_checks, fail_fast=True)
