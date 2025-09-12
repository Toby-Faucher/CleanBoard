import asyncio
import inspect
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Awaitable, Callable, Dict, List, Optional

from loguru import logger

from .models import CheckResult, HealthCheckResponse, HealthStatus, SystemHealth


@dataclass
class CacheEntry:
    """Cache entry for storing health check results with expiration time.

    Attributes:
        result: The cached health check result
        expires_at: UTC timestamp when this cache entry expires
    """

    result: CheckResult
    expires_at: datetime


@dataclass
class HealthCheck:
    """Configuration for a single health check.

    Attributes:
        name: Unique identifier for the health check
        check_func: Async function that returns True if healthy, False otherwise
        timeout: Maximum time in seconds to wait for check completion
        critical: Whether failure of this check should mark the system as unhealthy
        cache_ttl: Time-to-live in seconds for caching results (None to disable)
    """

    name: str
    check_func: Callable[[], Awaitable[bool]]
    timeout: Optional[float]
    critical: bool = True
    cache_ttl: Optional[float] = None


class HealthChecker:
    """Manages and executes health checks with caching and fail-fast capabilities.

    The HealthChecker orchestrates multiple health checks, providing features like:
    - Concurrent execution of checks
    - Result caching with TTL
    - Fail-fast mode for critical checks
    - Timeout handling
    - Separation of critical vs non-critical checks
    """

    def __init__(self):
        """Initialize a new HealthChecker instance."""
        logger.bind(
            component="health_checker",
            operation="Initialization",
        ).info("Health Checker Initialized", total_checks=0, cache_enabled=True)

        self.checks: List[HealthCheck] = []
        self._cache: Dict[str, CacheEntry] = {}

    def add_check(
        self,
        name: str,
        check_func: Callable,
        timeout: Optional[float] = 30.0,
        critical: bool = True,
        cache_ttl: Optional[float] = None,
    ):
        """Add a health check to the checker.

        Args:
            name: Unique identifier for the health check
            check_func: Async function that returns True if healthy, False otherwise
            timeout: Maximum time in seconds to wait for check completion (default: 30.0)
            critical: Whether failure should mark the system as unhealthy (default: True)
            cache_ttl: Time-to-live in seconds for caching results (default: None)

        Raises:
            ValueError: If check_func is not a valid async callable with no parameters
        """

        logger.bind(
            component="health_checker",
            operation="validation",
            check_name=name,
            critical=critical,
            timeout=timeout,
            cache_ttl=cache_ttl,
            metric=True,
        ).info(f"Health Check Reistered: {name}")

        self._validate_check_function(check_func, name)
        self.checks.append(HealthCheck(name, check_func, timeout, critical, cache_ttl))

    def _validate_check_function(self, check_func: Callable, name: str):
        """Validate that a check function meets requirements.

        Args:
            check_func: The function to validate
            name: Name of the check (for error messages)

        Raises:
            ValueError: If function is not callable, not async, or accepts parameters
        """
        if not callable(check_func):
            logger.bind(
                component="health_checker",
                operation="validation",
                check_name=name,
                error_type="not_callable",
                validation_failed=True,
            ).info(f"Health Check Failed: '{name}' Is Not Callable")

            raise ValueError(f"Check function '{name}' must be callable")

        if not inspect.iscoroutinefunction(check_func):
            logger.bind(
                component="health_checker",
                operation="validation",
                check_name=name,
                error_type="not_async",
                validation_failed=True,
            ).info(f"Health Check Failed: '{name}' Is Not Async")

            raise ValueError(f"Check function '{name}' must be an async function")

        sig = inspect.signature(check_func)
        if len(sig.parameters) > 0:
            logger.bind(
                component="health_checker",
                operation="validation",
                check_name=name,
                error_type="not_empty_params",
                validation_failed=True,
            ).info(f"Health Check Failed: '{name}' Must Not Have Any Parameters")

            raise ValueError(f"Check function '{name}' must not accept any parameters")

    def _get_cached_result(self, check_name: str) -> Optional[CheckResult]:
        """Retrieve a cached result if it exists and hasn't expired.

        Args:
            check_name: Name of the health check

        Returns:
            Cached CheckResult if valid, None otherwise
        """
        if check_name in self._cache:
            cache_entry = self._cache[check_name]
            if datetime.now(UTC) < cache_entry.expires_at:
                logger.bind(
                    component="cache",
                    operation="cache_hit",
                    check_name=check_name,
                    cache_performance=True,
                    metric=True,
                ).info(f"Cache hit for check: '{check_name}'")
                return cache_entry.result
            else:
                del self._cache[check_name]
        return None

    def _cache_result(self, check_name: str, result: CheckResult, ttl_seconds: float):
        """Store a check result in the cache with expiration time.

        Args:
            check_name: Name of the health check
            result: The CheckResult to cache
            ttl_seconds: Time-to-live in seconds
        """
        expires_at = datetime.now(UTC) + timedelta(seconds=ttl_seconds)
        self._cache[check_name] = CacheEntry(result=result, expires_at=expires_at)

    def _cleanup_expired_cache(self):
        """Remove all expired entries from the cache."""
        now = datetime.now(UTC)
        expired_keys = [
            key for key, entry in self._cache.items() if now >= entry.expires_at
        ]

        logger.bind(
            component="cache",
            operation="cache_hit",
            expired_keys=len(expired_keys),
            cache_performance=True,
            metric=True,
        ).info(f"Cleaned Up {len(expired_keys)} expired cache entries")

        for key in expired_keys:
            del self._cache[key]

    async def _execute_checks(
        self, checks_to_run: List[HealthCheck], fail_fast: bool = False
    ) -> HealthCheckResponse:
        """Execute a list of health checks with optional fail-fast behavior.

        Args:
            checks_to_run: List of health checks to execute
            fail_fast: If True, stop execution on first critical failure

        Returns:
            HealthCheckResponse containing results of all executed checks
        """
        self._cleanup_expired_cache()

        logger.bind(
            component="health_checker",
            operation="execution_start",
            total_checks=len(checks_to_run),
            fail_fast=fail_fast,
            # TODO: make generate_execution_id
            execution_id=generate_execution_id(),
            metric=True,
        )

        async def execute_single_check(check: HealthCheck) -> tuple[str, CheckResult]:
            start_logger = logger.bind(
                component="health_checker",
                operation="individual_check_start",
                check_name=check.name,
                check_critical=check.critical,
                check_timeout=check.timeout,
                execution_context=True,
            )
            start_logger.info(f"Starting health check: {check.name}")

            if check.cache_ttl is not None:
                cached_result = self._get_cached_result(check.name)
                if cached_result is not None:
                    return check.name, cached_result

            try:
                start_time = datetime.now(UTC)
                logger.bind(
                    component="health_checker",
                    operation="check_execution",
                    check_name=check.name,
                    start_time=start_time.isoformat(),
                    performance_tracking=True,
                ).debug(f"Executing check function: {check.name}")

                try:
                    result = await asyncio.wait_for(check.check_func(), check.timeout)

                    if not isinstance(result, bool):
                        # TODO: impl
                        logger.bind(
                            component="health_checker",
                            operation="check_bool",
                            check_name=check.name,
                            incorrect_type=type(result).__name__,
                            critical=check.critical,
                            error_type="not_bool",
                        ).error(f"Check '{check.name}' Is Not A Bool")
                        raise ValueError(
                            f"Check function must return a boolean, got {type(result).__name__}"
                        )

                    is_healthy = result
                except asyncio.TimeoutError:
                    logger.bind(
                        component="health_checker",
                        operation="check_timeout",
                        check_name=check.name,
                        timeout_duration=check.timeout,
                        critical=check.critical,
                        error_type="timeout",
                        performance_issue=True,
                        alert_level="warning" if not check.critical else "critical",
                    ).warning(
                        f"Health check '{check.name}' timed out after {check.timeout}s"
                    )
                    return check.name, CheckResult(
                        status=HealthStatus.TIMEDOUT,
                        error="Timed Out!",
                        critical=check.critical,
                        response_time=check.timeout,
                    )
                except TypeError as e:
                    logger.bind(
                        component="health_checker",
                        operation="check_exception",
                        check_name=check.name,
                        error_type=type(e).__name__,
                        error_messages=str(e),
                        critical=check.critical,
                        alert_level="error" if check.critical else "warning",
                        incidnet_tracking=True,
                    ).opt(exception=True).error(
                        f"Check '{check.name}' failed with the exception: {e}"
                    )

                    return check.name, CheckResult(
                        status=HealthStatus.ERROR,
                        response_time=0.0,
                        error=f"Function call error: {str(e)}",
                        critical=check.critical,
                    )

                end_time = datetime.now(UTC)
                response_time = (end_time - start_time).total_seconds() * 1000

                status = HealthStatus.HEALTHY if is_healthy else HealthStatus.UNHEALTHY

                logger.bind(
                    component="health_checker",
                    operation="check_timeout",
                    check_name=check.name,
                    status=status.value,
                    response_time=round(response_time, 2),
                    performance_metric=True,
                    metric=True,
                    start_time=start_time.isoformat(),
                    end_time=end_time.isoformat(),
                ).info(
                    f"Check: '{check.name}' completed: {status.value} | {response_time:.2f}ms"
                )

                result = CheckResult(
                    status=status,
                    response_time=round(response_time, 2),
                    critical=check.critical,
                )

                if check.cache_ttl is not None:
                    self._cache_result(check.name, result, check.cache_ttl)

                return check.name, result

            except Exception as e:
                logger.error(f"Health Check '{check.name}' Failed: {str(e)}")
                return check.name, CheckResult(
                    status=HealthStatus.ERROR,
                    response_time=0.0,
                    error=str(e),
                    critical=check.critical,
                )
            logger.bind(
                component="health_checker",
                operation="check_success",
                check_name=check.name,
                status=status.value,
                response_time=response_time,
                critical=check.critical,
                performance_metric=True,
                success_tracking=True,
                metric=True,
            ).success(
                f"Health check '{check.name}' passed: {status.value} ({response_time:.2f}ms)"
            )

        if fail_fast:
            # Early termination mode - stop on first critical failure
            tasks = {
                asyncio.create_task(execute_single_check(check)): check
                for check in checks_to_run
            }
            results = {}
            critical_failed = False

            try:
                for completed_task in asyncio.as_completed(tasks.keys()):
                    check_name, result = await completed_task
                    results[check_name] = result

                    if result.critical and result.status != HealthStatus.HEALTHY:
                        critical_failed = True
                        for task in tasks.keys():
                            if not task.done():
                                task.cancel()
                        break

                if critical_failed:
                    logger.bind(
                        component="health_checker",
                        operation="fail_fast_triggered",
                        check_name=check_name,
                        result_status=result.status.value,
                        critical_failure=True,
                        remaining_tasks=len([t for t in tasks.keys() if not t.done()]),
                        alert_level="critical",
                        incident_tracking=True,
                    ).critical(
                        f"Critical check '{check_name}' failed, triggering fail-fast mode"
                    )

                    for task, check in tasks.items():
                        if task.cancelled():
                            results[check.name] = CheckResult(
                                status=HealthStatus.CANCELLED,
                                response_time=0.0,
                                critical=check.critical,
                                error="Check cancelled due to critical failure in fail-fast mode",
                            )
                        elif not task.done():
                            try:
                                await task
                            except asyncio.CancelledError:
                                results[check.name] = CheckResult(
                                    status=HealthStatus.CANCELLED,
                                    response_time=0.0,
                                    critical=check.critical,
                                    error="Check cancelled due to critical failure in fail-fast mode",
                                )
            except asyncio.CancelledError:
                # Handle case where the entire operation is cancelled
                for check in checks_to_run:
                    if check.name not in results:
                        cancelled_checks = [
                            check.name
                            for task, check in tasks.items()
                            if task.cancelled()
                        ]
                        logger.bind(
                            component="health_checker",
                            operation="checks_cancelled",
                            cancelled_checks=cancelled_checks,
                            cancellation_reason="critical_failure_fail_fast",
                            impact_assessment=True,
                        ).warning(
                            f"Cancelled {len(cancelled_checks)} checks due to critical failure in fail-fast mode"
                        )

                        results[check.name] = CheckResult(
                            status=HealthStatus.CANCELLED,
                            response_time=0.0,
                            critical=check.critical,
                            error="Check cancelled",
                        )
                critical_failed = True
        else:
            check_results = await asyncio.gather(
                *[execute_single_check(check) for check in checks_to_run],
                return_exceptions=False,
            )
            results = dict(check_results)
            critical_failed = any(
                not result.status == HealthStatus.HEALTHY and result.critical
                for result in results.values()
            )

        system_status = (
            SystemHealth.UNHEALTHY if critical_failed else SystemHealth.HEALTHY
        )
        critical_failures = [
            name
            for name, result in results.items()
            if result.critical and result.status != HealthStatus.HEALTHY
        ]

        logger.bind(
            component="health_checker",
            operation="system_health_assessment",
            system_status=system_status.value,
            total_checks=len(results),
            critical_failures=len(critical_failures),
            failed_critical_checks=critical_failures,
            # TODO: make func
            health_score=calculate_health_score(results),
            metric=True,
            system_health_tracking=True,
        ).info(f"System health assessment: {system_status.value}")

        return HealthCheckResponse(status=system_status, checks=results)

    async def run_checks(self) -> HealthCheckResponse:
        """Run all registered health checks.

        Returns:
            HealthCheckResponse with results from all checks
        """
        return await self._execute_checks(self.checks)

    async def run_critical_checks(self) -> HealthCheckResponse:
        """Run only critical health checks.

        Returns:
            HealthCheckResponse with results from critical checks only
        """
        critical_checks = [check for check in self.checks if check.critical]
        return await self._execute_checks(critical_checks)

    async def run_checks_with_fail_fast(self) -> HealthCheckResponse:
        """Run all checks with fail-fast mode enabled.

        In fail-fast mode, execution stops on the first critical failure,
        and remaining checks are cancelled.

        Returns:
            HealthCheckResponse with results from executed checks
        """
        return await self._execute_checks(self.checks, fail_fast=True)

    async def run_critical_checks_with_fail_fast(self) -> HealthCheckResponse:
        """Run critical checks with fail-fast mode enabled.

        Combines critical-only filtering with fail-fast execution.

        Returns:
            HealthCheckResponse with results from executed critical checks
        """
        critical_checks = [check for check in self.checks if check.critical]
        return await self._execute_checks(critical_checks, fail_fast=True)

    def clear_cache(self, check_name: Optional[str] = None):
        """Clear cached results.

        Args:
            check_name: Specific check to clear from cache. If None, clears all cached results.
        """
        if check_name is not None:
            self._cache.pop(check_name, None)
        else:
            self._cache.clear()

    def get_cache_stats(self) -> Dict[str, int]:
        """Get statistics about the current cache state.

        Returns:
            Dictionary containing:
            - total_entries: Total number of cached entries
            - active_entries: Number of non-expired entries
            - expired_entries: Number of expired entries
        """
        now = datetime.now(UTC)
        total_entries = len(self._cache)
        expired_entries = sum(
            1 for entry in self._cache.values() if now >= entry.expires_at
        )
        active_entries = total_entries - expired_entries

        return {
            "total_entries": total_entries,
            "active_entries": active_entries,
            "expired_entries": expired_entries,
        }
