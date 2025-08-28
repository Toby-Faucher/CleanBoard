from dataclasses import dataclass
from typing import Callable, Awaitable, List, Optional, Dict
import asyncio
import inspect
from datetime import datetime, timedelta, UTC

from .models import HealthCheckResponse, HealthStatus, CheckResult, SystemHealth


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
            raise ValueError(f"Check function '{name}' must be callable")

        if not inspect.iscoroutinefunction(check_func):
            raise ValueError(f"Check function '{name}' must be an async function")

        sig = inspect.signature(check_func)
        if len(sig.parameters) > 0:
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

        async def execute_single_check(check: HealthCheck) -> tuple[str, CheckResult]:
            if check.cache_ttl is not None:
                cached_result = self._get_cached_result(check.name)
                if cached_result is not None:
                    return check.name, cached_result

            try:
                start_time = datetime.now(UTC)
                try:
                    result = await asyncio.wait_for(check.check_func(), check.timeout)

                    if not isinstance(result, bool):
                        raise ValueError(
                            f"Check function must return a boolean, got {type(result).__name__}"
                        )

                    is_healthy = result
                except asyncio.TimeoutError:
                    return check.name, CheckResult(
                        status=HealthStatus.TIMEDOUT,
                        error="Timed Out!",
                        critical=check.critical,
                        response_time=check.timeout,
                    )
                except TypeError as e:
                    return check.name, CheckResult(
                        status=HealthStatus.ERROR,
                        response_time=0.0,
                        error=f"Function call error: {str(e)}",
                        critical=check.critical,
                    )

                end_time = datetime.now(UTC)
                response_time = (end_time - start_time).total_seconds() * 1000

                status = HealthStatus.HEALTHY if is_healthy else HealthStatus.UNHEALTHY

                result = CheckResult(
                    status=status,
                    response_time=round(response_time, 2),
                    critical=check.critical,
                )

                if check.cache_ttl is not None:
                    self._cache_result(check.name, result, check.cache_ttl)

                return check.name, result

            except Exception as e:
                return check.name, CheckResult(
                    status=HealthStatus.ERROR,
                    response_time=0.0,
                    error=str(e),
                    critical=check.critical,
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
