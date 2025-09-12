# Professional Logging Implementation for Health Checker

Based on deep analysis of the Loguru repository, here are the specific places where enterprise-grade logging should be implemented in the health checker system.

## 🎯 Critical Logging Points

### 14. **Public Method Entry Points** (`checker.py:299, 307, 316, 327`)

```python
# For each public method, add entry logging
@logger.catch(level="ERROR", reraise=True)
async def run_checks(self) -> HealthCheckResponse:
    logger.bind(
        component="health_checker",
        operation="run_checks",
        method="run_all_checks",
        total_registered_checks=len(self.checks)
    ).info("Running all health checks")
    return await self._execute_checks(self.checks)
```

### 15. **Cache Statistics** (`checker.py:358-369`)

```python
# Enhanced cache stats with logging
def get_cache_stats(self) -> Dict[str, int]:
    stats = {
        "total_entries": total_entries,
        "active_entries": active_entries,
        "expired_entries": expired_entries
    }

    logger.bind(
        component="cache",
        operation="cache_stats",
        **stats,
        cache_hit_rate=calculate_cache_hit_rate(),
        metric=True,
        performance_monitoring=True
    ).debug("Cache statistics retrieved", **stats)

    return stats
```

## 🎯 **Ultimate Professional Logging Configuration**

### **1. Logger Configuration Module**

Create `backend/src/health/logging_config.py`:

```python
"""Professional logging configuration for health monitoring system."""

import os
import sys
import json
import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from loguru import logger
from pathlib import Path

def configure_health_logging(
    environment: str = "production",
    log_level: str = "INFO",
    service_name: str = "health-checker",
    version: str = "1.0.0"
):
    """Configure enterprise-grade logging for health monitoring."""

    # Remove default handler
    logger.remove()

    # Ensure log directory exists
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    # Console output (development/debugging)
    if environment != "production":
        logger.add(
            sys.stdout,
            format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
                   "<level>{level: <8}</level> | "
                   "<cyan>{extra[component]}</cyan> | "
                   "<blue>{extra[operation]}</blue> | "
                   "<level>{message}</level>",
            level="DEBUG",
            colorize=True,
            enqueue=True,
            diagnose=True,
            backtrace=True
        )

    # Main application logs (structured JSON)
    logger.add(
        "logs/health_checker.jsonl",
        format=create_health_log_formatter(),
        level=log_level,
        rotation="500 MB",
        retention="30 days",
        compression="zip",
        enqueue=True,
        serialize=False,  # Using custom formatter
        diagnose=environment != "production",
        backtrace=environment != "production"
    )

    # Performance and metrics logs
    logger.add(
        "logs/health_metrics.jsonl",
        filter=lambda record: record["extra"].get("metric", False),
        format=create_metrics_log_formatter(),
        level="INFO",
        rotation="100 MB",
        retention="7 days",
        compression="zip",
        enqueue=True
    )

    # Error and alert logs (for monitoring systems)
    logger.add(
        "logs/health_alerts.jsonl",
        filter=lambda record: record["level"].name in ["ERROR", "CRITICAL", "WARNING"],
        format=create_alert_log_formatter(),
        level="WARNING",
        rotation="100 MB",
        retention="90 days",
        compression="zip",
        enqueue=True
    )

    # Security and audit logs
    logger.add(
        "logs/health_audit.jsonl",
        filter=lambda record: record["extra"].get("audit", False),
        format=create_audit_log_formatter(),
        level="INFO",
        rotation="1 GB",
        retention="1 year",
        compression="zip",
        enqueue=True,
        diagnose=False,  # Never include diagnostics in audit logs
        backtrace=False
    )

    # Configure global context
    logger.configure(
        extra={
            "service": service_name,
            "version": version,
            "environment": environment,
            "component": "unknown",
            "operation": "unknown"
        }
    )

def create_health_log_formatter():
    """Create formatter for main health check logs."""
    def formatter(record: Dict[str, Any]) -> str:
        log_entry = {
            "timestamp": record["time"].isoformat(),
            "level": record["level"].name,
            "service": record["extra"].get("service", "health-checker"),
            "version": record["extra"].get("version", "unknown"),
            "environment": record["extra"].get("environment", "unknown"),
            "component": record["extra"].get("component", "unknown"),
            "operation": record["extra"].get("operation", "unknown"),
            "message": record["message"],
            "module": record["module"],
            "function": record["function"],
            "line": record["line"],
            "process_id": record["process"].id,
            "thread_id": record["thread"].id,
        }

        # Add all extra fields except reserved ones
        reserved_fields = {"service", "version", "environment", "component", "operation"}
        for key, value in record["extra"].items():
            if key not in reserved_fields:
                log_entry[key] = value

        # Add exception information if present
        if record["exception"]:
            log_entry["exception"] = {
                "type": record["exception"].type.__name__,
                "value": str(record["exception"].value),
                "traceback": record["exception"].traceback
            }

        return json.dumps(log_entry, default=str, ensure_ascii=False) + "\n"

    return formatter

def create_metrics_log_formatter():
    """Create formatter optimized for metrics and performance data."""
    def formatter(record: Dict[str, Any]) -> str:
        metric_entry = {
            "timestamp": record["time"].isoformat(),
            "service": record["extra"].get("service", "health-checker"),
            "metric_type": record["extra"].get("metric_type", "health_check"),
            "component": record["extra"].get("component", "unknown"),
            "operation": record["extra"].get("operation", "unknown"),
        }

        # Include all metric-related fields
        metric_fields = [
            "check_name", "status", "response_time", "critical", "timeout_duration",
            "cache_hit_rate", "total_checks", "failed_checks", "health_score",
            "system_status", "performance_metric", "cache_performance"
        ]

        for field in metric_fields:
            if field in record["extra"]:
                metric_entry[field] = record["extra"][field]

        return json.dumps(metric_entry, default=str) + "\n"

    return formatter

def create_alert_log_formatter():
    """Create formatter for alerts and monitoring."""
    def formatter(record: Dict[str, Any]) -> str:
        alert_entry = {
            "timestamp": record["time"].isoformat(),
            "level": record["level"].name,
            "service": record["extra"].get("service", "health-checker"),
            "alert_type": record["extra"].get("alert_level", record["level"].name.lower()),
            "component": record["extra"].get("component", "unknown"),
            "operation": record["extra"].get("operation", "unknown"),
            "message": record["message"],
            "severity": map_log_level_to_severity(record["level"].name),
        }

        # Include alert-specific fields
        alert_fields = [
            "check_name", "error_type", "critical", "incident_tracking",
            "performance_issue", "validation_failed", "critical_failure"
        ]

        for field in alert_fields:
            if field in record["extra"]:
                alert_entry[field] = record["extra"][field]

        # Include exception details for errors
        if record["exception"]:
            alert_entry["exception_type"] = record["exception"].type.__name__
            alert_entry["exception_message"] = str(record["exception"].value)

        return json.dumps(alert_entry, default=str) + "\n"

    return formatter

def create_audit_log_formatter():
    """Create formatter for security and compliance auditing."""
    def formatter(record: Dict[str, Any]) -> str:
        audit_entry = {
            "timestamp": record["time"].isoformat(),
            "service": record["extra"].get("service", "health-checker"),
            "audit_event": record["extra"].get("audit_event", "unknown"),
            "component": record["extra"].get("component", "unknown"),
            "operation": record["extra"].get("operation", "unknown"),
            "message": record["message"],
            "process_id": record["process"].id,
            "user_context": record["extra"].get("user_context", "system"),
        }

        # Include audit-specific fields (sanitized)
        audit_fields = [
            "check_name", "configuration_change", "system_access",
            "data_access", "security_event", "compliance_check"
        ]

        for field in audit_fields:
            if field in record["extra"]:
                audit_entry[field] = record["extra"][field]

        return json.dumps(audit_entry, default=str) + "\n"

    return formatter

def map_log_level_to_severity(level: str) -> str:
    """Map log levels to standardized severity levels."""
    mapping = {
        "DEBUG": "low",
        "INFO": "info",
        "SUCCESS": "info",
        "WARNING": "medium",
        "ERROR": "high",
        "CRITICAL": "critical"
    }
    return mapping.get(level, "unknown")

def generate_correlation_id() -> str:
    """Generate unique correlation ID for request tracking."""
    return str(uuid.uuid4())[:8]

def generate_execution_id() -> str:
    """Generate unique execution ID for health check runs."""
    return f"exec_{int(datetime.now().timestamp())}_{uuid.uuid4().hex[:8]}"

# Helper functions for metrics
def calculate_health_score(results: Dict[str, Any]) -> float:
    """Calculate overall health score based on check results."""
    if not results:
        return 0.0

    total_weight = 0
    weighted_score = 0

    for result in results.values():
        weight = 2 if result.critical else 1
        total_weight += weight

        if result.status.value == "healthy":
            weighted_score += weight
        elif result.status.value == "unhealthy":
            weighted_score += 0
        else:  # timeout, error, cancelled
            weighted_score += 0.3 * weight  # Partial credit for non-health issues

    return round((weighted_score / total_weight) * 100, 2) if total_weight > 0 else 0.0

def calculate_cache_hit_rate() -> float:
    """Calculate cache hit rate (placeholder - implement based on your cache metrics)."""
    # This would need to be implemented based on your actual cache statistics
    return 0.0

# Context managers for structured logging
class HealthCheckContext:
    """Context manager for health check operations."""

    def __init__(self, check_name: str, operation: str, **kwargs):
        self.check_name = check_name
        self.operation = operation
        self.context = kwargs
        self.start_time = None

    def __enter__(self):
        self.start_time = datetime.now()
        logger.bind(
            component="health_checker",
            operation=self.operation,
            check_name=self.check_name,
            **self.context
        ).debug(f"Starting {self.operation} for {self.check_name}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (datetime.now() - self.start_time).total_seconds() * 1000

        if exc_type is None:
            logger.bind(
                component="health_checker",
                operation=self.operation,
                check_name=self.check_name,
                duration=duration,
                **self.context
            ).debug(f"Completed {self.operation} for {self.check_name} in {duration:.2f}ms")
        else:
            logger.bind(
                component="health_checker",
                operation=self.operation,
                check_name=self.check_name,
                duration=duration,
                error_type=exc_type.__name__,
                **self.context
            ).error(f"Failed {self.operation} for {self.check_name} after {duration:.2f}ms: {exc_val}")
```

### **2. Integration Instructions**

1. **Import in your health checker**:

```python
from .logging_config import (
    configure_health_logging,
    generate_correlation_id,
    generate_execution_id,
    calculate_health_score,
    HealthCheckContext
)

# Configure logging at startup
configure_health_logging(
    environment=os.getenv("ENVIRONMENT", "development"),
    log_level=os.getenv("LOG_LEVEL", "INFO")
)
```

2. **Add to requirements.txt**:

```text
loguru>=0.7.0
```

3. **Create log rotation script** (`scripts/rotate_logs.sh`):

```bash
#!/bin/bash
find logs/ -name "*.log.*" -mtime +30 -delete
find logs/ -name "*.jsonl.*" -mtime +30 -delete
```

### **3. Production Deployment Considerations**

**Environment Variables**:

```bash
export ENVIRONMENT=production
export LOG_LEVEL=INFO
export HEALTH_CHECKER_SERVICE=health-checker
export HEALTH_CHECKER_VERSION=1.0.0
```

**Docker Configuration**:

```yaml
# docker-compose.yml
volumes:
  - ./logs:/app/logs
environment:
  - ENVIRONMENT=production
  - LOG_LEVEL=INFO
```

**Monitoring Integration**:

- **Prometheus**: Parse metrics from `health_metrics.jsonl`
- **Grafana**: Visualize performance and health scores
- **ELK Stack**: Ingest JSON logs for analysis
- **Datadog/New Relic**: Forward structured logs

## 📋 Implementation Checklist

- [ ] Create `logging_config.py` module
- [ ] Add logging configuration to health checker initialization
- [ ] Update all 15 critical logging points in `checker.py`
- [ ] Add helper functions for metrics calculation
- [ ] Create log directory structure
- [ ] Set up log rotation scripts
- [ ] Configure environment variables
- [ ] Test logging in development environment
- [ ] Validate structured log output
- [ ] Integrate with monitoring systems
- [ ] Set up alerts based on log patterns
- [ ] Document logging standards for team
- [ ] Create log analysis dashboards
- [ ] Implement log retention policies
- [ ] Set up automated log monitoring

This implementation provides enterprise-grade logging with structured data, performance metrics, error tracking, security auditing, and full observability for production health monitoring systems.
