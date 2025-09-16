import json
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from loguru import logger


def configure_health_logging(
    environment: str = "staging",
    log_level: str = "INFO",
    service_name: str = "health-checker",
    version: str = "0.0.1",
):
    logger.remove()

    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

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
            backtrace=True,
        )

    logger.add(
        "logs/health_checker.jsonl",
        level=log_level,
        rotation="500 MB",
        retention="30 days",
        compression="zip",
        enqueue=True,
        serialize=True,
        diagnose=environment != "production",
        backtrace=environment != "production",
    )

    logger.add(
        "logs/health_metrics.jsonl",
        filter=lambda record: record["extra"].get("metric", False),
        level="INFO",
        rotation="100 MB",
        retention="7 days",
        compression="zip",
        enqueue=True,
        serialize=True,
    )

    logger.add(
        "logs/health_alerts.jsonl",
        filter=lambda record: record["level"].name in ["ERROR", "CRITICAL", "WARNING"],
        level="WARNING",
        rotation="100 MB",
        retention="90 days",
        compression="zip",
        enqueue=True,
        serialize=True,
    )

    logger.add(
        "logs/health_audit.jsonl",
        filter=lambda record: record["extra"].get("audit", False),
        level="INFO",
        rotation="1 GB",
        retention="1 year",
        compression="zip",
        enqueue=True,
        serialize=True,
        diagnose=False,  # Never include diagnostics in audit logs
        backtrace=False,
    )

    logger.configure(
        extra={
            "service": service_name,
            "version": version,
            "environment": environment,
            "component": "unknown",
            "operation": "unknown",
        }
    )


def create_health_log_formatter():
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
        reserved_fields = {
            "service",
            "version",
            "environment",
            "component",
            "operation",
        }
        for key, value in record["extra"].items():
            if key not in reserved_fields:
                log_entry[key] = value

        # Add exception information if present
        if record["exception"]:
            log_entry["exception"] = {
                "type": record["exception"].type.__name__,
                "value": str(record["exception"].value),
                "traceback": record["exception"].traceback,
            }

        return json.dumps(log_entry, default=str, ensure_ascii=False) + "\n"

    return formatter


def create_metrics_log_formatter():
    def formatter(record: Dict[str, Any]) -> str:
        metrics_entry = {
            "timestamp": record["time"].isoformat(),
            "service": record["extra"].get("service", "health-checker"),
            "component": record["extra"].get("component", "unknown"),
            "operation": record["extra"].get("operation", "unknown"),
            "message": record["message"],
            "level": record["level"].name,
        }
        
        # Add metric-specific fields
        metric_fields = [
            "metric", "performance_metric", "cache_performance", 
            "system_health_tracking", "response_time", "health_score",
            "cache_hit_rate", "total_checks", "critical_failures"
        ]
        
        for field in metric_fields:
            if field in record["extra"]:
                metrics_entry[field] = record["extra"][field]
        
        return json.dumps(metrics_entry, default=str) + "\n"
    
    return formatter


def create_alert_log_formatter():
    def formatter(record: Dict[str, Any]) -> str:
        alert_entry = {
            "timestamp": record["time"].isoformat(),
            "service": record["extra"].get("service", "health-checker"),
            "severity": map_log_level_to_severity(record["level"].name),
            "level": record["level"].name,
            "component": record["extra"].get("component", "unknown"),
            "operation": record["extra"].get("operation", "unknown"),
            "message": record["message"],
            "alert_level": record["extra"].get("alert_level", record["level"].name.lower()),
        }
        
        # Add alert-specific fields
        alert_fields = [
            "check_name", "critical", "error_type", "incident_tracking",
            "performance_issue", "critical_failure", "system_status"
        ]
        
        for field in alert_fields:
            if field in record["extra"]:
                alert_entry[field] = record["extra"][field]
        
        if record["exception"]:
            alert_entry["exception"] = {
                "type": record["exception"].type.__name__,
                "value": str(record["exception"].value),
            }
        
        return json.dumps(alert_entry, default=str) + "\n"
    
    return formatter


def create_audit_log_formatter():
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

        audit_fields = [
            "check_name",
            "configuration_change",
            "system_access",
            "data_access",
            "security_event",
            "compliance_check",
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
        "CRITICAL": "critical",
    }
    return mapping.get(level, "unknown")


def generate_correlation_id() -> str:
    """Generate unique correlation ID for request tracking."""
    return str(uuid.uuid4())[:8]


def generate_execution_id() -> str:
    """Generate unique execution ID for health check runs."""
    return f"exec_{int(datetime.now().timestamp())}_{uuid.uuid4().hex[:8]}"


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
    # TODO: this needs to be based on cache statistics
    return 0.0


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
            **self.context,
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
                **self.context,
            ).debug(
                f"Completed {self.operation} for {self.check_name} in {duration:.2f}ms"
            )
        else:
            logger.bind(
                component="health_checker",
                operation=self.operation,
                check_name=self.check_name,
                duration=duration,
                error_type=exc_type.__name__,
                **self.context,
            ).error(
                f"Failed {self.operation} for {self.check_name} after {duration:.2f}ms: {exc_val}"
            )
