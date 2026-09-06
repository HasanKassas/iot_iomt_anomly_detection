import logging
import time
from typing import Dict, Any, Optional
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PipelineHealthMonitor:
    """Monitors pipeline health and stability across all components."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, "initialized"):
            self.counters = defaultdict(int)
            self.start_time = time.time()
            self.component_states = {}
            self.initialized = True

    def reset(self):
        """Reset all counters."""
        self.counters.clear()
        self.start_time = time.time()

    def record_success(self, component: str):
        """Record a successful operation."""
        self.counters[f"{component}_success"] += 1

    def record_failure(self, component: str):
        """Record a failed operation."""
        self.counters[f"{component}_failure"] += 1

    def record_skipped(self, component: str, reason: str = "schema_invalid"):
        """Record a skipped record."""
        self.counters[f"{component}_skipped"] += 1
        self.counters[f"{component}_skipped_{reason}"] += 1

    def record_invalid_schema(self, component: str):
        """Record an invalid schema event."""
        self.counters[f"{component}_invalid_schema"] += 1

    def get_summary(self) -> Dict[str, Any]:
        """Get health summary."""
        uptime = time.time() - self.start_time
        
        return {
            "uptime_seconds": round(uptime, 2),
            "counters": dict(self.counters),
            "total_failures": sum(v for k, v in self.counters.items() if "_failure" in k),
            "total_skipped": sum(v for k, v in self.counters.items() if "_skipped" in k and "_skipped_" not in k),
            "total_invalid": sum(v for k, v in self.counters.items() if "_invalid" in k),
        }

    def log_summary(self):
        """Log current health summary."""
        summary = self.get_summary()
        logger.info("=" * 60)
        logger.info("PIPELINE HEALTH SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Uptime: {summary['uptime_seconds']}s")
        logger.info(f"Total Failures: {summary['total_failures']}")
        logger.info(f"Total Skipped: {summary['total_skipped']}")
        logger.info(f"Total Invalid: {summary['total_invalid']}")
        for key, value in summary['counters'].items():
            if value > 0:
                logger.info(f"  {key}: {value}")
        logger.info("=" * 60)


_health_monitor = PipelineHealthMonitor()


def get_health_monitor() -> PipelineHealthMonitor:
    """Get the singleton health monitor instance."""
    return _health_monitor
