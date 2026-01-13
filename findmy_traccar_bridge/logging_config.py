"""Logging configuration for findmy-traccar-bridge.

Configures loguru as the main logger and intercepts stdlib logging
from the findmy library to maintain consistent log formatting.
"""

import logging
import os
import sys

from loguru import logger


class InterceptHandler(logging.Handler):
    """Handler that intercepts stdlib logging and redirects to loguru."""

    def emit(self, record: logging.LogRecord) -> None:
        # Get corresponding Loguru level if it exists
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Patch loguru record with the actual source info from the stdlib LogRecord
        def patcher(loguru_record: dict) -> None:
            loguru_record["file"] = type(
                "File", (), {"name": record.filename, "path": record.pathname}
            )()
            loguru_record["line"] = record.lineno
            loguru_record["function"] = record.funcName
            loguru_record["name"] = record.name

        logger.patch(patcher).opt(depth=0, exception=record.exc_info).log(
            level, record.getMessage()
        )


def setup_logging() -> None:
    """Configure loguru and intercept findmy library logs."""
    log_level = os.environ.get("BRIDGE_LOGGING_LEVEL", "INFO")

    # Configure loguru
    logger.remove()
    logger.add(sys.stderr, level=log_level)

    # Redirect findmy library logs to loguru
    logging.getLogger("findmy").setLevel(log_level)
    logging.getLogger("findmy").addHandler(InterceptHandler())


# Auto-configure on import
setup_logging()
