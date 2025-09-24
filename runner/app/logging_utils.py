import json
import logging
import os
import sys
from datetime import datetime, timezone


def setup_logger(level: str | None = None) -> logging.Logger:
    logger = logging.getLogger("agent")
    if logger.handlers:
        return logger

    lvl = getattr(logging, (level or os.getenv("LOG_LEVEL", "INFO")).upper(), logging.INFO)
    logger.setLevel(lvl)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(lvl)

    class JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            payload = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "message": record.getMessage(),
            }
            # Attach context extras if present
            if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
                payload.update(record.extra_fields)
            return json.dumps(payload)

    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def log_json(logger: logging.Logger, level: str, message: str, **kwargs) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    extra = {"extra_fields": kwargs}
    logger.log(lvl, message, extra=extra)
