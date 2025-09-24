from __future__ import annotations

import logging
from typing import Any, Dict

from .base import Strategy


class HeartbeatStrategy:
    def step(self, ctx: Dict[str, Any], logger: logging.Logger) -> None:
        # This minimal strategy just logs a heartbeat tick with some context
        addr = ctx.get("address")
        strategy = ctx.get("strategy")
        logger.info(
            "heartbeat_step",
            extra={
                "extra_fields": {
                    "strategy": strategy,
                    "address": addr,
                }
            },
        )
