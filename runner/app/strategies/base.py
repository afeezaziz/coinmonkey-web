from __future__ import annotations

from typing import Protocol, Any, Dict
import logging


class Strategy(Protocol):
    def step(self, ctx: Dict[str, Any], logger: logging.Logger) -> None:  # one iteration
        ...
