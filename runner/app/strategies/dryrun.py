from __future__ import annotations

import logging
from typing import Any, Dict, Callable

from app.exchange_client import EX


class DryRunStrategy:
    def step(self, ctx: Dict[str, Any], logger: logging.Logger) -> None:
        cfg = (ctx.get("config") or {})
        pairs = cfg.get("pairs") or ["ETH/USDT"]
        ex_name = (cfg.get("exchange") or ctx.get("exchange") or "binance").lower()
        sandbox = bool(cfg.get("testnet") or cfg.get("sandbox"))
        push_metric: Callable[[str, Dict[str, str], float], None] = ctx.get("push_metric")  # type: ignore

        ex = EX.get_public(ex_name, sandbox=sandbox)
        if ex is None:
            logger.warning("dryrun_exchange_unavailable", extra={"extra_fields": {"exchange": ex_name, "sandbox": sandbox}})
            return
        if not EX.ensure_markets(ex):
            logger.warning("dryrun_load_markets_error", extra={"extra_fields": {"exchange": ex_name}})
            return
        for p in pairs:
            try:
                t = ex.fetch_ticker(p)
                last = float(t.get("last") or 0.0)
                if last:
                    if push_metric:
                        push_metric("agent_pair_last_price", {"pair": p, "exchange": ex_name}, last)
                    logger.info(
                        "dryrun_ticker",
                        extra={"extra_fields": {"pair": p, "exchange": ex_name, "last": last}},
                    )
            except Exception as e:
                logger.warning(
                    "dryrun_ticker_error",
                    extra={"extra_fields": {"pair": p, "exchange": ex_name, "err": str(e)}}
                )
