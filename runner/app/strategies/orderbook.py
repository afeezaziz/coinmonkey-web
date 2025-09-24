from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Callable
from app.exchange_client import EX


class OrderbookStrategy:
    """
    Collects orderbook metrics for configured pairs using ccxt:
    - agent_pair_best_bid{pair,exchange}
    - agent_pair_best_ask{pair,exchange}
    - agent_pair_spread{pair,exchange}
    - agent_pair_mid{pair,exchange}
    - agent_pair_orderbook_imbalance{pair,exchange}

    Config example:
    {
      "pairs": ["ETH/USDT", "BTC/USDT"],
      "exchange": "binance",
      "depth": 5
    }
    """

    def __init__(self) -> None:
        self._exchange = None
        self._ex_name: Optional[str] = None
        self._markets_loaded: bool = False

    def _get_exchange(self, name: str):
        if self._exchange is not None and self._ex_name == name:
            return self._exchange
        try:
            import ccxt  # type: ignore
        except Exception:
            return None
        if not hasattr(ccxt, name):
            return None
        klass = getattr(ccxt, name)
        # Public-only client (orderbook is public)
        self._exchange = klass({"enableRateLimit": True})
        self._ex_name = name
        self._markets_loaded = False
        return self._exchange

    def step(self, ctx: Dict[str, Any], logger: logging.Logger) -> None:
        cfg = (ctx.get("config") or {})
        pairs = cfg.get("pairs") or ["ETH/USDT"]
        ex_name = (cfg.get("exchange") or ctx.get("exchange") or "binance").lower()
        sandbox = bool(cfg.get("testnet") or cfg.get("sandbox"))
        depth = int(cfg.get("depth") or 5)
        depth = max(1, min(50, depth))
        push_metric: Callable[[str, Dict[str, str], float], None] = ctx.get("push_metric")  # type: ignore

        ex = EX.get_public(ex_name, sandbox=sandbox)
        if ex is None:
            logger.warning("orderbook_exchange_unavailable", extra={"extra_fields": {"exchange": ex_name, "sandbox": sandbox}})
            return
        if not EX.ensure_markets(ex):
            logger.warning(
                "orderbook_load_markets_error",
                extra={"extra_fields": {"exchange": ex_name}}
            )
            return

        for p in pairs:
            try:
                ob = ex.fetch_order_book(p, limit=depth)
                bids = ob.get("bids") or []
                asks = ob.get("asks") or []
                best_bid = float(bids[0][0]) if bids else 0.0
                best_ask = float(asks[0][0]) if asks else 0.0
                if best_bid and best_ask:
                    spread = best_ask - best_bid
                    mid = (best_ask + best_bid) / 2.0
                    if push_metric:
                        push_metric("agent_pair_best_bid", {"pair": p, "exchange": ex_name}, best_bid)
                        push_metric("agent_pair_best_ask", {"pair": p, "exchange": ex_name}, best_ask)
                        push_metric("agent_pair_spread", {"pair": p, "exchange": ex_name}, spread)
                        push_metric("agent_pair_mid", {"pair": p, "exchange": ex_name}, mid)
                # imbalance calculation (volume in top N levels)
                bid_vol = sum(float(b[1]) for b in bids[:depth]) if bids else 0.0
                ask_vol = sum(float(a[1]) for a in asks[:depth]) if asks else 0.0
                denom = (bid_vol + ask_vol) or 1.0
                imb = (bid_vol - ask_vol) / denom
                if push_metric:
                    push_metric("agent_pair_orderbook_imbalance", {"pair": p, "exchange": ex_name}, imb)
                logger.info(
                    "orderbook_metrics",
                    extra={"extra_fields": {
                        "pair": p, "exchange": ex_name,
                        "best_bid": best_bid, "best_ask": best_ask,
                        "spread": (best_ask - best_bid) if (best_bid and best_ask) else None,
                        "imbalance": imb,
                    }}
                )
            except Exception as e:
                logger.warning(
                    "orderbook_error",
                    extra={"extra_fields": {"pair": p, "exchange": ex_name, "err": str(e)}}
                )
