from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Callable
from app.exchange_client import EX


class MarketDataStrategy:
    """
    External market data collector (public endpoints via ccxt):
    - agent_pair_last_price{pair,exchange}
    - agent_pair_24h_volume{pair,exchange}
    - agent_pair_funding_rate{pair,exchange}  (if supported)
    - agent_pair_open_interest{pair,exchange} (if supported)

    Config example:
    {
      "pairs": ["ETH/USDT", "BTC/USDT"],
      "exchange": "binance"
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
        self._exchange = klass({"enableRateLimit": True})
        self._ex_name = name
        self._markets_loaded = False
        return self._exchange

    def step(self, ctx: Dict[str, Any], logger: logging.Logger) -> None:
        cfg = (ctx.get("config") or {})
        pairs = cfg.get("pairs") or ["ETH/USDT"]
        ex_name = (cfg.get("exchange") or ctx.get("exchange") or "binance").lower()
        sandbox = bool(cfg.get("testnet") or cfg.get("sandbox"))
        push_metric: Callable[[str, Dict[str, str], float], None] = ctx.get("push_metric")  # type: ignore

        ex = EX.get_public(ex_name, sandbox=sandbox)
        if ex is None:
            logger.warning("marketdata_exchange_unavailable", extra={"extra_fields": {"exchange": ex_name, "sandbox": sandbox}})
            return
        if not EX.ensure_markets(ex):
            logger.warning(
                "marketdata_load_markets_error",
                extra={"extra_fields": {"exchange": ex_name}}
            )
            return

        for p in pairs:
            labels = {"pair": p, "exchange": ex_name}
            # Ticker (last price, 24h volume)
            try:
                t = ex.fetch_ticker(p)
                last = float(t.get("last") or 0.0)
                if last and push_metric:
                    push_metric("agent_pair_last_price", labels, last)
                vol = t.get("baseVolume") or t.get("quoteVolume") or 0.0
                try:
                    vol_f = float(vol)
                except Exception:
                    vol_f = 0.0
                if vol_f and push_metric:
                    push_metric("agent_pair_24h_volume", labels, vol_f)
            except Exception as e:
                logger.warning("marketdata_ticker_error", extra={"extra_fields": {**labels, "err": str(e)}})

            # Funding rate (derivatives only, exchange-dependent)
            try:
                if getattr(ex, 'has', {}).get('fetchFundingRate') and hasattr(ex, 'fetchFundingRate'):
                    fr = ex.fetchFundingRate(p)
                    rate = float(fr.get("fundingRate") or 0.0)
                    if rate and push_metric:
                        push_metric("agent_pair_funding_rate", labels, rate)
            except Exception as e:
                logger.warning("marketdata_funding_error", extra={"extra_fields": {**labels, "err": str(e)}})

            # Open interest (derivatives only)
            try:
                if getattr(ex, 'has', {}).get('fetchOpenInterest') and hasattr(ex, 'fetchOpenInterest'):
                    oi = ex.fetchOpenInterest(p)
                    # ccxt returns dict with "openInterest" sometimes
                    val = oi.get("openInterest") if isinstance(oi, dict) else None
                    if val is None and isinstance(oi, (int, float)):
                        val = oi
                    if val is not None:
                        try:
                            val = float(val)
                            if push_metric:
                                push_metric("agent_pair_open_interest", labels, val)
                        except Exception:
                            pass
            except Exception as e:
                logger.warning("marketdata_open_interest_error", extra={"extra_fields": {**labels, "err": str(e)}})
