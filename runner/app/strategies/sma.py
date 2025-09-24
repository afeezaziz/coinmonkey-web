from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Callable, Tuple
from app.exchange_client import EX


class SmaCrossStrategy:
    """
    Simple SMA cross with paper trading (optional live trading):
    - Computes SMA fast/slow on OHLCV timeframe
    - Buys when fast crosses above slow; sells when fast crosses below slow
    - Paper-trading portfolio tracked in-memory

    Config example:
    {
      "pair": "ETH/USDT",
      "exchange": "binance",
      "timeframe": "1m",
      "fast": 9,
      "slow": 21,
      "starting_cash": 10000,
      "allocation": 0.5,         # fraction of cash to deploy on BUY
      "fee_rate": 0.001,         # 10 bps
      "slippage_bps": 5,         # 5 bps
      "live_trading": false
    }
    """

    def __init__(self) -> None:
        self._pub_exchange = None
        self._priv_exchange = None
        self._ex_name: Optional[str] = None
        self._markets_loaded: bool = False
        # per (exchange, pair) state
        self._state: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def _get_pub_exchange(self, name: str, sandbox: bool):
        return EX.get_public(name, sandbox=sandbox)

    def _get_priv_exchange(self, name: str, sandbox: bool):
        return EX.get_private(name, sandbox=sandbox)

    @staticmethod
    def _sma(vals, n):
        n = int(n)
        if n <= 0 or not vals or len(vals) < n:
            return None
        return sum(vals[-n:]) / n

    def _ensure_state(self, key: Tuple[str, str], price: float, starting_cash: float) -> Dict[str, Any]:
        st = self._state.get(key)
        if not st:
            st = {
                "cash": float(starting_cash),
                "position": 0.0,
                "entry_price": 0.0,
                "trades": 0,
                "wins": 0,
                "last_signal": 0,
            }
            self._state[key] = st
        # mark-to-market equity
        st["equity"] = float(st["cash"]) + float(st["position"]) * float(price)
        return st

    def step(self, ctx: Dict[str, Any], logger: logging.Logger) -> None:
        cfg = (ctx.get("config") or {})
        pair = cfg.get("pair") or (cfg.get("pairs") or ["ETH/USDT"])[0]
        ex_name = (cfg.get("exchange") or ctx.get("exchange") or "binance").lower()
        timeframe = str(cfg.get("timeframe") or "1m")
        fast = int(cfg.get("fast") or 9)
        slow = int(cfg.get("slow") or 21)
        starting_cash = float(cfg.get("starting_cash") or 10000.0)
        allocation = float(cfg.get("allocation") or 0.5)
        fee_rate = float(cfg.get("fee_rate") or 0.001)
        slip_bps = float(cfg.get("slippage_bps") or 5.0)
        live_trading = bool(cfg.get("live_trading") or False)
        push_metric: Callable[[str, Dict[str, str], float], None] = ctx.get("push_metric")  # type: ignore
        push_trade: Callable[[str, str, float, float, str], None] = ctx.get("push_trade")  # type: ignore

        sandbox = bool(cfg.get("testnet") or cfg.get("sandbox"))
        ex = self._get_pub_exchange(ex_name, sandbox)
        if ex is None:
            logger.warning("sma_exchange_unavailable", extra={"extra_fields": {"exchange": ex_name}})
            return
        if not EX.ensure_markets(ex):
            logger.warning(
                "sma_load_markets_error",
                extra={"extra_fields": {"exchange": ex_name}}
            )
            return

        labels = {"pair": pair, "exchange": ex_name}

        # Fetch candles
        closes = []
        price = 0.0
        try:
            ohlcv = ex.fetch_ohlcv(pair, timeframe=timeframe, limit=max(100, slow + 5))
            closes = [float(c[4]) for c in ohlcv if isinstance(c, (list, tuple)) and len(c) >= 5]
            if closes:
                price = closes[-1]
                if push_metric:
                    push_metric("agent_pair_last_price", labels, price)
        except Exception as e:
            logger.warning("sma_ohlcv_error", extra={"extra_fields": {"pair": pair, "exchange": ex_name, "err": str(e)}})
            return
        if len(closes) < max(fast, slow):
            return

        sma_fast = self._sma(closes, fast)
        sma_slow = self._sma(closes, slow)
        if sma_fast is None or sma_slow is None:
            return
        if push_metric:
            push_metric("agent_pair_sma_fast", labels, float(sma_fast))
            push_metric("agent_pair_sma_slow", labels, float(sma_slow))

        # Determine signal: 1 buy, -1 sell, 0 hold
        prev_fast = self._sma(closes[:-1], fast)
        prev_slow = self._sma(closes[:-1], slow)
        sig = 0
        if prev_fast is not None and prev_slow is not None:
            if prev_fast <= prev_slow and sma_fast > sma_slow:
                sig = 1
            elif prev_fast >= prev_slow and sma_fast < sma_slow:
                sig = -1
        if push_metric:
            push_metric("agent_trade_signal", labels, float(sig))

        # Paper trading logic
        st = self._ensure_state((ex_name, pair), price, starting_cash)
        if push_metric:
            push_metric("agent_cash", labels, float(st["cash"]))
            push_metric("agent_position_size", labels, float(st["position"]))
            push_metric("agent_equity", labels, float(st.get("equity", st["cash"])) )
            push_metric("agent_trades_total", labels, float(st["trades"]))
            wr = (float(st["wins"]) / st["trades"]) if st["trades"] else 0.0
            push_metric("agent_win_rate", labels, wr)

        if sig == 1 and st["cash"] > 0:
            # buy using allocation fraction
            notional = st["cash"] * max(0.0, min(1.0, allocation))
            eff_price = price * (1 + slip_bps / 10000.0)
            qty = notional / eff_price if eff_price > 0 else 0.0
            fee = notional * fee_rate
            if qty > 0 and notional > 0:
                st["cash"] -= (notional + fee)
                st["position"] += qty
                st["entry_price"] = eff_price
                st["trades"] += 1
                st["last_signal"] = 1
                logger.info("sma_buy", extra={"extra_fields": {**labels, "qty": qty, "price": eff_price}})
                try:
                    if push_trade:
                        push_trade("buy", pair, float(qty), float(eff_price), ex_name)
                except Exception:
                    pass
                # Optional live trading (market order)
                if live_trading and ctx.get("cex_keys_configured"):
                    pe = self._get_priv_exchange(ex_name, sandbox)
                    if pe is not None:
                        try:
                            # best-effort precision
                            qty = EX.amount_to_precision(pe, pair, qty)
                            pe.create_order(pair, type='market', side='buy', amount=qty)
                            logger.info("live_buy_ok", extra={"extra_fields": {**labels, "qty": qty}})
                        except Exception as e:
                            logger.warning("live_buy_error", extra={"extra_fields": {**labels, "err": str(e)}})

        elif sig == -1 and st["position"] > 0:
            # sell entire position
            qty = st["position"]
            eff_price = price * (1 - slip_bps / 10000.0)
            proceeds = qty * eff_price
            fee = proceeds * fee_rate
            st["cash"] += max(0.0, proceeds - fee)
            pnl = (eff_price - st["entry_price"]) * qty
            if pnl > 0:
                st["wins"] += 1
            st["position"] = 0.0
            st["trades"] += 1
            st["last_signal"] = -1
            logger.info("sma_sell", extra={"extra_fields": {**labels, "qty": qty, "price": eff_price, "pnl": pnl}})
            try:
                if push_trade:
                    push_trade("sell", pair, float(qty), float(eff_price), ex_name)
            except Exception:
                pass
            # Optional live trading (market order)
            if live_trading and ctx.get("cex_keys_configured"):
                pe = self._get_priv_exchange(ex_name, sandbox)
                if pe is not None:
                    try:
                        qty = EX.amount_to_precision(pe, pair, qty)
                        pe.create_order(pair, type='market', side='sell', amount=qty)
                        logger.info("live_sell_ok", extra={"extra_fields": {**labels, "qty": qty}})
                    except Exception as e:
                        logger.warning("live_sell_error", extra={"extra_fields": {**labels, "err": str(e)}})
