from __future__ import annotations

from .base import Strategy


def load_strategy(name: str) -> Strategy:
    name = (name or "").strip().lower() or "heartbeat"
    if name in ("heartbeat", "noop", "custom"):
        from .heartbeat import HeartbeatStrategy
        return HeartbeatStrategy()
    if name in ("dryrun", "dry-run"):
        from .dryrun import DryRunStrategy
        return DryRunStrategy()
    if name in ("orderbook", "order-book", "ob"):
        from .orderbook import OrderbookStrategy
        return OrderbookStrategy()
    if name in ("sma", "sma_cross", "sma-cross"):
        from .sma import SmaCrossStrategy
        return SmaCrossStrategy()
    if name in ("marketdata", "market-data", "md"):
        from .marketdata import MarketDataStrategy
        return MarketDataStrategy()
    if name in ("defi", "defi_rebalance", "rebalance"):
        from .defi_rebalance import DefiRebalanceStrategy
        return DefiRebalanceStrategy()
    # default fallback
    from .heartbeat import HeartbeatStrategy
    return HeartbeatStrategy()
