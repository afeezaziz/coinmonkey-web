from __future__ import annotations

from typing import Any, Dict, Optional, Tuple, Set


class ExchangeClient:
    """
    Thin wrapper around ccxt exchanges with simple caching and sandbox support.
    - Caches public instances by (exchange, sandbox)
    - Caches private instances by (exchange, sandbox)
    - Provides ensure_markets() to load markets once per instance
    - Reads API keys from environment for private clients
    """

    def __init__(self) -> None:
        self._pub: Dict[Tuple[str, bool], Any] = {}
        self._priv: Dict[Tuple[str, bool], Any] = {}
        self._loaded_ids: Set[int] = set()

    def _get_ccxt_class(self, name: str):
        try:
            import ccxt  # type: ignore
        except Exception:
            return None
        name = (name or "").lower()
        if not hasattr(ccxt, name):
            return None
        return getattr(ccxt, name)

    def get_public(self, name: str, sandbox: bool = False):
        key = ((name or "").lower(), bool(sandbox))
        ex = self._pub.get(key)
        if ex is not None:
            return ex
        klass = self._get_ccxt_class(name)
        if klass is None:
            return None
        ex = klass({"enableRateLimit": True})
        try:
            if sandbox and hasattr(ex, "set_sandbox_mode"):
                ex.set_sandbox_mode(True)
        except Exception:
            pass
        self._pub[key] = ex
        return ex

    def get_private(self, name: str, sandbox: bool = False):
        import os
        key = ((name or "").lower(), bool(sandbox))
        ex = self._priv.get(key)
        if ex is not None:
            return ex
        klass = self._get_ccxt_class(name)
        if klass is None:
            return None
        api_key = os.getenv("CEX_API_KEY", "")
        api_secret = os.getenv("CEX_API_SECRET", "")
        passphrase = os.getenv("CEX_API_PASSPHRASE", "")
        if not (api_key and api_secret):
            return None
        params: Dict[str, Any] = {
            "apiKey": api_key,
            "secret": api_secret,
            "password": passphrase or None,
            "enableRateLimit": True,
        }
        try:
            ex = klass(params)
            try:
                if sandbox and hasattr(ex, "set_sandbox_mode"):
                    ex.set_sandbox_mode(True)
            except Exception:
                pass
            self._priv[key] = ex
            return ex
        except Exception:
            return None

    def ensure_markets(self, ex: Any) -> bool:
        if ex is None:
            return False
        try:
            if id(ex) in self._loaded_ids:
                return True
            ex.load_markets()
            self._loaded_ids.add(id(ex))
            return True
        except Exception:
            return False

    # Precision helpers (best-effort)
    @staticmethod
    def amount_to_precision(ex: Any, symbol: str, amount: float) -> float:
        try:
            if hasattr(ex, "amount_to_precision"):
                return float(ex.amount_to_precision(symbol, amount))
        except Exception:
            pass
        return float(amount)

    @staticmethod
    def price_to_precision(ex: Any, symbol: str, price: float) -> float:
        try:
            if hasattr(ex, "price_to_precision"):
                return float(ex.price_to_precision(symbol, price))
        except Exception:
            pass
        return float(price)


# Module-level singleton for convenience
EX = ExchangeClient()
