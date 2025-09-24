from __future__ import annotations

import json
import time
import logging
from typing import Any, Dict, Optional, Callable, Tuple

import requests
from eth_account import Account  # type: ignore

from app.exchange_client import EX


def _pad_hex(data: str) -> str:
    data = data.lower().replace("0x", "")
    return data.rjust(64, "0")


def _rpc_call(rpc_url: str, method: str, params: list) -> Any:
    resp = requests.post(rpc_url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=15)
    resp.raise_for_status()
    j = resp.json()
    if not isinstance(j, dict) or "result" not in j:
        raise RuntimeError(f"bad rpc response: {j}")
    return j["result"]


def _hex_to_int(x: Optional[str]) -> int:
    if not isinstance(x, str):
        return 0
    return int(x, 16)


def _int_to_hex(v: int) -> str:
    return hex(int(v))


class DefiRebalanceStrategy:
    """
    AI DeFi Rebalancer (ETH <-> USDC) via 0x API.

    - Computes a simple momentum signal on CEX price (ccxt), maps to target allocation in base asset (ETH)
    - Reads on-chain balances via JSON-RPC (ETH + ERC20)
    - If allocation drift > threshold, executes a swap via 0x (with allowance management)

    Config example (Ethereum mainnet):
    {
      "exchange": "binance",
      "pair": "ETH/USDT",
      "timeframe": "5m",
      "sma_fast": 20,
      "sma_slow": 60,
      "alloc_up": 0.7,
      "alloc_down": 0.3,
      "min_trade_usd": 50,
      "slippage_bps": 30,
      "cooldown_sec": 600,
      "live_trading": false,
      "chain_id": 1,
      "base_token": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  # WETH
      "quote_token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eb48"   # USDC
    }
    """

    def __init__(self) -> None:
        self._last_trade_ts: float = 0.0
        self._last_signal: int = 0

    @staticmethod
    def _sma(vals, n):
        n = int(n)
        if n <= 0 or not vals or len(vals) < n:
            return None
        return sum(vals[-n:]) / n

    @staticmethod
    def _agg_base_url(chain_id: int) -> str:
        # Common 0x endpoints
        return {
            1: "https://api.0x.org",            # Ethereum mainnet
            10: "https://optimism.api.0x.org",  # Optimism
            137: "https://polygon.api.0x.org",  # Polygon
            42161: "https://arbitrum.api.0x.org",  # Arbitrum One
            8453: "https://base.api.0x.org",    # Base
        }.get(chain_id, "https://api.0x.org")

    @staticmethod
    def _read_keypair(keystore_path: str = "/data/agent_key.json") -> Tuple[str, str]:
        try:
            data = json.loads(open(keystore_path).read())
            return str(data.get("address")), str(data.get("private_key"))
        except Exception:
            return ("", "")

    def _eth_balance(self, rpc: str, addr: str) -> float:
        wei_hex = _rpc_call(rpc, "eth_getBalance", [addr, "latest"])
        wei = _hex_to_int(wei_hex)
        return wei / 10**18

    def _erc20_decimals(self, rpc: str, token: str) -> int:
        selector = "0x313ce567"  # decimals()
        data = selector
        call = {"to": token, "data": data}
        out = _rpc_call(rpc, "eth_call", [call, "latest"])  # hex
        return _hex_to_int(out)

    def _erc20_balance(self, rpc: str, token: str, owner: str) -> float:
        selector = "0x70a08231"  # balanceOf(address)
        data = selector + _pad_hex(owner)
        call = {"to": token, "data": data}
        out = _rpc_call(rpc, "eth_call", [call, "latest"])  # hex
        dec = self._erc20_decimals(rpc, token)
        return _hex_to_int(out) / (10**dec if dec else 1)

    def _erc20_allowance(self, rpc: str, token: str, owner: str, spender: str) -> int:
        selector = "0xdd62ed3e"  # allowance(address,address)
        data = selector + _pad_hex(owner) + _pad_hex(spender)
        call = {"to": token, "data": data}
        out = _rpc_call(rpc, "eth_call", [call, "latest"])  # hex
        return _hex_to_int(out)

    def _erc20_approve(self, rpc: str, chain_id: int, token: str, owner: str, pk: str, spender: str, amount: int, gas_price_wei: Optional[int]) -> str:
        selector = "0x095ea7b3"  # approve(address,uint256)
        data = selector + _pad_hex(spender) + _pad_hex(hex(amount))
        nonce_hex = _rpc_call(rpc, "eth_getTransactionCount", [owner, "pending"])
        nonce = _hex_to_int(nonce_hex)
        if gas_price_wei is None:
            gas_price_wei = _hex_to_int(_rpc_call(rpc, "eth_gasPrice", []))
        tx = {
            "to": token,
            "from": owner,
            "value": 0,
            "gasPrice": gas_price_wei,
            "gas": 120000,  # conservative default
            "nonce": nonce,
            "data": data,
            "chainId": chain_id,
        }
        # estimate gas best-effort
        try:
            ghex = _rpc_call(rpc, "eth_estimateGas", [{k: (hex(v) if isinstance(v, int) else v) for k, v in tx.items()}])
            g = int(ghex, 16)
            tx["gas"] = max(50000, int(g * 1.2))
        except Exception:
            pass
        acct = Account.from_key(pk)
        signed = acct.sign_transaction(tx)
        txid = _rpc_call(rpc, "eth_sendRawTransaction", ["0x" + signed.rawTransaction.hex()])
        return txid

    def _quote_0x(self, chain_id: int, sell_token: str, buy_token: str, sell_amount: int, taker: str, slippage_bps: int) -> Dict[str, Any]:
        base = self._agg_base_url(chain_id)
        url = f"{base}/swap/v1/quote"
        params = {
            "sellToken": sell_token,
            "buyToken": buy_token,
            "sellAmount": str(sell_amount),
            "takerAddress": taker,
            "slippagePercentage": str(max(0, slippage_bps) / 10000.0),
            "intentOnFilling": "true",
        }
        r = requests.get(url, params=params, timeout=20)
        r.raise_for_status()
        return r.json()

    def _send_0x(self, rpc: str, pk: str, chain_id: int, quote: Dict[str, Any]) -> str:
        # 0x returns to, data, value, gas, gasPrice, etc.
        to = quote.get("to")
        data = quote.get("data")
        value = int(quote.get("value") or 0)
        gas = int(quote.get("gas") or 260000)
        gas_price = int(quote.get("gasPrice") or _hex_to_int(_rpc_call(rpc, "eth_gasPrice", [])))
        nonce = _hex_to_int(_rpc_call(rpc, "eth_getTransactionCount", [quote.get("from") or quote.get("takerAddress"), "pending"]))
        tx = {
            "to": to,
            "from": quote.get("from") or quote.get("takerAddress"),
            "value": value,
            "gasPrice": gas_price,
            "gas": gas,
            "nonce": nonce,
            "data": data,
            "chainId": chain_id,
        }
        acct = Account.from_key(pk)
        signed = acct.sign_transaction(tx)
        txid = _rpc_call(rpc, "eth_sendRawTransaction", ["0x" + signed.rawTransaction.hex()])
        return txid

    def step(self, ctx: Dict[str, Any], logger: logging.Logger) -> None:
        cfg = (ctx.get("config") or {})
        pair = cfg.get("pair") or (cfg.get("pairs") or ["ETH/USDT"])[0]
        ex_name = (cfg.get("exchange") or ctx.get("exchange") or "binance").lower()
        timeframe = str(cfg.get("timeframe") or "5m")
        sma_fast = int(cfg.get("sma_fast") or 20)
        sma_slow = int(cfg.get("sma_slow") or 60)
        alloc_up = float(cfg.get("alloc_up") or 0.7)
        alloc_down = float(cfg.get("alloc_down") or 0.3)
        min_trade_usd = float(cfg.get("min_trade_usd") or 50.0)
        slippage_bps = int(cfg.get("slippage_bps") or 30)
        cooldown = int(cfg.get("cooldown_sec") or 600)
        live_trading = bool(cfg.get("live_trading") or False)
        chain_id = int(cfg.get("chain_id") or 1)
        base_token = (cfg.get("base_token") or "").strip()  # WETH
        quote_token = (cfg.get("quote_token") or "").strip()  # USDC
        sandbox = bool(cfg.get("testnet") or cfg.get("sandbox"))
        evm_urls = ctx.get("evm_urls") or []
        rpc = evm_urls[0] if isinstance(evm_urls, list) and evm_urls else None
        push_metric: Callable[[str, Dict[str, str], float], None] = ctx.get("push_metric")  # type: ignore
        push_trade: Callable[[str, str, float, float, str], None] = ctx.get("push_trade")  # type: ignore

        addr, pk = self._read_keypair()
        if not rpc or not addr or not pk:
            logger.warning("defi_missing_env", extra={"extra_fields": {"rpc": bool(rpc), "addr": bool(addr)}})
            return

        # Price and momentum
        ex = EX.get_public(ex_name, sandbox=sandbox)
        if ex is None or not EX.ensure_markets(ex):
            logger.warning("defi_exchange_unavailable", extra={"extra_fields": {"exchange": ex_name}})
            return
        closes = []
        last = 0.0
        try:
            ohlcv = ex.fetch_ohlcv(pair, timeframe=timeframe, limit=max(100, sma_slow + 5))
            closes = [float(c[4]) for c in ohlcv if isinstance(c, (list, tuple)) and len(c) >= 5]
            if closes:
                last = float(closes[-1])
                if push_metric:
                    push_metric("agent_pair_last_price", {"pair": pair, "exchange": ex_name}, float(last))
        except Exception as e:
            logger.warning("defi_ohlcv_error", extra={"extra_fields": {"pair": pair, "exchange": ex_name, "err": str(e)}})
            return
        if len(closes) < max(sma_fast, sma_slow):
            return
        f = self._sma(closes, sma_fast) or 0.0
        s = self._sma(closes, sma_slow) or 0.0
        sig = 1 if f > s else -1
        self._last_signal = sig
        target_alloc = alloc_up if sig > 0 else alloc_down
        labels = {"pair": pair, "exchange": ex_name}
        if push_metric:
            push_metric("agent_defi_signal", labels, float(sig))
            push_metric("agent_defi_target_alloc", labels, float(target_alloc))

        # On-chain balances (ETH + ERC20)
        try:
            eth_bal = self._eth_balance(rpc, addr)
        except Exception as e:
            logger.warning("defi_eth_balance_error", extra={"extra_fields": {"err": str(e)}})
            return
        base_bal = 0.0
        quote_bal = 0.0
        base_dec = 18
        quote_dec = 6
        try:
            if base_token:
                base_bal = self._erc20_balance(rpc, base_token, addr)
                base_dec = self._erc20_decimals(rpc, base_token)
        except Exception:
            pass
        try:
            if quote_token:
                quote_bal = self._erc20_balance(rpc, quote_token, addr)
                quote_dec = self._erc20_decimals(rpc, quote_token)
        except Exception:
            pass
        # Portfolio value approximation in USD
        # Assume quote_token ~ USD stable and pair price is base vs USDT
        base_usd = last
        total_usd = quote_bal + base_bal * base_usd
        cur_alloc = (base_bal * base_usd) / total_usd if total_usd > 1e-9 else 0.0
        if push_metric:
            push_metric("agent_defi_base_alloc", labels, float(cur_alloc))
            push_metric("agent_defi_portfolio_usd", labels, float(total_usd))

        # Decide rebalance
        drift = target_alloc - cur_alloc
        trade_usd = abs(drift) * total_usd
        if trade_usd < max(10.0, min_trade_usd):
            return
        # Cooldown between trades
        now = time.time()
        if now - self._last_trade_ts < max(60, cooldown):
            return

        # Determine direction
        # If target > current, we need more base: buy base using quote
        buy_base = (drift > 0)
        try:
            if buy_base:
                # Sell quote (USDC) for base (WETH)
                sell_token = quote_token
                buy_token = base_token
                sell_amount_units = int((trade_usd) * (10 ** quote_dec))
            else:
                # Sell base (WETH) for quote (USDC)
                sell_token = base_token
                buy_token = quote_token
                sell_amount_units = int((trade_usd / max(1e-9, base_usd)) * (10 ** base_dec))
        except Exception:
            return

        # 0x quote
        try:
            quote = self._quote_0x(chain_id, sell_token, buy_token, sell_amount_units, addr, slippage_bps)
        except Exception as e:
            logger.warning("defi_0x_quote_error", extra={"extra_fields": {"err": str(e)}})
            return

        # Ensure allowance if selling ERC20
        try:
            if sell_token and sell_token.lower() != "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee":
                spender = quote.get("allowanceTarget") or quote.get("spender")
                if spender:
                    cur_allow = self._erc20_allowance(rpc, sell_token, addr, spender)
                    if cur_allow < sell_amount_units and live_trading:
                        gas_price = _hex_to_int(_rpc_call(rpc, "eth_gasPrice", []))
                        self._erc20_approve(rpc, chain_id, sell_token, addr, pk, spender, int(sell_amount_units * 1.1), gas_price)
        except Exception as e:
            logger.warning("defi_allowance_error", extra={"extra_fields": {"err": str(e)}})

        # Execute or dry run
        txid = None
        if live_trading:
            try:
                txid = self._send_0x(rpc, pk, chain_id, quote)
                self._last_trade_ts = time.time()
            except Exception as e:
                logger.warning("defi_swap_error", extra={"extra_fields": {"err": str(e)}})
                return
        else:
            logger.info("defi_dryrun_swap", extra={"extra_fields": {"quote": {k: quote.get(k) for k in ("to","value","gas","gasPrice")}}})
            self._last_trade_ts = time.time()

        # Record trade (paper ledger)
        try:
            side = "buy" if buy_base else "sell"
            qty = (trade_usd / base_usd) if buy_base else (trade_usd / base_usd)
            if push_trade:
                push_trade(side, pair, float(qty), float(base_usd), ex_name)
        except Exception:
            pass

        if txid:
            logger.info("defi_swap_submitted", extra={"extra_fields": {"txid": txid}})
