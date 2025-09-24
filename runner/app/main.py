import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from flask import Flask, jsonify, Response
from eth_account import Account

from .logging_utils import setup_logger, log_json
from .strategies import load_strategy


app = Flask(__name__)

# In-memory state for readiness/metrics
STATE = {
    "started_at": datetime.now(timezone.utc).isoformat(),
    "agent_id": os.getenv("AGENT_ID", "unknown"),
    "agent_name": os.getenv("AGENT_NAME", "agent"),
    "strategy": os.getenv("STRATEGY", "custom"),
    "address": None,
    "key_loaded": False,
    "heartbeats": 0,
    "rpc_checked": False,
    "rpc_ok": 0,
}

LOGGER = setup_logger()

# Simple in-memory metrics registry for dynamic strategy metrics
# key: (name, ((label, value), ...)) -> float value (latest)
METRICS: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
LAST_PRICE: dict[tuple[str, str], float] = {}  # (exchange, pair) -> price
TRADES: list[dict] = []  # append-only trade records
POSITIONS: dict[tuple[str, str], dict] = {}  # (exchange, pair) -> {size, avg_entry, realized_pnl}

import threading as _threading
_LEDGER_LOCK = _threading.Lock()


def push_metric(name: str, labels: dict[str, str], value: float) -> None:
    try:
        key = (name, tuple(sorted((labels or {}).items())))
        METRICS[key] = float(value)
        # capture last price for ledger if provided
        if name == "agent_pair_last_price":
            ex = str((labels or {}).get("exchange") or "").lower()
            pair = str((labels or {}).get("pair") or "")
            if ex and pair:
                LAST_PRICE[(ex, pair)] = float(value)
    except Exception:
        pass


def push_trade(side: str, pair: str, qty: float, price: float, exchange: str, fee: float = 0.0) -> None:
    """Record a trade and update positions. qty > 0.
    side: 'buy' or 'sell'
    """
    ts = datetime.now(timezone.utc).isoformat()
    side = side.lower()
    try:
        qty_f = float(qty)
        px_f = float(price)
        fee_f = float(fee or 0.0)
    except Exception:
        return
    if qty_f <= 0 or px_f <= 0 or side not in ("buy", "sell"):
        return
    key = (str(exchange or '').lower(), str(pair or ''))
    with _LEDGER_LOCK:
        pos = POSITIONS.get(key) or {"size": 0.0, "avg_entry": 0.0, "realized_pnl": 0.0}
        realized = 0.0
        if side == 'buy':
            new_cost = pos["size"] * pos["avg_entry"] + qty_f * px_f
            new_size = pos["size"] + qty_f
            pos["avg_entry"] = (new_cost / new_size) if new_size > 1e-12 else 0.0
            pos["size"] = new_size
        else:
            close_qty = min(qty_f, pos["size"])
            realized = (px_f - pos["avg_entry"]) * close_qty
            realized -= fee_f  # subtract fee on sell
            pos["size"] = max(0.0, pos["size"] - close_qty)
            if pos["size"] <= 1e-12:
                pos["size"] = 0.0
                pos["avg_entry"] = 0.0
            pos["realized_pnl"] = pos.get("realized_pnl", 0.0) + realized
        POSITIONS[key] = pos
        trade = {
            "ts": ts,
            "side": side,
            "pair": pair,
            "exchange": key[0],
            "qty": qty_f,
            "price": px_f,
            "notional": qty_f * px_f,
            "fee": fee_f,
            "realized_pnl": realized if side == 'sell' else 0.0,
        }
        TRADES.append(trade)
        if len(TRADES) > 1000:
            del TRADES[: len(TRADES) - 1000]


def keystore_dir() -> Path:
    ks = os.getenv("KEYSTORE_PATH", "/data")
    return Path(ks)


def key_file_path() -> Path:
    return keystore_dir() / "agent_key.json"


def ensure_dirs(path: Path) -> Path:
    try:
        path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        # Fallback to /tmp/data if we can't create the requested dir
        fallback = Path("/tmp/data")
        fallback.mkdir(parents=True, exist_ok=True)
        log_json(LOGGER, "WARNING", "Keystore path not writable; using fallback", requested=str(path), fallback=str(fallback))
        return fallback
    return path


def load_or_generate_keypair() -> dict:
    """Ensure a keypair exists on disk; if missing, generate a new EVM keypair."""
    dir_path = ensure_dirs(keystore_dir())
    fp = dir_path / "agent_key.json"
    if fp.exists():
        try:
            data = json.loads(fp.read_text())
            return data
        except Exception:
            pass

    # Generate new EVM key
    acct = Account.create()
    data = {
        "type": "evm",
        "address": acct.address,
        "private_key": acct.key.hex(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        fp.write_text(json.dumps(data, indent=2))
    except Exception as e:
        log_json(LOGGER, "ERROR", "Failed to write key file", err=str(e), path=str(fp))
    return data


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok", "agent_id": STATE["agent_id"]})


@app.get("/readyz")
def readyz():
    if STATE.get("key_loaded"):
        return jsonify({"status": "ready", "address": STATE.get("address")})
    return jsonify({"status": "starting"}), 503


@app.get("/address")
def address():
    if STATE.get("address"):
        return jsonify({"address": STATE["address"], "type": "evm"})
    return jsonify({"error": "address not available"}), 404


@app.get("/metrics")
def metrics() -> Response:
    # Very small Prometheus exposition
    lines = [
        f'# HELP agent_heartbeats_total Heartbeats emitted by the agent loop',
        f'# TYPE agent_heartbeats_total counter',
        f'agent_heartbeats_total{{agent_id="{STATE["agent_id"]}"}} {STATE["heartbeats"]}',
        f'# HELP agent_up 1 if agent process is up',
        f'# TYPE agent_up gauge',
        f'agent_up{{agent_id="{STATE["agent_id"]}"}} 1',
    ]
    # append dynamic metrics
    for (mname, labels), val in METRICS.items():
        label_str = ",".join(f'{k}="{v}"' for k, v in labels)
        lines.append(f'{mname}{{{label_str}}} {val}')
    return Response("\n".join(lines) + "\n", mimetype="text/plain")


@app.get("/positions")
def positions():
    out = []
    with _LEDGER_LOCK:
        for (ex, pair), pos in POSITIONS.items():
            size = float(pos.get("size") or 0.0)
            avg = float(pos.get("avg_entry") or 0.0)
            realized = float(pos.get("realized_pnl") or 0.0)
            last = float(LAST_PRICE.get((ex, pair)) or 0.0)
            unreal = (last - avg) * size if (size and last and avg) else 0.0
            out.append({
                "exchange": ex,
                "pair": pair,
                "size": size,
                "avg_entry": avg,
                "last": last,
                "unrealized_pnl": unreal,
                "realized_pnl": realized,
            })
    return jsonify({"positions": out})


@app.get("/trades")
def trades():
    with _LEDGER_LOCK:
        return jsonify({"trades": list(TRADES)[-200:]})


@app.get("/wallet")
def wallet():
    """Return basic wallet info including address and balance via first EVM RPC URL if available."""
    addr = STATE.get("address")
    out = {"address": addr, "rpc_checked": STATE.get("rpc_checked"), "rpc_ok": STATE.get("rpc_ok")}
    if not addr:
        return jsonify(out), 200
    try:
        urls = json.loads(os.getenv("EVM_RPC_URLS", "[]"))
    except Exception:
        urls = []
    if isinstance(urls, list) and urls:
        url = urls[0]
        try:
            # chainId
            chain = requests.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}, timeout=5).json().get("result")
            # balance
            bal_hex = requests.post(url, json={"jsonrpc": "2.0", "id": 2, "method": "eth_getBalance", "params": [addr, "latest"]}, timeout=5).json().get("result")
            wei = int(bal_hex, 16) if isinstance(bal_hex, str) else 0
            eth = wei / 10**18
            out.update({"chainId": chain, "balance_wei": wei, "balance_eth": eth})
        except Exception as e:
            out.update({"error": str(e)})
    return jsonify(out), 200


@app.get("/cex")
def cex():
    """Return basic CEX connectivity info using ccxt, if configured via env."""
    out = {
        "exchange": os.getenv("CEX_EXCHANGE", "").lower(),
        "configured": False,
        "connected": False,
    }
    ex = out["exchange"]
    if not ex:
        return jsonify(out), 200
    try:
        import ccxt  # type: ignore
    except Exception as e:
        out.update({"error": f"ccxt not available: {e}"})
        return jsonify(out), 500

    api_key = os.getenv("CEX_API_KEY", "")
    api_secret = os.getenv("CEX_API_SECRET", "")
    passphrase = os.getenv("CEX_API_PASSPHRASE", "")
    out["configured"] = bool(api_key and api_secret)
    try:
        if not hasattr(ccxt, ex):
            out.update({"error": f"unknown exchange: {ex}"})
            return jsonify(out), 400
        klass = getattr(ccxt, ex)
        exchange = klass({
            "apiKey": api_key,
            "secret": api_secret,
            "password": passphrase or None,
            "enableRateLimit": True,
        })
        # fetch_status (public) to verify connectivity
        status = None
        try:
            if hasattr(exchange, 'fetch_status'):
                status = exchange.fetch_status()
        except Exception as e:
            log_json(LOGGER, "WARNING", "cex_status_error", exchange=ex, err=str(e))
        out["status"] = status
        # try a private endpoint if keys are set
        if out["configured"]:
            try:
                bal = exchange.fetch_balance()
                out["connected"] = True
                out["balance_total"] = {k: v for k, v in (bal.get('total') or {}).items() if isinstance(v, (int, float)) and v}
            except Exception as e:
                log_json(LOGGER, "WARNING", "cex_private_error", exchange=ex, err=str(e))
        return jsonify(out), 200
    except Exception as e:
        out.update({"error": str(e)})
        return jsonify(out), 500
    try:
        urls = json.loads(os.getenv("EVM_RPC_URLS", "[]"))
    except Exception:
        urls = []
    if isinstance(urls, list) and urls:
        url = urls[0]
        try:
            # chainId
            chain = requests.post(url, json={"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}, timeout=5).json().get("result")
            # balance
            bal_hex = requests.post(url, json={"jsonrpc":"2.0","id":2,"method":"eth_getBalance","params":[addr, "latest"]}, timeout=5).json().get("result")
            wei = int(bal_hex, 16) if isinstance(bal_hex, str) else 0
            eth = wei / 10**18
            out.update({"chainId": chain, "balance_wei": wei, "balance_eth": eth})
        except Exception as e:
            out.update({"error": str(e)})
    return jsonify(out), 200


def strategy_loop():
    # Load/generate keypair first
    key = load_or_generate_keypair()
    STATE["address"] = key.get("address")
    STATE["key_loaded"] = True

    log_json(
        LOGGER,
        "INFO",
        "Agent started",
        agent_id=STATE["agent_id"],
        agent_name=STATE["agent_name"],
        strategy=STATE["strategy"],
        address=STATE["address"],
    )

    config_raw = os.getenv("CONFIG_JSON", "{}")
    try:
        config = json.loads(config_raw)
    except Exception:
        config = {}

    # Optional: EVM RPC connectivity check
    evm_urls = []
    try:
        evm_urls = json.loads(os.getenv("EVM_RPC_URLS", "[]"))
    except Exception:
        evm_urls = []
    ok_count = 0
    if isinstance(evm_urls, list) and evm_urls:
        for u in evm_urls:
            try:
                resp = requests.post(u, json={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}, timeout=5)
                if resp.status_code == 200 and isinstance(resp.json(), dict) and "result" in resp.json():
                    ok_count += 1
                    log_json(LOGGER, "INFO", "evm_rpc_ok", url=u)
                else:
                    log_json(LOGGER, "WARNING", "evm_rpc_bad_response", url=u, status=resp.status_code)
            except Exception as e:
                log_json(LOGGER, "WARNING", "evm_rpc_error", url=u, err=str(e))
        STATE["rpc_checked"] = True
        STATE["rpc_ok"] = ok_count
        log_json(LOGGER, "INFO", "evm_rpc_summary", total=len(evm_urls), ok=ok_count)

    # Strategy selection and context
    strategy_impl = load_strategy(STATE["strategy"])
    ctx = {
        "address": STATE["address"],
        "strategy": STATE["strategy"],
        "config": config,
        "evm_urls": evm_urls,
        "exchange": os.getenv("CEX_EXCHANGE", ""),
        "cex_keys_configured": bool(os.getenv("CEX_API_KEY") and os.getenv("CEX_API_SECRET")),
        "push_metric": push_metric,
        "push_trade": push_trade,
    }

    # No-op loop: just emit heartbeat and invoke strategy step
    while True:
        STATE["heartbeats"] += 1
        log_json(
            LOGGER,
            "INFO",
            "heartbeat",
            agent_id=STATE["agent_id"],
            count=STATE["heartbeats"],
        )
        try:
            strategy_impl.step(ctx, LOGGER)
        except Exception as e:
            log_json(LOGGER, "ERROR", "strategy_error", err=str(e))
        time.sleep(5)


def main():
    # Strategy loop runs in background thread
    t = threading.Thread(target=strategy_loop, name="strategy-loop", daemon=True)
    t.start()

    port = int(os.getenv("HEALTH_PORT", "8000"))
    app.run(host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
