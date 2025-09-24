from __future__ import annotations

from typing import Any, Dict, List, Tuple

try:
    from jsonschema import Draft7Validator
except Exception:  # pragma: no cover
    Draft7Validator = None  # type: ignore


# Per-strategy JSON Schemas (minimal, pragmatic)
SCHEMAS: Dict[str, Dict[str, Any]] = {
    "custom": {
        "type": "object",
        "additionalProperties": True,
    },
    "heartbeat": {
        "type": "object",
        "additionalProperties": True,
    },
    "dryrun": {
        "type": "object",
        "properties": {
            "pairs": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
            "exchange": {"type": "string"},
        },
        "required": ["pairs"],
        "additionalProperties": True,
    },
    "orderbook": {
        "type": "object",
        "properties": {
            "pairs": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
            "exchange": {"type": "string"},
            "depth": {"type": "integer", "minimum": 1},
        },
        "required": ["pairs"],
        "additionalProperties": True,
    },
    "marketdata": {
        "type": "object",
        "properties": {
            "pairs": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
            "exchange": {"type": "string"},
        },
        "required": ["pairs"],
        "additionalProperties": True,
    },
    "sma": {
        "type": "object",
        "properties": {
            "pair": {"type": "string", "minLength": 1},
            "exchange": {"type": "string"},
            "timeframe": {"type": "string", "enum": ["1m", "5m", "15m", "1h"]},
            "fast": {"type": "integer", "minimum": 1},
            "slow": {"type": "integer", "minimum": 1},
            "starting_cash": {"type": "number", "minimum": 0},
            "allocation": {"type": "number", "minimum": 0, "maximum": 1},
            "fee_rate": {"type": "number", "minimum": 0, "maximum": 0.01},
            "slippage_bps": {"type": "integer", "minimum": 0},
            "live_trading": {"type": "boolean"},
            "testnet": {"type": "boolean"},
        },
        "required": ["pair", "timeframe", "fast", "slow"],
        "additionalProperties": True,
    },
    "defi": {
        "type": "object",
        "properties": {
            "pair": {"type": "string", "minLength": 1},
            "exchange": {"type": "string"},
            "timeframe": {"type": "string", "enum": ["1m", "5m", "15m", "1h"]},
            "sma_fast": {"type": "integer", "minimum": 1},
            "sma_slow": {"type": "integer", "minimum": 1},
            "alloc_up": {"type": "number", "minimum": 0, "maximum": 1},
            "alloc_down": {"type": "number", "minimum": 0, "maximum": 1},
            "min_trade_usd": {"type": "number", "minimum": 0},
            "slippage_bps": {"type": "integer", "minimum": 0},
            "cooldown_sec": {"type": "integer", "minimum": 0},
            "live_trading": {"type": "boolean"},
            "testnet": {"type": "boolean"},
            "chain_id": {"type": "integer", "minimum": 1},
            "base_token": {"type": "string", "minLength": 1},
            "quote_token": {"type": "string", "minLength": 1}
        },
        "required": ["chain_id", "base_token", "quote_token"],
        "additionalProperties": True,
    },
}


def validate_config(strategy: str, cfg: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate strategy config against a minimal schema.

    Returns (ok, errors).
    If jsonschema is unavailable, treat as ok to avoid blocking.
    """
    if Draft7Validator is None:
        return True, []
    schema = SCHEMAS.get(strategy, SCHEMAS["custom"])
    v = Draft7Validator(schema)
    errs: List[str] = []
    for e in v.iter_errors(cfg or {}):
        # Build human-friendly messages like: "config.pairs: 'pairs' is a required property"
        path = ".".join(["config"] + [str(p) for p in e.path]) if e.path else "config"
        errs.append(f"{path}: {e.message}")
    return (len(errs) == 0, errs)


def ensure_object(json_str: str) -> Dict[str, Any]:
    """Parse JSON and ensure an object dict; return empty dict on failure."""
    import json as _json
    try:
        obj = _json.loads(json_str) if json_str else {}
        if not isinstance(obj, dict):
            return {}
        return obj
    except Exception:
        return {}
