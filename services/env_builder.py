from __future__ import annotations

import json
from typing import Dict, Optional

from models import Agent, Credential
from security import decrypt_dict


def build_agent_env(db, agent: Agent, include_secrets: bool = True) -> Dict[str, str]:
    """
    Compose the runtime environment for an agent from its record and credentials.

    - Always includes STRATEGY, CONFIG_JSON, AGENT_NAME, HEALTH_PORT, KEYSTORE_PATH
    - Adds RUNNER_IMAGE if present in agent.config["runner_image"]
    - When include_secrets is True, injects:
        - EVM_RPC_URLS (JSON array) from evm_rpc credentials
        - CEX_EXCHANGE / CEX_API_KEY / CEX_API_SECRET / CEX_API_PASSPHRASE from first cex credential
    """
    env: Dict[str, str] = {
        "STRATEGY": agent.strategy or "custom",
        "CONFIG_JSON": agent.config or "{}",
        "AGENT_NAME": agent.name,
        "HEALTH_PORT": "8000",
        "KEYSTORE_PATH": "/data",
    }
    # Runner image override from config
    try:
        cfg0 = json.loads(agent.config or "{}")
        if isinstance(cfg0, dict):
            ri = cfg0.get("runner_image")
            if ri:
                env["RUNNER_IMAGE"] = str(ri)
    except Exception:
        pass

    if not include_secrets:
        return env

    # Inject credentials
    evm_urls = []
    cex_env: Dict[str, str] = {}
    creds = db.query(Credential).filter(Credential.agent_id == agent.id).all()
    for cred in creds:
        try:
            data = decrypt_dict(cred.data_encrypted)
        except Exception:
            data = {}
        if cred.ctype == "evm_rpc":
            urls = data.get("urls")
            if isinstance(urls, list):
                evm_urls.extend([u for u in urls if isinstance(u, str) and u])
        elif cred.ctype == "cex" and not cex_env:
            cex_env = {
                "CEX_EXCHANGE": str(data.get("exchange", "")),
                "CEX_API_KEY": str(data.get("api_key", "")),
                "CEX_API_SECRET": str(data.get("api_secret", "")),
            }
            if data.get("passphrase"):
                cex_env["CEX_API_PASSPHRASE"] = str(data.get("passphrase"))

    if evm_urls:
        env["EVM_RPC_URLS"] = json.dumps(evm_urls)
    if cex_env:
        env.update(cex_env)

    return env
