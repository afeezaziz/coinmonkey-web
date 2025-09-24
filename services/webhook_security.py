from __future__ import annotations

import base64
import hmac
import os
import socket
import time
from hashlib import sha256
from typing import Dict, Tuple
from urllib.parse import urlparse
import ipaddress


def _host_in_allowlist(host: str, allow_csv: str | None) -> bool:
    if not allow_csv:
        return True
    host = (host or '').lower()
    for raw in (allow_csv or '').split(','):
        dom = raw.strip().lower()
        if not dom:
            continue
        if host == dom or host.endswith('.' + dom):
            return True
    return False


def is_webhook_allowed(url: str) -> Tuple[bool, str | None]:
    try:
        u = urlparse(url)
    except Exception:
        return False, 'invalid url'
    if u.scheme not in ('http', 'https'):
        return False, 'unsupported scheme'
    host = u.hostname or ''
    if not host:
        return False, 'missing host'
    # Optional allowlist
    allow_csv = os.getenv('WEBHOOK_ALLOW_HOSTS')
    if not _host_in_allowlist(host, allow_csv):
        return False, 'host not in allowlist'
    # Block private networks by default
    block_private = (os.getenv('WEBHOOK_BLOCK_PRIVATE', '1') or '1') not in ('0', 'false', 'no')
    if not block_private:
        return True, None
    # Resolve DNS and ensure all IPs are public
    try:
        infos = socket.getaddrinfo(host, u.port or (443 if u.scheme == 'https' else 80))
    except Exception:
        return False, 'dns resolution failed'
    if not infos:
        return False, 'no addresses'
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
                return False, f'address {addr} blocked'
        except Exception:
            return False, 'invalid address'
    return True, None


def build_hmac_headers(payload: Dict) -> Dict[str, str]:
    secret = os.getenv('WEBHOOK_HMAC_SECRET')
    if not secret:
        return {}
    try:
        ts = str(int(time.time()))
        import json as _json
        body = _json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
        sig = hmac.new(secret.encode('utf-8'), ts.encode('utf-8') + b'.' + body, sha256).hexdigest()
        return {
            'X-Webhook-Timestamp': ts,
            'X-Webhook-Signature': f'v1={sig}',
        }
    except Exception:
        return {}
