from __future__ import annotations

import os
import threading
import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

import requests

from models import SessionLocal, Alert, AlertEvent, AlertCooldown, new_agent_id
from orchestrator import orchestrator
from services.webhook_security import is_webhook_allowed, build_hmac_headers
from services.metrics import (
    scheduler_tick_total,
    scheduler_errors_total,
    alert_webhook_attempts_total,
    alert_webhook_duration_seconds,
    alert_webhook_attempts_by_alert_total,
    alert_webhook_duration_by_alert_seconds,
)
try:
    import sentry_sdk  # type: ignore
except Exception:  # pragma: no cover
    sentry_sdk = None  # type: ignore


_COOLDOWNS: Dict[Tuple[str, str, str], float] = {}
_THREAD: threading.Thread | None = None
_STOP = threading.Event()
_LOCK = threading.Lock()


def _parse_prom_metrics(text: str) -> List[Tuple[str, Dict[str, str], float]]:
    out: List[Tuple[str, Dict[str, str], float]] = []
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            if '{' in line and '}' in line:
                name = line.split('{', 1)[0]
                rest = line.split('{', 1)[1]
                labels_str, val_str = rest.split('}', 1)
                labels: Dict[str, str] = {}
                for part in labels_str.split(','):
                    if not part:
                        continue
                    k, v = part.split('=', 1)
                    labels[k.strip()] = v.strip().strip('"')
                value = float(val_str.strip())
                out.append((name, labels, value))
            else:
                parts = line.split()
                if len(parts) == 2:
                    out.append((parts[0], {}, float(parts[1])))
        except Exception:
            continue
    return out


def parse_prom_metrics(text: str) -> List[Tuple[str, Dict[str, str], float]]:
    """Public helper to parse Prometheus metrics text into (name, labels, value).

    This wraps the internal parser so other modules can reuse the logic.
    """
    return _parse_prom_metrics(text)


def _fetch_metrics(agent_id: str) -> str:
    backend = os.getenv('ORCHESTRATOR', 'memory').lower()
    if backend != 'docker':
        return ''
    port = orchestrator.host_port(agent_id)
    if not port:
        return ''
    try:
        resp = requests.get(f'http://127.0.0.1:{port}/metrics', timeout=5)
        if resp.status_code == 200:
            return resp.text
    except Exception:
        return ''
    return ''


def _should_fire(key: Tuple[str, str, str], cooldown: int) -> bool:
    ts = time.time()
    last = _COOLDOWNS.get(key, 0)
    if ts - last >= cooldown:
        _COOLDOWNS[key] = ts
        return True
    return False


def _run_loop():
    interval = int(os.getenv('ALERTS_SCHED_INTERVAL_SEC', '60') or '60')
    cooldown = int(os.getenv('ALERTS_SCHED_COOLDOWN_SEC', '300') or '300')
    backoff_base = int(os.getenv('ALERTS_BACKOFF_BASE_SEC', '30') or '30')
    backoff_max = int(os.getenv('ALERTS_BACKOFF_MAX_SEC', '3600') or '3600')
    while not _STOP.is_set():
        try:
            try:
                scheduler_tick_total.inc()
            except Exception:
                pass
            db = SessionLocal()
            try:
                alerts = db.query(Alert).filter(Alert.enabled == True).all()  # noqa: E712
            finally:
                db.close()
            # Group by agent_id
            by_agent: Dict[str, List[Alert]] = {}
            for al in alerts:
                by_agent.setdefault(al.agent_id, []).append(al)
            for agent_id, als in by_agent.items():
                text = _fetch_metrics(agent_id)
                if not text:
                    continue
                series = _parse_prom_metrics(text)
                # Index by metric for speed
                for al in als:
                    try:
                        filters = json.loads(al.labels_json or '{}')
                        if not isinstance(filters, dict):
                            filters = {}
                    except Exception:
                        filters = {}
                    # Evaluate
                    matches: List[Dict] = []
                    for (name, labels, value) in series:
                        if name != al.metric:
                            continue
                        ok = True
                        for k, v in (filters or {}).items():
                            if str(labels.get(k)) != str(v):
                                ok = False
                                break
                        if not ok:
                            continue
                        trig = (value > al.threshold) if al.operator == 'gt' else (value < al.threshold)
                        if trig:
                            matches.append({"labels": labels, "value": value})
                    if not matches:
                        continue
                    # DB-based cooldown/backoff per alert and label set
                    now = datetime.utcnow()
                    for m in matches:
                        label_key = json.dumps(m.get('labels') or {}, sort_keys=True)
                        # Check cooldown
                        cd = None
                        try:
                            db_cd = SessionLocal()
                            try:
                                cd = db_cd.query(AlertCooldown).filter(AlertCooldown.alert_id == al.id, AlertCooldown.label_key == label_key).first()
                                if cd and cd.next_allowed_at and cd.next_allowed_at > now:
                                    continue
                            finally:
                                db_cd.close()
                        except Exception:
                            pass
                        payload = {
                            "agent_id": al.agent_id,
                            "alert_id": al.id,
                            "metric": al.metric,
                            "operator": al.operator,
                            "threshold": al.threshold,
                            "match": m,
                        }
                        # SSRF allowlist check
                        allowed, reason = is_webhook_allowed(al.webhook_url)
                        status_code = None
                        success = False
                        error_msg = None
                        if not allowed:
                            error_msg = reason or 'blocked'
                        else:
                            try:
                                headers = build_hmac_headers(payload)
                                t0 = time.monotonic()
                                r = requests.post(al.webhook_url, json=payload, headers=headers, timeout=5)
                                status_code = r.status_code
                                success = (200 <= r.status_code < 300)
                            except Exception as e:
                                error_msg = str(e)
                                # Capture to Sentry with context (best-effort)
                                try:
                                    if sentry_sdk is not None:
                                        with sentry_sdk.push_scope() as scope:  # type: ignore
                                            scope.set_tag('agent_id', al.agent_id)
                                            scope.set_tag('alert_id', al.id)
                                            try:
                                                scope.set_context('labels', m.get('labels') or {})
                                            except Exception:
                                                pass
                                            sentry_sdk.capture_exception(e)  # type: ignore
                                except Exception:
                                    pass
                            finally:
                                try:
                                    alert_webhook_duration_seconds.observe(max(0.0, time.monotonic() - t0))
                                except Exception:
                                    pass
                            try:
                                res = 'success' if success else 'error'
                                alert_webhook_attempts_total.labels(result=res).inc()
                                alert_webhook_attempts_by_alert_total.labels(agent_id=al.agent_id, alert_id=al.id, result=res).inc()
                            except Exception:
                                pass
                        try:
                            if not allowed:
                                alert_webhook_attempts_total.labels(result='blocked').inc()
                                alert_webhook_attempts_by_alert_total.labels(agent_id=al.agent_id, alert_id=al.id, result='blocked').inc()
                            else:
                                # Also record per-alert duration
                                dt = max(0.0, time.monotonic() - t0)
                                alert_webhook_duration_by_alert_seconds.labels(agent_id=al.agent_id, alert_id=al.id).observe(dt)
                        except Exception:
                            pass
                        # Record last fired timestamp + event + cooldown/backoff
                        try:
                            dbu = SessionLocal()
                            try:
                                al2 = dbu.get(Alert, al.id)
                                if al2:
                                    al2.last_fired_at = datetime.utcnow()
                                    dbu.add(al2)
                                    # Add event row
                                    evt = AlertEvent(
                                        id=new_agent_id(),
                                        agent_id=al.agent_id,
                                        alert_id=al.id,
                                        metric=al.metric,
                                        labels_json=json.dumps(m.get('labels') or {}),
                                        value=float(m.get('value') or 0.0),
                                        success=success,
                                        status_code=status_code,
                                        error=error_msg,
                                    )
                                    dbu.add(evt)
                                    # Update cooldown/backoff
                                    if not cd:
                                        cd = AlertCooldown(id=new_agent_id(), alert_id=al.id, label_key=label_key)
                                    if success:
                                        cd.failure_count = 0
                                        cd.next_allowed_at = datetime.utcnow() + timedelta(seconds=cooldown)
                                    else:
                                        fc = int(cd.failure_count or 0) + 1
                                        cd.failure_count = fc
                                        delay = min(backoff_max, backoff_base * (2 ** min(fc, 10)))
                                        cd.next_allowed_at = datetime.utcnow() + timedelta(seconds=delay)
                                    dbu.add(cd)
                                    dbu.commit()
                            finally:
                                dbu.close()
                        except Exception:
                            pass
        except Exception:
            # Never crash the loop
            try:
                scheduler_errors_total.inc()
            except Exception:
                pass
            try:
                if sentry_sdk is not None:
                    sentry_sdk.capture_exception()  # type: ignore
            except Exception:
                pass
            pass
        _STOP.wait(interval)


def start_scheduler() -> None:
    global _THREAD
    with _LOCK:
        if _THREAD and _THREAD.is_alive():
            return
        _STOP.clear()
        t = threading.Thread(target=_run_loop, name='alerts-scheduler', daemon=True)
        t.start()
        _THREAD = t


def stop_scheduler() -> None:
    with _LOCK:
        _STOP.set()
        # thread will exit on next wake
