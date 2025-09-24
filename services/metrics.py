from __future__ import annotations

from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

# HTTP metrics
http_requests_total = Counter(
    'cm_http_requests_total',
    'Total HTTP requests',
    labelnames=['method', 'endpoint', 'status']
)

http_request_latency_seconds = Histogram(
    'cm_http_request_latency_seconds',
    'HTTP request latency in seconds',
    labelnames=['method', 'endpoint']
)

# App health gauges
app_live = Gauge(
    'cm_app_live',
    'Application liveness (1=live)'
)

app_ready = Gauge(
    'cm_app_ready',
    'Application readiness (1=ready)'
)

# Scheduler metrics
scheduler_tick_total = Counter(
    'cm_scheduler_tick_total',
    'Scheduler loop iterations'
)

scheduler_errors_total = Counter(
    'cm_scheduler_errors_total',
    'Scheduler loop errors'
)

# Alert delivery metrics
alert_webhook_attempts_total = Counter(
    'cm_alert_webhook_attempts_total',
    'Alert webhook attempts by result',
    labelnames=['result']  # success | error | blocked
)

alert_webhook_duration_seconds = Histogram(
    'cm_alert_webhook_duration_seconds',
    'Duration of alert webhook POST requests in seconds'
)

# Orchestrator metrics
orchestrator_actions_total = Counter(
    'cm_orchestrator_actions_total',
    'Orchestrator actions by result',
    labelnames=['action', 'result']  # start|stop|delete, success|error
)

orchestrator_status_checks_total = Counter(
    'cm_orchestrator_status_checks_total',
    'Orchestrator status checks by result',
    labelnames=['result']  # success|error
)

# Build info metric
build_info = Gauge(
    'cm_build_info',
    'Build information',
    labelnames=['version', 'environment']
)

# Per-alert breakdown metrics (careful with cardinality in large deployments)
alert_webhook_attempts_by_alert_total = Counter(
    'cm_alert_webhook_attempts_by_alert_total',
    'Alert webhook attempts by agent/alert and result',
    labelnames=['agent_id', 'alert_id', 'result']  # success | error | blocked
)

alert_webhook_duration_by_alert_seconds = Histogram(
    'cm_alert_webhook_duration_by_alert_seconds',
    'Alert webhook duration by agent/alert',
    labelnames=['agent_id', 'alert_id']
)
