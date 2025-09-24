import os
import time
from datetime import datetime
import requests
from flask import Flask, render_template, request, redirect, url_for, Response, stream_with_context, jsonify, session, g
from models import Agent, SessionLocal, init_db, apply_migrations, new_agent_id, Credential, Alert, AlertEvent, User, AlertCooldown
from security import encrypt_dict, decrypt_dict
from orchestrator import orchestrator
from services.env_builder import build_agent_env
from services.config_validation import validate_config, ensure_object
from services.alerts_scheduler import start_scheduler, parse_prom_metrics
from services.webhook_security import is_webhook_allowed, build_hmac_headers
from werkzeug.security import check_password_hash, generate_password_hash
from typing import Optional
from services.metrics import (
    http_requests_total,
    http_request_latency_seconds,
    alert_webhook_attempts_total,
    alert_webhook_duration_seconds,
    app_live,
    app_ready,
    orchestrator_actions_total,
    orchestrator_status_checks_total,
    build_info,
    alert_webhook_attempts_by_alert_total,
    alert_webhook_duration_by_alert_seconds,
    generate_latest,
    CONTENT_TYPE_LATEST,
)
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

app = Flask(__name__)

# Initialize database
init_db()
apply_migrations()

# App secret (required for sessions/CSRF). In production, set FLASK_SECRET.
app.secret_key = os.getenv('FLASK_SECRET', 'dev-secret-change-me')
# Cookie and request security defaults (override via env if needed)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Strict')
app.config['SESSION_COOKIE_SECURE'] = (os.getenv('SESSION_COOKIE_SECURE', '1') not in ('0','false','no'))
try:
    mbl = int(os.getenv('MAX_CONTENT_LENGTH_MB', '2'))
    app.config['MAX_CONTENT_LENGTH'] = max(1, mbl) * 1024 * 1024
except Exception:
    app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

# Sentry (optional)
_sentry_dsn = os.getenv('SENTRY_DSN')
if _sentry_dsn:
    try:
        sentry_sdk.init(
            dsn=_sentry_dsn,
            integrations=[FlaskIntegration()],
            traces_sample_rate=float(os.getenv('SENTRY_TRACES_SAMPLE_RATE', '0.0') or '0.0'),
            environment=os.getenv('SENTRY_ENVIRONMENT', 'production'),
        )
    except Exception:
        pass

# Start background alerts scheduler (idempotent)
try:
    start_scheduler()
except Exception:
    pass
try:
    app_live.set(1)
    app_ready.set(1)
    # Set build info gauge (1)
    _app_version = os.getenv('APP_VERSION', 'dev')
    _app_env = os.getenv('APP_ENV', os.getenv('SENTRY_ENVIRONMENT', 'production'))
    try:
        build_info.labels(version=_app_version, environment=_app_env).set(1)
    except Exception:
        pass
except Exception:
    pass


def _get_csrf_token() -> str:
    try:
        tok = session.get('csrf_token')
    except Exception:
        tok = None
    if not tok:
        try:
            import secrets
            tok = secrets.token_hex(16)
        except Exception:
            tok = str(time.time())
        session['csrf_token'] = tok
    return tok


@app.context_processor
def inject_csrf():
    # Allows templates to use {{ csrf_token() }} to get the token value
    return {'csrf_token': _get_csrf_token}


@app.after_request
def _set_security_headers(resp: Response):
    try:
        # Basic sane defaults; customize CSP as needed
        resp.headers.setdefault('X-Frame-Options', 'DENY')
        resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
        resp.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
        if (os.getenv('ENABLE_STRICT_CSP', '0') in ('1','true')):
            resp.headers.setdefault('Content-Security-Policy', "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https:; script-src 'self' 'unsafe-inline' https:; connect-src 'self' https: http:")
        # Only set HSTS if behind https
        if request.is_secure and os.getenv('ENABLE_HSTS', '1') not in ('0','false','no'):
            resp.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    except Exception:
        pass
    return resp


# Prometheus HTTP metrics middleware
@app.before_request
def _metrics_start():
    try:
        g._start_ts = time.monotonic()
    except Exception:
        g._start_ts = None


@app.after_request
def _metrics_end(resp: Response):
    try:
        method = (request.method or 'GET').upper()
        endpoint = request.endpoint or (request.path or 'unknown')
        status = getattr(resp, 'status_code', 200)
        http_requests_total.labels(method=method, endpoint=endpoint, status=str(status)).inc()
        st = getattr(g, '_start_ts', None)
        if st is not None:
            dt = max(0.0, time.monotonic() - st)
            http_request_latency_seconds.labels(method=method, endpoint=endpoint).observe(dt)
    except Exception:
        pass
    return resp


@app.route('/metrics')
def app_metrics():
    try:
        data = generate_latest()
        return Response(data, mimetype=CONTENT_TYPE_LATEST)
    except Exception as e:
        return Response(f"metrics error: {e}", status=500)


@app.route('/healthz')
def healthz():
    try:
        app_live.set(1)
    except Exception:
        pass
    return jsonify({"live": True}), 200


@app.route('/readyz')
def readyz():
    try:
        app_ready.set(1)
    except Exception:
        pass
    return jsonify({"ready": True}), 200


@app.route('/version')
def version_info():
    return jsonify({
        "version": os.getenv('APP_VERSION', 'dev'),
        "environment": os.getenv('APP_ENV', os.getenv('SENTRY_ENVIRONMENT', 'production'))
    })


def _is_admin() -> bool:
    try:
        return (session.get('user_role') == 'admin')
    except Exception:
        return False


def _current_user() -> Optional[User]:
    try:
        uid = session.get('user_id')
        if not uid:
            return None
        db = SessionLocal()
        try:
            return db.get(User, uid)
        finally:
            db.close()
    except Exception:
        return None


def _wants_json() -> bool:
    p = request.path or ''
    if p.endswith('.json') or p.endswith('.txt'):
        return True
    accept = request.headers.get('Accept', '')
    return 'application/json' in (accept or '')


@app.before_request
def _guard_routes():
    p = request.path or ''
    # Skip CSRF/auth checks for static and login page
    if p.startswith('/static'):
        return
    # CSRF: verify for POST (except login, because token is injected there too but allow bootstrap)
    if request.method == 'POST' and p != '/login':
        token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        if not token or token != session.get('csrf_token'):
            if _wants_json():
                return jsonify({'error': 'csrf validation failed'}), 400
            return 'CSRF validation failed', 400
    # Admin area requires admin
    if p.startswith('/admin') and p not in ('/login',):
        if not _is_admin():
            if _wants_json():
                return jsonify({'error': 'auth required'}), 401
            nxt = request.url
            return redirect(url_for('login', next=nxt))
    # Mutating agent routes require admin (POST under /agents, /credentials, /alerts)
    if request.method == 'POST' and (p.startswith('/agents') or p.startswith('/credentials') or p.startswith('/alerts')):
        if not _is_admin():
            if _wants_json():
                return jsonify({'error': 'auth required'}), 401
            nxt = request.url
            return redirect(url_for('login', next=nxt))


def _ensure_initial_admin():
    db = SessionLocal()
    try:
        first_user = db.query(User).first()
        if not first_user:
            email = (os.getenv('ADMIN_EMAIL') or '').strip().lower()
            pwd_hash = os.getenv('ADMIN_PASSWORD_HASH')
            pwd = os.getenv('ADMIN_PASSWORD', 'admin')
            if email:
                if not pwd_hash:
                    try:
                        pwd_hash = generate_password_hash(pwd)
                    except Exception:
                        return
                u = User(id=new_agent_id(), email=email, password_hash=pwd_hash, role='admin')
                db.add(u)
                db.commit()
    finally:
        db.close()


_ensure_initial_admin()


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        pwd = request.form.get('password', '')
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.email == email).first()
        finally:
            db.close()
        if user and check_password_hash(user.password_hash, pwd):
            session['user_id'] = user.id
            session['user_role'] = user.role
            _get_csrf_token()  # ensure token exists
            nxt = request.args.get('next') or url_for('admin_index')
            return redirect(nxt)
        else:
            error = 'Invalid email or password'
    return render_template('login.html', error=error)


@app.route('/logout', methods=['POST'])
def logout():
    try:
        session.pop('user_id', None)
        session.pop('user_role', None)
    except Exception:
        pass
    return redirect(url_for('home'))

@app.route('/')
def home():
    # Provide a lightweight preview of recent agents for the homepage
    db = SessionLocal()
    try:
        agents = db.query(Agent).order_by(Agent.created_at.desc()).limit(6).all()
    finally:
        db.close()
    runtime_status_map = {}
    try:
        for a in agents:
            try:
                runtime_status_map[a.id] = orchestrator.status(a.id)
                orchestrator_status_checks_total.labels(result='success').inc()
            except Exception:
                orchestrator_status_checks_total.labels(result='error').inc()
                raise
    except Exception:
        runtime_status_map = {a.id: a.status for a in agents}
    return render_template('index.html', agents=agents, runtime_status_map=runtime_status_map)

@app.route('/about')
def about():
    return render_template('about.html')


# Admin dashboard
@app.route('/admin')
def admin_index():
    backend = os.getenv('ORCHESTRATOR', 'memory').lower()
    agent_image = os.getenv('AGENT_IMAGE', '')
    db = SessionLocal()
    try:
        agents = db.query(Agent).order_by(Agent.created_at.desc()).all()
    finally:
        db.close()
    runtime = {}
    ports = {}
    rimages = {}
    for a in agents:
        try:
            try:
                runtime[a.id] = orchestrator.status(a.id)
                orchestrator_status_checks_total.labels(result='success').inc()
            except Exception:
                orchestrator_status_checks_total.labels(result='error').inc()
                raise
            ports[a.id] = orchestrator.host_port(a.id)
        except Exception:
            runtime[a.id] = a.status
            ports[a.id] = None
        # Pull runner_image from config
        try:
            import json as _json
            cfg = _json.loads(a.config or '{}')
            if isinstance(cfg, dict):
                ri = cfg.get('runner_image')
                if ri:
                    rimages[a.id] = str(ri)
        except Exception:
            pass
    return render_template('admin/index.html', backend=backend, agent_image=agent_image, agents=agents, runtime=runtime, ports=ports, rimages=rimages)


@app.route('/admin/observability')
def admin_observability():
    version = os.getenv('APP_VERSION', 'dev')
    environment = os.getenv('APP_ENV', os.getenv('SENTRY_ENVIRONMENT', 'production'))
    sentry_enabled = bool(os.getenv('SENTRY_DSN'))
    return render_template('admin/observability.html', version=version, environment=environment, sentry_enabled=sentry_enabled)


@app.route('/admin/docker.json')
def admin_docker_info():
    backend = os.getenv('ORCHESTRATOR', 'memory').lower()
    out = {"backend": backend, "containers": []}
    try:
        import docker  # type: ignore
        client = docker.from_env()
        for c in client.containers.list(all=True):
            name = (c.name or '')
            if not name.startswith('agent-'):
                continue
            try:
                c.reload()
                ports = c.attrs.get('NetworkSettings', {}).get('Ports', {})
                # Best-effort resource stats
                cpu_percent = None
                mem_usage = None
                mem_limit = None
                mem_percent = None
                try:
                    stats = c.stats(stream=False)
                    cpu_stats = stats.get('cpu_stats', {})
                    precpu = stats.get('precpu_stats', {})
                    cpu_delta = float(cpu_stats.get('cpu_usage', {}).get('total_usage', 0)) - float(precpu.get('cpu_usage', {}).get('total_usage', 0))
                    system_delta = float(cpu_stats.get('system_cpu_usage', 0)) - float(precpu.get('system_cpu_usage', 0))
                    num_cpus = int(cpu_stats.get('online_cpus') or len(cpu_stats.get('cpu_usage', {}).get('percpu_usage', []) or [1]) or 1)
                    if system_delta > 0 and cpu_delta > 0:
                        cpu_percent = (cpu_delta / system_delta) * num_cpus * 100.0
                    mem = stats.get('memory_stats', {})
                    mem_usage = float(mem.get('usage') or 0.0)
                    mem_limit = float(mem.get('limit') or 0.0)
                    if mem_limit > 0:
                        mem_percent = (mem_usage / mem_limit) * 100.0
                except Exception:
                    pass
            except Exception:
                ports = {}
            out['containers'].append({
                'id': c.id[:12],
                'name': name,
                'status': c.status,
                'image': getattr(c.image, 'tags', [''])[0] if getattr(c, 'image', None) else '',
                'ports': ports,
                'cpu_percent': cpu_percent,
                'mem_usage': mem_usage,
                'mem_limit': mem_limit,
                'mem_percent': mem_percent,
            })
    except Exception as e:
        out['error'] = str(e)
    return jsonify(out)


@app.route('/admin/agents/<agent_id>/env.json')
def admin_agent_env(agent_id: str):
    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        if not agent:
            return jsonify({"error": "agent not found"}), 404
        # Build full env then redact below
        env = build_agent_env(db, agent, include_secrets=True)
        # Redact secrets by default unless explicitly revealed
        reveal = (request.args.get('reveal') == '1')
        if not reveal:
            def _mask(v: str) -> str:
                if not v:
                    return ''
                try:
                    s = str(v)
                except Exception:
                    return '***'
                if len(s) <= 6:
                    return '*' * len(s)
                return s[:2] + '***' + s[-4:]
            # Mask CEX secrets
            for k in ("CEX_API_KEY", "CEX_API_SECRET", "CEX_API_PASSPHRASE"):
                if k in env and env.get(k):
                    env[k] = _mask(env.get(k))
            # Replace EVM RPC list with a redacted summary
            if 'EVM_RPC_URLS' in env:
                try:
                    import json as _json
                    urls = _json.loads(env['EVM_RPC_URLS'])
                    env['EVM_RPC_URLS'] = f"[{len(urls)} urls redacted]"
                except Exception:
                    env['EVM_RPC_URLS'] = "[redacted]"
        return jsonify({"agent_id": agent_id, "env": env, "redacted": (not reveal)})
    finally:
        db.close()

@app.route('/admin/containers/<name>/logs')
def admin_container_logs(name: str):
    # Only allow viewing logs for agent-* containers
    if not name.startswith('agent-'):
        return jsonify({"error": "invalid container name"}), 400
    try:
        import docker  # type: ignore
        client = docker.from_env()
        c = client.containers.get(name)
        n = int(request.args.get('lines', '200') or '200')
        raw = c.logs(tail=n)
        txt = raw.decode('utf-8', errors='ignore') if isinstance(raw, (bytes, bytearray)) else str(raw)
        return jsonify({"name": name, "lines": n, "logs": txt})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/admin/containers/<name>/logs/stream')
def admin_container_logs_stream(name: str):
    # SSE tail logs for a given container (admin-only)
    if not name.startswith('agent-'):
        return jsonify({"error": "invalid container name"}), 400
    backend = os.getenv('ORCHESTRATOR', 'memory').lower()
    if backend != 'docker':
        return jsonify({"error": "stream unavailable"}), 400
    try:
        import docker  # type: ignore
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    def event_stream():
        yield 'retry: 2000\n\n'
        try:
            client = docker.from_env()
            c = client.containers.get(name)
            # Tail last N lines then follow
            n = int(request.args.get('lines', '200') or '200')
            for chunk in c.logs(stream=True, follow=True, tail=n):
                try:
                    line = chunk.decode('utf-8', errors='ignore')
                except Exception:
                    line = str(chunk)
                # Ensure each line is a separate event
                for ln in line.splitlines():
                    yield f'data: {ln}\n\n'
        except Exception as e:
            yield f'data: [stream error] {str(e)}\n\n'

    return Response(stream_with_context(event_stream()), mimetype='text/event-stream')

@app.route('/admin/agents/start_all', methods=['POST'])
def admin_start_all():
    db = SessionLocal()
    try:
        agents = db.query(Agent).all()
        for agent in agents:
            env = build_agent_env(db, agent, include_secrets=True)
            try:
                orchestrator.start(agent.id, env=env)
                orchestrator_actions_total.labels(action='start', result='success').inc()
            except Exception:
                orchestrator_actions_total.labels(action='start', result='error').inc()
                pass
            agent.status = 'running'
            db.add(agent)
        db.commit()
    finally:
        db.close()
    return redirect(url_for('admin_index'))


# Admin: set per-agent runner image (stores under agent.config.runner_image)
@app.route('/admin/agents/<agent_id>/runner_image', methods=['POST'])
def admin_set_runner_image(agent_id: str):
    runner_image = (request.form.get('runner_image') or '').strip()
    redeploy = (request.form.get('redeploy') == '1')
    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        if not agent:
            return redirect(url_for('admin_index'))
        # Update config JSON
        cfg = {}
        if agent.config:
            try:
                import json as _json
                cfg = _json.loads(agent.config)
                if not isinstance(cfg, dict):
                    cfg = {}
            except Exception:
                cfg = {}
        if runner_image:
            cfg['runner_image'] = runner_image
        else:
            cfg.pop('runner_image', None)
        try:
            import json as _json
            agent.config = _json.dumps(cfg)
        except Exception:
            pass
        db.add(agent)
        db.commit()
    finally:
        db.close()
    if redeploy:
        # Recreate container using existing env builder
        return redirect(url_for('agents_redeploy', agent_id=agent_id))
    return redirect(url_for('admin_index'))


@app.route('/admin/agents/restart_all', methods=['POST'])
def admin_restart_all():
    db = SessionLocal()
    try:
        agents = db.query(Agent).all()
        from security import decrypt_dict as _dec
        import json as _json
        for agent in agents:
            # Stop without failing the loop
            try:
                orchestrator.stop(agent.id)
                orchestrator_actions_total.labels(action='stop', result='success').inc()
            except Exception:
                orchestrator_actions_total.labels(action='stop', result='error').inc()
                pass
            env = build_agent_env(db, agent, include_secrets=True)
            try:
                orchestrator.start(agent.id, env=env)
                orchestrator_actions_total.labels(action='start', result='success').inc()
            except Exception:
                orchestrator_actions_total.labels(action='start', result='error').inc()
                pass
            agent.status = 'running'
            db.add(agent)
        db.commit()
    finally:
        db.close()
    return redirect(url_for('admin_index'))


@app.route('/admin/agents/stop_all', methods=['POST'])
def admin_stop_all():
    db = SessionLocal()
    try:
        agents = db.query(Agent).all()
        for agent in agents:
            try:
                orchestrator.stop(agent.id)
                orchestrator_actions_total.labels(action='stop', result='success').inc()
            except Exception:
                orchestrator_actions_total.labels(action='stop', result='error').inc()
                pass
            agent.status = 'stopped'
            db.add(agent)
        db.commit()
    finally:
        db.close()
    return redirect(url_for('admin_index'))


@app.route('/admin/agents/redeploy_all', methods=['POST'])
def admin_redeploy_all():
    db = SessionLocal()
    try:
        agents = db.query(Agent).all()
        from security import decrypt_dict as _dec
        import json as _json
        for agent in agents:
            env = build_agent_env(db, agent, include_secrets=True)
            try:
                orchestrator.delete(agent.id)
                orchestrator_actions_total.labels(action='delete', result='success').inc()
            except Exception:
                orchestrator_actions_total.labels(action='delete', result='error').inc()
                pass
            try:
                orchestrator.start(agent.id, env=env)
                orchestrator_actions_total.labels(action='start', result='success').inc()
            except Exception:
                orchestrator_actions_total.labels(action='start', result='error').inc()
                pass
            agent.status = 'running'
            db.add(agent)
        db.commit()
    finally:
        db.close()
    return redirect(url_for('admin_index'))


# Agents: list
@app.route('/agents')
def agents_index():
    db = SessionLocal()
    try:
        agents = db.query(Agent).order_by(Agent.created_at.desc()).all()
    finally:
        db.close()
    # Derive runtime status for each agent (orchestrator-backed)
    runtime_status_map = {}
    try:
        for a in agents:
            runtime_status_map[a.id] = orchestrator.status(a.id)
            orchestrator_status_checks_total.labels(result='success').inc()
    except Exception:
        runtime_status_map = {a.id: a.status for a in agents}
        orchestrator_status_checks_total.labels(result='error').inc()
    return render_template('agents/index.html', agents=agents, runtime_status_map=runtime_status_map)


# Agents: new form
@app.route('/agents/new')
def agents_new():
    return render_template('agents/new.html')


# Agents: create
@app.route('/agents', methods=['POST'])
def agents_create():
    name = request.form.get('name', '').strip()
    strategy = request.form.get('strategy', 'custom')
    config = request.form.get('config', '')
    exchange = (request.form.get('exchange') or '').strip()
    runner_image = (request.form.get('runner_image') or '').strip()

    if not name:
        return redirect(url_for('agents_new'))
    # Parse config JSON (object) and merge optionals
    cfg = ensure_object(config)
    if exchange:
        cfg['exchange'] = exchange
    if runner_image:
        cfg['runner_image'] = runner_image
    try:
        import json as _json
        config = _json.dumps(cfg)
    except Exception:
        pass

    # Validate against strategy schema
    ok, errs = validate_config(strategy, cfg)
    if not ok:
        return render_template('agents/new.html', error_msg='\n'.join(errs), name=name, strategy=strategy, config=config, exchange=exchange)

    db = SessionLocal()
    try:
        agent = Agent(id=new_agent_id(), name=name, strategy=strategy, status='stopped', config=config)
        db.add(agent)
        db.commit()
        return redirect(url_for('agents_show', agent_id=agent.id))
    finally:
        db.close()


# Agents: show
@app.route('/agents/<agent_id>')
def agents_show(agent_id: str):
    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        credentials = db.query(Credential).filter(Credential.agent_id == agent_id).all()
        alerts = db.query(Alert).filter(Alert.agent_id == agent_id).order_by(Alert.created_at.desc()).all()
        events = db.query(AlertEvent).filter(AlertEvent.agent_id == agent_id).order_by(AlertEvent.fired_at.desc()).limit(50).all()
    finally:
        db.close()
    if not agent:
        return redirect(url_for('agents_index'))
    try:
        runtime_status = orchestrator.status(agent_id)
        orchestrator_status_checks_total.labels(result='success').inc()
    except Exception:
        orchestrator_status_checks_total.labels(result='error').inc()
        runtime_status = 'unknown'
    # published port for runner endpoints (docker backend only)
    host_port = orchestrator.host_port(agent_id) if os.getenv('ORCHESTRATOR', 'memory').lower() == 'docker' else None
    # parse exchange/runner_image from config JSON
    exchange_val = ''
    runner_image_val = ''
    if agent and agent.config:
        try:
            import json as _json
            cfg = _json.loads(agent.config)
            if isinstance(cfg, dict):
                exchange_val = str(cfg.get('exchange') or '')
                runner_image_val = str(cfg.get('runner_image') or '')
        except Exception:
            exchange_val = ''
            runner_image_val = ''
    # Build map for template
    alert_name_map = {a.id: a.name for a in alerts}
    return render_template('agents/show.html', agent=agent, runtime_status=runtime_status, credentials=credentials, alerts=alerts, alert_events=events, alert_name_map=alert_name_map, host_port=host_port, exchange_val=exchange_val, runner_image_val=runner_image_val)


# Agents: update (strategy/config) and optional redeploy
@app.route('/agents/<agent_id>/update', methods=['POST'])
def agents_update(agent_id: str):
    strategy = request.form.get('strategy', 'custom')
    config = request.form.get('config', '')
    new_name = (request.form.get('name') or '').strip()
    exchange = (request.form.get('exchange') or '').strip()
    runner_image = (request.form.get('runner_image') or '').strip()
    redeploy = request.form.get('redeploy') == '1'
    # Validate config JSON if provided
    if config:
        import json as _json
        try:
            _json.loads(config)
        except Exception:
            # Re-render show page with error and without mutating DB
            dbv = SessionLocal()
            try:
                agentv = dbv.get(Agent, agent_id)
                credsv = dbv.query(Credential).filter(Credential.agent_id == agent_id).all()
            finally:
                dbv.close()
            if not agentv:
                return redirect(url_for('agents_index'))
            try:
                runtime_status = orchestrator.status(agent_id)
                orchestrator_status_checks_total.labels(result='success').inc()
            except Exception:
                orchestrator_status_checks_total.labels(result='error').inc()
                runtime_status = 'unknown'
            host_port = orchestrator.host_port(agent_id) if os.getenv('ORCHESTRATOR', 'memory').lower() == 'docker' else None
            # compute exchange_val/runner_image_val from posted values or invalid config best-effort
            exchange_val = exchange or ''
            runner_image_val = runner_image or ''
            if not exchange_val:
                try:
                    cfg_try = _json.loads(config)
                    if isinstance(cfg_try, dict):
                        exchange_val = str(cfg_try.get('exchange') or '')
                except Exception:
                    exchange_val = ''
            if not runner_image_val:
                try:
                    cfg_try = _json.loads(config)
                    if isinstance(cfg_try, dict):
                        runner_image_val = str(cfg_try.get('runner_image') or '')
                except Exception:
                    runner_image_val = ''
            return render_template('agents/show.html', agent=agentv, runtime_status=runtime_status, credentials=credsv, host_port=host_port, error_msg='Invalid JSON in config. Please provide valid JSON.', exchange_val=exchange_val, runner_image_val=runner_image_val)
    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        if not agent:
            return redirect(url_for('agents_index'))
        # Merge exchange/runner_image into config JSON
        merged_config = {}
        if config:
            import json as _json
            try:
                merged_config = _json.loads(config)
                if not isinstance(merged_config, dict):
                    merged_config = {}
            except Exception:
                merged_config = {}
        if exchange:
            merged_config['exchange'] = exchange
        else:
            merged_config.pop('exchange', None)
        if runner_image:
            merged_config['runner_image'] = runner_image
        else:
            merged_config.pop('runner_image', None)
        # Schema validation before mutating DB
        ok, errs = validate_config(strategy, merged_config)
        if not ok:
            # Re-render show page with validation errors
            credsv = db.query(Credential).filter(Credential.agent_id == agent_id).all()
            runtime_status = orchestrator.status(agent_id)
            host_port = orchestrator.host_port(agent_id) if os.getenv('ORCHESTRATOR', 'memory').lower() == 'docker' else None
            exchange_val = merged_config.get('exchange') or ''
            runner_image_val = merged_config.get('runner_image') or ''
            return render_template('agents/show.html', agent=agent, runtime_status=runtime_status, credentials=credsv, host_port=host_port, error_msg='\n'.join(errs), exchange_val=exchange_val, runner_image_val=runner_image_val)
        # Passed validation, update record
        if new_name:
            agent.name = new_name
        agent.strategy = strategy
        try:
            import json as _json
            agent.config = _json.dumps(merged_config)
        except Exception:
            agent.config = config
        db.add(agent)
        db.commit()
    finally:
        db.close()
    if redeploy:
        # Build env and redeploy inline (avoid POST redirect)
        db2 = SessionLocal()
        try:
            agent2 = db2.get(Agent, agent_id)
            if agent2:
                env = build_agent_env(db2, agent2, include_secrets=True)
                # restart
                try:
                    orchestrator.delete(agent_id)
                    orchestrator_actions_total.labels(action='delete', result='success').inc()
                except Exception:
                    orchestrator_actions_total.labels(action='delete', result='error').inc()
                    pass
                try:
                    orchestrator.start(agent_id, env=env)
                    orchestrator_actions_total.labels(action='start', result='success').inc()
                except Exception:
                    orchestrator_actions_total.labels(action='start', result='error').inc()
                    pass
                agent2.status = 'running'
                db2.add(agent2)
                db2.commit()
        finally:
            db2.close()
        return redirect(url_for('agents_show', agent_id=agent_id))


# Alerts: toggle enabled
@app.route('/agents/<agent_id>/alerts/<alert_id>/toggle', methods=['POST'])
def alerts_toggle(agent_id: str, alert_id: str):
    db = SessionLocal()
    try:
        alert = db.get(Alert, alert_id)
        if alert and alert.agent_id == agent_id:
            alert.enabled = not bool(alert.enabled)
            db.add(alert)
            db.commit()
    finally:
        db.close()
    return redirect(url_for('agents_show', agent_id=agent_id))


# Agents: purge runner state (docker backend only) - removes container and volume; keeps Agent record
@app.route('/agents/<agent_id>/purge', methods=['POST'])
def agents_purge(agent_id: str):
    backend = os.getenv('ORCHESTRATOR', 'memory').lower()
    # Remove container via orchestrator
    try:
        orchestrator.delete(agent_id)
        orchestrator_actions_total.labels(action='delete', result='success').inc()
    except Exception:
        orchestrator_actions_total.labels(action='delete', result='error').inc()
        pass
    # If docker, also remove volume used for /data
    if backend == 'docker':
        try:
            import docker  # type: ignore
            client = docker.from_env()
            # Try common volume names
            vol_names = []
            # Prefer using orchestrator volume prefix if available
            try:
                prefix = getattr(orchestrator, '_volume_prefix', 'agent-')
            except Exception:
                prefix = 'agent-'
            vol_names.append(f"{prefix}{agent_id}-data")
            for vn in vol_names:
                try:
                    v = client.volumes.get(vn)
                    v.remove(force=True)
                except Exception:
                    pass
        except Exception:
            pass
    # Mark as stopped
    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        if agent:
            agent.status = 'stopped'
            db.add(agent)
            db.commit()
    finally:
        db.close()
    return redirect(url_for('agents_show', agent_id=agent_id))


# Agents: restart (stop then start)
@app.route('/agents/<agent_id>/restart', methods=['POST'])
def agents_restart(agent_id: str):
    # Stop first (best-effort)
    try:
        orchestrator.stop(agent_id)
        orchestrator_actions_total.labels(action='stop', result='success').inc()
    except Exception:
        orchestrator_actions_total.labels(action='stop', result='error').inc()
        pass
    # Build env and start
    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        if agent:
            env = build_agent_env(db, agent, include_secrets=True)
            try:
                orchestrator.start(agent_id, env=env)
                orchestrator_actions_total.labels(action='start', result='success').inc()
            except Exception:
                orchestrator_actions_total.labels(action='start', result='error').inc()
                raise
            agent.status = 'running'
            db.add(agent)
            db.commit()
    finally:
        db.close()
    return redirect(url_for('agents_show', agent_id=agent_id))
# Agents: start (stub)
@app.route('/agents/<agent_id>/start', methods=['POST'])
def agents_start(agent_id: str):
    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        if agent:
            # Update runtime orchestrator and persist desired state
            env = build_agent_env(db, agent, include_secrets=True)
            try:
                orchestrator.start(agent_id, env=env)
                orchestrator_actions_total.labels(action='start', result='success').inc()
            except Exception:
                orchestrator_actions_total.labels(action='start', result='error').inc()
                raise
            agent.status = 'running'
            db.add(agent)
            db.commit()
    finally:
        db.close()
    return redirect(url_for('agents_show', agent_id=agent_id))


# Credentials: edit form
@app.route('/agents/<agent_id>/credentials/<cred_id>/edit')
def credentials_edit(agent_id: str, cred_id: str):
    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        cred = db.get(Credential, cred_id)
    finally:
        db.close()
    if not agent or not cred or cred.agent_id != agent_id:
        return redirect(url_for('agents_index'))
    # decrypt for prefilling
    try:
        data = decrypt_dict(cred.data_encrypted)
    except Exception:
        data = {}
    return render_template('agents/credentials_edit.html', agent=agent, cred=cred, data=data)


# Credentials: update
@app.route('/agents/<agent_id>/credentials/<cred_id>', methods=['POST'])
def credentials_update(agent_id: str, cred_id: str):
    name = (request.form.get('name') or 'default').strip()
    db = SessionLocal()
    try:
        cred = db.get(Credential, cred_id)
        if not cred or cred.agent_id != agent_id:
            return redirect(url_for('agents_show', agent_id=agent_id))
        if cred.ctype == 'evm_rpc':
            raw = request.form.get('urls', '')
            parts = [p.strip() for p in raw.replace(',', '\n').split('\n') if p.strip()]
            data = {"urls": parts}
        elif cred.ctype == 'cex':
            data = {
                "exchange": request.form.get('exchange', '').strip(),
                "api_key": request.form.get('api_key', '').strip(),
                "api_secret": request.form.get('api_secret', '').strip(),
                "passphrase": request.form.get('passphrase', '').strip(),
            }
        else:
            return redirect(url_for('agents_show', agent_id=agent_id))
        cred.name = name
        cred.data_encrypted = encrypt_dict(data)
        db.add(cred)
        db.commit()
    finally:
        db.close()
    return redirect(url_for('agents_show', agent_id=agent_id))


# Agents: redeploy (recreate container with latest env)
@app.route('/agents/<agent_id>/redeploy', methods=['POST'])
def agents_redeploy(agent_id: str):
    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        if agent:
            env = build_agent_env(db, agent, include_secrets=True)

            # Recreate runtime
            try:
                orchestrator.delete(agent_id)
                orchestrator_actions_total.labels(action='delete', result='success').inc()
            except Exception:
                orchestrator_actions_total.labels(action='delete', result='error').inc()
                raise
            try:
                orchestrator.start(agent_id, env=env)
                orchestrator_actions_total.labels(action='start', result='success').inc()
            except Exception:
                orchestrator_actions_total.labels(action='start', result='error').inc()
                raise
            agent.status = 'running'
            db.add(agent)
            db.commit()
    finally:
        db.close()
    return redirect(url_for('agents_show', agent_id=agent_id))


# Credentials: new form
@app.route('/agents/<agent_id>/credentials/new')
def credentials_new(agent_id: str):
    ctype = request.args.get('type', 'evm_rpc')
    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
    finally:
        db.close()
    if not agent:
        return redirect(url_for('agents_index'))
    return render_template('agents/credentials_new.html', agent=agent, ctype=ctype)


# Credentials: create
@app.route('/agents/<agent_id>/credentials', methods=['POST'])
def credentials_create(agent_id: str):
    ctype = request.form.get('ctype', 'evm_rpc')
    name = (request.form.get('name') or 'default').strip()
    data = {}
    if ctype == 'evm_rpc':
        # Textarea can be newline or comma separated
        raw = request.form.get('urls', '')
        parts = [p.strip() for p in raw.replace(',', '\n').split('\n') if p.strip()]
        data = {"urls": parts}
    elif ctype == 'cex':
        data = {
            "exchange": request.form.get('exchange', '').strip(),
            "api_key": request.form.get('api_key', '').strip(),
            "api_secret": request.form.get('api_secret', '').strip(),
            "passphrase": request.form.get('passphrase', '').strip(),
        }
    else:
        return redirect(url_for('credentials_new', agent_id=agent_id, type=ctype))

    enc = encrypt_dict(data)
    db = SessionLocal()
    try:
        cred = Credential(id=new_agent_id(), agent_id=agent_id, ctype=ctype, name=name, data_encrypted=enc)
        db.add(cred)
        db.commit()
    finally:
        db.close()
    return redirect(url_for('agents_show', agent_id=agent_id))


# Credentials: delete
@app.route('/agents/<agent_id>/credentials/<cred_id>/delete', methods=['POST'])
def credentials_delete(agent_id: str, cred_id: str):
    db = SessionLocal()
    try:
        cred = db.get(Credential, cred_id)
        if cred and cred.agent_id == agent_id:
            db.delete(cred)
            db.commit()
    finally:
        db.close()
    return redirect(url_for('agents_show', agent_id=agent_id))


# Agents: stop (stub)
@app.route('/agents/<agent_id>/stop', methods=['POST'])
def agents_stop(agent_id: str):
    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        if agent:
            # Update runtime orchestrator and persist desired state
            try:
                orchestrator.stop(agent_id)
                orchestrator_actions_total.labels(action='stop', result='success').inc()
            except Exception:
                orchestrator_actions_total.labels(action='stop', result='error').inc()
                raise
            agent.status = 'stopped'
            db.add(agent)
            db.commit()
    finally:
        db.close()
    return redirect(url_for('agents_show', agent_id=agent_id))


# Agents: delete
@app.route('/agents/<agent_id>/delete', methods=['POST'])
def agents_delete(agent_id: str):
    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        if agent:
            orchestrator.delete(agent_id)
            orchestrator_actions_total.labels(action='delete', result='success').inc()
            db.delete(agent)
            db.commit()
    finally:
        db.close()
    return redirect(url_for('agents_index'))


# Logs: SSE streaming (Docker backend only)
@app.route('/agents/<agent_id>/logs/stream')
def agents_logs_stream(agent_id: str):
    backend = os.getenv('ORCHESTRATOR', 'memory').lower()
    if backend != 'docker':
        def _no_logs():
            yield 'data: Logs not available with current orchestrator (memory)\n\n'
            time.sleep(0.5)
        return Response(stream_with_context(_no_logs()), mimetype='text/event-stream', headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
        })

    def generate():
        try:
            import docker  # type: ignore
        except Exception:
            yield 'data: Docker SDK not available on server\n\n'
            return
        client = docker.from_env()
        name = f"agent-{agent_id}"
        try:
            container = client.containers.get(name)
        except Exception:
            yield f'data: Container {name} not found\n\n'
            return
        try:
            # Tail last 100 lines then follow
            for line in container.logs(stream=True, follow=True, tail=100):
                try:
                    txt = line.decode('utf-8', errors='ignore').rstrip('\n')
                except Exception:
                    txt = str(line)
                yield f'data: {txt}\n\n'
        except Exception as e:
            yield f'data: log stream error: {e}\n\n'

    return Response(stream_with_context(generate()), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',
    })


# Read generated address from container volume via Docker exec
@app.route('/agents/<agent_id>/address.json')
def agents_address(agent_id: str):
    backend = os.getenv('ORCHESTRATOR', 'memory').lower()
    if backend != 'docker':
        return jsonify({"error": "address unavailable"}), 404
    try:
        import docker  # type: ignore
        import json as _json
    except Exception:
        return jsonify({"error": "docker sdk unavailable"}), 500
    client = docker.from_env()
    name = f"agent-{agent_id}"
    try:
        container = client.containers.get(name)
    except Exception:
        return jsonify({"error": "container not found"}), 404

    try:
        # cat the JSON file inside container
        exec_res = container.exec_run("cat /data/agent_key.json", stdout=True, stderr=False)
        out = exec_res.output.decode('utf-8', errors='ignore') if hasattr(exec_res, 'output') else str(exec_res)
        data = _json.loads(out)
        addr = data.get('address')
        if addr:
            return jsonify({"address": addr, "type": data.get('type', 'evm')})
        return jsonify({"error": "address not found"}), 404
    except Exception:
        return jsonify({"error": "address not ready"}), 404


@app.route('/agents/<agent_id>/wallet.json')
def agents_wallet(agent_id: str):
    # Proxy to the runner's /wallet using published host port if available
    backend = os.getenv('ORCHESTRATOR', 'memory').lower()
    if backend != 'docker':
        return jsonify({"error": "wallet unavailable"}), 404
    port = orchestrator.host_port(agent_id)
    if not port:
        return jsonify({"error": "runner port unknown"}), 404
    try:
        resp = requests.get(f'http://127.0.0.1:{port}/wallet', timeout=12)
        return jsonify(resp.json()), resp.status_code
    except Exception:
        return jsonify({"error": "runner not reachable"}), 502


# Positions proxy
@app.route('/agents/<agent_id>/positions.json')
def agents_positions(agent_id: str):
    backend = os.getenv('ORCHESTRATOR', 'memory').lower()
    if backend != 'docker':
        return jsonify({"positions": []}), 200
    port = orchestrator.host_port(agent_id)
    if not port:
        return jsonify({"positions": []}), 200
    try:
        resp = requests.get(f'http://127.0.0.1:{port}/positions', timeout=6)
        return jsonify(resp.json()), resp.status_code
    except Exception:
        return jsonify({"positions": []}), 200


# Trades proxy
@app.route('/agents/<agent_id>/trades.json')
def agents_trades(agent_id: str):
    backend = os.getenv('ORCHESTRATOR', 'memory').lower()
    if backend != 'docker':
        return jsonify({"trades": []}), 200
    port = orchestrator.host_port(agent_id)
    if not port:
        return jsonify({"trades": []}), 200
    try:
        resp = requests.get(f'http://127.0.0.1:{port}/trades', timeout=6)
        return jsonify(resp.json()), resp.status_code
    except Exception:
        return jsonify({"trades": []}), 200

# Alerts: create
@app.route('/agents/<agent_id>/alerts', methods=['POST'])
def alerts_create(agent_id: str):
    name = (request.form.get('name') or '').strip()
    metric = (request.form.get('metric') or '').strip()
    labels = (request.form.get('labels') or '').strip()
    operator = (request.form.get('operator') or 'gt').strip().lower()
    threshold_raw = (request.form.get('threshold') or '').strip()
    webhook_url = (request.form.get('webhook_url') or '').strip()
    # Basic validation
    try:
        threshold = float(threshold_raw)
    except Exception:
        threshold = None
    import json as _json
    labels_json = '{}'
    if labels:
        try:
            d = _json.loads(labels)
            if isinstance(d, dict):
                labels_json = _json.dumps(d)
        except Exception:
            labels_json = '{}'
    if not metric or threshold is None or operator not in ('gt', 'lt') or not webhook_url:
        return redirect(url_for('agents_show', agent_id=agent_id))
    enabled_flag = (request.form.get('enabled') or '').lower() in ('1', 'true', 'on', 'yes')
    db = SessionLocal()
    try:
        alert = Alert(
            id=new_agent_id(),
            agent_id=agent_id,
            name=name or f"{metric} {operator} {threshold}",
            metric=metric,
            labels_json=labels_json,
            operator=operator,
            threshold=threshold,
            webhook_url=webhook_url,
            enabled=enabled_flag,
        )
        db.add(alert)
        db.commit()
    finally:
        db.close()
    return redirect(url_for('agents_show', agent_id=agent_id))


# Alerts: delete
@app.route('/agents/<agent_id>/alerts/<alert_id>/delete', methods=['POST'])
def alerts_delete(agent_id: str, alert_id: str):
    db = SessionLocal()
    try:
        alert = db.get(Alert, alert_id)
        if alert and alert.agent_id == agent_id:
            db.delete(alert)
            db.commit()
    finally:
        db.close()
    return redirect(url_for('agents_show', agent_id=agent_id))


def _parse_prom_metrics(text: str):
    """Return list of tuples (name, labels_dict, value)."""
    out = []
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            if '{' in line and '}' in line:
                name = line.split('{', 1)[0]
                rest = line.split('{', 1)[1]
                labels_str, val_str = rest.split('}', 1)
                labels = {}
                for part in labels_str.split(','):
                    if not part:
                        continue
                    k, v = part.split('=', 1)
                    labels[k.strip()] = v.strip().strip('"')
                value = float(val_str.strip())
                out.append((name, labels, value))
            else:
                # no labels metric
                parts = line.split()
                if len(parts) == 2:
                    out.append((parts[0], {}, float(parts[1])))
        except Exception:
            continue
    return out


# Alerts: check now
@app.route('/agents/<agent_id>/alerts/check', methods=['POST'])
def alerts_check(agent_id: str):
    # fetch metrics
    try:
        mresp = requests.get(url_for('agents_metrics', agent_id=agent_id, _external=True), timeout=5)
        text = mresp.text if mresp.status_code == 200 else ''
    except Exception:
        text = ''
    series = parse_prom_metrics(text)
    # Load alerts
    db = SessionLocal()
    results = []
    try:
        alerts = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.enabled == True).all()  # noqa: E712
        import json as _json
        from datetime import timedelta
        cooldown = int(os.getenv('ALERTS_SCHED_COOLDOWN_SEC', '300') or '300')
        backoff_base = int(os.getenv('ALERTS_BACKOFF_BASE_SEC', '30') or '30')
        backoff_max = int(os.getenv('ALERTS_BACKOFF_MAX_SEC', '3600') or '3600')
        now = datetime.utcnow()
        for al in alerts:
            try:
                filters = _json.loads(al.labels_json) if al.labels_json else {}
            except Exception:
                filters = {}
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
                if not trig:
                    continue
                label_key = _json.dumps(labels or {}, sort_keys=True)
                cd = db.query(AlertCooldown).filter(AlertCooldown.alert_id == al.id, AlertCooldown.label_key == label_key).first()
                if cd and cd.next_allowed_at and cd.next_allowed_at > now:
                    results.append({"alert": al.id, "sent": False, "skipped": True, "reason": "cooldown"})
                    continue
                payload = {
                    "agent_id": agent_id,
                    "alert_id": al.id,
                    "metric": al.metric,
                    "operator": al.operator,
                    "threshold": al.threshold,
                    "match": {"labels": labels, "value": value},
                }
                allowed, reason = is_webhook_allowed(al.webhook_url)
                status_code = None
                success = False
                error_msg = None
                if not allowed:
                    error_msg = reason or 'blocked'
                    try:
                        alert_webhook_attempts_total.labels(result='blocked').inc()
                        alert_webhook_attempts_by_alert_total.labels(agent_id=agent_id, alert_id=al.id, result='blocked').inc()
                    except Exception:
                        pass
                else:
                    t0 = time.monotonic()
                    try:
                        headers = build_hmac_headers(payload)
                        wh = requests.post(al.webhook_url, json=payload, headers=headers, timeout=5)
                        status_code = wh.status_code
                        success = (200 <= wh.status_code < 300)
                    except Exception as e:
                        error_msg = str(e)
                    finally:
                        try:
                            dt = max(0.0, time.monotonic() - t0)
                            alert_webhook_duration_seconds.observe(dt)
                            alert_webhook_duration_by_alert_seconds.labels(agent_id=agent_id, alert_id=al.id).observe(dt)
                        except Exception:
                            pass
                    try:
                        res = 'success' if success else 'error'
                        alert_webhook_attempts_total.labels(result=res).inc()
                        alert_webhook_attempts_by_alert_total.labels(agent_id=agent_id, alert_id=al.id, result=res).inc()
                    except Exception:
                        pass
                # Update cooldown/backoff
                if not cd:
                    cd = AlertCooldown(id=new_agent_id(), alert_id=al.id, label_key=label_key)
                if success:
                    cd.failure_count = 0
                    cd.next_allowed_at = now + timedelta(seconds=cooldown)
                else:
                    fc = int(cd.failure_count or 0) + 1
                    cd.failure_count = fc
                    delay = min(backoff_max, backoff_base * (2 ** min(fc, 10)))
                    cd.next_allowed_at = now + timedelta(seconds=delay)
                db.add(cd)
                # Update last fired and add event
                al.last_fired_at = now
                db.add(al)
                try:
                    evt = AlertEvent(
                        id=new_agent_id(),
                        agent_id=agent_id,
                        alert_id=al.id,
                        metric=al.metric,
                        labels_json=label_key,
                        value=float(value),
                        success=success,
                        status_code=status_code,
                        error=error_msg,
                    )
                    db.add(evt)
                except Exception:
                    pass
                db.commit()
                results.append({"alert": al.id, "sent": bool(success), "status": status_code, "error": error_msg})
        return jsonify({"results": results})
    finally:
        db.close()


# Runner health proxy (liveness/readiness)
@app.route('/agents/<agent_id>/health.json')
def agents_health(agent_id: str):
    backend = os.getenv('ORCHESTRATOR', 'memory').lower()
    if backend != 'docker':
        return jsonify({"live": False, "ready": False, "port": None}), 200
    port = orchestrator.host_port(agent_id)
    if not port:
        return jsonify({"live": False, "ready": False, "port": None}), 200
    live = False
    ready = False
    try:
        r = requests.get(f'http://127.0.0.1:{port}/healthz', timeout=2)
        live = (r.status_code == 200)
    except Exception:
        live = False
    try:
        r = requests.get(f'http://127.0.0.1:{port}/readyz', timeout=2)
        ready = (r.status_code == 200)
    except Exception:
        ready = False
    return jsonify({"live": live, "ready": ready, "port": port}), 200


# Per-credential test
@app.route('/agents/<agent_id>/credentials/<cred_id>/test.json')
def credentials_test(agent_id: str, cred_id: str):
    db = SessionLocal()
    try:
        cred = db.get(Credential, cred_id)
    finally:
        db.close()
    if not cred or cred.agent_id != agent_id:
        return jsonify({"error": "not found"}), 404
    try:
        data = decrypt_dict(cred.data_encrypted)
    except Exception:
        return jsonify({"error": "decrypt failed"}), 400

    if cred.ctype == 'evm_rpc':
        # Test each URL with eth_chainId
        results = []
        urls = data.get('urls') or []
        ok = 0
        for u in urls:
            try:
                resp = requests.post(u, json={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}, timeout=5)
                if resp.status_code == 200 and isinstance(resp.json(), dict) and "result" in resp.json():
                    ok += 1
                    results.append({"url": u, "ok": True, "chainId": resp.json().get("result")})
                else:
                    results.append({"url": u, "ok": False, "status": resp.status_code})
            except Exception as e:
                results.append({"url": u, "ok": False, "error": str(e)})
        return jsonify({"type": "evm_rpc", "total": len(urls), "ok": ok, "results": results})

    if cred.ctype == 'cex':
        # Use ccxt to test connectivity
        out = {"type": "cex"}
        try:
            import ccxt  # type: ignore
        except Exception as e:
            out.update({"error": f"ccxt not available: {e}"})
            return jsonify(out), 500
        ex = (data.get('exchange') or '').lower()
        if not ex or not hasattr(ccxt, ex):
            return jsonify({"type": "cex", "error": f"unknown exchange: {ex}"}), 400
        api_key = data.get('api_key') or ''
        api_secret = data.get('api_secret') or ''
        passphrase = data.get('passphrase') or ''
        klass = getattr(ccxt, ex)
        exchange = klass({
            "apiKey": api_key,
            "secret": api_secret,
            "password": passphrase or None,
            "enableRateLimit": True,
        })
        status = None
        try:
            if hasattr(exchange, 'fetch_status'):
                status = exchange.fetch_status()
        except Exception as e:
            status = {"error": str(e)}
        private_ok = False
        bal = None
        if api_key and api_secret:
            try:
                bal = exchange.fetch_balance()
                private_ok = True
            except Exception as e:
                bal = {"error": str(e)}
        return jsonify({"type": "cex", "exchange": ex, "public_status": status, "private_ok": private_ok, "balance": bal})

    return jsonify({"error": "unsupported type"}), 400


@app.route('/agents/<agent_id>/metrics.txt')
def agents_metrics(agent_id: str):
    backend = os.getenv('ORCHESTRATOR', 'memory').lower()
    if backend != 'docker':
        return Response("agent_up 0\n", mimetype='text/plain')
    port = orchestrator.host_port(agent_id)
    if not port:
        return Response("agent_up 0\n", mimetype='text/plain')
    try:
        resp = requests.get(f'http://127.0.0.1:{port}/metrics', timeout=3)
        return Response(resp.text, mimetype='text/plain')
    except Exception:
        return Response("agent_up 0\n", mimetype='text/plain')


@app.route('/agents/<agent_id>/cex.json')
def agents_cex(agent_id: str):
    backend = os.getenv('ORCHESTRATOR', 'memory').lower()
    if backend != 'docker':
        return jsonify({"error": "cex unavailable"}), 404
    port = orchestrator.host_port(agent_id)
    if not port:
        return jsonify({"error": "runner port unknown"}), 404
    try:
        resp = requests.get(f'http://127.0.0.1:{port}/cex', timeout=12)
        return jsonify(resp.json()), resp.status_code
    except Exception:
        return jsonify({"error": "runner not reachable"}), 502

if __name__ == "__main__":
    app.run(debug=True)
