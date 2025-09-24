import os
import time
import requests
from flask import Flask, render_template, request, redirect, url_for, Response, stream_with_context, jsonify
from models import Agent, SessionLocal, init_db, new_agent_id, Credential, Alert
from security import encrypt_dict, decrypt_dict
from orchestrator import orchestrator

app = Flask(__name__)

# Initialize database
init_db()

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
            runtime_status_map[a.id] = orchestrator.status(a.id)
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
    for a in agents:
        try:
            runtime[a.id] = orchestrator.status(a.id)
            ports[a.id] = orchestrator.host_port(a.id)
        except Exception:
            runtime[a.id] = a.status
            ports[a.id] = None
    return render_template('admin/index.html', backend=backend, agent_image=agent_image, agents=agents, runtime=runtime, ports=ports)


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
            except Exception:
                ports = {}
            out['containers'].append({
                'id': c.id[:12],
                'name': name,
                'status': c.status,
                'image': getattr(c.image, 'tags', [''])[0] if getattr(c, 'image', None) else '',
                'ports': ports,
            })
    except Exception as e:
        out['error'] = str(e)
    return jsonify(out)


@app.route('/admin/agents/start_all', methods=['POST'])
def admin_start_all():
    db = SessionLocal()
    try:
        agents = db.query(Agent).all()
        for agent in agents:
            # reuse logic from agents_start
            env = {
                "STRATEGY": agent.strategy or "custom",
                "CONFIG_JSON": agent.config or "{}",
                "AGENT_NAME": agent.name,
                "HEALTH_PORT": "8000",
                "KEYSTORE_PATH": "/data",
            }
            # credentials env
            from security import decrypt_dict as _dec
            evm_urls = []
            cex_env = {}
            creds = db.query(Credential).filter(Credential.agent_id == agent.id).all()
            for cred in creds:
                try:
                    data = _dec(cred.data_encrypted)
                except Exception:
                    data = {}
                if cred.ctype == 'evm_rpc':
                    urls = data.get('urls')
                    if isinstance(urls, list):
                        evm_urls.extend([u for u in urls if isinstance(u, str) and u])
                elif cred.ctype == 'cex' and not cex_env:
                    cex_env = {
                        "CEX_EXCHANGE": str(data.get('exchange', '')),
                        "CEX_API_KEY": str(data.get('api_key', '')),
                        "CEX_API_SECRET": str(data.get('api_secret', '')),
                    }
                    if data.get('passphrase'):
                        cex_env["CEX_API_PASSPHRASE"] = str(data.get('passphrase'))
            if evm_urls:
                import json as _json
                env["EVM_RPC_URLS"] = _json.dumps(evm_urls)
            if cex_env:
                env.update(cex_env)
            try:
                orchestrator.start(agent.id, env=env)
                agent.status = 'running'
                db.add(agent)
            except Exception:
                pass
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
                agent.status = 'stopped'
                db.add(agent)
            except Exception:
                pass
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
            env = {
                "STRATEGY": agent.strategy or "custom",
                "CONFIG_JSON": agent.config or "{}",
                "AGENT_NAME": agent.name,
                "HEALTH_PORT": "8000",
                "KEYSTORE_PATH": "/data",
            }
            evm_urls = []
            cex_env = {}
            creds = db.query(Credential).filter(Credential.agent_id == agent.id).all()
            for cred in creds:
                try:
                    data = _dec(cred.data_encrypted)
                except Exception:
                    data = {}
                if cred.ctype == 'evm_rpc':
                    urls = data.get('urls')
                    if isinstance(urls, list):
                        evm_urls.extend([u for u in urls if isinstance(u, str) and u])
                elif cred.ctype == 'cex' and not cex_env:
                    cex_env = {
                        "CEX_EXCHANGE": str(data.get('exchange', '')),
                        "CEX_API_KEY": str(data.get('api_key', '')),
                        "CEX_API_SECRET": str(data.get('api_secret', '')),
                    }
                    if data.get('passphrase'):
                        cex_env["CEX_API_PASSPHRASE"] = str(data.get('passphrase'))
            if evm_urls:
                env["EVM_RPC_URLS"] = _json.dumps(evm_urls)
            if cex_env:
                env.update(cex_env)
            try:
                orchestrator.delete(agent.id)
                orchestrator.start(agent.id, env=env)
                agent.status = 'running'
                db.add(agent)
            except Exception:
                pass
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
    except Exception:
        runtime_status_map = {a.id: a.status for a in agents}
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

    if not name:
        return redirect(url_for('agents_new'))
    # Validate config JSON if provided
    if config:
        import json as _json
        try:
            _json.loads(config)
        except Exception:
            # Re-render form with error and prefilled values
            return render_template('agents/new.html', error_msg='Invalid JSON in config. Please provide valid JSON.', name=name, strategy=strategy, config=config, exchange=exchange)

    # Merge exchange into config JSON if provided
    if config:
        import json as _json
        try:
            cfg = _json.loads(config)
            if not isinstance(cfg, dict):
                cfg = {}
        except Exception:
            cfg = {}
    else:
        cfg = {}
    if exchange:
        cfg['exchange'] = exchange
    try:
        import json as _json
        config = _json.dumps(cfg)
    except Exception:
        pass

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
    finally:
        db.close()
    if not agent:
        return redirect(url_for('agents_index'))
    runtime_status = orchestrator.status(agent_id)
    # published port for runner endpoints (docker backend only)
    host_port = orchestrator.host_port(agent_id) if os.getenv('ORCHESTRATOR', 'memory').lower() == 'docker' else None
    # parse exchange from config JSON
    exchange_val = ''
    if agent and agent.config:
        try:
            import json as _json
            cfg = _json.loads(agent.config)
            if isinstance(cfg, dict):
                exchange_val = str(cfg.get('exchange') or '')
        except Exception:
            exchange_val = ''
    return render_template('agents/show.html', agent=agent, runtime_status=runtime_status, credentials=credentials, alerts=alerts, host_port=host_port, exchange_val=exchange_val)


# Agents: update (strategy/config) and optional redeploy
@app.route('/agents/<agent_id>/update', methods=['POST'])
def agents_update(agent_id: str):
    strategy = request.form.get('strategy', 'custom')
    config = request.form.get('config', '')
    new_name = (request.form.get('name') or '').strip()
    exchange = (request.form.get('exchange') or '').strip()
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
            runtime_status = orchestrator.status(agent_id)
            host_port = orchestrator.host_port(agent_id) if os.getenv('ORCHESTRATOR', 'memory').lower() == 'docker' else None
            # compute exchange_val from posted exchange or invalid config best-effort
            exchange_val = exchange or ''
            if not exchange_val:
                try:
                    cfg_try = _json.loads(config)
                    if isinstance(cfg_try, dict):
                        exchange_val = str(cfg_try.get('exchange') or '')
                except Exception:
                    exchange_val = ''
            return render_template('agents/show.html', agent=agentv, runtime_status=runtime_status, credentials=credsv, host_port=host_port, error_msg='Invalid JSON in config. Please provide valid JSON.', exchange_val=exchange_val)
    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        if not agent:
            return redirect(url_for('agents_index'))
        if new_name:
            agent.name = new_name
        agent.strategy = strategy
        # Merge exchange into config JSON
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
            # if exchange empty, remove key if exists
            merged_config.pop('exchange', None)
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
                env = {
                    "STRATEGY": agent2.strategy or "custom",
                    "CONFIG_JSON": agent2.config or "{}",
                    "AGENT_NAME": agent2.name,
                    "HEALTH_PORT": "8000",
                    "KEYSTORE_PATH": "/data",
                }
                # credentials env
                evm_urls = []
                cex_env = {}
                creds = db2.query(Credential).filter(Credential.agent_id == agent_id).all()
                for cred in creds:
                    try:
                        data = decrypt_dict(cred.data_encrypted)
                    except Exception:
                        data = {}
                    if cred.ctype == 'evm_rpc':
                        urls = data.get('urls')
                        if isinstance(urls, list):
                            evm_urls.extend([u for u in urls if isinstance(u, str) and u])
                    elif cred.ctype == 'cex' and not cex_env:
                        cex_env = {
                            "CEX_EXCHANGE": str(data.get('exchange', '')),
                            "CEX_API_KEY": str(data.get('api_key', '')),
                            "CEX_API_SECRET": str(data.get('api_secret', '')),
                        }
                        if data.get('passphrase'):
                            cex_env["CEX_API_PASSPHRASE"] = str(data.get('passphrase'))
                if evm_urls:
                    import json as _json
                    env["EVM_RPC_URLS"] = _json.dumps(evm_urls)
                if cex_env:
                    env.update(cex_env)
                # restart
                orchestrator.delete(agent_id)
                orchestrator.start(agent_id, env=env)
                agent2.status = 'running'
                db2.add(agent2)
                db2.commit()
        finally:
            db2.close()
        return redirect(url_for('agents_show', agent_id=agent_id))
    return redirect(url_for('agents_show', agent_id=agent_id))


# Agents: start (stub)
@app.route('/agents/<agent_id>/start', methods=['POST'])
def agents_start(agent_id: str):
    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        if agent:
            # Update runtime orchestrator and persist desired state
            env = {
                "STRATEGY": agent.strategy or "custom",
                "CONFIG_JSON": agent.config or "{}",
                "AGENT_NAME": agent.name,
                "HEALTH_PORT": "8000",
                "KEYSTORE_PATH": "/data",
            }
            # Gather credentials for env injection
            evm_urls = []
            cex_env = {}
            creds = db.query(Credential).filter(Credential.agent_id == agent_id).all()
            for cred in creds:
                try:
                    data = decrypt_dict(cred.data_encrypted)
                except Exception:
                    data = {}
                if cred.ctype == 'evm_rpc':
                    # Expect data: {"urls": ["https://..."]}
                    urls = data.get('urls')
                    if isinstance(urls, list):
                        evm_urls.extend([u for u in urls if isinstance(u, str) and u])
                elif cred.ctype == 'cex' and not cex_env:
                    # Use first CEX by default; expect data: {exchange, api_key, api_secret, passphrase?}
                    cex_env = {
                        "CEX_EXCHANGE": str(data.get('exchange', '')),
                        "CEX_API_KEY": str(data.get('api_key', '')),
                        "CEX_API_SECRET": str(data.get('api_secret', '')),
                    }
                    if data.get('passphrase'):
                        cex_env["CEX_API_PASSPHRASE"] = str(data.get('passphrase'))
            if evm_urls:
                import json as _json
                env["EVM_RPC_URLS"] = _json.dumps(evm_urls)
            if cex_env:
                env.update(cex_env)
            orchestrator.start(agent_id, env=env)
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
            env = {
                "STRATEGY": agent.strategy or "custom",
                "CONFIG_JSON": agent.config or "{}",
                "AGENT_NAME": agent.name,
                "HEALTH_PORT": "8000",
                "KEYSTORE_PATH": "/data",
            }
            # Add credentials env
            evm_urls = []
            cex_env = {}
            creds = db.query(Credential).filter(Credential.agent_id == agent_id).all()
            for cred in creds:
                try:
                    data = decrypt_dict(cred.data_encrypted)
                except Exception:
                    data = {}
                if cred.ctype == 'evm_rpc':
                    urls = data.get('urls')
                    if isinstance(urls, list):
                        evm_urls.extend([u for u in urls if isinstance(u, str) and u])
                elif cred.ctype == 'cex' and not cex_env:
                    cex_env = {
                        "CEX_EXCHANGE": str(data.get('exchange', '')),
                        "CEX_API_KEY": str(data.get('api_key', '')),
                        "CEX_API_SECRET": str(data.get('api_secret', '')),
                    }
                    if data.get('passphrase'):
                        cex_env["CEX_API_PASSPHRASE"] = str(data.get('passphrase'))
            if evm_urls:
                import json as _json
                env["EVM_RPC_URLS"] = _json.dumps(evm_urls)
            if cex_env:
                env.update(cex_env)

            # Recreate runtime
            orchestrator.delete(agent_id)
            orchestrator.start(agent_id, env=env)
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
            orchestrator.stop(agent_id)
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
    series = _parse_prom_metrics(text)
    # Load alerts
    db = SessionLocal()
    results = []
    try:
        alerts = db.query(Alert).filter(Alert.agent_id == agent_id).all()
    finally:
        db.close()
    import json as _json
    for al in alerts:
        try:
            filters = _json.loads(al.labels_json) if al.labels_json else {}
        except Exception:
            filters = {}
        matched = []
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
                matched.append({"labels": labels, "value": value})
        if matched:
            # Fire webhook for each match (simple MVP)
            payload = {
                "agent_id": agent_id,
                "alert_id": al.id,
                "metric": al.metric,
                "operator": al.operator,
                "threshold": al.threshold,
                "matches": matched,
            }
            try:
                wh = requests.post(al.webhook_url, json=payload, timeout=5)
                results.append({"alert": al.id, "sent": True, "status": wh.status_code, "count": len(matched)})
            except Exception as e:
                results.append({"alert": al.id, "sent": False, "error": str(e)})
        else:
            results.append({"alert": al.id, "sent": False, "count": 0})
    return jsonify({"results": results})


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
